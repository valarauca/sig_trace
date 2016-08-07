#[macro_use] extern crate lazy_static;

extern crate libc;
use libc::{ptrace,waitpid,WIFEXITED,WIFSTOPPED,WIFSIGNALED,WSTOPSIG, WCOREDUMP};

extern crate regex;
use regex::{Regex, Captures};

extern crate kernelx64;

use std::io::SeekFrom;

use std::mem;

pub mod reg;
use reg::UserRegs;

use std::hash::{Hash, Hasher, SipHasher};


//
//Various error messages that can occur
//
pub enum TracingFault {
    PTrace(i64),
    ProcFS(::std::io::Error),
    CastError(::std::num::ParseIntError),
    CouldNotFindStack,
    ProcessExited,
    ProcessCrashed
}


//
//Very unsafe way of convert a buffer to a string slice
//
fn buffer_to_str<'a>( buffer: &'a [u8], new_len: usize ) -> &'a str {
    let mut tup = (0usize,0usize);
    let buffer_slice: (usize,usize) = unsafe{ mem::transmute( buffer ) };
    tup.0 = buffer_slice.0;
    tup.1 = new_len;
    unsafe{ mem::transmute(tup) }
}

//
//Clear buffer
//
fn clear_buffer( buffer: &mut [u8] ) {
    for index in 0..2000000 {
        buffer[index] = 0u8
    }
}

//
//Allocate Buffer
//
fn allocate_buffer<'a>() -> &'a mut [u8] {
    let mut v = Vec::with_capacity(2000000);
    for _ in 0..2000000 {
        v.push(0u8)
    }
    let mut tup = (0usize,0usize);
    tup.1 = 2000000;
    let ptr: *const u8 = v.as_slice().as_ptr();
    tup.0 = unsafe{ mem::transmute( ptr ) };
    unsafe{ mem::transmute(tup)}
}
#[test]
fn test_allocate_buffer() {
    let heap_slice = allocate_buffer();
    assert_eq!( heap_slice.len(), 2000000 );
    assert_eq!( heap_slice[0], 0u8 );
    assert_eq!( heap_slice[10], 0u8 );
    assert_eq!( heap_slice[100], 0u8 );
    assert_eq!( heap_slice[1000], 0u8 );
    assert_eq!( heap_slice[10000], 0u8 );
    assert_eq!( heap_slice[100000], 0u8 );
    assert_eq!( heap_slice[1000000], 0u8 );
    assert_eq!( heap_slice[1999999], 0u8 );
}

//
//Read Proc FS File System
//
fn read_maps( fd: i32, buffer: &mut [u8] ) -> Result<usize,TracingFault> {
    clear_buffer( buffer );
    //get size of proc_maps
    let len = match kernelx64::fsize( fd ) {
        Ok(x) => x as usize,
        Err(e) => return Err(TracingFault::ProcFS(e))
    };
    //read into buffer
    match kernelx64::safe_read( fd, buffer, len ) {
        Ok(_) => { },
        Err(e) => return Err(TracingFault::ProcFS(e))
    };
    Ok(len)
}

//
//Find Stack Location
//
fn find_stack( proc_maps_data: &str ) -> Result<(u64,u64),TracingFault> {
    //build regex at compile time to search for stack
    lazy_static! {
        static ref RE: Regex = Regex::new(r"([\dabcdef]{12})-([\dabcdef]{12}).+\[stack\]").unwrap();
    }
    //search for stack line in the proc/PID/maps data
    match RE.captures( &proc_maps_data ) {
        Option::Some(c) => match c.at(1) {
            Option::Some(stack_lo_str) => match c.at(2) {
                Option::Some(stack_hi_str) => match u64::from_str_radix( stack_lo_str, 16 ) {
                    Ok(stack_low) => match u64::from_str_radix( stack_hi_str, 16 ) {
                        Ok(stack_high) => Ok( (stack_low,stack_high) ),
                        Err(e) => Err(TracingFault::CastError(e))
                    },
                    Err(e) => Err(TracingFault::CastError(e))
                },
                _ => Err(TracingFault::CouldNotFindStack)
            },
            _ => Err(TracingFault::CouldNotFindStack)
        },
        _ => Err(TracingFault::CouldNotFindStack)
    }
}

//
//Find all RWX Allocations
//
fn find_rwx<'a>( proc_maps_data: &'a str, rwx_allocs: &mut Vec<(u64,u64)> ) {
    //build regex at compile time to search for stack
    lazy_static! {
        static ref RE: Regex = Regex::new(r"([\wabcdef]{12})-([\wabcdef]{12}) rwx").unwrap();
    }
    //empty the table
    rwx_allocs.clear();
    //build a lambda to find captures
    let caps = | line: &'a str | -> Option<Captures<'a>> {
        RE.captures(line)
    };
    //convert captures to a parsed int
    let alloc = | c: Captures<'a> | -> Option<(u64,u64)> {
        match u64::from_str_radix( c.at(1).unwrap(), 16 ) {
            Ok(low) => match u64::from_str_radix( c.at(2).unwrap(),16 ) {
                Ok(high) => Some( (low,high) ),
                _ => None
            },
            _ => None
        }
    };
    //loop over the data
    for a in proc_maps_data.lines().filter_map( caps ).filter_map( alloc ) {
        rwx_allocs.push( a );
    }
}

//
//Read proc FS memory allocation
//
//      Returns the pointer's offset within the read memory (from index[0])
//
fn read_memory_allocation( fd: i32, alloc_lo: u64, alloc_hi: u64, ptr: u64, buffer: &mut [u8] ) -> Result<u64, TracingFault> {
    //clear the buffer
    clear_buffer( buffer );
    //find size of allocation
    let len_of_alloc = alloc_hi - alloc_lo;
    //seek to start of read
    match kernelx64::fseek( fd, SeekFrom::Start(alloc_lo)) {
        Ok(_) => { },
        Err(e) => return Err(TracingFault::ProcFS(e))
    };
    //ensure allocation is smaller then buffer
    if len_of_alloc <= 2000000 {
        //read data
        match kernelx64::safe_read( fd, buffer, len_of_alloc as usize ) {
            Ok(_) => Ok( ptr-alloc_lo),
            Err(e) => Err(TracingFault::ProcFS(e))
        }
    } else {
        //build tenative start/end markers
        let initial_start = ptr - 1000000;
        let initial_end = ptr + 1000000;
        //check if these are still within allocation
        if (initial_end <= alloc_hi) & (initial_start>=alloc_lo) {
            //seek to start of allocation slab
            match kernelx64::fseek( fd, SeekFrom::Start(initial_start) ) {
                Ok(_) => { },
                Err(e) => return Err(TracingFault::ProcFS(e))
            };
            //read the slab
            match kernelx64::safe_read( fd, buffer, 2000000 ) {
                Ok(_) => Ok( ptr + 1000000 ),
                Err(e) => Err(TracingFault::ProcFS(e))
            }
        } else if initial_end > alloc_hi && ( (initial_start - (initial_end - alloc_hi)) >= alloc_lo ) {
            let delta = initial_end  - alloc_hi;
            let initial_start = initial_start - delta;
            let initial_end = initial_end - delta;
            let len = (initial_end - initial_start) as usize;
            //seek to start of allocation slab
            match kernelx64::fseek( fd, SeekFrom::Start(initial_start) ) {
                Ok(_) => { },
                Err(e) => return Err(TracingFault::ProcFS(e))
            };
            //read the slab
            match kernelx64::safe_read( fd, buffer, len ) {
                Ok(_) => Ok( ptr + 1000000 ),
                Err(e) => Err(TracingFault::ProcFS(e))
            }
        } else {
            let delta = alloc_lo - initial_start;
            let initial_start = initial_start + delta;
            let initial_end = initial_end + delta;
            let len = (initial_end - initial_start) as usize;
            //seek to start of allocation slab
            match kernelx64::fseek( fd, SeekFrom::Start(initial_start) ) {
                Ok(_) => { },
                Err(e) => return Err(TracingFault::ProcFS(e))
            };
            //read the slab
            match kernelx64::safe_read( fd, buffer, len ) {
                Ok(_) => Ok( ptr + 1000000 ),
                Err(e) => Err(TracingFault::ProcFS(e))
            }
        }

    }
}


//
//Hashes a string
//
pub fn hash_str( buffer: &str ) -> (u64,u64) {
    let mut s = SipHasher::new();
    buffer.hash( &mut s );
    let key_0 = s.finish();
    let mut s = SipHasher::new_with_keys( 0, key_0 );
    buffer.hash( &mut s );
    let key_1 = s.finish();
    (key_0,key_1)
}



//
//Tracing Class:
//
//      The goal of this class is to trace a process and guess when a system call
//      is a malicious
//
#[repr(C)]
pub struct Tracing<'a> {
    pub pid: i32,
    pub proc_maps_fd: i32,
    pub proc_mems_fd: i32,
    pub padding: u32,
    pub proc_maps_hash_0: u64,
    pub proc_maps_hash_1: u64,
    pub stack_lo: u64,
    pub stack_hi: u64,
    pub buffer: &'a mut [u8],
    pub rwx: Vec<(u64,u64)>,
    pub reg: UserRegs,
}


impl<'a> Tracing<'a> {

    //
    //Constructor
    //
    //      Seize a process and start ptracing it.
    //
    //      This function handles allocating any buffers that'll be used later. It also does some
    //      background work. Namely:
    //          -Seize a PID
    //          -open PID's /proc/$PID/maps file (list of all virtual memory allocations)
    //          -build a 64bit hash of the /proc/$PID/maps file
    //          -Find seized process stack's allocation TOP/BOTTOM
    //          -scan seized process allocations for those flagged RWX, note their start/end
    //              in virtual memory
    //
    pub fn seize<'new>( pid: i32 ) -> Result<Tracing<'new>,TracingFault> {
        //ptrace(PTRACE_SEIZE,0,0,PTRACE_O_TRACESYSGOOD) on x86_64 linux
        let ret = unsafe{ ptrace( 16902, pid,0,1) };
        //check if error exists
        if ret != 0 {
            return Err(TracingFault::PTrace(ret));
        }
        //allocate the read buffer
        let mut read_buffer = allocate_buffer();
        //start by building a memory map of the file
        let maps_path = format!("/proc/{}/maps\x00", pid);
        let mems_path = format!("/proc/{}/mem\x00", pid );
        //open maps_fd
        let maps_fd = match ::kernelx64::ExtOpenOptions::new().direct().open( &maps_path ) {
            Ok(x) => x as i32,
            Err(e) => return Err(TracingFault::ProcFS(e))
        };
        //open mem_fd
        let mems_fd = match ::kernelx64::ExtOpenOptions::new().direct().open( &mems_path ) {
            Ok(x) => x as i32,
            Err(e) => return Err(TracingFault::ProcFS(e))
        };
        //allocate buffer for RWX data (8KB)
        let mut rwx_alloc = Vec::<(u64,u64)>::with_capacity(500);
        //attempt to read ptracing process's allocation data
        let len_of_maps = match read_maps(maps_fd, &mut read_buffer) {
            Ok(x) => x,
            Err(e) => return Err(e)
        };
        //fetch stack data
        let stack = match find_stack( buffer_to_str(read_buffer,len_of_maps) ) {
            Ok(x) => x,
            Err(e) => return Err(e)
        };
        //fetch rwx allocations
        find_rwx( buffer_to_str(read_buffer,len_of_maps), &mut rwx_alloc );
        //hash the data from the /proc/PID/maps
        let proc_map = hash_str( buffer_to_str( &read_buffer, len_of_maps ) );
        //everything was OK we can return
        Ok( Tracing{
            pid: pid,
            proc_maps_fd: maps_fd,
            proc_mems_fd: mems_fd,
            padding: 0u32,
            proc_maps_hash_0: proc_map.0,
            proc_maps_hash_1: proc_map.1,
            stack_lo: stack.0,
            stack_hi: stack.1,
            buffer: read_buffer,
            rwx: rwx_alloc,
            reg: UserRegs::default(),
        })
    }

    //
    //Read Registers
    //
    //      When a process is haulted by PTrace on a system call. An additional PTrace system call
    //      can be fired to clone a snap shot of it's registers at time of the systemcall, this
    //      structure is also used by the kernel to figure out WTH the program is attempting
    //      to accomplish.
    //
    //      Once this structure is cloned it can be inspected for malicious behavior
    //
    pub fn get_regs( &mut self ) -> Result<(),TracingFault> {
        //ptrace(PTRACE_GETREGS, pid, 0, *user_regs_struct); on x86_64 linux
        let ret = unsafe{ ptrace( 12, self.pid, 0, &self.reg) };
        if ret == 0 {
            Ok(())
        } else {
            Err(TracingFault::PTrace(ret))
        }
    }

    //
    //Re-Build map
    //
    //      A Process may allocate new memory, or free old memory. It could also re-size it's
    //      stack. This function rebuilds the current information about the PID's memory
    //      we're tracing... If it is necessary. If the hash of /proc/$PID/maps hasn't changed
    //      no rebuilding is done.
    //
    pub fn rebuild_mem_maps( &mut self ) -> Result< (), TracingFault> {

        // get current hash of the /proc/PID/maps data
        let hash0 = self.proc_maps_hash_0;
        let hash1 = self.proc_maps_hash_1;
        //zero buffer
        clear_buffer( &mut self.buffer );
        //read the /proc/PID/maps data
        let proc_maps_len = match read_maps( self.proc_maps_fd, &mut self.buffer ) {
            Ok(x) => x,
            Err(e) => return Err(e)
        };
        //get a hash of the value
        let hash = hash_str( buffer_to_str(self.buffer,proc_maps_len) );
        //test for changes
        if (hash0==hash.0)&&(hash1==hash.1) {
            Ok( () )
        } else {
            //update the hash value
            self.proc_maps_hash_1 = hash.1;
            self.proc_maps_hash_0 = hash.0;
            //rebuild rwx allocations
            find_rwx( buffer_to_str(self.buffer,proc_maps_len), &mut self.rwx );
            //rebuild the stack
            match find_stack( buffer_to_str(self.buffer,proc_maps_len) ) {
                Ok(x) => {
                    //update stack values
                    self.stack_lo = x.0;
                    self.stack_hi = x.1;
                    Ok( () )
                },
                Err(e) => Err(e)
            }
        }
    }

    //
    //Instruction Pointer on Stack
    //
    //      This function just checks if the value of RIP (x64 Instruction Pointer) is one the PID
    //      stack. If it is, I think there is a very high chance we have a malicious chunk of code.
    //
    pub fn rip_on_stack(&self) -> bool {
        let stck_lw = self.stack_lo;
        let stck_hi = self.stack_hi;
        let rip = self.reg.get_instruction();
        //see if instruction pointer is on stack
        (rip >=stck_lw) & (rip <= stck_hi)
    }

    //
    //Instruction pointer in RWX allocation?
    //
    //      This function scans though the RWX allocations and sees if the Instruction Pointer is
    //      within their bounds. Being in these bounds is not necessarily malicious. But it
    //      does warrent some inspection.
    //
    pub fn rip_on_rwx(&self) -> Option<(u64,u64)> {
        if self.rwx.len() > 1 {
            let rip = self.reg.get_instruction();
            let fm = | y: &(u64,u64) | -> Option<(u64,u64)> {
                if (rip >= y.0) & (rip <= y.1 ) {
                    Some( y.clone() )
                } else {
                    None
                }
            };
            //check each allocation 1 by 1
            let x: (u64,u64) = self.rwx.iter().filter_map( fm ).fold( (0u64,0u64), |_,y| y );
            if (x.0 != 0) & (x.1 != 0) {
                Some( x )
            } else {
                None
            }
        } else {
            None
        }
    }

    //
    //Wait on a system call
    //
    pub fn wait_on_syscall(&self) -> Result<(),TracingFault > {
        //create a free variable that can be passed to waitpid
        let mut status = 0i32;
        //just put PID on the stack
        let pid = self.pid;
        loop {
            //ptrace(PTRACE_SYSCALL, PID, 0,0 )
            let reg = unsafe{ ptrace(24,pid,0,0) };
            if reg > 0 {
                return Err(TracingFault::PTrace(reg));
            }
            //wait until the process that is being traced stops
            let reg = unsafe{ waitpid(pid, &mut status, 0 ) };
            //process that is being traced exited
            if unsafe{ WIFEXITED(reg) } {
                return Err(TracingFault::ProcessExited);
            }
            //process that is being traced crashed
            if unsafe{ WIFSIGNALED(reg) && WCOREDUMP(reg) } {
                return Err(TracingFault::ProcessCrashed);
            }
            //process that is being traced was paused by PTRACE
            if unsafe{ WIFSTOPPED(reg) && (( WSTOPSIG(reg) & 0x08 ) > 0) } {
                return Ok( () );
            }
        }
    }

    //
    //Read location of rip
    //
    //      Reads ~2MB memory area around the instruction pointer
    //
    pub fn read_rip_mem_area(&mut self, lo: u64, hi: u64) -> Result<u64, TracingFault> {
        read_memory_allocation( self.proc_mems_fd, lo, hi, self.reg.get_instruction(), &mut self.buffer )
    }

    //
    //Search for NOP sled
    //
    pub fn test_nop_sled( &self, ptr_offset: u64, nop_len: u64, dist: u64 ) -> bool {
        let nop = 0x90u8;
        let mut count = 0usize;
        for search in 0..dist {
            let index = (ptr_offset + search) as usize;
            if self.buffer[ index ] == nop {
                count += 1usize;
                if count >= nop_len as usize {
                    return true;
                }
            } else {
                count = 0usize;
            };
        }
        count = 0;
        for search in dist..0 {
            let index = (ptr_offset - search) as usize;
            if self.buffer[ index ] == nop {
                count += 1usize;
                if count >= nop_len as usize {
                    return true;
                }
            } else {
                count = 0usize;
            };
        }
        return false;
    }
}
