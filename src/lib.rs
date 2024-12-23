#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(incomplete_features)]

#![feature(
    test,
    bigint_helper_methods,
    generic_const_exprs
)]

#![no_std]
#![warn(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;


#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;


/// build static C lib
#[cfg(all(not(feature = "std"), feature = "build-lib"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// build static C lib
#[cfg(all(not(feature = "std"), feature = "build-lib"))]
use libc_alloc::LibcAlloc;

/// build static C lib
#[cfg(all(not(feature = "std"), feature = "build-lib"))]
#[global_allocator]
static ALLOCATOR: LibcAlloc = LibcAlloc;

pub mod sha3;
pub mod tick;

pub mod mlkem;
pub mod mldsa;

pub mod mldsa_tpc;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

#[cfg(test)]
pub fn hex_print(a: &[u8]){
    for i in a{
        print!("{:02x}",*i)
    }

}

#[cfg(test)]
pub fn hex_println(a: &[u8]){
    for i in a{
        print!("{:02x}",*i)
    }
    println!()
}