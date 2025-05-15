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

#[cfg(not(any(feature = "std", test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(feature = "std"))]
use libc_alloc::LibcAlloc;

#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOCATOR: LibcAlloc = LibcAlloc;

pub mod sha3;
pub mod tick;

pub mod mlkem;
pub mod mldsa;



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
