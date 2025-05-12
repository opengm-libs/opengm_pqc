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
