pub mod mldsa44;
pub mod mldsa65;
pub mod mldsa87;

pub(crate) const Q: i32 = 8380417; // 1<<23 - 1<<13 + 1
pub(crate) const N: usize = 256;
pub(crate) const d: usize = 13;

pub(crate) mod auxiliary;
pub(crate) mod errors;
pub(crate) mod hash;
pub(crate) mod internal;
pub(crate) mod reduce;
pub(crate) mod rq;
pub(crate) mod util;
