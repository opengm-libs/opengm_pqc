mod barrett_reduce;
mod mont_reduce;
mod mont19_reduce;
mod mont20_reduce;

use core::ops::Shr;

pub(crate) use mont_reduce::*;
pub(crate) use barrett_reduce::*;

use super::Q;


// add q if a <= -q
// sub q if a >= q
#[inline]
pub(crate) fn reduce_once(a: i16) -> i16 {
    // test if a > q - 1
    let b0 = (Q - 1).wrapping_sub(a);
    // test if a < -q+1
    let b1 = a.wrapping_sub(-Q + 1);

    // mask = 0xffff if bi < 0.
    let mask0 = b0.shr(i16::BITS - 1);
    let mask1 = b1.shr(i16::BITS - 1);

    a - (mask0 & Q) + (mask1 & Q)
}

// for a in (-Q, Q), reduce to [0, q).
#[inline]
pub(crate) fn reduce_to_positive(a: i16) -> i16 {
    a + ( (a >> (i16::BITS - 1)) & Q)
}