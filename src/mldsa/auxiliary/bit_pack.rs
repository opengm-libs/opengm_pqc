use crate::mldsa::{rq::Rq, util::bitlen};

use super::simple_bit_pack::{simple_bit_pack, simple_bit_unpack};

// BITLEN = bitlen(a+b)
// |w| in [-a,b]
#[inline]
pub(crate) fn bit_pack<const a: usize, const b: usize>(v: &mut [u8], w: &Rq) {
    let mut w = w.clone();
    for wi in &mut w.coeffs {
        *wi = b as i32 - *wi;
    }
    simple_bit_pack(v,&w, bitlen(a+b));
}



// BITLEN = bitlen(a+b)
#[inline]
pub(crate) fn bit_unpack<const a: usize, const b: usize>(w: &mut Rq,v: &[u8]) {
    simple_bit_unpack(w, v, bitlen(a+b));
    for wi in &mut w.coeffs {
        *wi = b as i32 - *wi;
    }
}
