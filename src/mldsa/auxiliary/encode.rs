use core::iter::zip;

use super::{super::{rq::Rq, util::bitlen, Q}, simple_bit_pack};

pub(crate) fn w1_encode<const k: usize, const gamma2: usize>(
    b: &mut [u8; 32 * k * bitlen((Q as usize - 1) / (2 * gamma2) - 1)],
    w1: &[Rq; k],
) {
    let c: usize = bitlen((Q as usize - 1) / (2 * gamma2) - 1);
    for (b, w) in zip(b.chunks_exact_mut(32 * c), w1) {
        simple_bit_pack::simple_bit_pack(b, w, c);
    }
}