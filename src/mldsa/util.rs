use super::rq::Rq;

#[inline(always)]
pub(crate) fn get_bits(b: &[u8], idx: usize) -> u8 {
    (b[idx / 8] >> (idx & 7)) & 1
}

#[inline(always)]
pub(crate) const fn bitlen(b: usize) -> usize {
    (usize::BITS - b.leading_zeros()) as usize
}

// Return true if |r| < upper_bound for all r in v.
// Assume r reduced, i.e., coeffs in (-q/2, q/2).
#[inline]
pub(crate) fn vec_norm_less_than(v: &[Rq], upper_bound: i32) -> bool{
    for r in v{
        let infnorm = r.norm();
        if infnorm >= upper_bound{
            return false
        }
    }
    return true

}