
use crate::mlkem::Q;

use super::mont_mul16;

// The Montgomery params with R = 2^19.
pub(crate) const MONT_R_BITS: usize = 19;
pub(crate) const MONT_R: i32 = 1 << MONT_R_BITS;
pub(crate) const QINV_MOD_R: i32 = 62209; // q^-1 mod R

// reduce x in [-qR/2, qR/2-1] to the range [-(q-1), q-1]
#[inline]
fn mont_reduce(x: i32) -> i16 {
    let t = (x.wrapping_mul(QINV_MOD_R) << (32 - MONT_R_BITS)) >> (32 - MONT_R_BITS);

    //no-overflow: |t| < R/2, and Rq/2 < 2^31
    let tq = t * Q as i32;

    let y = x - tq;

    let r = (y >> MONT_R_BITS) as i16;
    r
}

// input t with |t| < 2*8q*8q, note that qR > 128q^2 > qR/2
#[inline]
fn mont_reduce_2x8qx8q(t: i32) -> i16 {
    // super::reduce_2q_q(mont_reduce_8qx8q(a0 as i32 * b1 as i32) + mont_reduce_8qx8q(a1 as i32 * b0 as i32))

    // |t| may be 2*8q*8q and q2^19/2 < |t| < q2^19.
    // thus if |t| > qR/2, then t -= qR/2.
    let mut t = t;
    const half_qr: i32 = (Q as i32) << (MONT_R_BITS - 1);

    // if t > qR/2 - 1, then t -= qR/2
    t -= ((half_qr - 1 - t) >> 31) & half_qr;
    // if t < -qR/2, then t += qR/2
    t += ((t + half_qr) >> 31) & half_qr;
    mont_reduce(t)
}

#[inline]
pub(crate) fn base_case_mul(a0: i16, a1: i16, b0: i16, b1: i16, mont16_gamma: i16) -> (i16, i16) {
    let c0 = mont_reduce(a0 as i32 * b0 as i32 + a1 as i32 * mont_mul16(b1, mont16_gamma) as i32);
    let c1 = mont_reduce_2x8qx8q(a0 as i32 * b1 as i32 + a1 as i32 * b0 as i32);
    (c0, c1)
}

#[cfg(test)]
mod tests {

    use crate::mlkem::Q;

    use super::{MONT_R_BITS, mont_reduce};

    #[test]
    fn test_mont_reduce() {
        // [-qR/2, qR/2-1]
        for a in -((Q as i32) << (MONT_R_BITS - 1))..(Q as i32) << (MONT_R_BITS - 1) {
            let r = mont_reduce(a);
            if r >= Q || r <= -Q || (a as i64 - ((r as i64) << MONT_R_BITS)) % Q as i64 != 0 {
                println!("{a}, {r}, {}", (a as i64 - ((r as i64) << MONT_R_BITS)) % Q as i64);
            }
        }
    }
    extern crate test;
    use test::Bencher;
    #[bench]
    fn bench_mont_reduce(b: &mut Bencher) {
        // test mlkem::ntt::mont19::tests::bench_mont_reduce ... bench:      2,399.55 ns/iter (+/- 556.16)
        let mut y = 0i16;
        b.iter(|| {
            test::black_box({
                for x in -10000..10000 {
                    y = y.wrapping_add(mont_reduce(x));
                }
            });
        });
        // println!("{}", x);
    }
}
