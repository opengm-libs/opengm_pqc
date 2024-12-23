use core::iter::zip;
use crate::mlkem::Q;

use super::mont_mul16;

// The Montgomery params with R = 2^19.
pub(crate) const MONT_R_BITS: usize = 20;
pub(crate) const MONT_R: i32 = 1 << MONT_R_BITS;
pub(crate) const QINV_MOD_R: i32 = -462079; // q^-1 mod R

// reduce x in [-qR/2, qR/2-1] to the range [-(q-1), q-1]
#[inline]
pub(crate) fn mont_reduce(x: i32) -> i16 {
    let t = (x.wrapping_mul(QINV_MOD_R) << (32 - MONT_R_BITS)) >> (32 - MONT_R_BITS);

    //no-overflow: |t| < R/2, and Rq/2 < 2^31
    let tq = t * Q as i32;

    if true {
        // let y = x.wrapping_sub(tq); // not work, may overflow.
        let y = x as i64 - tq as i64;
        (y >> MONT_R_BITS) as i16
    } else {
        // The equal implements, no i64 sub by hand, but slower.
        if true {
            // if borrow and y > 0, y should sub 2^32
            // if borrow and y < 0, y should add 2^32
            let (y, borrow) = x.borrowing_sub(tq, false);

            // if borrow and y > 0, z should sub 2^12, or set the high 20 bits to 1.
            // if borrow and y < 0, z should add 2^12, or set the high 20 bits to 0.
            let mut z = y >> MONT_R_BITS;

            // In all, if borrow, we just flip the high 20 bits.
            if borrow {
                z ^= (-1) << 12;
            }
            return z as i16;
        } else {
            // a mimic of i64 sub, much slow (in 64 bits platform)
            let (y, borrow) = x.borrowing_sub(tq, false);
            let (z, _) = 0i32.borrowing_sub(0, borrow);
            let w = (y >> MONT_R_BITS) ^ (z << (32 - MONT_R_BITS));
            w as i16
        }
    }
}

#[inline]
pub(crate) fn base_case_mul(a0: i16, a1: i16, b0: i16, b1: i16, mont16_gamma: i16) -> (i16, i16) {
    let c0 = mont_reduce(a0 as i32 * b0 as i32 + a1 as i32 * mont_mul16(b1, mont16_gamma) as i32);
    let c1 = mont_reduce(a0 as i32 * b1 as i32 + a1 as i32 * b0 as i32);
    (c0, c1)
}

#[inline]
pub(crate) fn ntt_dot_mul(dst: &mut [i16; 256], va: &[[i16; 256]], vb: &[[i16; 256]], ntt_mul_table: &[i16; 128]) {
    for (a, b) in zip(va, vb) {
        let mut i = 0;
        while i < 256 {
            dst[i] = mont_reduce(
                dst[i] as i32
                    + a[i] as i32 * b[i] as i32
                    + a[i + 1] as i32 * mont_mul16(b[i + 1], ntt_mul_table[i / 2]) as i32,
            );
            dst[i + 1] = mont_reduce(dst[i + 1] as i32 + a[i] as i32 * b[i + 1] as i32 + a[i + 1] as i32 * b[i] as i32);
            i += 2
        }
    }
}

#[cfg(test)]
mod tests {
    use std::i32;

    use crate::mlkem::Q;

    use super::{MONT_R_BITS, mont_reduce};

    #[test]
    fn test_sub() {
        let x = i32::MAX;
        let y = -1;
        let (z, _borrow) = x.borrowing_sub(y, false);
        println!("{x} - {y} = {z}")
    }

    #[test]
    fn test_mont_reduce() {
        // [-qR/2, qR/2-1]
        for a in -((Q as i32) << (MONT_R_BITS - 1))..(Q as i32) << (MONT_R_BITS - 1) {
            // for a in 402128896..(q as i32) << (MONT_R_BITS - 1) {
            let r = mont_reduce(a);
            if r >= Q || r <= -Q || (a as i64 - ((r as i64) << MONT_R_BITS)) % Q as i64 != 0 {
                println!("{a}, {r}, {}", (a as i64 - ((r as i64) << MONT_R_BITS)) % Q as i64);
                return;
            }
        }
    }

    extern crate test;
    use test::Bencher;
    #[bench]
    fn bench_mont_reduce(b: &mut Bencher) {
        // test mlkem::ntt::mont20::tests::bench_mont_reduce ... bench:      4,382.40 ns/iter ns/iter (+/- 467.03)
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
