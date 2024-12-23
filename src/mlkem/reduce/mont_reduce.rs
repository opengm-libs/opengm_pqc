use crate::mlkem::Q;

/// The ring Rq = Zq[x] / (x^n + 1) for q = 3329, n = 256.
/// zeta = 17 is the primitive nth root in Zq.

// The Montgomery params with R = 2^16.
pub(crate) const MONT_R16_BITS: usize = 16;
pub(crate) const MONT_R16: i32 = 1 << MONT_R16_BITS;
pub(crate) const QINV_MOD_R16: i16 = -3327; // q^-1 mod R

// reduce x in [-qR/2, qR/2-1] to the range [-(q-1), q-1],
#[inline]
pub(crate) fn mont_reduce16(x: i32) -> i16 {
    let t = (x as i16).wrapping_mul(QINV_MOD_R16);
    let tq = t as i32 * Q as i32;
    let y = x - tq;
    // let y = x.wrapping_sub(tq);
    let r = (y >> MONT_R16_BITS) as i16;
    r
}

// in: x,y st. |x*y| < qR/2
// |out| < q
#[inline]
pub(crate) fn mont_mul16(x: i16, y: i16) -> i16 {
    mont_reduce16(x as i32 * y as i32)
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mont_reduce() {
        // [-qR/2, qR/2-1]
        for a in -((Q as i32) << (MONT_R16_BITS - 1))..(Q as i32) << (MONT_R16_BITS - 1) {
            let r = mont_reduce16(a);
            if r >= Q || r <= -Q || (a as i64 - ((r as i64) << MONT_R16_BITS)) % Q as i64 != 0 {
                println!("{a}, {r}, {}", (a as i64 - ((r as i64) << MONT_R16_BITS)) % Q as i64);
            }
        }
    }

    #[test]
    fn test_mont_reduce_i16() {
        // mont_reduce16 works for all i32, but the result may not in (-q,q)
        for a in i32::MIN+1..i32::MAX {
            let r = mont_reduce16(a);
            if (a as i64 - ((r as i64) << MONT_R16_BITS)) % Q as i64 != 0 {
                println!("{a}, {r}, {}", (a as i64 - ((r as i64) << MONT_R16_BITS)) % Q as i64);
                return;
            }
        }
    }

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_mont_reduce16(b: &mut Bencher) {
        // test mlkem::ntt::tests::bench_mont_reduce16       ... bench:       1,922.51 ns/iter (+/- 58.14)
        let mut y = 0i16;
        b.iter(|| {
            test::black_box({
                for x in -10000..10000 {
                    y = y.wrapping_add(mont_reduce16(x));
                }
            });
        });
        // println!("{}", x);
    }
}