use crate::mlkem::reduce::{mont_mul16, mont_reduce16};

// reduce_i16 reduce any i16 to the range (-q,q)
// note: the barrett_reduce in std ref implements.
#[inline]
pub(crate) fn reduce_i16(x: i16) -> i16 {
    const rbits: usize = 13;
    const q: i16 = 3329;
    // round(R^2/q)
    const v: i16 = (((1u32 << (2 * rbits)) + q as u32 / 2) / q as u32) as i16;

    // round(x * U / R^2)
    // To provide x * u does not overflow, rbits <= 13
    let t = (((x as i32 * v as i32) + (1 << (2 * rbits - 1))) >> (2 * rbits)) as i16;
    let t = t * q;

    x - t
}

// reduce_i32 reduce x to (-q, q) use barrett reduction.
// reduce_i32 not works for all i32, but works for (-128q^2 + q, 128q^2 + q).
#[inline]
pub(crate) fn reduce_i32(x: i32) -> i16 {
    match 1 {
        1 => {
            // 4,753.78 ns/iter
            // faster, works for |x| < 128*q^2 + q.
            // Note that 128*q^2 > qR/2 for R = 2^16.

            // let y = mont_reduce16(x)
            // then |y| = | (x - (x as i16 * qinv)*q)/R|
            //          < (|x| + 2^15*2^12)/R
            //          <= (128q^2 + q + 2^27)/R
            //          < 2^15
            // and |y*rr| < qR/2,
            // thus |mont_mul16(y,rr)| < q.
            const rr: i16 = 1353; //((1u64 << 32) % Q as u64) as i16;
            let r = mont_reduce16(x); // r = x/R mod q, |r| may not < q, but it's ok
            return mont_mul16(r, rr); // Now |r| < q.
        }
        
        2 => {
            const rbits: usize = 16;
            const q: i32 = 3329;
            // round(R^2/q)
            const v: i32 = (((1u64 << (2 * rbits)) + q as u64 / 2) / q as u64) as i32;

            // round(x * U / R^2)
            // To provide x * v does not overflow, rbits <= 13
            let t = (((x as i64 * v as i64) + (1 << (2 * rbits - 1))) >> (2 * rbits)) as i32;
            let t = t * q as i32;

            (x - t) as i16
        }
        _ => {
            panic!()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mlkem::Q;

    use super::*;
    extern crate test;
    use test::Bencher;

    // cargo test --release --package opengm_pqc --lib -- mlkem::reduce::barrett_reduce::tests::test_reduce_i32 --exact --show-output 
    #[test]
    fn test_reduce_i32() {
        let q = Q as i32;
        // not need works for all i32, but for (-128q^2-q, 128q^2+q)
        // for x in i32::MIN as i64..=i32::MAX as i64 {
            for x in -128 * q * q - q..128 * q * q +q{
            let y = reduce_i32(x as i32);
            if (y as i64 - x as i64) % Q as i64 != 0 {
                println!("1: {x}, {y}, {}",(y as i64 - x as i64) % Q as i64);
                return;
            }
            if y >= Q {
                println!("2: {x}, {y}");
                return;
            }
            if y <= -Q{
                println!("3: {x}, {y}");
                return;
            }
        }
    }

    #[bench]
    fn bench_reduce_i32(b: &mut Bencher) {
        //   4,673.75 ns/iter (+/- 58.14)
        let mut y = 0i16;
        b.iter(|| {
            test::black_box({
                for x in -10000..10000 {
                    y = y.wrapping_add(reduce_i32(x));
                }
            });
        });
        // println!("{}", x);
    }

    #[bench]
    fn bench_reduce_i16(b: &mut Bencher) {
        //   4,673.75 ns/iter (+/- 58.14)
        let mut y = 0i16;
        b.iter(|| {
            test::black_box({
                for x in -10000..10000 {
                    y = y.wrapping_add(reduce_i16(x));
                }
            });
        });
        println!("{}", y);
    }
}
