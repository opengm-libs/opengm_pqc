use crate::mldsa::Q;

#[inline(always)]
fn mul_q(a: i32) -> i32 {
    // a * Q;
    (a << 23) - (a << 13) + a
}

// let |a| <= 2^31*q, output r = a/2^32 mod q with |r| < 2q:
// |r| = |a - tq|/2^32 <= (|a| + |tq|)/2^32 <= (2^31 + |t|)/2^32 * q < 1.5q
//
// NOTE: here use q^-1 instead of -q^-1 (c.f., HAC) is because
// -q^-1 mod 2^32 = 4236238847 overflow for int32
#[inline]
pub(crate) fn mont_reduce(a: i64) -> i32 {
    const qinv: i32 = 58728449;
    let t = (a as i32).wrapping_mul(qinv); // ((a mod R) * qint) mod R

    if true {
        let tq = (t as i64) * (Q as i64);
        let r = a - tq;
        (r >> 32) as i32
    } else {
        // The following does the same thing.
        // tq_low = a mod R;
        let (_, tq_hi) = t.widening_mul(Q);
        ((a >> 32) as i32) - tq_hi
    }
}

#[inline]
pub(crate) fn mont_mul(a: i32, b: i32) -> i32 {
    return mont_reduce((a as i64) * (b as i64));
}


// For any i32 a <= 2^31 - 2^22 - 1 (make sure a + 2^22 < 2^31, non-overflow), 
// returns r = a mod Q
// such that -Q < -6283008 <= r <= 6283008 < Q
#[inline]
pub(crate) fn reduce_i32(a: i32) -> i32 {
    // round(a/2^23), note that Q ~ 2^23
    let t = (a + (1 << 22)) >> 23;
    a - t * Q 
}


// for b in (-q,q), returns r = b mod q and r in [0,q)
#[inline]
pub(crate) fn reduce_to_positive(a: i32) -> i32 {
    a + ((a >> (i32::BITS - 1)) & Q)
}

// returns r = b mod q, r in [0,q)
pub(crate) fn mod_q(b: i32) -> i32 {
    // reduce_to_positive(barrett_reduce_i32(b))
    reduce_to_positive(reduce_i32(b))
}

// returns r = b mods q, r in (-q/2, q/2)
pub(crate) fn mods_q(b: i32) -> i32 {
    let b = reduce_i32(b); // |b| < q
    const half_q: i32 = (Q - 1) / 2;
    const neg_half_q: i32 = -(Q - 1) / 2;

    // if b < -q/2, add q
    let mask0 = ((b - neg_half_q) >> 31) & Q;
    // if b > q/2, sub q
    let mask1 = ((half_q - b) >> 31) & Q;

    b + (mask0 & Q) - (mask1 & Q)
}

#[cfg(test)]
mod tests {

    use crate::{
        mldsa::{Q, reduce::reduce_i32},
        tick::tick_counter,
    };


    #[test]
    fn test_reduce_i32() {
        // let mut rng = rand::rng();
        let a = i32::MIN as i64;
        // let b = i32::MAX as i64;
        let b = (1 << 31) - (1 << 22);
        for i in a..b {
            let x = i as i32;
            let y = reduce_i32(x);
            let z = ((x as i64) - (y as i64)) % (Q as i64);
            if y <= -Q || y >= Q {
                println!("{i}: not in range: |{y}| > {Q}");
                return;
            }
            if z != 0 {
                println!("{i}: mod unequal: {x} mod Q = {y}");
                return;
            }
        }
    }

    extern crate test;

    #[cfg(target_arch="aarch64")]
    #[test]
    fn bench_reduce_i32() {
        let begin = tick_counter();
        for i in 0..100000000 {
            test::black_box({
                reduce_i32(i);
            });
        }
        let end = tick_counter();
        println!("elapse: {}", end - begin);
    }
}
