use core::panic;

use crate::mldsa::{N, Q, d, reduce::mod_q};

// input: r in Zq
// output: r = r1*2^d + r0, where r0 in [-q/2,q/2]
// Note that param d always equals 13.
pub(crate) fn power2_round(r: i32) -> (i32, i32) {
    // Assume the input r in Zq.
    let rplus = r;

    // r1 = round(r/2^d)
    let r1 = (rplus + (1 << (d - 1)) - 1) >> d;
    let r0 = rplus - (r1 << d);
    (r0, r1)
}

/// For a in i32, compute high and low bits a0, a1 such
/// a1 * (2gamma2) + a0 = a mod Q,
/// where
/// -gamma2 < a0 <= gamma2 and 0 <= a1 < m-1, m =  (Q-1)/(2gamma2),
/// or
/// -gamma2 < a0 <= 0 and a1 = 0,
///
///           Q-1-2gamma2       Q-gamma2-1   Q-gamma2      ...    Q-2      Q-1           0         
///           -----+----------------+-----------+------------------+--------+------------+------->
///         (m-1)*(2gamma2)                                              m*(2gamma2)                                  
/// (a0,a1):   (0, m-1)       (gamma2, m-1)  (-gamma2, 0)  ...   (-2,0)    (-1, 0)     (0, 0)
fn decompose<const gamma2: usize>(a: i32) -> (i32, i32) {
    // fixme
    let a = mod_q(a);

    let double_gamma2: i32 = gamma2 as i32 * 2;

    let mut a0;

    // a1 = ceil(a/2^7)
    let mut a1 = (a + 127) >> 7;

    if gamma2 as i32 == (Q - 1) / 32 {
        // 1025 = floor(2^29/(2*gamma2))
        // a1 = round( floor(a/2^7) * floor(2^29/(2*gamma2)) / 2^22 )
        //    = round(a/(2*gamma2))
        a1 = (a1 * 1025 + (1 << 21)) >> 22;

        // Q-1 = 16*(2*gamma2)
        // thus 0 <= a1 <= 16, if a1 == 16, then a1 = 0;
        a1 &= 15;
    } else {
        debug_assert!(gamma2 as i32 == (Q - 1) / 88);

        // 11275 = floor(2^31/(2*gamma2))
        a1 = (a1 * 11275 + (1 << 23)) >> 24;

        // Q-1 = 44*(2*gamma2)
        // thus 0 <= a1 <= 44, if a1 == 44 i.e., a1 > 43, then a1 = 0;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    a0 = a - a1 * double_gamma2;

    // for a1 = 1,..., m-1, -gamma2 < a0 <= gamma2;
    // for a1 = 0, a0 = Q-gamma2, Q-gamma2+1, ..., 0, 1, 2,... gamma2;

    // if a0 > (Q - gamma2 - 1), then a0 -= Q, only if when a1 = m.
    // also we can use any test number in [gamma2+1, Q-gamma2-1]
    // (Q-1)/2 is a choose for both gamma2 = (Q-1)/88 or (Q-1)/32
    //
    // a0 -= (((gamma2 as i32 + 1) - a0) >> 31) & Q;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    return (a0, a1);
}

#[inline]
pub(crate) fn high_bits<const gamma2: usize>(r: i32) -> i32 {
    let (_r0, r1) = decompose::<gamma2>(r);
    r1
}

#[inline]
pub(crate) fn low_bits<const gamma2: usize>(r: i32) -> i32 {
    let (r0, _r1) = decompose::<gamma2>(r);
    r0
}

#[inline]
pub(crate) fn make_hint<const gamma2: usize>(z: i32, r: i32) -> u8 {
    let v1 = high_bits::<gamma2>(r);
    let v2 = high_bits::<gamma2>(r + z);
    if v1 != v2 {
        1
    } else {
        0
    }
}

pub(crate) fn use_hint<const gamma2: usize>(h: u8, r: i32) -> i32 {
    debug_assert!(h == 0 || h == 1);
    let (r0, r1) = decompose::<gamma2>(r);
    if h == 0 {
        return r1;
    }

    match gamma2 {
        //  (Q-1)/32
        261888 => return if r0 > 0 { (r1 + 1) & 15 } else { (r1 - 1) & 15 },
        //  (Q-1)/88
        95232 => {
            if r0 > 0 {
                return if r1 == 43 { 0 } else { r1 + 1 };
            } else {
                return if r1 == 0 { 43 } else { r1 - 1 };
            }
        }
        _ => panic!("gamma2 invalid"),
    }

    // let m = (Q - 1) / (2 * gamma2 as i32);
    // if r0 > 0 {
    //     return (r1 + 1) % m;
    // }

    // if r0 <= 0 {
    //     //void negative: r1-1 % m = r1+(m-1) % m
    //     return (r1 + m - 1) % m;
    // }

    // return r1;
}

pub(crate) fn hint_bit_pack<const k: usize, const omega: usize>(y: &mut [u8; omega + k], h: &[[u8; N]; k]) {
    let mut index = 0;
    for i in 0..k {
        for j in 0..N {
            if h[i][j] != 0 {
                y[index] = j as u8;
                index += 1
            }
        }
        y[omega + i] = index as u8;
    }
}

pub(crate) fn hint_bit_unpack<const k: usize, const omega: usize>(h: &mut [[u8; N]; k], y: &[u8; omega + k]) -> bool {
    let mut index = 0usize;
    for i in 0..k {
        if (y[omega + i] as usize) < index || (y[omega + i] as usize) > omega {
            return false;
        }
        let first = index;
        while index < (y[omega + i] as usize) {
            if index > first {
                if y[index - 1] >= y[index] {
                    return false;
                }
            }
            h[i][y[index] as usize] = 1;
            index += 1
        }
    }
    for i in index..omega {
        if y[i] != 0 {
            return false;
        }
    }
    return true;
}

#[cfg(test)]
mod tests {

    use crate::mldsa::{Q, auxiliary::power2_round, d, reduce::mod_q};

    use super::decompose;
    #[test]
    fn test_power2round() {
        for x in 0..Q {
            let (r0, r1) = power2_round(x);
            assert!(-(1 << (d - 1)) < r0 && r0 <= (1 << (d - 1)));
            assert!((r1 << d) + r0 == x)
        }
    }

    // Input r in i32.
    // return (r0, r1) s.t. r = r1*(2*gamma2) + r0,
    // where r0 in (-gamma2, gamma2].
    pub(crate) fn decompose_naive<const gamma2: usize>(r: i32) -> (i32, i32) {
        let gamma: i32 = gamma2 as i32;

        let rplus = mod_q(r);

        let rt = rplus % (2 * gamma);
        let mut r0 = if rt > gamma2 as i32 { rt - 2 * gamma } else { rt };

        let t = rplus - r0;
        let mut r1 = t / (2 * gamma);
        if t == Q - 1 {
            r1 = 0;
            r0 -= 1
        }
        (r0, r1)
    }

    const gamma2: usize = (Q as usize - 1) / 88;

    #[test]
    fn test_decompose() {
        for x in 0..Q + 1 {
            let (r0, r1) = decompose::<{ (Q as usize - 1) / 88 }>(x as i32);
            let (t0, t1) = decompose_naive::<{ (Q as usize - 1) / 88 }>(x as i32);
            assert_eq!(r0, t0);
            assert_eq!(r1, t1);

            let (r0, r1) = decompose::<{ (Q as usize - 1) / 32 }>(x as i32);
            let (t0, t1) = decompose_naive::<{ (Q as usize - 1) / 32 }>(x as i32);
            assert_eq!(r0, t0);
            assert_eq!(r1, t1);
        }
    }

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_decompress(b: &mut Bencher) {
        let mut y = 0i32;
        b.iter(|| {
            test::black_box({
                for x in 0..Q {
                    // 13,259,645.90 ns/iter
                    let (r0, _r1) = decompose::<gamma2>(x);
                    y = y.wrapping_add(r0);
                }
            });
        });
        println!("{}", y);
    }

    #[test]
    fn test_t(){
        const gamma2: usize = (Q as usize - 1) / 32;

        let (r0,r1) = decompose::<gamma2>(7598404);
        println!("{r0} {r1}");

        let (r0,r1) = decompose::<gamma2>(7594749);
        println!("{r0} {r1}");
    }
}
