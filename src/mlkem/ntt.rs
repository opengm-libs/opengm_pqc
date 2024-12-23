use crate::mlkem::reduce::mont_reduce16;

use super::{Q, reduce::{mont_mul16, reduce_i32, MONT_R16_BITS}};

// powOfZeta[i] = zeta^BitRev7(i)*R mod q
const fn to_mont<const N: usize>(a: [i16; N], mont_r_bits: usize) -> [i16; N] {
    let mut b = [0; N];
    let mut i = 0;
    while i < N {
        let t = (((a[i] as u64) << mont_r_bits) % Q as u64) as i16;
        b[i] = if t > Q / 2 { t - 3329 } else { t };
        i += 1
    }
    b
}

const ZETAS: [i16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476,
    3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
    2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220,
    375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

// MONT_ZETAS[i] = ZETAS[i] * R mod q
const MONT_ZETAS: [i16; 128] = to_mont(ZETAS, MONT_R16_BITS);

// The NTT and NTT inverse works for f,g in Rq (with coeff in non-Montgomery domain),
// then, f*g = NTT^(-1)( NTT(f) o NTT(g) ).
//
// We use Montgomery mul in NTT, NTT^-1 and o.
// ^f = NTT(f):  f and ^f all in non-Montgomery domain.
// ^h = ^f o ^g: coeffs of ^h are divided by R, i.e., ^h[i] = (^f[i] * ^g[i])/R mod q
//               where * is the ordinary ntt mul(i.e., use ordinary mul instead of mont_mul).
// h = NTT^(-1)(^h): h in non-Montgomery domain. We mul R^2/128 mod q (instead of 1/128 mod q)
//                   in the last step of NTT^-1, to cancel the 1/R factors in ^h.

// Transform f to NTT domain, the ref implementation
pub(crate) fn ntt(coeff: &mut [i16; 256]) {
    let mut i = 1;
    let mut length = 128;

    // In each loop, |coeff| increse at most q,
    // thus the |coeff| < q + 7q = 8q < 2^15.
    while length >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = MONT_ZETAS[i];
            i += 1;
            for j in start..start + length {
                let t = mont_mul16(zeta, coeff[j + length]);
                coeff[j + length] = coeff[j] - t;
                coeff[j] = coeff[j] + t;
            }
            start += 2 * length
        }
        length >>= 1
    }
}

// Transform f from NTT domain
// input coeff is of the form x/R(after a mont mul),
// thus the last step we perform a mont_reduce for f * R^2/128
// to cancel the 1/R.
pub(crate) fn ntt_inverse(coeff: &mut [i16; 256]) {
    // note 16q > 2^15 and thus not fit in a i16.
    // So we reduce when necessary:
    // length          :   2   4    8   16    32    64     128
    // (befor loop) |f|:   q   2q   4q  8q     q    2q      4q
    // (after loop) |f|:  2q   4q   8q   q    2q    4q      8q
    //                                   ^
    //                                 reduce
    // Note: if we use i32, we can void reduce. but
    // the bench shows that i16 mul is faster than i32.
    // Thus, we still use i16 as the zq elements' type.

    let mut i = 127;
    let mut length = 2;

    // length = 2, 4, 8, No mont_reduce
    while length <= 8 {
        let mut start = 0;
        while start < 256 {
            let zeta = MONT_ZETAS[i];
            i -= 1;
            for j in start..start + length {
                let t = coeff[j];
                coeff[j] = t + coeff[j + length];
                coeff[j + length] = coeff[j + length] - t;
                coeff[j + length] = mont_mul16(zeta, coeff[j + length]);
            }
            start += 2 * length;
        }
        length <<= 1;
    }

    // length = 16, reduce the |coeffs| < q
    {
        let mut start = 0;
        while start < 256 {
            let zeta = MONT_ZETAS[i];
            i -= 1;
            for j in start..start + length {
                let t0 = coeff[j];

                coeff[j] = mont_reduce16(t0 as i32 + coeff[j + length] as i32);
                coeff[j + length] = mont_mul16(zeta, mont_reduce16(coeff[j + length] as i32 - t0 as i32));
            }
            start += 2 * length;
        }
        length <<= 1;
    }

    // length = 32, 64, 128
    while length <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = MONT_ZETAS[i];
            i -= 1;
            for j in start..start + length {
                let t = coeff[j];
                coeff[j] = t + coeff[j + length];
                coeff[j + length] = coeff[j + length] - t;
                coeff[j + length] = mont_mul16(zeta, coeff[j + length]);
            }
            start += 2 * length;
        }
        length <<= 1;
    }

    // |ntt| < q/2
    const nrr: i16 = {
        let mut t = ((1u64 << (2 * MONT_R16_BITS)) % 3329 * 3303 % 3329) as i32;
        if t > 3329 / 2 {
            t -= 3329;
        }
        t as i16
    };

    // mul n^-1 mod q
    for i in 0..256 {
        // coeff[i] = mont_reduce_8qx8q(coeff[i] as i32 * nrr);
        coeff[i] = mont_mul16(coeff[i], nrr);
    }
}

const NTT_MUL: [i16; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667,
    3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
    1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992,
    268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
    1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029,
    2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

const MONT_NTT_MUL: [i16; 128] = to_mont(NTT_MUL, MONT_R16_BITS);

// Returns dst with |dst| < q.
pub(crate) fn ntt_mul(dst: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) {
    let mut i = 0;
    while i < 256 {
        dst[i] =
            reduce_i32(a[i] as i32 * b[i] as i32 + a[i + 1] as i32 * mont_mul16(b[i + 1], MONT_NTT_MUL[i / 2]) as i32);
        dst[i + 1] = reduce_i32(a[i] as i32 * b[i + 1] as i32 + a[i + 1] as i32 * b[i] as i32);
        i += 2
    }
}

// dst += f*g
// |dst| < q
// reduce_i32(x) should works for |x| < 128q^2 + q.
pub(crate) fn ntt_add_mul(dst: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) {
    let mut i = 0;
    while i < 256 {
        dst[i] = reduce_i32(
            dst[i] as i32
                + a[i] as i32 * b[i] as i32
                + a[i + 1] as i32 * mont_mul16(b[i + 1], MONT_NTT_MUL[i / 2]) as i32,
        );
        dst[i + 1] = reduce_i32(dst[i + 1] as i32 + a[i] as i32 * b[i + 1] as i32 + a[i + 1] as i32 * b[i] as i32);
        i += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;


    #[test]
    fn test_ntt_overflow() {
        let mut f = [Q - 1; 256];
        let mut g = [Q - 1; 256];
        let mut rng = rand::rng();

        // ntt and ntt_inverse works for any input of |.| < q.
        ntt(&mut f);
        ntt_inverse(&mut g);

        for _ in 0..100000 {
            for i in 0..256 {
                f[i] = rng.random::<i16>() % Q;
                g[i] = rng.random::<i16>() % Q;
            }
            ntt(&mut f);
            ntt_inverse(&mut g);
        }
    }

    #[test]
    fn test_ntt_sample() {
        let mut f = [0; 256];
        let mut g = [0; 256];
        let mut h = [0; 256];

        // 1 + 2x + 3x^2 + ...
        for i in 0..256 {
            f[i] = i as i16 + 1;
        }
        g[1] = 1; // g(x) = x

        ntt(&mut f);
        ntt(&mut g);
        ntt_mul(&mut h, &f, &g);
        ntt_inverse(&mut h);

        // h = -256 + x + 2x^2 + ...
        assert!((h[0] + 256) % Q == 0);
        for i in 1..256 {
            assert!((h[i] - i as i16) % Q == 0);
        }
        // println!("{:?}", h);
    }

    #[test]
    fn fuzz_ntt() {
        let mut f = [0; 256];
        let mut g = [0; 256];
        let mut h = [0; 256];
        let mut rng = rand::rng();

        let mut one = [0; 256];
        one[0] = 1;
        ntt(&mut one);

        for _ in 0..1000000000 {
            for i in 0..256 {
                f[i] = rng.random::<i16>() % Q;
            }
            g.copy_from_slice(&f);

            ntt(&mut f);
            ntt_mul(&mut h, &f, &one);
            ntt_inverse(&mut h);

            for i in 0..256 {
                assert!((h[i] - g[i]) % Q == 0);
            }
        }
    }


    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_ntt(b: &mut Bencher) {
        let mut rng = rand::rng();

        let mut f: [i16; 256] = rng.random();
        let mut g: [i16; 256] = rng.random();
        let mut h = [0; 256];

        b.iter(|| {
            // test mlkem::zq::tests::bench_ntt     ... bench:         693.06 ns/iter (+/- 17.28)
            test::black_box({
                ntt(&mut f);
                ntt(&mut g);
                ntt_mul(&mut h, &f, &g);
                ntt_inverse(&mut h);
            });
        });
        println!("{:?}", h);
    }



    //The following bench shows that i16 mul is faster than i32 mul(on M1).
    #[bench]
    fn bench_mul_i16(b: &mut Bencher) {
        let mut rng = rand::rng();
        let mut x = rng.random::<i16>();
        let y = rng.random::<i16>();

        b.iter(|| {
            // test mlkem::zq::tests::bench_mul_i16 ... bench:      29,488.89 ns/iter (+/- 454.08)
            test::black_box({
                for _ in 0..1000000 {
                    x = x.wrapping_mul(y);
                }
            });
        });
        println!("{}", x);
    }

    #[bench]
    fn bench_mul_i32(b: &mut Bencher) {
        let mut rng = rand::rng();
        let mut x = rng.random::<i32>();
        let y = rng.random::<i32>();

        b.iter(|| {
            // test mlkem::zq::tests::bench_mul_i32 ... bench:      59,068.49 ns/iter (+/- 1,456.94)
            test::black_box({
                for _ in 0..1000000 {
                    x = x.wrapping_mul(y);
                }
            });
        });
        println!("{}", x);
    }

    #[bench]
    fn bench_mul_i64(b: &mut Bencher) {
        let mut rng = rand::rng();
        let mut x = rng.random::<i64>();
        let y = rng.random::<i64>();

        b.iter(|| {
            // test mlkem::zq::tests::bench_mul_i64 ... bench:     473,511.63 ns/iter (+/- 16,488.24)
            test::black_box({
                for _ in 0..1000000 {
                    x = x.wrapping_mul(y);
                }
            });
        });
        println!("{}", x);
    }
}
