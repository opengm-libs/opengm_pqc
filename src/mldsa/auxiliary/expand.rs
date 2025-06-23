use crate::{
    mldsa::{
        auxiliary::{bit_pack::bit_unpack, coeff_from_three_bytes},
        hash::new_h,
        rq::Rq,
        shake4::Shake4,
        util::bitlen,
    },
    sha3::{self, XOF},
};

use super::sample::{rej_bounded_poly, rej_ntt_poly};

// input: rho in B^32
// output: a^ in Tq
#[inline]
fn rej_ntt_poly_x4(
    a0: &mut Rq,
    a1: &mut Rq,
    a2: &mut Rq,
    a3: &mut Rq,
    h: &mut Shake4<16>,
    k0: u8,
    k1: u8,
    k2: u8,
    k3: u8,
    l0: u8,
    l1: u8,
    l2: u8,
    l3: u8,
) {
    h.absorb_byte(k0, k1, k2, k3).absorb_byte(l0, l1, l2, l3);

    // the rate for shake128 is 200 - 2*16 = 168
    let mut s0 = [0; 1680];
    let mut s1 = [0; 1680];
    let mut s2 = [0; 1680];
    let mut s3 = [0; 1680];

    h.squeeze(&mut s0, &mut s1, &mut s2, &mut s3);
    let mut j = 0;
    for s in s0.chunks_exact(3) {
        let (c, res) = coeff_from_three_bytes(s[0], s[1], s[2]);
        a0.coeffs[j] = c;
        j = j + res;
        if j == 256 {
            break;
        }
    }
    debug_assert_eq!(j, 256);

    let mut j = 0;
    for s in s0.chunks_exact(3) {
        let (c, res) = coeff_from_three_bytes(s[0], s[1], s[2]);
        a1.coeffs[j] = c;
        j = j + res;
        if j == 256 {
            break;
        }
    }
    debug_assert_eq!(j, 256);

    let mut j = 0;
    for s in s0.chunks_exact(3) {
        let (c, res) = coeff_from_three_bytes(s[0], s[1], s[2]);
        a2.coeffs[j] = c;
        j = j + res;
        if j == 256 {
            break;
        }
    }
    debug_assert_eq!(j, 256);

    let mut j = 0;
    for s in s0.chunks_exact(3) {
        let (c, res) = coeff_from_three_bytes(s[0], s[1], s[2]);
        a3.coeffs[j] = c;
        j = j + res;
        if j == 256 {
            break;
        }
    }
    debug_assert_eq!(j, 256);

    // let mut j1 = 0;
    // let mut j2 = 0;
    // let mut j3 = 0;
    // while j0 < 256 - 8 && j1 < 256 - 8 && j2 < 256 - 8 && j3 < 256 - 8 {
    //     h.squeeze(&mut s0, &mut s1, &mut s2, &mut s3);

    //     let mut i = 0;
    //     while i < s0.len() {
    //         let (c, res) = coeff_from_three_bytes(s0[i], s0[i + 1], s0[i + 2]);
    //         a0.coeffs[j0] = c;
    //         j0 += res;

    //         let (c, res) = coeff_from_three_bytes(s1[i], s1[i + 1], s1[i + 2]);
    //         a1.coeffs[j1] = c;
    //         j1 += res;

    //         let (c, res) = coeff_from_three_bytes(s2[i], s2[i + 1], s2[i + 2]);
    //         a2.coeffs[j2] = c;
    //         j2 += res;

    //         let (c, res) = coeff_from_three_bytes(s3[i], s3[i + 1], s3[i + 2]);
    //         a3.coeffs[j3] = c;
    //         j3 += res;

    //         i += 3;
    //     }
    // }

    // while j0 < 256 && j1 < 256 && j2 < 256 && j3 < 256 {
    //     h.squeeze(&mut s0, &mut s1, &mut s2, &mut s3);

    //     if j0 < 256 {
    //         let mut i = 0;
    //         while i < s0.len() {
    //             let (c, res) = coeff_from_three_bytes(s0[i], s0[i + 1], s0[i + 2]);
    //             a0.coeffs[j0] = c;
    //             j0 += res;
    //             if j0 == 256 {
    //                 break;
    //             }
    //             i += 3;
    //         }
    //     }

    //     if j1 < 256 {
    //         let mut i = 0;
    //         while i < s1.len() {
    //             let (c, res) = coeff_from_three_bytes(s1[i], s1[i + 1], s1[i + 2]);
    //             a1.coeffs[j1] = c;
    //             j1 += res;
    //             if j1 == 256 {
    //                 break;
    //             }
    //             i += 3;
    //         }
    //     }

    //     if j2 < 256 {
    //         let mut i = 0;
    //         while i < s2.len() {
    //             let (c, res) = coeff_from_three_bytes(s2[i], s2[i + 1], s2[i + 2]);
    //             a2.coeffs[j2] = c;
    //             j2 += res;
    //             if j2 == 256 {
    //                 break;
    //             }
    //             i += 3;
    //         }
    //     }

    //     if j3 < 256 {
    //         let mut i = 0;
    //         while i < s3.len() {
    //             let (c, res) = coeff_from_three_bytes(s3[i], s3[i + 1], s3[i + 2]);
    //             a3.coeffs[j3] = c;
    //             j3 += res;
    //             if j3 == 256 {
    //                 break;
    //             }
    //             i += 3;
    //         }
    //     }
    // }
}

pub(crate) fn expand_a_simd<const k: usize, const l: usize>(a: &mut [[Rq; l]; k], rho: &[u8; 32]) {
    if k == 6 && l == 5 {
        // mldsa 65
        let mut h = Shake4::<16>::default();
        h.absorb(rho);
        let mut x0 = Rq::default();
        let mut x1 = Rq::default();
        let mut x2 = Rq::default();
        let mut x3 = Rq::default();

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 0, 0, 0, 0, 0, 1, 2, 3);
        (a[0][0], a[0][1], a[0][2], a[0][3]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 0, 1, 1, 1, 4, 0, 1, 2);
        (a[0][4], a[1][0], a[1][1], a[1][2]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 1, 1, 2, 2, 3, 4, 0, 1);
        (a[1][3], a[1][4], a[2][0], a[2][1]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 2, 2, 2, 3, 2, 3, 4, 0);
        (a[2][2], a[2][3], a[2][4], a[3][0]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 3, 3, 3, 3, 1, 2, 3, 4);
        (a[3][1], a[3][2], a[3][3], a[3][4]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 4, 4, 4, 4, 0, 1, 2, 3);
        (a[4][0], a[4][1], a[4][2], a[4][3]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 4, 5, 5, 5, 4, 0, 1, 2);
        (a[4][4], a[5][0], a[5][1], a[5][2]) = (x0, x1, x2, x3);

        rej_ntt_poly_x4(&mut x0, &mut x1, &mut x2, &mut x3, &mut h.clone(), 5, 5, 0, 0, 3, 4, 0, 0);
        (a[5][3], a[5][4]) = (x0, x1);
    }
}

pub(crate) fn expand_a<const k: usize, const l: usize>(a: &mut [[Rq; l]; k], rho: &[u8; 32]) {
    let mut ctx = sha3::new_shake128();
    ctx.absorb(rho);
    for r in 0..k {
        for s in 0..l {
            rej_ntt_poly(&mut a[r][s], &mut ctx.clone(), s as u8, r as u8);
        }
    }
}

pub(crate) fn expand_s<const k: usize, const l: usize, const eta: usize>(s1: &mut [Rq; l], s2: &mut [Rq; k], rho: &[u8; 64]) {
    for r in 0..l {
        rej_bounded_poly::<eta>(&mut s1[r], rho, r as u16);
    }

    for r in 0..k {
        rej_bounded_poly::<eta>(&mut s2[r], rho, (r + l) as u16);
    }
}

pub(crate) fn expand_mask<const k: usize, const l: usize, const gamma1: usize>(y: &mut [Rq; l], rho: &[u8], mu: u16) {
    match gamma1 {
        131072 => {
            // gamma1 = 2^17
            const c: usize = bitlen(1 << 17);
            let mut v = [0; 32 * c];
            let mut ctx = new_h();
            ctx.absorb(rho);
            for r in 0..l {
                ctx.clone()
                    .absorb(&[(mu + r as u16) as u8, ((mu + r as u16) >> 8) as u8])
                    .squeeze(&mut v);
                bit_unpack::<131071, 131072>(&mut y[r], &v);
            }
        }
        524288 => {
            // gamma1 = 2^19
            const c: usize = bitlen(1 << 19);
            let mut v = [0; 32 * c];
            let mut ctx = new_h();
            ctx.absorb(rho);
            for r in 0..l {
                ctx.clone()
                    .absorb(&[(mu + r as u16) as u8, ((mu + r as u16) >> 8) as u8])
                    .squeeze(&mut v);
                bit_unpack::<524287, 524288>(&mut y[r], &v);
            }
        }
        // FIXME: for tpc
        65536 => {
            // gamma1 = 2^16
            const c: usize = bitlen(1 << 16);
            let mut v = [0; 32 * c];
            let mut ctx = new_h();
            ctx.absorb(rho);
            for r in 0..l {
                ctx.clone()
                    .absorb(&[(mu + r as u16) as u8, ((mu + r as u16) >> 8) as u8])
                    .squeeze(&mut v);
                bit_unpack::<65535, 65536>(&mut y[r], &v);
            }
        }
        262144 => {
            // gamma1 = 2^19
            const c: usize = bitlen(1 << 18);
            let mut v = [0; 32 * c];
            let mut ctx = new_h();
            ctx.absorb(rho);
            for r in 0..l {
                ctx.clone()
                    .absorb(&[(mu + r as u16) as u8, ((mu + r as u16) >> 8) as u8])
                    .squeeze(&mut v);
                bit_unpack::<262143, 262144>(&mut y[r], &v);
            }
        }

        _ => panic!("wrone gamma1"),
    };
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::mldsa::{
        auxiliary::{expand_a, expand_a_simd},
        rq::Rq,
    };

    #[test]
    fn test_expand_a_simd() {
        let mut rng = rand::rng();
        for _ in 0..10000 {
            let rho = rng.random();

            let mut a = [[Rq::default(); 5]; 6];
            expand_a_simd(&mut a, &rho);
        }
    }

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_expand_a(b: &mut Bencher) {
        let mut rng = rand::rng();
        let rho = rng.random();

        let mut a = [[Rq::default(); 5]; 6];

        b.iter(|| {
            // 38,841.03 ns/iter
            test::black_box({
                expand_a(&mut a, &rho);
            });
        });
    }

    #[bench]
    fn bench_expand_a_simd(b: &mut Bencher) {
        let mut rng = rand::rng();
        let rho = rng.random();

        let mut a = [[Rq::default(); 5]; 6];

        b.iter(|| {
            // 33,413.84 ns/iter
            test::black_box({
                expand_a_simd(&mut a, &rho);
            });
        });
    }
}
