use crate::{
    mldsa::{auxiliary::bit_pack::bit_unpack, hash::new_h, rq::Rq, util::bitlen},
    sha3::XOF,
};

use super::sample::{rej_bounded_poly, rej_ntt_poly};

pub(crate) fn expand_a<const k: usize, const l: usize>(a: &mut [[Rq; l]; k], rho: &[u8; 32]) {
    for r in 0..k {
        for s in 0..l {
            rej_ntt_poly(&mut a[r][s], rho, s as u8, r as u8);
        }
    }
}

pub(crate) fn expand_s<const k: usize, const l: usize, const eta:usize>(s1: &mut [Rq; l], s2: &mut [Rq; k], rho: &[u8; 64]) {
    for r in 0..l {
        rej_bounded_poly::<eta>(&mut s1[r], rho, r as u16);
    }

    for r in 0..k {
        rej_bounded_poly::<eta>(&mut s2[r], rho, (r + l) as u16);
    }
}

pub(crate) fn expand_mask<const k: usize, const l: usize, const gamma1:usize>(y: &mut [Rq; l], rho: &[u8], mu: u16) {
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
