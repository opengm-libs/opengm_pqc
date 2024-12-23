use std::iter::zip;

use crate::{cipher_len, dk_len, ek_len};

use super::{
    compress_decode::{
        compress_and_encode, compress_and_encode_vecs, decode_and_decompress, decode_and_decompress_vecs,
    },
    hash::G,
    ntt::ntt_add_mul,
    rq::Rq,
    sample::{sample_ntt, sample_poly_cbd_prf},
};

#[derive(Clone,Debug)]
pub(crate) struct Ek<const k: usize> {
    a: [[Rq; k]; k],

    rho: [u8; 32],
    t: [Rq; k],
}

#[derive(Clone,Debug)]
pub(crate) struct Dk<const k: usize> {
    s: [Rq; k],
}

#[derive(Clone)]
pub(crate) struct Cipher<const k: usize, const du: usize, const dv: usize> {
    pub u: [Rq; k],
    pub v: Rq,
}

impl< const k: usize, const du: usize, const dv: usize> Cipher<k, du,dv>{
    pub(crate) const fn cipher_len()-> usize{
        32*(du*k+dv)
    }
}

impl<const k: usize> Default for Ek<k> {
    fn default() -> Self {
        Self {
            a: [[Rq::default(); k]; k],
            rho: Default::default(),
            t: [Rq::default(); k],
        }
    }
}

impl<const k: usize> Ek<k> {
    // ByteEncode12(t^) || rho
    pub(crate) fn byte_encode(&self, b: &mut [u8;ek_len!(k)]) {
        // debug_assert!(b.len() == ek_len!(k));
        for (t,b) in zip(&self.t, b[..384*k].chunks_exact_mut(384)){
            t.byte_encode(b.try_into().unwrap());
        }
        b[384*k..].copy_from_slice(&self.rho);
    }

    pub(crate) fn byte_decode(b: &[u8; ek_len!(k)]) -> Self {
        let mut ek = Self::default();
        
        for (t,b) in zip(&mut ek.t, b[..384*k].chunks_exact(384)){
            t.byte_decode(b.try_into().unwrap());
        }

        ek.rho.copy_from_slice(&b[384*k..]);

        // re-generate A
        sample_matrix_ntt(&mut ek.a, &ek.rho);

        ek
    }
}

impl<const k: usize> Dk<k> {
    // ByteEncode12(s)
    pub(crate) fn byte_encode(&self, b: &mut [u8; 384*k]) {
        for (t,b) in zip(&self.s, b[..384*k].chunks_exact_mut(384)){
            t.byte_encode(b.try_into().unwrap());
        }
    }

    pub(crate) fn byte_decode(b: &[u8; 384*k]) -> Self {
        let mut dk = Self::default();
        
        for (t,b) in zip(&mut dk.s, b[..384*k].chunks_exact(384)){
            t.byte_decode(b.try_into().unwrap());
        }
        dk
    }
}

impl<const k: usize> Default for Dk<k> {
    fn default() -> Self {
        Self { s: [Rq::default(); k] }
    }
}

#[inline]
fn sample_matrix_ntt<const k:usize>(a:&mut [[Rq; k]; k], rho: &[u8;32]){
    for i in 0..k {
        for j in 0..k {
            // FIXME: repeat sha3
            sample_ntt(&mut a[i][j].coeffs, rho, i as u8, j as u8);
        }
    }
}

pub(crate) fn keygen<const k: usize, const eta1: usize>(d: &[u8]) -> (Ek<k>, Dk<k>) {
    let mut ek = Ek::default();
    let mut dk = Dk::default();

    let mut sigma = [0; 32];
    G(&mut ek.rho, &mut sigma, d, &[k as u8]);

    let a = &mut ek.a;
    sample_matrix_ntt(a, &ek.rho);

    let mut n = 0;
    for s in &mut dk.s {
        sample_poly_cbd_prf::<eta1>(&mut s.coeffs, &sigma, n);
        s.ntt();
        // |s| < 8q
        s.reduce();
        n += 1;
    }
    // 

    let e = &mut ek.t;
    for e in e {
        sample_poly_cbd_prf::<eta1>(&mut e.coeffs, &sigma, n);
        e.ntt();
        n += 1;
    }

    // t = As + e,
    let t = &mut ek.t;
    for i in 0..k {
        for j in 0..k {
            // |dk.s| < q, and ntt_add_mul allow any input range in [0,8q)
            ntt_add_mul(&mut t[i].coeffs, &a[i][j].coeffs, &dk.s[j].coeffs);
        }
        // |t| < q
        t[i].reduce_to_positive();
    }

    // ek, dk all has elements in range (-q,q)
    (ek, dk)
}

#[inline(never)]
pub(crate) fn encrypt<const k: usize, const eta1: usize, const eta2: usize, const du: usize, const dv: usize>(
    c: &mut [u8; cipher_len!(k,du,dv)],
    ek: &Ek<k>,
    m: &[u8; 32],
    r: &[u8; 32],
) {
    let mut y = [Rq::default(); k];
    let mut e1 = [Rq::default(); k];
    let mut e2 = Rq::default();

    let mut n = 0;
    for i in 0..k {
        sample_poly_cbd_prf::<eta1>(&mut y[i].coeffs, r, n);
        y[i].ntt();
        n += 1;
    }

    for i in 0..k {
        sample_poly_cbd_prf::<eta2>(&mut e1[i].coeffs, r, n);
        n += 1;
    }

    sample_poly_cbd_prf::<eta2>(&mut e2.coeffs, r, n);

    // u = A^T * y + e1
    let mut u = [Rq::default(); k];
    for j in 0..k {
        for i in 0..k {
            // u[j] = sum
            ntt_add_mul(&mut u[j].coeffs, &ek.a[i][j].coeffs, &y[i].coeffs);
        }
        // |u[j]| < q
        u[j].ntt_inverse();
        u[j].add(&e1[j]);
        // |u[i]| < 2q
    }

    let mut mu = Rq::default();
    decode_and_decompress(&mut mu.coeffs, m, 1);

    // v = NTT^-1(t * y) + e2 + mu.
    let mut v = Rq::default();
    for i in 0..k {
        ntt_add_mul(&mut v.coeffs, &ek.t[i].coeffs, &y[i].coeffs);
    }
    v.ntt_inverse();
    v.add(&mu);
    v.add(&e2);

    // note that |e2 + mu| < q, thus |v| < 2q.

    compress_and_encode_vecs(&mut c[..k * 32 * du], &u, du);

    compress_and_encode(&mut c[k * 32 * du..], &v.coeffs, dv);
}

pub(crate) fn decrypt<const k: usize, const eta1: usize, const eta2: usize, const du: usize, const dv: usize>(
    m: &mut [u8; 32],
    dk: &Dk<k>,
    c: &[u8],
) {
    let c1 = &c[..k * 32 * du];
    let c2 = &c[k * 32 * du..];

    let mut u = [Rq::default(); k];
    let mut v = Rq::default();
    decode_and_decompress_vecs(&mut u, c1, du);
    decode_and_decompress(&mut v.coeffs, c2, dv);

    for ui in &mut u {
        ui.ntt();
    }

    // w = v-su
    let mut w = Rq::default();
    for i in 0..k {
        ntt_add_mul(&mut w.coeffs, &dk.s[i].coeffs, &u[i].coeffs);
    }
    w.ntt_inverse();
    v.sub(&w);

    // |v| < 2q
    compress_and_encode(m, &v.coeffs, 1);
}

#[cfg(test)]
mod tests {

    use rand::Rng;
    use crate::mlkem::mlkem768::*;
    use crate::{
        tick::{frequency, tick_counter},
    };

    use super::{decrypt, encrypt, keygen};

    #[test]
    fn test_pke() {
        let d = [1u8; 32];
        let m = [2u8; 32];
        let mut mm = [2u8; 32];
        let r = [3u8; 32];

        let (ek, dk) = keygen::<k, eta1>(&d);
        let mut c = [0u8; 32*(du*k+dv)];
        encrypt::<k, eta1, eta2, du, dv>(&mut c, &ek, &m, &r);
        decrypt::<k, eta1, eta2, du, dv>(&mut mm, &dk, &c);

        assert_eq!(m, mm);
    }

    #[test]
    fn fuzz_pke() {
        let mut rng = rand::rng();
        for _ in 0..10000000 {
            let d = rng.random::<[u8;32]>();
            let m = rng.random();
            let r = rng.random();
            let mut mm = [0; 32];

            let (ek, dk) = keygen::<k, eta1>(&d);
            let mut c = [0u8; 32*(du*k+dv)];
            encrypt::<k, eta1, eta2, du, dv>(&mut c, &ek, &m, &r);
            decrypt::<k, eta1, eta2, du, dv>(&mut mm, &dk, &c);
            assert_eq!(m, mm);
        }
    }

    #[test]
    fn encrypt_tps() {
        let mut rng = rand::rng();
        let d = rng.random::<[u8;32]>();
        let m = rng.random();
        let r = rng.random();

        let (ek, _dk) = keygen::<k, eta1>(&d);
        let mut c = [0u8; 32*(du*k+dv)];

        let loop_times = 1000_000;
        let frequence = frequency();
        let start = tick_counter();
        for _i in 0..loop_times {
            encrypt::<k, eta1, eta2, du, dv>(&mut c, &ek, &m, &r);
        }
        let end = tick_counter();

        let cycles = (end - start) / loop_times;

        println!("decrypt use cycles {:?}, {},{}", end - start, cycles, frequence);

        // decrypt (tps): 198987
        println!(
            "decrypt (tps): {}",
            (frequence as f64 * loop_times as f64 / (end - start) as f64) as u64
        );
    }

    #[test]
    fn decrypt_tps() {
        let mut rng = rand::rng();
        let d = rng.random::<[u8;32]>();
        let m = rng.random();
        let r = rng.random();

        let (ek, dk) = keygen::<k, eta1>(&d);
        let mut c = [0u8; 32*(du*k+dv)];
        let mut mm = rng.random();
        encrypt::<k, eta1, eta2, du, dv>(&mut c, &ek, &m, &r);

        let loop_times = 1000_000;
        let frequence = frequency();
        let start = tick_counter();

        for _i in 0..loop_times {
            test::black_box({
                decrypt::<k, eta1, eta2, du, dv>(&mut mm, &dk, &c);
            });
        }
        let end = tick_counter();
        println!("{start}, {end}");

        let cycles = (end - start) / loop_times;

        println!("decrypt use cycles {:?}, {},{}", end - start, cycles, frequence);
        // decrypt (tps): 598242
        println!(
            "decrypt (tps): {}",
            (frequence as f64 * loop_times as f64 / (end - start) as f64) as u64
        );
    }

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_pke(b: &mut Bencher) {
        let mut rng = rand::rng();
        let d = rng.random::<[u8;32]>();
        let m = rng.random();
        let r = rng.random();

        let (ek, _dk) = keygen::<k, eta1>(&d);
        let mut c = [0u8; 32*(du*k+dv)];

        // 5,041.04 ns/iter
        b.iter(|| {
            test::black_box({
                encrypt::<k, eta1, eta2, du, dv>(&mut c, &ek, &m, &r);
            });
        });

        println!("{:?}", c);
    }
}
