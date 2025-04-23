use core::iter::zip;

use crate::mlkem::errors::{Error, Result};
use crate::{cipher_len, dk_len, ek_len};

use super::pke;
use super::{
    hash::{G, H, J},
    ntt::ntt_add_mul,
    rq::Rq,
    sample::{sample_matrix_ntt, sample_poly_cbd_prf},
};

#[derive(Clone, Debug)]
pub(crate) struct DecapKey<const k: usize, const eta1: usize, const eta2: usize>
where
    [(); ek_len!(k)]:,
{
    // d: Option<[u8;32]>,
    z: [u8; 32],
    s: [Rq; k],

    pub(crate) ek: EncapKey<k, eta1, eta2>,
}
impl<const k: usize, const eta1: usize, const eta2: usize> Default for DecapKey<k, eta1, eta2>
where
    [(); ek_len!(k)]:,
{
    fn default() -> Self {
        Self {
            z: [0; 32],
            s: [Rq::default(); k],
            ek: Default::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EncapKey<const k: usize, const eta1: usize, const eta2: usize>
where
    [(); ek_len!(k)]:,
{
    a: [[Rq; k]; k],

    rho: [u8; 32],
    t: [Rq; k],

    h: [u8; 32],
}

impl<const k: usize, const eta1: usize, const eta2: usize> Default for EncapKey<k, eta1, eta2>
where
    [(); ek_len!(k)]:,
{
    fn default() -> Self {
        Self {
            a: [[Default::default(); k]; k],
            rho: Default::default(),
            t: [Default::default(); k],
            h: [0; 32],
        }
    }
}

impl<const k: usize, const eta1: usize, const eta2: usize> DecapKey<k, eta1, eta2>
where
    [(); ek_len!(k)]:,
{
    // we need pass ek,z as input.
    pub(crate) fn decaps_internal_<const du: usize, const dv: usize>(
        &self,
        c: &[u8; cipher_len!(k, du, dv)],
    ) -> [u8; 32] {
        let mut m = [0; 32];
        pke::decrypt::<k, eta1, eta2, du, dv>(&mut m, &self.s, c);

        // re-encrypt
        #[allow(non_snake_case)]
        let mut K = [0; 32];
        let mut r = [0; 32];
        G(&mut K, &mut r, &m, &self.ek.h);

        #[allow(non_snake_case)]
        let K_ = J(&self.z, c);
        let mut cp = [0; cipher_len!(k, du, dv)];
        pke::encrypt::<k, eta1, eta2, du, dv>(&mut cp, &self.ek.a, &self.ek.t, &m, &r);

        let mut equal = 0;
        for (a, b) in zip(c.chunks_exact(4), cp.chunks_exact(4)) {
            equal |= u32::from_ne_bytes(a.try_into().unwrap()) ^ u32::from_ne_bytes(b.try_into().unwrap());
        }

        if equal != 0 {
            K.copy_from_slice(&K_);
        }
        K
    }

    // ByteEncode12(s) || ek || h(ek) || z
    pub(crate) fn byte_encode_inplace(&self, b: &mut [u8; dk_len!(k)]) {
        for (t, b) in zip(&self.s, b[..384 * k].chunks_exact_mut(384)) {
            t.byte_encode(b.try_into().unwrap());
        }

        self.ek
            .byte_encode_inplace((&mut b[384 * k..384 * k + ek_len!(k)]).try_into().unwrap());
        b[384 * k + ek_len!(k)..384 * k + ek_len!(k) + 32].copy_from_slice(&self.ek.h);
        b[384 * k + ek_len!(k) + 32..384 * k + ek_len!(k) + 64].copy_from_slice(&self.z);
    }

    pub(crate) fn byte_encode(&self) -> [u8; dk_len!(k)] {
        let mut b = [0; dk_len!(k)];
        self.byte_encode_inplace(&mut b);
        b
    }

    pub(crate) fn byte_decode(b: &[u8; dk_len!(k)]) -> Result<Self> {
        let mut dk = Self::default();
        let b_ek = &b[384 * k..384 * k + ek_len!(k)];
        let b_h = &b[384 * k + ek_len!(k)..384 * k + ek_len!(k) + 32];
        let z = &b[384 * k + ek_len!(k) + 32..384 * k + ek_len!(k) + 64];

        let h = H(&b_ek);
        for (a, b) in zip(h, b_h) {
            if a != *b {
                return Err(Error::DecapKeyDecodeError);
            }
        }

        dk.z.copy_from_slice(z);

        dk.ek = EncapKey::<k, eta1, eta2>::byte_decode(b_ek.try_into().unwrap())?;

        for (t, b) in zip(&mut dk.s, b[..384 * k].chunks_exact(384)) {
            t.byte_decode(b.try_into().unwrap())?;
        }
        Ok(dk)
    }

    // s || z || ek
    pub fn bytes(&self) -> [u8; (2 * k + k * k) * 512 + 96]
    where
        [(); (2 * k + k * k) * 512 + 96]:,
        [(); (k + k * k) * 512 + 64]:,
    {
        let mut b = [0u8; (2 * k + k * k) * 512 + 96];
        self.bytes_inplace(&mut b);
        b
    }

    pub fn bytes_inplace(&self, b: &mut [u8; (2 * k + k * k) * 512 + 96])
    where
        [(); (2 * k + k * k) * 512 + 96]:,
        [(); (k + k * k) * 512 + 64]:,
    {
        for (s, b) in zip(&self.s, b[..k * 512].chunks_exact_mut(512)) {
            s.bytes_inplace(b.try_into().unwrap());
        }

        b[k * 512..k * 512 + 32].copy_from_slice(&self.z);
        self.ek.bytes_inplace((&mut b[k * 512 + 32..]).try_into().unwrap());
    }


    pub fn new_from_bytes(b:&[u8; (2 * k + k * k) * 512 + 96])-> Self
    where
    [(); (2 * k + k * k) * 512 + 96]:,
    [(); (k + k * k) * 512 + 64]:,
    {
        let mut dk = DecapKey::default();
        
        for (s, b) in zip(&mut dk.s, b[..k * 512].chunks_exact(512)) {
            s.from_bytes(b.try_into().unwrap());
        }

        dk.z.copy_from_slice(&b[k * 512..k * 512 + 32]);
        dk.ek.from_bytes( (&b[k * 512 + 32..]).try_into().unwrap());

        dk
    }



    pub fn from_bytes(&mut self, b:&[u8; (2 * k + k * k) * 512 + 96])
    where
    [(); (2 * k + k * k) * 512 + 96]:,
    [(); (k + k * k) * 512 + 64]:,
    {   
        for (s, b) in zip(&mut self.s, b[..k * 512].chunks_exact(512)) {
            s.from_bytes(b.try_into().unwrap());
        }

        self.z.copy_from_slice(&b[k * 512..k * 512 + 32]);
        self.ek.from_bytes( (&b[k * 512 + 32..]).try_into().unwrap());
    }
}

impl<const k: usize, const eta1: usize, const eta2: usize> EncapKey<k, eta1, eta2>
where
    [(); ek_len!(k)]:,
{
    pub(crate) fn encaps_internal_<const du: usize, const dv: usize>(
        &self,
        m: &[u8; 32],
    ) -> ([u8; 32], [u8; cipher_len!(k, du, dv)]) {
        #[allow(non_snake_case)]
        let mut K = [0; 32];
        let mut r = [0; 32];

        G(&mut K, &mut r, m, &self.h);

        let mut c = [0; cipher_len!(k, du, dv)];
        pke::encrypt::<k, eta1, eta2, du, dv>(&mut c, &self.a, &self.t, m, &r);

        (K, c)
    }

    // ByteEncode12(t^) || rho
    pub(crate) fn byte_encode_inplace(&self, b: &mut [u8; ek_len!(k)]) {
        for (t, b) in zip(&self.t, b[..384 * k].chunks_exact_mut(384)) {
            t.byte_encode(b.try_into().unwrap());
        }
        b[384 * k..].copy_from_slice(&self.rho);
    }

    pub(crate) fn byte_encode(&self) -> [u8; ek_len!(k)] {
        let mut b = [0; ek_len!(k)];
        self.byte_encode_inplace(&mut b);
        b
    }

    pub(crate) fn byte_decode(b: &[u8; ek_len!(k)]) -> Result<Self> {
        let mut ek = Self::default();

        for (t, b) in zip(&mut ek.t, b[..384 * k].chunks_exact(384)) {
            t.byte_decode(b.try_into().unwrap())?;
        }

        ek.rho.copy_from_slice(&b[384 * k..]);

        // re-generate A
        sample_matrix_ntt(&mut ek.a, &ek.rho);
        ek.h = H(b);

        Ok(ek)
    }

    // t || A || rho || h

    pub fn bytes(&self) -> [u8; (k + k * k) * 512 + 64]
    where
        [(); (k + k * k) * 512 + 64]:,
    {
        let mut b = [0u8; (k + k * k) * 512 + 64];
        self.bytes_inplace(&mut b);
        b
    }

    pub fn bytes_inplace(&self, b: &mut [u8; (k + k * k) * 512 + 64])
    where
        [(); (k + k * k) * 512 + 64]:,
    {
        for (t, b) in zip(&self.t, b[..k * 512].chunks_exact_mut(512)) {
            t.bytes_inplace(b.try_into().unwrap());
        }

        for (ai, b) in zip(&self.a, b[k * 512..k * 512 + k * k * 512].chunks_exact_mut(k * 512)) {
            for (aij, b) in zip(ai, b.chunks_exact_mut(512)) {
                aij.bytes_inplace(b.try_into().unwrap());
            }
        }

        b[k * 512 + k * k * 512..k * 512 + k * k * 512 + 32].copy_from_slice(&self.rho);
        b[k * 512 + k * k * 512 + 32..k * 512 + k * k * 512 + 64].copy_from_slice(&self.h);
    }

    pub fn new_from_bytes(b:&[u8; (k + k * k) * 512 + 64])-> Self{
        let mut ek = EncapKey::default();
        
        for (t, b) in zip(&mut ek.t, b[..k * 512].chunks_exact(512)) {
            t.from_bytes(b.try_into().unwrap());
        }

        for (ai, b) in zip(&mut ek.a, b[k * 512..k * 512 + k * k * 512].chunks_exact(k * 512)) {
            for (aij, b) in zip(ai, b.chunks_exact(512)) {
                aij.from_bytes(b.try_into().unwrap());
            }
        }
        ek.rho.copy_from_slice( &b[k * 512 + k * k * 512..k * 512 + k * k * 512 + 32]);
        ek.h.copy_from_slice(&b[k * 512 + k * k * 512 + 32..k * 512 + k * k * 512 + 64]);

        ek
    }

    pub fn from_bytes(&mut self, b:&[u8; (k + k * k) * 512 + 64]){
        for (t, b) in zip(&mut self.t, b[..k * 512].chunks_exact(512)) {
            t.from_bytes(b.try_into().unwrap());
        }

        for (ai, b) in zip(&mut self.a, b[k * 512..k * 512 + k * k * 512].chunks_exact(k * 512)) {
            for (aij, b) in zip(ai, b.chunks_exact(512)) {
                aij.from_bytes(b.try_into().unwrap());
            }
        }
        self.rho.copy_from_slice( &b[k * 512 + k * k * 512..k * 512 + k * k * 512 + 32]);
        self.h.copy_from_slice(&b[k * 512 + k * k * 512 + 32..k * 512 + k * k * 512 + 64]);
    }

}

pub(crate) fn keygen_internal_<const k: usize, const eta1: usize, const eta2: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> DecapKey<k, eta1, eta2>
where
    [(); ek_len!(k)]:,
{
    let mut dk = DecapKey::<k, eta1, eta2>::default();
    let mut sigma = [0; 32];

    G(&mut dk.ek.rho, &mut sigma, d, &[k as u8]);

    let a = &mut dk.ek.a;
    sample_matrix_ntt(a, &dk.ek.rho);

    let mut n = 0;
    for s in &mut dk.s {
        sample_poly_cbd_prf::<eta1>(&mut s.coeffs, &sigma, n);
        s.ntt();
        // |s| < 8q
        s.reduce();
        n += 1;
    }
    //

    let e = &mut dk.ek.t;
    for e in e {
        sample_poly_cbd_prf::<eta1>(&mut e.coeffs, &sigma, n);
        e.ntt();
        n += 1;
    }

    // t = As + e,
    let t = &mut dk.ek.t;
    for i in 0..k {
        for j in 0..k {
            // |dk.s| < q, and ntt_add_mul allow any input range in [0,8q)
            ntt_add_mul(&mut t[i].coeffs, &a[i][j].coeffs, &dk.s[j].coeffs);
        }
        // |t| < q
        t[i].reduce_to_positive();
    }

    let b = dk.ek.byte_encode();
    dk.ek.h = H(&b);

    dk.z.copy_from_slice(z);

    // ek, dk all has elements in range (-q,q)
    dk
}
