use std::iter::zip;

use crate::{cipher_len, ek_len};

use super::{
    hash::{G, H, J},
    pke::{self, Dk, Ek},
};

#[derive(Clone, Debug)]
pub(crate) struct DecapsulationKey<const k: usize, const eta1: usize, const eta2: usize> {
    dk: Dk<k>,
    // h: [u8; 32], // h(ek)
}
impl<const k: usize, const eta1: usize, const eta2: usize> DecapsulationKey<k, eta1, eta2> {
    pub(crate) fn byte_encode(&self, b: &mut [u8; 384 * k]) {
        self.dk.byte_encode(b);
    }

    pub(crate) fn byte_decode(b: &[u8; 384 * k]) -> Self {
        DecapsulationKey {
            dk: Dk::<k>::byte_decode(b),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EncapsulationKey<const k: usize, const eta1: usize, const eta2: usize> {
    ek: Ek<k>,

    h: [u8; 32], // h(ek)
}

impl<const k: usize, const eta1: usize, const eta2: usize> EncapsulationKey<k, eta1, eta2> {
    pub(crate) fn byte_encode(&self, b: &mut [u8; ek_len!(k)]) {
        self.ek.byte_encode(b);
    }

    pub(crate) fn byte_decode(b: &[u8; ek_len!(k)]) -> Self {
        EncapsulationKey {
            ek: Ek::<k>::byte_decode(b),
            h: H(b),
        }
    }
}

pub(crate) fn keygen_internal<const k: usize, const eta1: usize, const eta2: usize>(
    dz: &[u8; 64],
) -> (EncapsulationKey<k, eta1, eta2>, DecapsulationKey<k, eta1, eta2>)
where
    [(); ek_len!(k)]:,
{
    let (pke_ek, pke_dk) = pke::keygen::<k, eta1>(&dz[..32]);

    let mut pke_ek_bytes = [0u8; ek_len!(k)];
    pke_ek.byte_encode(&mut pke_ek_bytes);
    let h = H(&pke_ek_bytes);

    (
        EncapsulationKey::<k, eta1, eta2> { ek: pke_ek, h },
        DecapsulationKey::<k, eta1, eta2> { dk: pke_dk },
    )
}

impl<const k: usize, const eta1: usize, const eta2: usize> EncapsulationKey<k, eta1, eta2> {
    pub(crate) fn encaps_internal<const du: usize, const dv: usize>(
        &self,
        m: &[u8; 32],
    ) -> ([u8; 32], [u8; cipher_len!(k, du, dv)]) {
        #[allow(non_snake_case)]
        let mut K = [0; 32];
        let mut r = [0; 32];

        G(&mut K, &mut r, m, &self.h);

        let mut c = [0; cipher_len!(k, du, dv)];
        pke::encrypt::<k, eta1, eta2, du, dv>(&mut c, &self.ek, m, &r);

        (K, c)
    }
}

impl<const k: usize, const eta1: usize, const eta2: usize> DecapsulationKey<k, eta1, eta2> {
    // we need pass ek,z as input.
    pub(crate) fn decaps_internal<const du: usize, const dv: usize>(
        &self, ek: &EncapsulationKey<k,eta1,eta2>, z: &[u8], c: &[u8; cipher_len!(k,du,dv)]) -> [u8; 32] {
        let mut m = [0; 32];
        pke::decrypt::<k, eta1, eta2, du, dv>(&mut m, &self.dk, c);

        // re-encrypt
        #[allow(non_snake_case)]
        let mut K = [0; 32];
        let mut r = [0; 32];
        G(&mut K, &mut r, &m, &ek.h);

        #[allow(non_snake_case)]
        let K_ = J(z,c);
        let mut cp = [0; cipher_len!(k,du,dv)];
        pke::encrypt::<k,eta1,eta2,du,dv>( &mut cp, &ek.ek, &m, &r);
        
        let mut equal = 0;
        for (a,b) in zip(c.chunks_exact(4), cp.chunks_exact(4)){
            equal |= u32::from_ne_bytes(a.try_into().unwrap()) ^ u32::from_ne_bytes(b.try_into().unwrap());
        } 

        if equal != 0{
            K.copy_from_slice(&K_);
        }
        K
    }
}
