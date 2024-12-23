use rand::Rng;

use super::internal;

pub(crate) const k: usize = 3;
pub(crate) const eta1: usize = 2;
pub(crate) const eta2: usize = 2;
pub(crate) const du: usize = 10;
pub(crate) const dv: usize = 4;

pub(crate) const ek_len:usize = crate::ek_len!(k);
pub(crate) const dk_len:usize = crate::dk_len!(k);
pub(crate) const cipher_len:usize = crate::cipher_len!(k,du,dv);

#[derive(Clone)]
pub struct EncapsulationKey(internal::EncapsulationKey<k, eta1, eta2>);

#[derive(Clone)]
pub struct DecapsulationKey {
    dz: [u8; 64],
    ek: EncapsulationKey,
    dk: internal::DecapsulationKey<k, eta1, eta2>,
}

pub fn keygen() -> DecapsulationKey {
    let mut rng = rand::rng();
    let dz = rng.random();
    DecapsulationKey::from_randomness(&dz)
}


impl EncapsulationKey {
    pub fn encaps(&self) -> ([u8; 32], [u8; 32 * (du * k + dv)]) {
        let mut rng = rand::rng();
        let m = rng.random();
        self.0.encaps_internal::<du, dv>(&m)
    }

    pub fn byte_encode(&self) {}

    pub fn byte_decode() -> Self {
        todo!()
    }
}

impl DecapsulationKey {
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        self.ek.clone()
    }

    pub fn encapsulation_key_ref(&self) -> &EncapsulationKey {
        &self.ek
    }

    // returns the dz
    pub fn randomness_ref(&self)-> &[u8;64]{
        &self.dz
    }

    pub fn from_randomness(dz: &[u8; 64]) -> Self {
        let (ek, dk) = internal::keygen_internal(&dz);
        DecapsulationKey {
            dz: *dz,
            ek: EncapsulationKey(ek),
            dk,
        }
    }

    pub fn decaps(&self, c: &[u8; 32 * (du * k + dv)]) -> [u8; 32] {
        self.dk.decaps_internal::<du, dv>(c)
    }

    pub fn byte_encode(&self) {}

    pub fn byte_decode() -> Self {
        todo!()
    }
}
