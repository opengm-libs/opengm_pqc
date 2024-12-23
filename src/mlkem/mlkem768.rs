use rand::Rng;

use super::{hash::H, internal};

pub(crate) const k: usize = 3;
pub(crate) const eta1: usize = 2;
pub(crate) const eta2: usize = 2;
pub(crate) const du: usize = 10;
pub(crate) const dv: usize = 4;

pub(crate) const ek_len:usize = crate::ek_len!(k);
pub(crate) const dk_len:usize = crate::dk_len!(k);
pub(crate) const cipher_len:usize = crate::cipher_len!(k,du,dv);

#[derive(Clone,Debug)]
pub struct EncapsulationKey(internal::EncapsulationKey<k, eta1, eta2>);

#[derive(Clone, Debug)]
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
    pub fn encaps(&self) -> ([u8; 32], [u8; cipher_len]) {
        let mut rng = rand::rng();
        let m = rng.random();
        self.0.encaps_internal::<du, dv>(&m)
    }

    pub fn byte_encode(&self, b:&mut [u8;ek_len]) {
        self.0.byte_encode(b);
    }

    pub fn byte_decode(b:&[u8;ek_len]) -> Self {
        EncapsulationKey(internal::EncapsulationKey::<k,eta1,eta2>::byte_decode(b))
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

    pub fn decaps(&self, c: &[u8; cipher_len]) -> [u8; 32] {
        self.dk.decaps_internal::<du, dv>(&self.ek.0,&self.dz[32..], c)
    }

    pub fn byte_encode(&self, b:&mut [u8; dk_len]){
        self.dk.byte_encode((&mut b[..384*k]).try_into().unwrap());
        
        self.ek.byte_encode((&mut b[384*k..384*k+ek_len]).try_into().unwrap());
        let h = H(&b[384*k..384*k+ek_len]);
        b[384*k+ek_len..384*k+ek_len+32].copy_from_slice(&h);
        b[384*k+ek_len+32..384*k+ek_len+64].copy_from_slice(&self.dz[32..]);
    }

    pub fn byte_decode(b:&[u8;dk_len]) -> Self {
        let dk = internal::DecapsulationKey::<k,eta1,eta2>::byte_decode((&b[..384*k]).try_into().unwrap());
        let ek = EncapsulationKey::byte_decode((&b[384*k..384*k+ek_len]).try_into().unwrap());
        let mut d = DecapsulationKey { dz:[0;64], ek, dk };
        d.dz[32..].copy_from_slice(&b[384*k+ek_len+32..384*k+ek_len+64]);
        d
    }
}


// exports C api

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_keygen(ek: *mut u8, dk: *mut u8)  {
    let d = keygen();
    let e = d.encapsulation_key_ref();

    let ek = unsafe {core::slice::from_raw_parts_mut(ek, ek_len)};
    let dk = unsafe {core::slice::from_raw_parts_mut(dk, dk_len)};
    
    d.byte_encode(dk.try_into().unwrap());
    e.byte_encode(ek.try_into().unwrap());
}

#[cfg(test)]
mod tests {
    use crate::mlkem::mlkem768::*;

    #[test]
    fn test_kem() {
        let d = keygen();
        let e = d.encapsulation_key_ref();
    
        let mut ek_bytes = [0;ek_len];
        let mut dk_bytes = [0;dk_len];
        
        d.byte_encode(&mut dk_bytes);
        e.byte_encode(&mut ek_bytes);

        let d = DecapsulationKey::byte_decode(&dk_bytes);
        let e = EncapsulationKey::byte_decode(&ek_bytes);


        let (key, c) = e.encaps();

        let key2 = d.decaps(&c);
        assert_eq!(key, key2);
    }
}