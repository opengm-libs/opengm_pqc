
use crate::mlkem::internal::{self, keygen_internal_};
use rand::{CryptoRng, Rng};

pub(crate) const k: usize = 4;
pub(crate) const eta1: usize = 2;
pub(crate) const eta2: usize = 2;
pub(crate) const du: usize = 11;
pub(crate) const dv: usize = 5;

pub(crate) const ek_len: usize = crate::ek_len!(k);
pub(crate) const dk_len: usize = crate::dk_len!(k);
pub(crate) const cipher_len: usize = crate::cipher_len!(k, du, dv);

pub type EncapKey  = internal::EncapKey<k, eta1, eta2>;
pub type DecapKey =internal::DecapKey<k, eta1, eta2>;

pub fn keygen(rng: &mut dyn CryptoRng) -> DecapKey {
    let d = rng.random();
    let z = rng.random();
    keygen_internal_(&d, &z)
}

impl EncapKey {
    pub fn encaps(&self, rng: &mut dyn CryptoRng) -> ([u8; 32], [u8; cipher_len]) {
        let m = rng.random();
        self.encaps_internal_::<du, dv>(&m)
    }

    pub fn encaps_internal(&self, m: &[u8; 32]) -> ([u8; 32], [u8; cipher_len]) {
        self.encaps_internal_::<du, dv>(m)
    }
}

impl DecapKey {
    pub fn encapsulation_key(&self) -> EncapKey {
        self.ek.clone()
    }

    pub fn encapsulation_key_ref(&self) -> &EncapKey {
        &self.ek
    }

    pub fn decaps(&self, c: &[u8; cipher_len]) -> [u8; 32] {
        self.decaps_internal_::<du, dv>(c)
    }
}


/////////////////////////////////////////////////////////////////////
///  exports C api
/////////////////////////////////////////////////////////////////////



#[unsafe(no_mangle)]
pub extern "C" fn mlkem1024_keygen_internal(ek: *mut u8, dk: *mut u8, d: *const u8, z: *const u8) {
    let d = unsafe { core::slice::from_raw_parts(d, 32) }.try_into().unwrap();
    let z = unsafe { core::slice::from_raw_parts(z, 32) }.try_into().unwrap();
    let ek = unsafe { core::slice::from_raw_parts_mut(ek, ek_len) }
        .try_into()
        .unwrap();
    let dk = unsafe { core::slice::from_raw_parts_mut(dk, dk_len) }
        .try_into()
        .unwrap();

    let decapkey = internal::keygen_internal_::<k, eta1, eta2>(d, z);
    let encapkey = decapkey.encapsulation_key_ref();

    decapkey.byte_encode_inplace(dk);
    encapkey.byte_encode_inplace(ek);
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem1024_encap_internal(key: *mut u8, c: *mut u8, ek: *const u8, m: *const u8) -> i32 {
    let ek = unsafe { core::slice::from_raw_parts(ek, ek_len) }.try_into().unwrap();
    let m = unsafe { core::slice::from_raw_parts(m, 32) }.try_into().unwrap();
    let out_key = unsafe { core::slice::from_raw_parts_mut(key, 32) };
    let out_c = unsafe { core::slice::from_raw_parts_mut(c, cipher_len) };

    match EncapKey::byte_decode(ek) {
        Ok(ek) => {
            let (key, c) = ek.encaps_internal(m);
            out_key.copy_from_slice(&key);
            out_c.copy_from_slice(&c);
            0
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem1024_decap(key: *mut u8, c: *const u8, dk: *const u8) -> i32 {
    let dk = unsafe { core::slice::from_raw_parts(dk, dk_len) };
    let out_key = unsafe { core::slice::from_raw_parts_mut(key, 32) };
    let in_c = unsafe { core::slice::from_raw_parts(c, cipher_len) };

    match DecapKey::byte_decode(dk.try_into().unwrap()) {
        Ok(dk) => {
            let key = dk.decaps(in_c.try_into().unwrap());
            out_key.copy_from_slice(&key);
            0
        }
        Err(_) => -1,
    }
}
