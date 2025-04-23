use crate::mlkem::internal::{self, keygen_internal_};
use rand::{CryptoRng, Rng};

pub(crate) const k: usize = 3;
pub(crate) const eta1: usize = 2;
pub(crate) const eta2: usize = 2;
pub(crate) const du: usize = 10;
pub(crate) const dv: usize = 4;

pub(crate) const ek_len: usize = crate::ek_len!(k);
pub(crate) const dk_len: usize = crate::dk_len!(k);
pub(crate) const cipher_len: usize = crate::cipher_len!(k, du, dv);

pub type EncapKey = internal::EncapKey<k, eta1, eta2>;
pub type DecapKey = internal::DecapKey<k, eta1, eta2>;

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

const dk_bytes_len:usize =  (2 * k + k * k) * 512 + 96;
const ek_bytes_len:usize = (k + k * k) * 512 + 64;

/// mlkem768_keygen_internal 密钥生成,dk必须指向(2 * k + k * k) * 512 + 96的缓冲区,k = 3
/// d,z必须指向32字节, d,z由调用者使用随机数发生器生成.
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_keygen_internal(dk: *mut u8, d: *const u8, z: *const u8) {
    let d = unsafe { core::slice::from_raw_parts(d, 32) }.try_into().unwrap();
    let z = unsafe { core::slice::from_raw_parts(z, 32) }.try_into().unwrap();
    let dk = unsafe { core::slice::from_raw_parts_mut(dk, dk_bytes_len) }
        .try_into()
        .unwrap();

    let decapkey = internal::keygen_internal_::<k, eta1, eta2>(d, z);
    decapkey.bytes_inplace(dk);
}


#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encap_internal(key: *mut u8, c: *mut u8, ek: *const u8, m: *const u8) -> i32 {
    let ek = unsafe { core::slice::from_raw_parts(ek, ek_bytes_len) }.try_into().unwrap();
    let m = unsafe { core::slice::from_raw_parts(m, 32) }.try_into().unwrap();
    let out_key = unsafe { core::slice::from_raw_parts_mut(key, 32) };
    let out_c = unsafe { core::slice::from_raw_parts_mut(c, cipher_len) };

    let ek = EncapKey::new_from_bytes(ek);
    let (key, c) = ek.encaps_internal(m);
    out_key.copy_from_slice(&key);
    out_c.copy_from_slice(&c);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_decap(key: *mut u8, c: *const u8, dk: *const u8) -> i32 {
    let dk = unsafe { core::slice::from_raw_parts(dk, dk_bytes_len) };
    let out_key = unsafe { core::slice::from_raw_parts_mut(key, 32) };
    let in_c = unsafe { core::slice::from_raw_parts(c, cipher_len) };

    let dk = DecapKey::new_from_bytes(dk.try_into().unwrap());
    let key = dk.decaps(in_c.try_into().unwrap());
    out_key.copy_from_slice(&key);
    0
}

// byte_encode encapkey
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encapkey_encode(ek_encoded: *mut u8, ek_unencoded: *const u8) {
    let ek_encoded = unsafe { core::slice::from_raw_parts_mut(ek_encoded, ek_len) }
    .try_into()
    .unwrap();
    let ek_unencoded = unsafe { core::slice::from_raw_parts(ek_unencoded, ek_bytes_len) }
        .try_into()
        .unwrap();

    let ek = EncapKey::new_from_bytes(ek_unencoded);
    
    ek.byte_encode_inplace(ek_encoded);
}

// byte_encode decapkey
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_decapkey_encode(dk_encoded: *mut u8, dk_unencoded: *const u8) {
    let dk_encoded = unsafe { core::slice::from_raw_parts_mut(dk_encoded, dk_len) }
    .try_into()
    .unwrap();
    let dk_unencoded = unsafe { core::slice::from_raw_parts(dk_unencoded, dk_bytes_len) }
        .try_into()
        .unwrap();

    let dk = DecapKey::new_from_bytes(dk_unencoded);
    
    dk.byte_encode_inplace(dk_encoded);
}