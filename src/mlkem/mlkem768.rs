use core::ffi::c_void;
use alloc::boxed::Box;

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

/// mlkem768_keygen_internal 密钥生成,dk必须指向dk_len的缓冲区
/// d,z必须指向32字节, d,z由调用者使用随机数发生器生成.
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_keygen_internal(d: *const u8, z: *const u8) -> *mut c_void {
    let d = unsafe { core::slice::from_raw_parts(d, 32) }.try_into().unwrap();
    let z = unsafe { core::slice::from_raw_parts(z, 32) }.try_into().unwrap();
    
    Box::leak(Box::new(internal::keygen_internal_::<k, eta1, eta2>(d, z))) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encapkey(dk_handle: *mut c_void) -> *mut c_void {
    let dk = unsafe { Box::from_raw(dk_handle as *mut DecapKey) };
    
    let ek = Box::leak(Box::new(dk.encapsulation_key())) as *mut _ as *mut c_void;
    Box::leak(dk);
    ek


}
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encap_internal(key: *mut u8, c: *mut u8, ek_handle: *mut c_void, m: *const u8) -> i32 {
    let ek = unsafe { Box::from_raw(ek_handle as *mut EncapKey) };

    let m = unsafe { core::slice::from_raw_parts(m, 32) }.try_into().unwrap();
    let out_key = unsafe { core::slice::from_raw_parts_mut(key, 32) };
    let out_c = unsafe { core::slice::from_raw_parts_mut(c, cipher_len) };

    let (key, c) = ek.encaps_internal(m);
    out_key.copy_from_slice(&key);
    out_c.copy_from_slice(&c);

    Box::leak(ek);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_decap(key: *mut u8, c: *const u8, dk_handle: *mut c_void) -> i32 {
    let dk = unsafe { Box::from_raw(dk_handle as *mut DecapKey) };

    let out_key = unsafe { core::slice::from_raw_parts_mut(key, 32) };
    let in_c = unsafe { core::slice::from_raw_parts(c, cipher_len) };

    let key = dk.decaps(in_c.try_into().unwrap());
    out_key.copy_from_slice(&key);

    Box::leak(dk);
    0
}

// byte_encode encapkey
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encapkey_encode(ek_encoded: *mut u8, ek_handle: *mut c_void) {
    let ek_encoded = unsafe { core::slice::from_raw_parts_mut(ek_encoded, ek_len) }
    .try_into()
    .unwrap();
    let ek = unsafe { Box::from_raw(ek_handle as *mut EncapKey) };
    
    ek.byte_encode_inplace(ek_encoded);
    Box::leak(ek);
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encapkey_decode(ek_encoded: *const u8) -> *mut c_void {
    let ek_encoded = unsafe { core::slice::from_raw_parts(ek_encoded, ek_len) }
    .try_into()
    .unwrap();
    Box::leak(Box::new(EncapKey::byte_decode(ek_encoded).unwrap())) as *mut _ as *mut c_void
}

// byte_encode decapkey
#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_decapkey_encode(dk_encoded: *mut u8, dk_handle: *mut c_void) {
    let dk = unsafe { Box::from_raw(dk_handle as *mut DecapKey) };
    let dk_encoded = unsafe { core::slice::from_raw_parts_mut(dk_encoded, dk_len) }
    .try_into()
    .unwrap();
    
    dk.byte_encode_inplace(dk_encoded);

    Box::leak(dk);
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_decapkey_decode(dk_encoded: *const u8) -> *mut c_void {
    let dk_encoded = unsafe { core::slice::from_raw_parts(dk_encoded, dk_len) }
    .try_into()
    .unwrap();
    Box::leak(Box::new(DecapKey::byte_decode(dk_encoded).unwrap())) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
extern "C" fn  mlkem768_drop_encapkey_handle(ek_handle: *mut c_void) {
    drop(unsafe { Box::from_raw(ek_handle as *mut EncapKey) });
}

#[unsafe(no_mangle)]
extern "C" fn mlkem768_drop_decapkey_handle(dk_handle: *mut c_void) {
    drop(unsafe { Box::from_raw(dk_handle as *mut DecapKey) });
}