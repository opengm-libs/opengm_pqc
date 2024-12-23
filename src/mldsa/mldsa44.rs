use core::ffi::c_void;
use alloc::boxed::Box;

use super::{
    Q,
    internal,
};

pub(crate) const d:usize =       13;
pub(crate) const tau:usize =     39;
pub(crate) const lambda:usize =  128;
pub(crate) const gamma1:usize =  1 << 17;
pub(crate) const gamma2:usize =  (Q as usize - 1) / 88; //95232
pub(crate) const k:usize =       4;
pub(crate) const l:usize =       4;
pub(crate) const eta:usize =     2;
pub(crate) const beta:usize =    78;
pub(crate) const omega:usize =       80;
pub(crate) const sklen:usize =   2560;
pub(crate) const pklen:usize =   1312;
pub(crate) const siglen:usize =  2420;


pub type PublicKey = internal::PublicKey<k, l>;
pub type PrivateKey = internal::PrivateKey<k, l>;
pub type Signature = internal::Signature<k, l, lambda>;

pub fn keygen_internal(xi: &[u8; 32]) -> PrivateKey {
    internal::keygen_internal::<k, l, eta>(xi)
}

impl PrivateKey {
    pub fn sign_internal(&self, m: &[u8], rnd: &[u8; 32]) -> Signature {
        self.sign_internal_::<gamma1, gamma2, lambda, tau, beta, omega>(m, rnd)
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key_()
    }

    pub fn public_key_ref(&self) -> &PublicKey {
        self.public_key_ref_()
    }

    pub fn sk_encode_inplace(&self, b: &mut [u8; sklen]) {
        self.sk_encode_inplace_::<eta>(b);
    }

    pub fn sk_encode(&self) -> [u8; sklen] {
        self.sk_encode_::<eta>()
    }

    pub fn sk_decode(b: &[u8; sklen]) -> Self {
        internal::PrivateKey::sk_decode_::<eta>(b)
    }
}

impl PublicKey {
    pub fn verify_internal(&self, m: &[u8], sig: &Signature) -> bool {
        self.verify_internal_::<gamma1, gamma2, lambda, tau, beta>(m, &sig)
    }

    pub fn pk_encode_inplace(&self, b: &mut [u8; pklen]) {
        self.pk_encode_inplace_(b);
    }

    pub fn pk_encode(&self) -> [u8; pklen] {
        self.pk_encode_()
    }

    pub fn pk_decode(b: &[u8; pklen]) -> Self {
        internal::PublicKey::pk_decode_(b)
    }
}

impl Signature {
    pub fn sig_encode_inplace(&self, b: &mut [u8; siglen]) {
        self.sig_encode_inplace_::<gamma1, omega>(b);
    }

    pub fn sig_encode(&self) -> [u8; siglen] {
        self.sig_encode_::<gamma1, omega>()
    }

    pub fn sig_decode(b: &[u8; siglen]) -> Option<Self> {
        internal::Signature::sig_decode_::<gamma1, omega>(b)
    }
}

/////////////////////////////////////////////////////////////////////
///  exports C api
/////////////////////////////////////////////////////////////////////

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_generate_key_internal(xi: *const u8) -> *mut c_void {
    let xi = unsafe { core::slice::from_raw_parts(xi, 32) }.try_into().unwrap();
    Box::leak(Box::new(keygen_internal(xi))) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_public_key(sk_handle:  *mut c_void) -> *mut c_void {
    let private_key = unsafe { Box::from_raw(sk_handle as *mut PrivateKey) };
    let public_key = Box::leak(Box::new(private_key.public_key())) as *mut _ as *mut c_void;
    Box::leak(private_key);
    public_key
}


#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_private_key_encode(sk: *mut u8, sk_handle: *mut c_void) {
    // SAFTY: key_handle must be imported or generate key's returns.
    let private_key: Box<internal::PrivateKey<4, 4>> = unsafe { Box::from_raw(sk_handle as *mut PrivateKey) };

    let sk = unsafe { core::slice::from_raw_parts_mut(sk, sklen) }
        .try_into()
        .unwrap();

    private_key.sk_encode_inplace(sk);

    Box::leak(private_key);
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_public_key_encode(pk: *mut u8, pk_handle: *mut c_void) {
    // SAFTY: key_handle must be imported or generate key's returns.
    let public_key = unsafe { Box::from_raw(pk_handle as *mut PublicKey) };

    let pk = unsafe { core::slice::from_raw_parts_mut(pk, pklen) }
        .try_into()
        .unwrap();
    public_key.pk_encode_inplace(pk);

    Box::leak(public_key);
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_import_private_key(sk: *const u8) -> *mut c_void {
    let sk = unsafe { core::slice::from_raw_parts(sk, sklen) }.try_into().unwrap();
    Box::leak(Box::new(PrivateKey::sk_decode(&sk))) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_import_public_key(pk: *const u8) -> *mut c_void {
    let pk= unsafe { core::slice::from_raw_parts(pk, pklen) }.try_into().unwrap();
    Box::leak(Box::new(PublicKey::pk_decode(&pk))) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_sign_internal(
    sig: *mut u8,
    sk_handle: *mut c_void,
    m: *const u8,
    mlen: usize,
    rnd: *const u8,
) -> u32 {
    let sig = unsafe { core::slice::from_raw_parts_mut(sig, siglen) }
        .try_into()
        .unwrap();
    let sk = unsafe { Box::from_raw(sk_handle as *mut PrivateKey) };
    let m = unsafe { core::slice::from_raw_parts(m, mlen) }.try_into().unwrap();
    let rnd = unsafe { core::slice::from_raw_parts(rnd, 32) }.try_into().unwrap();
    let signature = sk.sign_internal(m, rnd);
    signature.sig_encode_inplace(sig);

    Box::leak(sk);
    // TODO: return error code.
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa44_verify_internal(sig: *const u8, pk_handle: *mut c_void, m: *const u8, mlen: usize) -> bool {
     let m = unsafe { core::slice::from_raw_parts(m, mlen)}.try_into().unwrap();
    let pk = unsafe { Box::from_raw(pk_handle as *mut PublicKey) };
    let sig = unsafe { core::slice::from_raw_parts(sig, siglen) }.try_into().unwrap();

    let sig = Signature::sig_decode(sig);
    if sig.is_none(){
        return false;
    }
    let ok = pk.verify_internal(m, sig.as_ref().unwrap());
    Box::leak(pk);
    ok
}

#[unsafe(no_mangle)]
extern "C" fn mldsa44_drop_private_key_handle(sk_handle: *mut c_void) {
    drop(unsafe { Box::from_raw(sk_handle as *mut PrivateKey) });
}

#[unsafe(no_mangle)]
extern "C" fn mldsa44_drop_public_key_handle(pk_handle: *mut c_void) {
    drop(unsafe { Box::from_raw(pk_handle as *mut PublicKey) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_sign_verify_internal() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let m: [u8; 32] = rng.random();
            let sk = keygen_internal(&rng.random());
            let mut b = [0;sklen];
            sk.sk_encode_inplace(&mut b);
            let rnd = rng.random();
            let sig = sk.sign_internal(&m, &rnd);
            let result = sk.public_key_ref().verify_internal(&m, &sig);
            assert!(result);
        }
    }
}
