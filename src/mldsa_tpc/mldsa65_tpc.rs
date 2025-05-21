use core::{ffi::c_void, iter::zip, ptr::null};

use alloc::boxed::Box;

use crate::mldsa::{mldsa65::*, rq::Rq};

use super::{errors::Result, internal::{self}};

pub type ClientKey = internal::ClientKey<k, l>;
pub type ServerKey = internal::ServerKey<k, l>;
pub type ClientKeyGenCtx = internal::ClientKeyGenCtx<k,l,eta>;
pub type ClientSignCtx = internal::ClientSignCtx<k, l>;

impl ClientKeyGenCtx {
    pub fn encode_client_t(&self, b: &mut [u8;512*k]){
        self.encode_client_t_(b)
    }
    pub fn new_internal(xi: &[u8; 32], r: &[u8; 64]) -> Self {
        Self::new_internal_(xi, r)
    }
    // send t: [Rq;k] to server
    pub fn generate_key(self, server_t: &[Rq; k], server_tr: &[u8; 64]) -> Result<ClientKey> {
        self.generate_key_(server_t, server_tr)
    }
}

impl ClientSignCtx {
    pub fn client_sign0(client_key: &ClientKey, client_rnd: &[u8; 32], m: &[u8]) -> Result<ClientSignCtx> {
        ClientSignCtx::client_sign0_::<gamma1, gamma2, lambda, tau, beta, omega, eta>(client_key, client_rnd, m)
    }

    pub fn client_sign1(
        &self,
        client_key: &ClientKey,
        server_w: &[Rq; k],
        server_z: &[Rq; l],
        server_cs2: &[Rq; k],
    ) -> Result<Signature> {
        self.client_sign1_::<gamma1, gamma2, lambda, tau, beta, omega, eta>(client_key, server_w, server_z, server_cs2)
    }
}

impl ClientKey{
    pub fn sk_encode(&self) -> [u8; sklen] {
        self.0.sk_encode()
    }

}
impl ServerKey {
    pub fn sk_encode(&self) -> [u8; sklen] {
        self.0.sk_encode()
    }
    pub fn keygen(xi: &[u8; 32], r: &[u8; 64], client_t: &[Rq; k]) -> (Self, [Rq; k]) {
        ServerKey::keygen_::<eta>(xi, r, client_t)
    }

    pub(crate) fn server_sign(
        &self,
        server_rnd: &[u8; 32],
        m: &[u8],
        client_mu: &[u8; 64],
        client_w: &[Rq; k],
    ) -> Result<([Rq; k], [Rq; l], [Rq; k])> {
        self.server_sign_::<gamma1, gamma2, lambda, tau, beta, omega, eta>(server_rnd, m, client_mu, client_w)
    }
}

/// xi: point to bytes array of length 32
/// r: point to bytes array of length 64
/// to_server: point to bytes array of length 512 * k, send this to server.
#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_keygen0_internal(xi: *const u8, r: *const u8, to_server: *mut u8) -> *mut c_void {
    let xi = unsafe { core::slice::from_raw_parts(xi, 32) }.try_into().unwrap();
    let r = unsafe { core::slice::from_raw_parts(r, 64) }.try_into().unwrap();
    let mut to_server:[u8;512*k] = unsafe { core::slice::from_raw_parts_mut(to_server, 512*k) }.try_into().unwrap();

    let ctx= ClientKeyGenCtx::new_internal(xi, r);
    ctx.encode_client_t(&mut to_server);

    Box::leak(Box::new(ctx)) as *mut _ as *mut c_void
}


#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_keygen1_internal( ctx: *const c_void, from_server: *const u8) -> *mut c_void {
    let ctx = unsafe { Box::from_raw(ctx as *mut ClientKeyGenCtx) };
    let from_server:&[u8;512*k+64] = unsafe { core::slice::from_raw_parts(from_server, 512*k) }.try_into().unwrap();  
    let mut t = [Rq::default(); k];

    let server_t:&[u8;512*k] = from_server[..512*k].try_into().unwrap();
    let server_tr:&[u8;64] = from_server[512*k..].try_into().unwrap();

    for (r, b) in zip(&mut t, server_t.chunks_exact(512)){
        r.from_bytes(b.try_into().unwrap());
    }
    let client_key_result = ctx.generate_key(&t, server_tr);
    if client_key_result.is_err(){
        return null::<c_void>() as *mut c_void
    }
    Box::leak(Box::new(client_key_result.unwrap())) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_server_keygen_internal( xi: *const u8, r: *const u8, from_client: *const u8, to_client: *mut u8) -> *mut c_void {
    let xi = unsafe { core::slice::from_raw_parts(xi, 32) }.try_into().unwrap();
    let r = unsafe { core::slice::from_raw_parts(r, 64) }.try_into().unwrap();
    let from_client:&[u8;512*k] = unsafe { core::slice::from_raw_parts(from_client, 512*k) }.try_into().unwrap();  
    let to_client:&mut [u8;512*k + 64] = unsafe { core::slice::from_raw_parts_mut(to_client, 512*k + 64) }.try_into().unwrap();  

    let out_server_t:&mut [u8;512*k] = &mut to_client[..512*k].try_into().unwrap();
    let out_server_tr:&mut [u8;64] = &mut to_client[512*k..].try_into().unwrap();

    let mut t = [Rq::default(); k];

    for (r, b) in zip(&mut t, from_client.chunks_exact(512)){
        r.from_bytes(b.try_into().unwrap());
    }

    let (server_key, server_t) = ServerKey::keygen(xi, r, &t);

    for (r, b) in zip(&server_t, out_server_t.chunks_exact_mut(512)){
        r.bytes_inplace(b.try_into().unwrap());
    }

    out_server_tr.copy_from_slice(&server_key.0.tr);


    Box::leak(Box::new(server_key)) as *mut _ as *mut c_void

}



// #[unsafe(no_mangle)]
// pub extern "C" fn mldsa65_tpc_client_sign0_internal(client_key: *mut c_void, client_rnd: *const u8, m: *const u8) -> *mut c_void {


// }

#[cfg(test)]
mod tests {

    use super::*;
    use rand::Rng;

    #[test]
    fn test_keygen() {
        for _i in 0..1000 {
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let ctx = ClientKeyGenCtx::new_internal(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t) = ServerKey::keygen(&xi, &server_r, &ctx.client_t);

            let client_key_result = ctx.generate_key( &server_t, &server_key.0.tr);
            assert!(client_key_result.is_ok());
            let client_key_result = client_key_result.unwrap();

            assert_eq!(client_key_result.0.K, server_key.0.K);
            assert_eq!(client_key_result.0.t0_, server_key.0.t0_);
        }
    }

    #[test]
    fn test_sign() {
        for _ in 0..10 {
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let ctx = ClientKeyGenCtx::new_internal(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t) = ServerKey::keygen(&xi, &server_r, &ctx.client_t);

            let client_key_result = ctx.generate_key( &server_t, &server_key.0.tr);
            assert!(client_key_result.is_ok());
            let client_key = client_key_result.unwrap();

            for _ in 0..100 {
                let mut client_rnd = rng.random();
                let mut server_rnd = rng.random();

                let m = [1u8; 32];
                let sig = loop {
                    let client_ctx = ClientSignCtx::client_sign0(&client_key, &client_rnd, &m).unwrap();

                    let (server_w, server_z, server_cs2) = server_key
                        .server_sign(&server_rnd, &m, &client_ctx.mu, &client_ctx.w)
                        .unwrap();

                    let result = client_ctx.client_sign1(&client_key, &server_w, &server_z, &server_cs2);
                    // result.unwrap()

                    if result.is_ok() {
                        break result.unwrap();
                    } else {
                        client_rnd = rng.random();
                        server_rnd = rng.random();
                    }
                };

                let public_key = client_key.0.public_key();
                let ok = public_key.verify_internal(&m, &sig);
                assert!(ok);
            }
        }
    }
}
