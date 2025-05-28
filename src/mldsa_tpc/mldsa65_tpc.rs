use core::{ffi::c_void, iter::zip, ptr::null};

use alloc::boxed::Box;

use crate::mldsa::{internal::PrivateKey, mldsa65::*, rq::Rq};

use super::{
    errors::Result,
    internal::{self, mu_w_encode},
};

pub type ClientKey = internal::ClientKey<k, l>;
pub type ServerKey = internal::ServerKey<k, l>;
pub type ClientKeyGenCtx = internal::ClientKeyGenCtx<k, l, eta>;
pub type ClientSignCtx = internal::ClientSignCtx<k, l>;

impl ClientKeyGenCtx {
    pub fn encode_client_t(&self, b: &mut [u8; 1024 * k]) {
        self.encode_client_t_(b)
    }
    pub fn new_internal(xi: &[u8; 32], r: &[u8; 64]) -> Self {
        Self::new_internal_(xi, r)
    }
    // send t: [Rq;k] to server
    pub fn generate_key(&mut self, server_t: &[Rq; k], server_tr: &[u8; 64]) -> Result<ClientKey> {
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

impl ClientKey {
    pub fn sk_encode(&self) -> [u8; sklen] {
        self.0.sk_encode()
    }

    pub fn sk_encode_inplace(&self, b:& mut [u8; sklen] ){
        self.0.sk_encode_inplace(b)
    }

    pub fn sk_decode(b: &[u8;sklen])-> Self{
        internal::ClientKey(PrivateKey::<k,l>::sk_decode(b))
    }
}
impl ServerKey {
    pub fn sk_encode(&self) -> [u8; sklen] {
        self.0.sk_encode()
    }
    pub fn sk_encode_inplace(&self, b:& mut [u8; sklen] ){
        self.0.sk_encode_inplace(b)
    }

    pub fn sk_decode(b: &[u8;sklen])-> Self{
        internal::ServerKey(PrivateKey::<k,l>::sk_decode(b))
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

pub const KeygenClientToServerDataLen: usize = 1024 * k;
// w || z || cs2
pub const KeygenServerToClientDataLen: usize = 1024 * k + 64;

/// xi: point to bytes array of length 32
/// r: point to bytes array of length 64
/// to_server: point to bytes array of length 1024 * k, send this to server.
#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_keygen0_internal(xi: *const u8, r: *const u8, to_server: *mut u8) -> *mut c_void {
    let xi = unsafe { core::slice::from_raw_parts(xi, 32) }.try_into().unwrap();
    let r = unsafe { core::slice::from_raw_parts(r, 64) }.try_into().unwrap();
    let to_server: &mut [u8;KeygenClientToServerDataLen] = unsafe { core::slice::from_raw_parts_mut(to_server, KeygenClientToServerDataLen) }
        .try_into()
        .unwrap();

    let ctx = ClientKeyGenCtx::new_internal(xi, r);
    ctx.encode_client_t(to_server);

    Box::leak(Box::new(ctx)) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_keygen1_internal(ctx: *const c_void, from_server: *const u8) -> *mut c_void {
    let mut ctx = unsafe { Box::from_raw(ctx as *mut ClientKeyGenCtx) };
    let from_server: &[u8; KeygenServerToClientDataLen] = unsafe { core::slice::from_raw_parts(from_server, KeygenServerToClientDataLen) }
        .try_into()
        .unwrap();
    let mut t = [Rq::default(); k];

    for (r, b) in zip(&mut t, from_server[..1024 * k].chunks_exact(1024)) {
        r.from_bytes(b.try_into().unwrap());
    }
    let client_key_result = ctx.generate_key(&t, from_server[1024 * k..].try_into().unwrap());
    if client_key_result.is_err() {
        return null::<c_void>() as *mut c_void;
    }
    Box::leak(ctx);
    Box::leak(Box::new(client_key_result.unwrap())) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_key_encode(sk_out: *mut u8, pk_out: *mut u8, sk_handle: *mut c_void) {
    let sk_out = unsafe { core::slice::from_raw_parts_mut(sk_out, sklen) }.try_into().unwrap();
    let pk_out = unsafe { core::slice::from_raw_parts_mut(pk_out, pklen) }.try_into().unwrap();
    let sk = unsafe { Box::from_raw(sk_handle as *mut ClientKey) };
    sk.0.public_key_ref().pk_encode_inplace(pk_out);
    sk.sk_encode_inplace(sk_out);
    Box::leak(sk);
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_server_key_encode(sk_out: *mut u8, pk_out: *mut u8, sk_handle: *mut c_void) {
    let sk_out = unsafe { core::slice::from_raw_parts_mut(sk_out, sklen) }.try_into().unwrap();
    let pk_out = unsafe { core::slice::from_raw_parts_mut(pk_out, pklen) }.try_into().unwrap();
    let sk = unsafe { Box::from_raw(sk_handle as *mut ServerKey) };
    sk.0.public_key_ref().pk_encode_inplace(pk_out);
    sk.sk_encode_inplace(sk_out);
    Box::leak(sk);
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_key_decode(b: *mut u8)-> *mut c_void {
    let b = unsafe { core::slice::from_raw_parts(b, sklen) }.try_into().unwrap();
    Box::leak(Box::new(ClientKey::sk_decode(b)))as *mut _ as *mut c_void
}
#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_server_key_decode(b: *mut u8)-> *mut c_void {
    let b = unsafe { core::slice::from_raw_parts(b, sklen) }.try_into().unwrap();
    Box::leak(Box::new(ServerKey::sk_decode(b)))as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_server_keygen_internal(
    xi: *const u8,
    r: *const u8,
    from_client: *const u8,
    to_client: *mut u8,
) -> *mut c_void {
    let xi = unsafe { core::slice::from_raw_parts(xi, 32) }.try_into().unwrap();
    let r = unsafe { core::slice::from_raw_parts(r, 64) }.try_into().unwrap();
    let from_client: &[u8;KeygenClientToServerDataLen] = unsafe { core::slice::from_raw_parts(from_client, KeygenClientToServerDataLen) }
        .try_into()
        .unwrap();
    let to_client: &mut [u8; KeygenServerToClientDataLen] = unsafe { core::slice::from_raw_parts_mut(to_client, KeygenServerToClientDataLen) }
        .try_into()
        .unwrap();

    let mut t = [Rq::default(); k];

    for (r, b) in zip(&mut t, from_client.chunks_exact(1024)) {
        r.from_bytes(b.try_into().unwrap());
    }

    let (server_key, server_t) = ServerKey::keygen(xi, r, &t);

    for (r, b) in zip(&server_t, to_client[..1024*k].chunks_exact_mut(1024)) {
        r.bytes_inplace(b.try_into().unwrap());
    }
    to_client[1024*k..].copy_from_slice(&server_key.0.tr);

    Box::leak(Box::new(server_key)) as *mut _ as *mut c_void
}

#[derive(Default)]
struct KeyAndSignCtx {
    ctx: ClientSignCtx,
    sk: ClientKey,
}

// mu || w
pub const SignClientToServerDataLen: usize = 64 + 1024 * k;
// w || z || cs2
pub const SignServerToClientDataLen: usize = 1024 * (2 * k + l);

#[unsafe(no_mangle)]
extern "C" fn mldsa65_tpc_drop_client_key_handle(handle: *mut c_void) {
    drop(unsafe { Box::from_raw(handle as *mut ClientKey) });
}

#[unsafe(no_mangle)]
extern "C" fn mldsa65_tpc_drop_server_key_handle(handle: *mut c_void) {
    drop(unsafe { Box::from_raw(handle as *mut ServerKey) });
}

#[unsafe(no_mangle)]
extern "C" fn mldsa65_tpc_drop_client_sign_ctx_handle(handle: *mut c_void) {
    drop(unsafe { Box::from_raw(handle as *mut ClientSignCtx) });
}

#[unsafe(no_mangle)]
extern "C" fn mldsa65_tpc_drop_client_keygen_ctx_handle(handle: *mut c_void) {
    drop(unsafe { Box::from_raw(handle as *mut ClientKeyGenCtx) });
}

#[unsafe(no_mangle)]
extern "C" fn mldsa65_tpc_import_client_key(sk: *const u8) ->*mut c_void {
    let sk = unsafe { core::slice::from_raw_parts(sk, sklen) }
        .try_into()
        .unwrap();
    Box::leak(Box::new(ClientKey::sk_decode(sk))) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
extern "C" fn mldsa65_tpc_import_server_key(sk: *const u8) ->*mut c_void {
    let sk = unsafe { core::slice::from_raw_parts(sk, sklen) }
        .try_into()
        .unwrap();
    Box::leak(Box::new(ServerKey::sk_decode(sk))) as *mut _ as *mut c_void
}

// to_server must have 64+1024*k bytes
#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_sign0_internal(
    to_server: *mut u8,
    client_key_handle: *mut c_void,
    client_rnd: *const u8,
    m: *const u8,
    mlen: usize,
) -> *mut c_void {
    let to_server = unsafe { core::slice::from_raw_parts_mut(to_server, SignClientToServerDataLen) }
        .try_into()
        .unwrap();

    let client_key =   unsafe { Box::from_raw(client_key_handle as *mut ClientKey) };

    let client_rnd = unsafe { core::slice::from_raw_parts(client_rnd, 32) }
        .try_into()
        .unwrap();
    let m = unsafe { core::slice::from_raw_parts(m, mlen) };

    // FIXME
    let ctx = ClientSignCtx::client_sign0(&client_key, client_rnd, m).unwrap();

    mu_w_encode(to_server, &ctx.mu, &ctx.w);
    
    Box::leak(client_key);
    Box::leak(Box::new(ctx)) as *mut _ as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_client_sign1(ctx: *mut c_void, client_key_handle: *mut c_void, signature: *mut u8, from_server: *const u8) -> bool {
    let client_key =   unsafe { Box::from_raw(client_key_handle as *mut ClientKey) };
    let signature: &mut [u8; siglen] = unsafe { core::slice::from_raw_parts_mut(signature, siglen) }
        .try_into()
        .unwrap();
    let from_server: &[u8; SignServerToClientDataLen] =
        unsafe { core::slice::from_raw_parts(from_server, SignServerToClientDataLen) }
            .try_into()
            .unwrap();

    let mut server_w = [Rq::default(); k];
    let mut server_z = [Rq::default(); l];
    let mut server_cs2 = [Rq::default(); k];
    for (w, b) in zip(&mut server_w, from_server[..1024 * k].chunks_exact(1024)) {
        w.from_bytes(b.try_into().unwrap());
    }
    for (z, b) in zip(&mut server_z, from_server[1024 * k..1024 * (k + l)].chunks_exact(1024)) {
        z.from_bytes(b.try_into().unwrap());
    }
    for (cs2, b) in zip(&mut server_cs2, from_server[1024 * (k + l)..].chunks_exact(1024)) {
        cs2.from_bytes(b.try_into().unwrap());
    }

    let ctx = unsafe { Box::from_raw(ctx as *mut ClientSignCtx) };
    let sig_result = ctx.client_sign1(&client_key, &server_w, &server_z, &server_cs2);
    
    Box::leak(client_key);
    Box::leak(ctx);
    if sig_result.is_err() {
        return false;
    }
    {
        sig_result.unwrap().sig_encode_inplace(signature);
        return true;
    }
}

// to_server must have 64+1024*k bytes
#[unsafe(no_mangle)]
pub extern "C" fn mldsa65_tpc_server_sign_internal(
    to_client: *mut u8,
    server_key_handle: *mut c_void,
    server_rnd: *const u8,
    m: *const u8,
    mlen: usize,
    from_client: *const u8,
) -> bool {
    let to_client: &mut [u8; SignServerToClientDataLen] =
        unsafe { core::slice::from_raw_parts_mut(to_client, SignServerToClientDataLen) }
            .try_into()
            .unwrap();
    let server_key =   unsafe { Box::from_raw(server_key_handle as *mut ServerKey) };

    let server_rnd: &[u8; 32] = unsafe { core::slice::from_raw_parts(server_rnd, 32) }
        .try_into()
        .unwrap();
    let m = unsafe { core::slice::from_raw_parts(m, mlen) };
    let from_client: &[u8; SignClientToServerDataLen] =
        unsafe { core::slice::from_raw_parts(from_client, SignClientToServerDataLen) }
            .try_into()
            .unwrap();

    let client_mu:&[u8;64] = &from_client[..64].try_into().unwrap();
    let mut client_w = [Rq::default(); k];

    for (w, b) in zip(&mut client_w, from_client[64..].chunks_exact(1024)) {
        w.from_bytes(b.try_into().unwrap());
    }

    let result = server_key.server_sign(server_rnd, m, client_mu, &client_w);
    Box::leak(server_key);
    if result.is_err() {
        return false;
    } else {
        let (server_w, server_z, server_cs2) = result.unwrap();
        for (w, b) in zip(&server_w, to_client[..1024 * k].chunks_exact_mut(1024)) {
            w.bytes_inplace(b.try_into().unwrap());
        }
        for (z, b) in zip(&server_z, to_client[1024 * k..1024 * (k + l)].chunks_exact_mut(1024)) {
            z.bytes_inplace(b.try_into().unwrap());
        }
        for (cs2, b) in zip(&server_cs2, to_client[1024 * (k + l)..].chunks_exact_mut(1024)) {
            cs2.bytes_inplace(b.try_into().unwrap());
        }
        return true;
    }
}

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
            let mut ctx = ClientKeyGenCtx::new_internal(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t) = ServerKey::keygen(&xi, &server_r, &ctx.client_t);

            let client_key_result = ctx.generate_key(&server_t, &server_key.0.tr);
            assert!(client_key_result.is_ok());
            let client_key_result = client_key_result.unwrap();

            assert_eq!(client_key_result.0.K, server_key.0.K);
            assert_eq!(client_key_result.0.t0_, server_key.0.t0_);
            assert_eq!(client_key_result.0.tr, server_key.0.tr);
        }
    }

    #[test]
    fn test_sign() {
        for _ in 0..10 {
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let mut ctx = ClientKeyGenCtx::new_internal(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t) = ServerKey::keygen(&xi, &server_r, &ctx.client_t);

            let client_key_result = ctx.generate_key(&server_t, &server_key.0.tr);
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
