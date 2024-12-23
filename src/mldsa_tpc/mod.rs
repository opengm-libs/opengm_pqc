use core::iter::zip;
use crate::mldsa::auxiliary::{
    expand_a, expand_mask, expand_s, high_bits, low_bits, make_hint, power2_round, rej_bounded_poly, sample_in_ball,
    w1_encode,
};
use crate::mldsa::errors::{Error, Result};
use crate::mldsa::hash::H;
use crate::mldsa::internal::{PublicKey, Signature};
use crate::mldsa::reduce::mod_q;
use crate::mldsa::util::{bitlen, vec_norm_less_than};
use crate::mldsa::{N, Q};
use crate::mldsa::{internal::PrivateKey, rq::Rq};

use crate::{mldsa::hash::new_h, sha3::XOF};

// MLDSA 客户端和服务端的部分私钥
#[derive(Clone)]
pub(crate) struct PartialKey<const k: usize, const l: usize> {
    rho: [u8; 32],
    A: [[Rq; l]; k],

    K: [u8; 32],

    // in ntt form.
    s1_: [Rq; l],
    s2_: [Rq; k],
    t0_: [Rq; k],
}

impl<const k: usize, const l: usize> Default for PartialKey<k, l> {
    fn default() -> Self {
        Self {
            rho: [0; 32],
            A: [[Rq::default(); l]; k],
            K: [0; 32],
            s1_: [Rq::default(); l],
            s2_: [Rq::default(); k],
            t0_: [Rq::default(); k],
        }
    }
}

fn expand_error<const k: usize, const eta: usize>(e: &mut [Rq; k], rho: &[u8; 64], mu: usize) {
    for r in 0..k {
        // e[r] = Rq::default();
        rej_bounded_poly::<eta>(&mut e[r], rho, (r + mu) as u16);
    }
}

// r to generate s instead of rho_prime
fn partial_keygen_internal<const k: usize, const l: usize, const eta: usize>(
    xi: &[u8; 32],
    r: &[u8; 64],
) -> (PartialKey<k, l>, [Rq; k])
where
    [(); eta / 2]:,
{
    let mut sk = PartialKey::default();

    let mut rho_prime = [0; 64];
    let mut h = new_h();
    h.absorb(xi).absorb(&[k as u8, l as u8]);
    h.squeeze(&mut sk.rho).squeeze(&mut rho_prime).squeeze(&mut sk.K);

    expand_a::<k, l>(&mut sk.A, &sk.rho);

    expand_s::<k, l, { eta / 2 }>(&mut sk.s1_, &mut sk.s2_, r);

    // NTT(s1)
    for s1 in &mut sk.s1_ {
        s1.ntt();
    }

    // t = As1 + s2
    let mut t = [Rq::default(); k];
    for i in 0..k {
        t[i].dot_mul(&sk.A[i], &sk.s1_);
        t[i].ntt_inverse();
        t[i].add_assign(&sk.s2_[i]);
    }

    //note: s2 is in ntt form
    for s2 in &mut sk.s2_ {
        s2.ntt();
    }

    (sk, t)
}

#[derive(Default)]
pub struct ClientKey<const k: usize, const l: usize> {
    k: PrivateKey<k, l>,
}

#[derive(Default)]
pub struct ServerKey<const k: usize, const l: usize> {
    k: PrivateKey<k, l>,
}

// send t: [Rq;k] to server
pub(crate) fn ClientKeyGen0<const k: usize, const l: usize, const eta: usize>(
    xi: &[u8; 32],
    r: &[u8; 64],
) -> (PartialKey<k, l>, [Rq; k])
where
    [(); eta / 2]:,
{
    partial_keygen_internal::<k, l, eta>(xi, r)
}

// return server's key, server's t, and tr
pub fn ServerKeyGen<const k: usize, const l: usize, const eta: usize>(
    xi: &[u8; 32],
    client_t: [Rq; k],
    r: &[u8; 64],
) -> (ServerKey<k, l>, [Rq; k], [u8; 64])
where
    [(); eta / 2]:,
    [(); 32 + 320 * k]:,
{
    let (server_partial_key, server_t) = partial_keygen_internal::<k, l, eta>(xi, r);

    let mut t = [Rq::default(); k];
    let mut t0 = [Rq::default(); k];
    let mut t1 = [Rq::default(); k];
    for i in 0..k {
        t[i].add(&server_t[i], &client_t[i]);
    }

    for i in 0..k {
        for j in 0..N {
            (t0[i][j], t1[i][j]) = power2_round(mod_q(t[i][j]))
        }
        t0[i].ntt();
    }

    let mut tr = [0; 64];
    let pk = PublicKey::<k, l> {
        rho: server_partial_key.rho,
        t1: t1,
        A: server_partial_key.A,
    };
    H(&mut tr, &pk.pk_encode_());
    let server_key = ServerKey {
        k: PrivateKey::<k, l> {
            pk: pk,
            K: server_partial_key.K,
            tr: tr,
            s1_: server_partial_key.s1_,
            s2_: server_partial_key.s2_,
            t0_: t0,
        },
    };

    (server_key, server_t, tr)
}

// send t: [Rq;k] to server
pub(crate) fn ClientKeyGen1<const k: usize, const l: usize, const eta: usize>(
    client_partial_key: &PartialKey<k, l>,
    client_t: &[Rq; k],
    server_t: &[Rq; k],
    server_tr: &[u8; 64],
) -> Option<ClientKey<k, l>>
where
    [(); eta / 2]:,
    [(); 32 + 320 * k]:,
{
    let mut t = [Rq::default(); k];
    let mut t0 = [Rq::default(); k];
    let mut t1 = [Rq::default(); k];
    for i in 0..k {
        t[i].add(&server_t[i], &client_t[i]);
    }

    for i in 0..k {
        for j in 0..N {
            (t0[i][j], t1[i][j]) = power2_round(mod_q(t[i][j]))
        }
        t0[i].ntt();
    }

    let mut tr = [0; 64];
    let pk = PublicKey::<k, l> {
        rho: client_partial_key.rho,
        t1: t1,
        A: client_partial_key.A,
    };
    H(&mut tr, &pk.pk_encode_());

    for (a, b) in zip(tr, server_tr) {
        if a != *b {
            return None;
        }
    }

    let client_key = ClientKey {
        k: PrivateKey::<k, l> {
            pk: pk,
            K: client_partial_key.K,
            tr: tr,
            s1_: client_partial_key.s1_,
            s2_: client_partial_key.s2_,
            t0_: t0,
        },
    };

    Some(client_key)
}

struct ClientSignCtx<const k: usize, const l: usize> {
    e1: [Rq; k],
    e2: [Rq; k],
    e: [Rq; k],
    y: [Rq; l],
    w: [Rq; k],
    mu: [u8; 64],
}
impl<const k: usize, const l: usize> Default for ClientSignCtx<k, l> {
    fn default() -> Self {
        ClientSignCtx {
            e1: [Rq::default(); k],
            e2: [Rq::default(); k],
            e: [Rq::default(); k],
            y: [Rq::default(); l],
            w: [Rq::default(); k],
            mu: [0; 64],
        }
    }
}

impl<const k: usize, const l: usize> ClientSignCtx<k, l> {
    pub fn client_sign0<
        const gamma1: usize,
        const gamma2: usize,
        const lambda: usize,
        const tau: usize,
        const beta: usize,
        const omega: usize,
        const eta: usize,
    >(
        client_key: &ClientKey<k, l>,
        client_rnd: &[u8; 32],
        m: &[u8],
    ) -> Result<ClientSignCtx<k, l>>
    where
        [(); gamma1 / 2]:,
        [(); 32 * k * bitlen((Q as usize - 1) / (2 * gamma2) - 1)]:,
        [(); lambda / 4]:,
    {
        let mut ctx = ClientSignCtx::default();
        let mut h = new_h();
        h.absorb(&client_key.k.tr).absorb(m).squeeze(&mut ctx.mu);

        // rho_pp use to generate server side y and e.
        let mut rho_pp = [0; 64];
        h.init()
            .absorb(&client_key.k.K)
            .absorb(client_rnd)
            .absorb(&ctx.mu)
            .squeeze(&mut rho_pp);

        // rho_ppp shared with client, to generate shared e.
        let mut rho_ppp = [0; 64];
        h.init().absorb(&client_key.k.K).absorb(&ctx.mu).squeeze(&mut rho_ppp);
        // let mut kappa: usize = 0;
        // e = e1 - e2
        expand_error::<k, eta>(&mut ctx.e, &rho_ppp, 0);

        let mut y_ = [Rq::default(); l];

        expand_mask::<k, l, { gamma1 / 2 }>(&mut ctx.y, &rho_pp, 0);
        expand_error::<k, eta>(&mut ctx.e2, &rho_pp, l);
        // e = e1 - e2
        for i in 0..k {
            ctx.e1[i].add(&ctx.e[i], &ctx.e2[i]);
        }

        for i in 0..l {
            y_[i] = ctx.y[i];
            y_[i].ntt();
        }

        // client_w = A*y+e1
        for i in 0..k {
            ctx.w[i].dot_mul(&client_key.k.pk.A[i], &y_);
            ctx.w[i].ntt_inverse();
            ctx.w[i].add_assign(&ctx.e1[i]);
        }

        Ok(ctx)
    }

    pub fn client_sign1<
        const gamma1: usize,
        const gamma2: usize,
        const lambda: usize,
        const tau: usize,
        const beta: usize,
        const omega: usize,
        const eta: usize,
    >(
        &self,
        client_key: &ClientKey<k, l>,
        server_w: &[Rq; k],
        server_z: &[Rq; l],
        server_cs2: &[Rq; k],
    ) -> Result<Signature<k, l, lambda>>
    where
        [(); 32 * k * bitlen((Q as usize - 1) / (2 * gamma2) - 1)]:,
        [(); lambda / 4]:,
    {
        let mut w = [Rq::default(); k];
        let mut w1 = [Rq::default(); k];
        let mut z = [Rq::default(); l];
        let mut c_tilde = [0u8; lambda / 4];

        // w = server_w + client_w = (A*y+e1) + client_w
        // w1 = HighBits(w)
        for i in 0..k {
            w[i].add(&self.w[i], &server_w[i]);
            w[i].mod_q();
            for j in 0..N {
                w1[i].coeffs[j] = high_bits::<gamma2>(w[i].coeffs[j]);
            }
        }

        let mut shake = new_h();

        let mut b = [0u8; 32 * k * bitlen((Q as usize - 1) / (2 * gamma2) - 1)];

        w1_encode::<k, gamma2>(&mut b, &w1);

        shake.absorb(&self.mu).absorb(&b).squeeze(&mut c_tilde);

        let mut c = Rq::default();
        sample_in_ball::<tau>(&mut c, &c_tilde);
        c.ntt();

        // z = y + cs1
        let mut client_z = [Rq::default(); l];
        for i in 0..l {
            client_z[i].mul(&c, &client_key.k.s1_[i]);
            client_z[i].ntt_inverse();
            client_z[i].add_assign(&self.y[i]);
        }

        // z = client_z + server_z
        for i in 0..l {
            z[i].add(&client_z[i], &server_z[i]);
        }

        // cs2 = c*s2 + e2 + server_cs2
        let mut cs2 = [Rq::default(); k];
        for i in 0..k {
            cs2[i].mul(&c, &client_key.k.s2_[i]);
            cs2[i].ntt_inverse();
            cs2[i].add_assign(&self.e2[i]);
            cs2[i].add_assign(&server_cs2[i]);
        }

        // check
        let mut w_cs2 = [Rq::default(); k];
        let mut r0 = [Rq::default(); k];
        for i in 0..k {
            w_cs2[i].sub(&w[i], &cs2[i]);
            for j in 0..N {
                r0[i][j] = low_bits::<gamma2>(w_cs2[i][j]);
            }
        }

        if !vec_norm_less_than(&z, (gamma1 - beta) as i32) || !vec_norm_less_than(&r0, (gamma2 - beta - 3 * eta) as i32)
        {
            return Err(Error::TPCServerCheckFailed);
        }

        let mut ct0 = [Rq::default(); k];
        for i in 0..k {
            ct0[i].mul(&c, &client_key.k.t0_[i]);
            ct0[i].ntt_inverse();
        }

        let mut hw = 0;
        let mut h = [[0u8; N]; k];
        // make hint
        for i in 0..k {
            for j in 0..N {
                let a = -ct0[i].coeffs[j];
                let b = w_cs2[i].coeffs[j] + ct0[i].coeffs[j];
                h[i][j] = make_hint::<gamma2>(a, b);
                hw += h[i][j] as usize;
            }
        }

        if hw > omega {
            return Err(Error::TPCServerCheckFailed);
        }
        if !vec_norm_less_than(&ct0, gamma2 as i32) {
            return Err(Error::TPCServerCheckFailed);
        }
        // break;
        Ok(Signature {
            c_wave: c_tilde,
            z: z,
            h: h,
        })
    }
}

impl<const k: usize, const l: usize> ServerKey<k, l> {
    // server side is stateless.
    // each time generage a fress server_rnd, by increasing kappa.
    pub(crate) fn server_sign<
        const gamma1: usize,
        const gamma2: usize,
        const lambda: usize,
        const tau: usize,
        const beta: usize,
        const omega: usize,
        const eta: usize,
    >(
        &self,
        server_rnd: &[u8; 32],
        m: &[u8],
        client_mu: &[u8; 64],
        client_w: &[Rq; k],
    ) -> Result<([Rq; k], [Rq; l], [Rq; k])>
    where
        [(); gamma1 / 2]:,
        [(); 32 * k * bitlen((Q as usize - 1) / (2 * gamma2) - 1)]:,
        [(); lambda / 4]:,
    {
        let mut mu = [0; 64];
        let mut h = new_h();
        h.absorb(&self.k.tr).absorb(m).squeeze(&mut mu);
        // check if mu == client_mu
        if client_mu != &mu {
            return Err(Error::TPCServerCheckFailed);
        }

        // rho_pp use to generate server side y and e.
        let mut rho_pp = [0; 64];
        h.init()
            .absorb(&self.k.K)
            .absorb(server_rnd)
            .absorb(&mu)
            .squeeze(&mut rho_pp);

        // rho_ppp shared with client, to generate shared e.
        let mut rho_ppp = [0; 64];
        h.init().absorb(&self.k.K).absorb(&mu).squeeze(&mut rho_ppp);

        // let mut kappa: usize = 0;
        // e = e2 - e1
        let mut e1 = [Rq::default(); k];
        let mut e2 = [Rq::default(); k];
        let mut e = [Rq::default(); k];
        expand_error::<k, eta>(&mut e, &rho_ppp, 0);

        let mut y = [Rq::default(); l];
        let mut y_ = [Rq::default(); l];
        let mut server_w = [Rq::default(); k];
        let mut w1 = [Rq::default(); k];
        let mut c_tilde = [0u8; lambda / 4];

        expand_mask::<k, l, { gamma1 / 2 }>(&mut y, &rho_pp, 0);
        expand_error::<k, eta>(&mut e1, &rho_pp, l);
        // e = e2 - e1
        for i in 0..k {
            e2[i].add(&e[i], &e1[i]);
        }

        for i in 0..l {
            y_[i] = y[i];
            y_[i].ntt();
        }

        // w = server_w + client_w = (A*y+e1) + client_w
        // w1 = HighBits(w)
        for i in 0..k {
            server_w[i].dot_mul(&self.k.pk.A[i], &y_);
            server_w[i].ntt_inverse();
            server_w[i].add_assign(&e1[i]);
            w1[i].add(&client_w[i], &server_w[i]);
            w1[i].mod_q();
        }
        for i in 0..k {
            for j in 0..N {
                w1[i].coeffs[j] = high_bits::<gamma2>(w1[i].coeffs[j]);
            }
        }

        let mut shake = new_h();

        let mut b = [0u8; 32 * k * bitlen((Q as usize - 1) / (2 * gamma2) - 1)];

        w1_encode::<k, gamma2>(&mut b, &w1);

        shake.absorb(&mu).absorb(&b).squeeze(&mut c_tilde);
        let mut c = Rq::default();
        sample_in_ball::<tau>(&mut c, &c_tilde);
        c.ntt();

        // z = y + cs1
        let mut server_z = [Rq::default(); l];
        for i in 0..l {
            server_z[i].mul(&c, &self.k.s1_[i]);
            server_z[i].ntt_inverse();
            server_z[i].add_assign(&y[i]);
        }

        // cs2 = c*s2 + e2
        let mut server_cs2 = [Rq::default(); k];
        for i in 0..k {
            server_cs2[i].mul(&c, &self.k.s2_[i]);
            server_cs2[i].ntt_inverse();
            server_cs2[i].add_assign(&e2[i]);
        }

        Ok((server_w, server_z, server_cs2))
    }
}

fn combie_key<const k: usize, const l: usize>(
    client_key: &ClientKey<k, l>,
    server_key: &ServerKey<k, l>,
) -> PrivateKey<k, l> {
    let mut sk = PrivateKey::default();
    sk.pk = client_key.k.pk.clone();
    sk.K = client_key.k.K;
    sk.tr = client_key.k.tr;
    sk.t0_ = client_key.k.t0_;
    for i in 0..l {
        sk.s1_[i].add(&client_key.k.s1_[i], &server_key.k.s1_[i]);
    }
    for i in 0..k {
        sk.s2_[i].add(&client_key.k.s2_[i], &server_key.k.s2_[i]);
    }

    sk
}

fn check_key<const k: usize, const l: usize>(sk: &PrivateKey<k, l>) -> bool {
    // t = As1 + s2
    let mut t = [Rq::default(); k];
    let mut t0 = sk.t0_.clone();
    let mut s2 = sk.s2_.clone();
    for i in 0..k {
        t[i].dot_mul(&sk.pk.A[i], &sk.s1_);
        t[i].ntt_inverse();
        s2[i].ntt_inverse_raw();
        t[i].add_assign(&s2[i]);
        t[i].mod_q();

        t0[i].ntt_inverse_raw();
        for j in 0..N {
            let want = t0[i][j] + (sk.pk.t1[i][j] << 13);
            if t[i][j] != want {
                return false;
            }
        }
    }
    true
}
#[cfg(test)]
mod tests {

    
    use rand::Rng;

    use crate::{
        hex_println,
        mldsa::mldsa65::*,
        mldsa_tpc::{ClientSignCtx, check_key, combie_key},
    };

    use super::{ClientKeyGen0, ClientKeyGen1, ServerKeyGen};

    #[test]
    fn test_keygen() {
        for _i in 0..1000000 {
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let (client_partial_key, client_t) = ClientKeyGen0::<k, l, eta>(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t, server_tr) = ServerKeyGen::<k, l, eta>(&xi, client_t, &server_r);

            let client_key = ClientKeyGen1::<k, l, eta>(&client_partial_key, &client_t, &server_t, &server_tr);
            assert!(client_key.is_some());
            let client_key = client_key.unwrap();
            assert_eq!(client_key.k.K, server_key.k.K);
            assert_eq!(client_key.k.t0_, server_key.k.t0_);

            let sk = combie_key(&client_key, &server_key);
            assert!(check_key(&sk));
            let m: [u8; 32] = rng.random();
            let sig = sk.sign_internal(&m, &rng.random());
            let ok = client_key.k.public_key_ref().verify_internal(&m, &sig);
            assert!(ok);
        }
    }

    #[test]
    fn test_sign() {
        for i in 0..1000000 {
            println!("{}", i * 1000);
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let (client_partial_key, client_t) = ClientKeyGen0::<k, l, eta>(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t, server_tr) = ServerKeyGen::<k, l, eta>(&xi, client_t, &server_r);

            let client_key = ClientKeyGen1::<k, l, eta>(&client_partial_key, &client_t, &server_t, &server_tr);
            assert!(client_key.is_some());
            let client_key = client_key.unwrap();
            assert_eq!(client_key.k.K, server_key.k.K);
            assert_eq!(client_key.k.tr, server_key.k.tr);

            let sk = combie_key(&client_key, &server_key);
            assert!(check_key(&sk));

            for _ in 0..1000 {
                let mut client_rnd = rng.random();
                let mut server_rnd = rng.random();

                let m = [1u8; 32];
                let sig = loop {
                    let client_ctx = ClientSignCtx::client_sign0::<gamma1, gamma2, lambda, tau, beta, omega, eta>(
                        &client_key,
                        &client_rnd,
                        &m,
                    )
                    .unwrap();

                    let (server_w, server_z, server_cs2) = server_key
                        .server_sign::<gamma1, gamma2, lambda, tau, beta, omega, eta>(
                            &server_rnd,
                            &m,
                            &client_ctx.mu,
                            &client_ctx.w,
                        )
                        .unwrap();

                    let result = client_ctx.client_sign1::<gamma1, gamma2, lambda, tau, beta, omega, eta>(
                        &client_key,
                        &server_w,
                        &server_z,
                        &server_cs2,
                    );
                    // result.unwrap()

                    if result.is_ok() {
                        break result.unwrap();
                    } else {
                        client_rnd = rng.random();
                        server_rnd = rng.random();
                    }
                };

                let public_key = client_key.k.public_key();
                let ok = public_key.verify_internal(&m, &sig);
                if !ok {
                    hex_println(&xi);
                    hex_println(&client_r);
                    hex_println(&server_r);
                    hex_println(&client_rnd);
                    hex_println(&server_rnd);
                    assert!(ok);
                }
            }
        }
    }
}
