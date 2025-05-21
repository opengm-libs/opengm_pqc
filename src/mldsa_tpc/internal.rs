use super::errors::{Error, Result};
use crate::mldsa::auxiliary::{
    expand_a, expand_mask, expand_s, high_bits, low_bits, make_hint, power2_round, rej_bounded_poly, sample_in_ball,
    w1_encode,
};
use crate::mldsa::hash::H;
use crate::mldsa::internal::Signature;
use crate::mldsa::reduce::mod_q;
use crate::mldsa::util::{bitlen, vec_norm_less_than};
use crate::mldsa::{N, Q};
use crate::mldsa::{internal::PrivateKey, rq::Rq};
use core::iter::zip;

use crate::{mldsa::hash::new_h, sha3::XOF};

fn expand_error<const k: usize, const eta: usize>(e: &mut [Rq; k], rho: &[u8; 64], mu: usize) {
    for r in 0..k {
        rej_bounded_poly::<eta>(&mut e[r], rho, (r + mu) as u16);
    }
}

// r to generate s instead of rho_prime
fn partial_keygen_internal<const k: usize, const l: usize, const eta: usize>(
    xi: &[u8; 32],
    r: &[u8; 64],
) -> (PrivateKey<k, l>, [Rq; k])
where
    [(); eta / 2]:,
{
    let mut sk = PrivateKey::default();

    let mut rho_prime = [0; 64];
    let mut h = new_h();
    h.absorb(xi).absorb(&[k as u8, l as u8]);
    h.squeeze(&mut sk.pk.rho).squeeze(&mut rho_prime).squeeze(&mut sk.K);

    expand_a::<k, l>(&mut sk.pk.A, &sk.pk.rho);

    expand_s::<k, l, { eta / 2 }>(&mut sk.s1_, &mut sk.s2_, r);
    // expand_s::<k, l, eta>(&mut sk.s1_, &mut sk.s2_, r);

    // NTT(s1)
    for s1 in &mut sk.s1_ {
        s1.ntt();
    }

    // t = As1 + s2
    let mut t = [Rq::default(); k];
    for i in 0..k {
        t[i].dot_mul(&sk.pk.A[i], &sk.s1_);
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
pub struct ClientKey<const k: usize, const l: usize>(pub(crate) PrivateKey<k, l>);

impl<const k: usize, const l: usize> From<PrivateKey<k, l>> for ClientKey<k, l> {
    fn from(value: PrivateKey<k, l>) -> Self {
        ClientKey(value)
    }
}
impl<const k: usize, const l: usize> From<ClientKey<k, l>> for PrivateKey<k, l> {
    fn from(value: ClientKey<k, l>) -> Self {
        value.0
    }
}
#[derive(Default)]
pub struct ServerKey<const k: usize, const l: usize>(pub(crate) PrivateKey<k, l>);

impl<const k: usize, const l: usize> From<PrivateKey<k, l>> for ServerKey<k, l> {
    fn from(value: PrivateKey<k, l>) -> Self {
        ServerKey(value)
    }
}
impl<const k: usize, const l: usize> From<ServerKey<k, l>> for PrivateKey<k, l> {
    fn from(value: ServerKey<k, l>) -> Self {
        value.0
    }
}

pub struct ClientKeyGenCtx<const k: usize, const l: usize, const eta: usize> {
    // send to server
    pub(crate) client_t: [Rq; k],
    pub(crate) client_key: PrivateKey<k, l>,
}

impl<const k: usize, const l: usize, const eta: usize> ClientKeyGenCtx<k, l, eta> {
    pub(crate) fn new_internal_(xi: &[u8; 32], r: &[u8; 64]) -> Self
    where
        [(); eta / 2]:,
    {
        let (client_key, client_t) = partial_keygen_internal::<k, l, eta>(xi, r);
        ClientKeyGenCtx { client_t, client_key }
    }

    pub(crate) fn encode_client_t_(&self, b: &mut [u8; 512 * k]) {
        for (r, b) in zip(&self.client_t, b.chunks_exact_mut(512)) {
            r.bytes_inplace(b.try_into().unwrap());
        }
    }

    pub(crate) fn generate_key_(mut self, server_t: &[Rq; k], server_tr: &[u8; 64]) -> Result<ClientKey<k, l>>
    where
        [(); eta / 2]:,
        [(); 32 + 320 * k]:,
    {
        let mut t = [Rq::default(); k];
        for i in 0..k {
            t[i].add(&server_t[i], &self.client_t[i]);
        }

        for i in 0..k {
            for j in 0..N {
                (self.client_key.t0_[i][j], self.client_key.pk.t1[i][j]) = power2_round(mod_q(t[i][j]))
            }
            self.client_key.t0_[i].ntt();
        }

        H(&mut self.client_key.tr, &self.client_key.pk.pk_encode_());

        for (a, b) in zip(self.client_key.tr, server_tr) {
            if a != *b {
                return Err(Error::TPCPublicKeyUnMatch);
            }
        }

        Ok(ClientKey(self.client_key))
    }
}

impl<const k: usize, const l: usize> ServerKey<k, l> {
    // return server's key, server's t, and tr
    pub(crate) fn keygen_<const eta: usize>(xi: &[u8; 32], r: &[u8; 64], client_t: &[Rq; k]) -> (Self, [Rq; k])
    where
        [(); eta / 2]:,
        [(); 32 + 320 * k]:,
    {
        let (mut server_key, server_t) = partial_keygen_internal::<k, l, eta>(xi, r);

        let mut t = [Rq::default(); k];
        for i in 0..k {
            t[i].add(&server_t[i], &client_t[i]);
        }

        for i in 0..k {
            for j in 0..N {
                (server_key.t0_[i][j], server_key.pk.t1[i][j]) = power2_round(mod_q(t[i][j]))
            }
            server_key.t0_[i].ntt();
        }

        H(&mut server_key.tr, &server_key.pk.pk_encode_());

        (server_key.into(), server_t)
    }
}

pub struct ClientSignCtx<const k: usize, const l: usize> {
    pub(crate) e1: [Rq; k],
    pub(crate) e2: [Rq; k],
    pub(crate) e: [Rq; k],
    pub(crate) y: [Rq; l],
    pub(crate) w: [Rq; k],
    pub(crate) mu: [u8; 64],
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
    pub(crate) fn client_sign0_<
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
        let client_key = &client_key.0;

        let mut ctx = ClientSignCtx::default();
        let mut h = new_h();
        h.absorb(&client_key.tr).absorb(m).squeeze(&mut ctx.mu);

        // rho_pp use to generate server side y and e.
        let mut rho_pp = [0; 64];
        h.init()
            .absorb(&client_key.K)
            .absorb(client_rnd)
            .absorb(&ctx.mu)
            .squeeze(&mut rho_pp);

        // rho_ppp shared with client, to generate shared e.
        let mut rho_ppp = [0; 64];
        h.init().absorb(&client_key.K).absorb(&ctx.mu).squeeze(&mut rho_ppp);
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
            ctx.w[i].dot_mul(&client_key.pk.A[i], &y_);
            ctx.w[i].ntt_inverse();
            ctx.w[i].add_assign(&ctx.e1[i]);
        }

        Ok(ctx)
    }

    pub(crate) fn client_sign1_<
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
        let client_key = &client_key.0;
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
            client_z[i].mul(&c, &client_key.s1_[i]);
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
            cs2[i].mul(&c, &client_key.s2_[i]);
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
            ct0[i].mul(&c, &client_key.t0_[i]);
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
    pub(crate) fn server_sign_<
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
        let server_key = &self.0;

        let mut mu = [0; 64];
        let mut h = new_h();
        h.absorb(&server_key.tr).absorb(m).squeeze(&mut mu);
        // check if mu == client_mu
        if client_mu != &mu {
            return Err(Error::TPCServerCheckFailed);
        }

        // rho_pp use to generate server side y and e.
        let mut rho_pp = [0; 64];
        h.init()
            .absorb(&server_key.K)
            .absorb(server_rnd)
            .absorb(&mu)
            .squeeze(&mut rho_pp);

        // rho_ppp shared with client, to generate shared e.
        let mut rho_ppp = [0; 64];
        h.init().absorb(&server_key.K).absorb(&mu).squeeze(&mut rho_ppp);

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
            server_w[i].dot_mul(&server_key.pk.A[i], &y_);
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
            server_z[i].mul(&c, &server_key.s1_[i]);
            server_z[i].ntt_inverse();
            server_z[i].add_assign(&y[i]);
        }

        // cs2 = c*s2 + e2
        let mut server_cs2 = [Rq::default(); k];
        for i in 0..k {
            server_cs2[i].mul(&c, &server_key.s2_[i]);
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
    sk.pk = client_key.0.pk.clone();
    sk.K = client_key.0.K;
    sk.tr = client_key.0.tr;
    sk.t0_ = client_key.0.t0_;
    for i in 0..l {
        sk.s1_[i].add(&client_key.0.s1_[i], &server_key.0.s1_[i]);
    }
    for i in 0..k {
        sk.s2_[i].add(&client_key.0.s2_[i], &server_key.0.s2_[i]);
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
        mldsa::{auxiliary::expand_mask, mldsa65::*, rq::Rq},
        mldsa_tpc::internal::{check_key, combie_key, expand_error, ClientKey, ClientKeyGenCtx, ClientSignCtx, ServerKey},
    };

    #[test]
    fn test_keygen() {
        for _i in 0..1000 {
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let client_keygen_ctx = ClientKeyGenCtx::<k,l,eta>::new_internal_(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t) = ServerKey::<k, l>::keygen_::<eta>(&xi, &server_r, &client_keygen_ctx.client_t);

            let client_key = client_keygen_ctx.generate_key_(&server_t, &server_key.0.tr);
            assert!(client_key.is_ok());
            let client_key = client_key.unwrap();


            assert_eq!(client_key.0.K, server_key.0.K);
            assert_eq!(client_key.0.t0_, server_key.0.t0_);

            let sk = combie_key(&client_key, &server_key);
            assert!(check_key(&sk));
            let m: [u8; 32] = rng.random();
            let sig = sk.sign_internal(&m, &rng.random());
            let ok = client_key.0.public_key_ref().verify_internal(&m, &sig);
            assert!(ok);
        }
    }

    #[test]
    fn test_sign() {
        for _ in 0..10 {
            let mut rng = rand::rng();
            let xi = rng.random();
            let client_r = rng.random();
            let client_keygen_ctx = ClientKeyGenCtx::<k,l,eta>::new_internal_(&xi, &client_r);

            let server_r = rng.random();
            let (server_key, server_t) = ServerKey::<k, l>::keygen_::<eta>(&xi, &server_r, &client_keygen_ctx.client_t);

            let client_key = client_keygen_ctx.generate_key_(&server_t, &server_key.0.tr);
            assert!(client_key.is_ok());
            let client_key = client_key.unwrap();


            let sk = combie_key(&client_key, &server_key);
            assert!(check_key(&sk));

            for _ in 0..100 {
                let mut client_rnd = rng.random();
                let mut server_rnd = rng.random();

                let m = [1u8; 32];
                let sig = loop {
                    let client_ctx = ClientSignCtx::client_sign0_::<gamma1, gamma2, lambda, tau, beta, omega, eta>(
                        &client_key,
                        &client_rnd,
                        &m,
                    )
                    .unwrap();

                    let (server_w, server_z, server_cs2) = server_key
                        .server_sign_::<gamma1, gamma2, lambda, tau, beta, omega, eta>(
                            &server_rnd,
                            &m,
                            &client_ctx.mu,
                            &client_ctx.w,
                        )
                        .unwrap();

                    let result = client_ctx.client_sign1_::<gamma1, gamma2, lambda, tau, beta, omega, eta>(
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

                let public_key = client_key.0.public_key();
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

    #[test]
    fn test_prob() {
        const k: usize = 6;
        const l: usize = 5;
        const eta: usize = 4;
        pub(crate) const gamma1: usize = 1 << 19;
        let mut e1 = [Rq::default(); k];
        let mut e2 = [Rq::default(); k];
        let mut e = [Rq::default(); k];
        let mut rng = rand::rng();
        let rho = rng.random();
        expand_error::<k, { eta / 2 }>(&mut e1, &rho, 0);
        expand_error::<k, { eta / 2 }>(&mut e2, &rho, k);

        e[0].add(&e1[0], &e2[0]);

        let mut prob = [0; 9];
        for i in 0..256 {
            prob[(e[0][i] + 4) as usize] += 1;
        }
        println!("{:?}", prob);

        let mut y1 = [Rq::default(); l];
        let mut y2 = [Rq::default(); l];
        let mut y = [Rq::default(); l];
        expand_mask::<k, l, { gamma1 / 2 }>(&mut y1, &rho, 0);
        expand_mask::<k, l, { gamma1 / 2 }>(&mut y2, &rho, l as u16);
        y[0].add(&y1[0], &y2[0]);
        let mut zeros = 0;
        for i in 0..256 {
            if y[0][i] == 0 {
                zeros += 1;
            }
        }
        println!("{:?}", zeros);
    }
}
