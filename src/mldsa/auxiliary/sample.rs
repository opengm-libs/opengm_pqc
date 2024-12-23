use crate::{mldsa::{hash::new_h, rq::Rq, util::get_bits, Q}, sha3::{self, XOF}};


// sample a poly with coefficients in {0,1,p-1} an Hamming weight tau <= 64
// len(rho) = lambda/4
pub(crate) fn sample_in_ball<const tau: usize>(c: &mut Rq, rho: &[u8]) {
    let c = &mut c.coeffs;

    let mut s = [0u8; 8];
    let mut buf = [0u8; 32];

    let mut ctx = new_h();
    ctx.absorb(rho).squeeze(&mut s).squeeze(&mut buf);

    let mut i = 256 - tau;
    while i < 256 {
        for j in 0..buf.len() {
            if buf[j] <= i as u8 {
                c[i] = c[buf[j] as usize];

                c[buf[j] as usize] = if get_bits(&s, i + tau - 256) == 0 { 1 } else { -1 };
                i += 1;
                if i == 256{
                    break
                }
            }
        }
        ctx.squeeze(&mut buf);
    }
}

// returns the (coeff, 1) or (⊥, 0)
#[inline]
pub(crate) fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> (i32, usize) {
    let z = (b0 as u32) | (b1 as u32) << 8 | (b2 as u32 & 0x7f) << 16;
    (z as i32, ((((z as i32) - Q) >> 31) & 1) as usize)
}

// input: rho in B^32
// output: a^ in Tq
pub(crate) fn rej_ntt_poly(a: &mut Rq, rho: &[u8], k: u8, l: u8) {
    let mut ctx = sha3::new_shake128();
    ctx.absorb(rho).absorb(&[k, l]);

    let mut s = [0; 3 * 8];
    let mut j = 0;
    while j < 256 - 8 {
        ctx.squeeze(&mut s);
        for s in s.chunks_exact(3) {
            let (c, res) = coeff_from_three_bytes(s[0], s[1], s[2]);
            a.coeffs[j] = c;
            j = j + res
        }
    }

    while j < 256 {
        ctx.squeeze(&mut s);
        for s in s.chunks_exact(3) {
            let (c, res) = coeff_from_three_bytes(s[0], s[1], s[2]);
            a.coeffs[j] = c;
            j = j + res;
            if j == 256 {
                break;
            }
        }
    }
}

// Assuming eta = 2 or 4
// Input b in {0,1,.., 15}, generate an elemnet of [-eta, eta]
#[inline]
pub(crate) fn coeff_from_half_byte<const eta: usize>(b: u8) -> (i32, usize) {
    match eta {
        // does b%5 use constant time?
        2 => (2 - (b % 5) as i32, (((b as i8 - 15) >> 7) & 1) as usize),
        4 =>    (4 - (b as i32), (((b as i8 - 9) >> 7) & 1) as usize),
        _ => panic!("wrong eta"),
    }
}

// input: len(rho) = 64
// output: a in Rq, with coefficients in [0, eta]U[q-eta, q-1]
pub(crate) fn rej_bounded_poly<const eta: usize>(a: &mut Rq, rho: &[u8], r: u16) {
    let mut ctx = new_h();
    ctx.absorb(rho).absorb(&[r as u8, (r >> 8) as u8]);
    let coeffs = &mut a.coeffs;

    let mut z = [0; 8];
    let mut j = 0;
    while j < 256-16{
        ctx.squeeze(&mut z);
        for z in z{
    		let (z0, ok0) = coeff_from_half_byte::<eta>(z&15);
    		coeffs[j] = z0;
    		j += ok0;

    		let (z1, ok1) = coeff_from_half_byte::<eta>(z>>4);
    		coeffs[j] = z1;
    		j += ok1
    	}
    }

    while j < 256{
        ctx.squeeze(&mut z);
        for z in z{
    		let (z0, ok0) = coeff_from_half_byte::<eta>(z&15);
    		coeffs[j] = z0;
    		j += ok0;
            if j == 256{
                break
            }

    		let (z1, ok1) = coeff_from_half_byte::<eta>(z>>4);
    		coeffs[j] = z1;
    		j += ok1;
            if j == 256{
                break
            }
    	}
    }
}
