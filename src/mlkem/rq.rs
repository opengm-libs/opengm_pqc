use core::iter::zip;

use super::{
    errors::{Error, Result}, ntt::{ntt, ntt_inverse}, N, Q, reduce::{reduce_i16, reduce_once, reduce_to_positive}
};

#[derive(Clone, Copy,Debug)]
pub(crate) struct Rq {
    pub(crate) coeffs: [i16; N],
}

impl Default for Rq {
    fn default() -> Self {
        Self { coeffs: [0; N] }
    }
}

impl Rq {
    
    #[inline]
    pub(crate) fn bytes(&self) -> [u8;512]{
        let mut b = [0;512];
        self.bytes_inplace(&mut b);    
        b
    }

    #[inline]
    pub(crate) fn bytes_inplace(&self, b: &mut [u8;256*2]){
        b.copy_from_slice(unsafe { self.coeffs.align_to::<u8>().1 });
    }

    #[inline]
    pub(crate) fn new_from_bytes(b: &[u8;256*2]) -> Self{
        let mut f =Rq::default();
        f.coeffs.copy_from_slice(unsafe { b.align_to::<i16>().1 });
        f
    }

    #[inline]
    pub(crate) fn from_bytes(&mut self, b: &[u8;256*2]) {
        self.coeffs.copy_from_slice(unsafe { b.align_to::<i16>().1 });
    }


    // polyByteEncode appends the encoding of f to b, use ByteEncode12, FIPS 203, Algorithm 5.
    //
    // Assume f reduced, i.e., coeffs of f in [0, q).
    pub fn byte_encode(&self, b: &mut [u8; 384]) {
        debug_assert!(b.len() == 384);
        // each coeff encodes to 12 bits, encode two coeffs one time.
        for (f, b) in zip(self.coeffs.chunks_exact(2), b.chunks_exact_mut(3)) {
            let x = (f[0] as u32) | (f[1] as u32) << 12;
            b[0] = (x >> 0) as u8;
            b[1] = (x >> 8) as u8;
            b[2] = (x >> 16) as u8;
        }
    }

    // polyByteDecode decodes the 384-byte encoding of a polynomial, checking that
    // all the coefficients are properly reduced. This fulfills the "Modulus check"
    // step of ML-KEM Encapsulation.
    //
    // It implements ByteDecode₁₂, according to FIPS 203, Algorithm 6.
    pub fn byte_decode(&mut self, b: &[u8; 384]) -> Result<()> {
        for (f, b) in zip(self.coeffs.chunks_exact_mut(2), b.chunks_exact(3)) {
            let d = (b[0] as u32) | (b[1] as u32) << 8 | (b[2] as u32) << 16;
            const mask12: u32 = 0b1111_1111_1111;
            f[0] = (d & mask12) as i16;
            f[1] = ((d >> 12) & mask12) as i16;
        }

        let mut result = 0;
        for fi in self.coeffs {
            result |= Q - 1 - fi;
        }
        if result < 0 {
            return Err(Error::ByteDecodeOverflow);
        } else {
            return Ok(());
        }
    }

    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    pub fn ntt_inverse(&mut self) {
        ntt_inverse(&mut self.coeffs);
    }

    pub fn add(&mut self, rhs: &Self) {
        for (x, y) in zip(&mut self.coeffs, rhs.coeffs) {
            *x += y;
        }
    }

    pub fn sub(&mut self, rhs: &Self) {
        for (x, y) in zip(&mut self.coeffs, rhs.coeffs) {
            *x -= y;
        }
    }

    // reduce any i16 to [0,q)
    pub fn reduce(&mut self) {
        for i in 0..self.coeffs.len() {
            self.coeffs[i] = reduce_to_positive(reduce_i16(self.coeffs[i]));
        }
    }

    // The reduce functions.

    // reduce to [0,q) with |self| < nq
    // max(n) is 8.
    pub fn reduce_once<const n: usize>(&mut self) {
        for i in 0..self.coeffs.len() {
            for _ in 0..n {
                self.coeffs[i] = reduce_once(self.coeffs[i]);
            }
        }
    }

    pub fn reduce_q(&mut self) {
        for i in 0..self.coeffs.len() {
            self.coeffs[i] = reduce_i16(self.coeffs[i]);
        }
    }

    pub fn reduce_to_positive(&mut self) {
        for i in 0..self.coeffs.len() {
            self.coeffs[i] = reduce_to_positive(self.coeffs[i]);
        }
    }
}
