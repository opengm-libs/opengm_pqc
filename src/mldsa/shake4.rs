use core::cmp::min;
use core::mem::transmute;
use crate::sha3::keccak_f1600_x4;
const dsbyteShake: u8 = 0b00011111;

// The general parameter DIGEST_SIZE is 224/8, 256/8, 384/8 or 512/8.
// Then the rate is (200-2*L)
#[derive(Debug, Clone)]
pub struct Shake4<const DIGEST_SIZE: usize> {
    a: [u8; 200],
    b: [u8; 200],
    c: [u8; 200],
    d: [u8; 200],
    n: usize,

    pad_and_permuted: bool,
}


impl<const DIGEST_SIZE: usize> Default for Shake4<DIGEST_SIZE> {
    fn default() -> Self {
        Self { 
            a: [u8::default();200], 
            b: [u8::default();200], 
            c: [u8::default();200], 
            d: [u8::default();200], 
            n: Default::default(),
            pad_and_permuted: false,
        }
    }
}


impl<const DIGEST_SIZE: usize> Shake4<DIGEST_SIZE> {
    #[inline]
    pub(crate) fn reset(&mut self) -> &mut Self {
        *self = Self::default();
        self
    }


    // write to the 4 Shake with the same p
    // assume p.len() % 8 == 0 and self.n % 32 == 0
    // in mldsa, absorb at most 34 bytes.
    #[inline]
    pub(crate) fn absorb(&mut self, p: &[u8]) -> &mut Self {
        let rate = 200 - 2 * DIGEST_SIZE;
        debug_assert!(self.n + p.len() <= rate);
        debug_assert!(self.n % 32 == 0);
        debug_assert!(p.len() % 8 == 0);
        
        // self.n always 0
        self.a[self.n..self.n+p.len()].copy_from_slice(p);
        self.b[self.n..self.n+p.len()].copy_from_slice(p);
        self.c[self.n..self.n+p.len()].copy_from_slice(p);
        self.d[self.n..self.n+p.len()].copy_from_slice(p);
        self.n += p.len();
        self
    }

    #[inline]
    pub(crate) fn absorb_byte(&mut self, b0: u8, b1: u8, b2: u8, b3: u8) -> &mut Self {
        let rate = 200 - 2 * DIGEST_SIZE;
        debug_assert!(self.n < rate);

        self.a[self.n] = b0;
        self.b[self.n] = b1;
        self.c[self.n] = b2;
        self.d[self.n] = b3;

        self
    }

    pub(crate) fn squeeze(&mut self, out0: &mut[u8], out1: &mut[u8],out2: &mut[u8],out3: &mut[u8]) {
        let rate = 200 - 2 * DIGEST_SIZE;

        if !self.pad_and_permuted{
            self.pad_and_permute()
        }

        let n = out0.len();
        let mut copy_bytes = 0;
        while copy_bytes < n{
            if self.n == rate {
                self.permute();
            }
            let copy_len = min(n - copy_bytes, rate - self.n);
            out0[copy_bytes..copy_bytes+copy_len].copy_from_slice(&self.a[self.n..self.n + copy_len]);
            out1[copy_bytes..copy_bytes+copy_len].copy_from_slice(&self.b[self.n..self.n + copy_len]);
            out2[copy_bytes..copy_bytes+copy_len].copy_from_slice(&self.c[self.n..self.n + copy_len]);
            out3[copy_bytes..copy_bytes+copy_len].copy_from_slice(&self.d[self.n..self.n + copy_len]);

            self.n += copy_len;
            copy_bytes += copy_len;
        }
    }

    fn permute(&mut self) {
        #[cfg(target_endian = "little")]
        unsafe {
            keccak_f1600_x4(transmute(&mut self.a));
        }

        #[cfg(target_endian = "big")]
        {
            panic!("todo");
            let mut a = [0u64; 25];

            for (i, ai) in a.iter_mut().enumerate() {
                *ai = u64::from_le_bytes(self.a[8 * i..8 * i + 8].try_into().unwrap());
            }

            keccak_f1600_generic(&mut a);

            for (i, ai) in a.iter_mut().enumerate() {
                self.a[8 * i..8 * i + 8].copy_from_slice(&u64::to_le_bytes(*ai));
            }
        }

        self.n = 0;
    }

    fn pad_and_permute(&mut self) {
        let rate = 200 - 2 * DIGEST_SIZE;
        self.a[self.n] ^= dsbyteShake;
        self.b[self.n] ^= dsbyteShake;
        self.c[self.n] ^= dsbyteShake;
        self.d[self.n] ^= dsbyteShake;

        self.a[rate - 1] ^= 0x80;
        self.permute();
    }
}
