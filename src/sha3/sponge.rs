use core::cmp::min;
use core::iter::zip;
use core::mem::transmute;

use super::Hash;
use super::keccakf::keccak_f1600;

#[derive(Debug, PartialEq, Eq, Clone)]
enum SpongeDirection {
    // spongeAbsorbing indicates that the sponge is absorbing input.
    Absorbing,
    // spongeSqueezing indicates that the sponge is being squeezed.
    Squeezing,
}

// The general parameter DIGEST_SIZE is 224/8, 256/8, 384/8 or 512/8.
// Then the rate is (200-2*L)
#[derive(Debug, Clone)]
pub struct Digest<const DIGEST_SIZE: usize> {
    a: [u8; 200], // main state of the hash
    n: usize,
    ds: u8,
    state: SpongeDirection, // whether the sponge is absorbing or squeezing
}

impl<const DIGEST_SIZE: usize> Hash<DIGEST_SIZE> for Digest<DIGEST_SIZE> {
    fn reset(&mut self) {
        // Zero the permutation's state.
        for ai in &mut self.a {
            *ai = 0;
        }
        self.state = SpongeDirection::Absorbing;
        self.n = 0;
    }

    fn write(&mut self, p: &[u8]) {
        let rate = 200 - 2 * DIGEST_SIZE;

        assert_eq!(self.state, SpongeDirection::Absorbing);

        let mut p = p;
        while self.n + p.len() >= rate {
            for (d, s) in zip(&mut self.a[self.n..rate], &p[..rate - self.n]) {
                *d ^= *s
            }
            p = &p[rate - self.n..];
            self.permute();
        }

        for (d, s) in zip(&mut self.a[self.n..self.n + p.len()], p) {
            *d ^= *s
        }
        self.n += p.len()
    }

    fn sum_into(&self, digest: &mut [u8]) {
        let mut copy = self.clone();
        copy.read( digest);
    }

    fn sum(&self) -> [u8; DIGEST_SIZE] {
        let mut out = [0u8; DIGEST_SIZE];
        self.sum_into(&mut out);
        out
    }

    // BlockSize returns the rate of sponge underlying this hash function.
    fn block_size(&self) -> usize {
        return 200 - 2 * DIGEST_SIZE;
    }
    // Size returns the output size of the hash function in bytes.
    fn size(&self) -> usize {
        return DIGEST_SIZE / 8;
    }
}

impl<const DIGEST_SIZE: usize> Digest<DIGEST_SIZE> {
    pub fn new(ds: u8) -> Self {
        Digest {
            a: [0; 200],
            n: 0,
            ds: ds,
            state: SpongeDirection::Absorbing,
        }
    }


    pub(crate) fn read(&mut self, out: &mut [u8]) {
        let rate = 200 - 2 * DIGEST_SIZE;

        if self.state == SpongeDirection::Absorbing {
            self.pad_and_permute();
        }

        let mut out = out;
        while out.len() > 0 {
            if self.n == rate {
                self.permute();
            }
            let copy_len = min(out.len(), rate - self.n);
            out[..copy_len].copy_from_slice(&self.a[self.n..self.n + copy_len]);
            self.n += copy_len;
            out = &mut out[copy_len..];
        }
    }


    fn permute(&mut self) {
        #[cfg(target_endian = "little")]
        keccak_f1600(unsafe { transmute(&mut self.a) });

        #[cfg(target_endian = "big")]
        {
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
        self.a[self.n] ^= self.ds;
        self.a[rate - 1] ^= 0x80;
        self.permute();
        self.state = SpongeDirection::Squeezing;
    }
}
