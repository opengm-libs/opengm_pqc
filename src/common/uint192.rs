use super::{
    GetMSBCount,
    primitive::{adc, sbb},
};
use core::ops;

#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub struct U192 {
    v: [u64; 3],
}

impl GetMSBCount for &U192 {
    #[inline]
    fn get_msb_count(self) -> u32 {
        self.v.get_msb_count()
    }
}

impl ops::Shl<u32> for &U192 {
    type Output = U192;

    fn shl(self, n: u32) -> Self::Output {
        let mut result = {
            if n & 128 != 0 {
                [0, 0, self.v[0]]
            } else if n & 64 != 0 {
                [0, self.v[0], self.v[1]]
            } else {
                [self.v[0], self.v[1], self.v[2]]
            }
        };

        let n = n & 63;
        if n > 0 {
            // still have n bits to go
            let m = 64 - n;
            result[2] = (result[2] << n) | (result[1] >> m);
            result[1] = (result[1] << n) | (result[0] >> m);
            result[0] = result[0] << n;
        }

        return U192 { v: result };
    }
}

impl ops::Shl<u32> for U192 {
    type Output = U192;

    fn shl(self, n: u32) -> Self::Output {
        (&self) << n
    }
}

impl ops::ShlAssign<u32> for U192 {
    fn shl_assign(&mut self, n: u32) {
        let v = &mut self.v;
        if n & 128 != 0 {
            v[2] = v[0];
            v[1] = 0;
            v[0] = 0;
        } else if n & 64 != 0 {
            v[2] = v[1];
            v[1] = v[0];
            v[0] = 0;
        }

        let n = n & 63;
        if n > 0 {
            // still have n bits to go
            let m = 64 - n;
            v[2] = (v[2] << n) | (v[1] >> m);
            v[1] = (v[1] << n) | (v[0] >> m);
            v[0] = v[0] << n;
        }
    }
}

impl ops::Shr<u32> for &U192 {
    type Output = U192;

    fn shr(self, n: u32) -> Self::Output {
        let mut result = {
            if n & 128 != 0 {
                [self.v[2], 0, 0]
            } else if n & 64 != 0 {
                [self.v[1], self.v[2], 0]
            } else {
                [self.v[0], self.v[1], self.v[2]]
            }
        };

        let n = n & 63;
        if n > 0 {
            // still have n bits to go
            let m = 64 - n;
            result[2] = (result[2] >> n) | (result[1] << m);
            result[1] = (result[1] >> n) | (result[0] << m);
            result[0] = result[0] >> n;
        }

        return U192 { v: result };
    }
}

impl ops::Shr<u32> for U192 {
    type Output = U192;

    fn shr(self, n: u32) -> Self::Output {
        (&self) >> n
    }
}

impl ops::ShrAssign<u32> for U192 {
    fn shr_assign(&mut self, n: u32) {
        let v = &mut self.v;
        if n & 128 != 0 {
            v[0] = v[2];
            v[1] = 0;
            v[2] = 0;
        } else if n & 64 != 0 {
            v[0] = v[1];
            v[1] = v[2];
            v[2] = 0;
        }

        let n = n & 63;
        if n > 0 {
            // still have n bits to go
            let m = 64 - n;
            v[2] = (v[2] >> n) | (v[1] << m);
            v[1] = (v[1] >> n) | (v[0] << m);
            v[0] = v[0] >> n;
        }
    }
}

impl U192 {
    fn add(&self, rhs: &Self) -> (Self, bool) {
        let (v0, carry) = adc(self.v[0], rhs.v[0], false);
        let (v1, carry) = adc(self.v[1], rhs.v[1], carry);
        let (v2, carry) = adc(self.v[2], rhs.v[2], carry);
        (U192 { v: [v0, v1, v2] }, carry)
    }

    fn sub(&self, rhs: &Self) -> (Self, bool) {
        let (v0, borrow) = sbb(self.v[0], rhs.v[0], false);
        let (v1, borrow) = sbb(self.v[1], rhs.v[1], borrow);
        let (v2, borrow) = sbb(self.v[2], rhs.v[2], borrow);
        (U192 { v: [v0, v1, v2] }, borrow)
    }

    pub fn new(v: &[u64; 3]) -> Self {
        U192 {
            v: [v[0], v[1], v[2]],
        }
    }

    pub fn new_u64(a: u64) -> Self {
        U192 { v: [a, 0, 0] }
    }

    pub fn new_u128(a: u128) -> Self {
        U192 {
            v: [a as u64, (a >> 64) as u64, 0],
        }
    }

    /// returns (self / denominator , self % denominator)
    pub fn div_u64(&self, denominator: u64) -> (U192, u64) {
        if true {
            // use u128 division, not constant time, but faster.

            let denominator = denominator as u128;
            if self.v[2] == 0 {
                let a = ((self.v[1] as u128) << 64) + (self.v[0] as u128);
                let quo = a / denominator;
                let remainder = a - quo * denominator;
                return (U192::new_u128(quo), remainder as u64);
            }

            let hi = ((self.v[2] as u128) << 64) + (self.v[1] as u128);
            let q_hi = hi / denominator;
            let r_hi = hi - denominator * q_hi;
            let lo = (r_hi << 64) + self.v[0] as u128;

            let q_lo = lo / denominator;
            let r_lo = lo - denominator * q_lo;

            let q = q_hi + (q_lo >> 64);
            let result = U192::new_u128(q) << 64;
            (result, r_lo as u64)
        } else {
            // use shift

            let mut numerator = self.clone();

            let mut n_bits = self.get_msb_count();
            let mut d_bits = denominator.get_msb_count();
            if n_bits < d_bits {
                return (U192::default(), denominator);
            }

            let mut quotient = U192::default();
            let remainder: u64;

            let u64_count = (n_bits + 63) / 64;

            // only self.v[0] counts.
            if u64_count == 1 {
                quotient.v[0] = numerator.v[0] / denominator;
                remainder = numerator.v[0] - quotient.v[0] * denominator;
                return (quotient, remainder);
            }

            let mut shifted_denominator = U192::new_u64(denominator);
            let denominator_shift = n_bits - d_bits;

            shifted_denominator <<= denominator_shift;
            d_bits += denominator_shift;

            let mut remaining_shifts = denominator_shift;
            let mut difference: U192;
            let mut borrow: bool;
            while n_bits == d_bits {
                (difference, borrow) = (&numerator).sub(&shifted_denominator);
                if borrow {
                    // numerator < denominator_shift
                    if remaining_shifts == 0 {
                        break;
                    }
                    difference.add(&numerator);
                    quotient <<= 1;
                    remaining_shifts -= 1;
                }

                quotient.v[0] |= 1;
                n_bits = difference.get_msb_count();
                let mut numerator_shift = d_bits - n_bits;
                if numerator_shift > remaining_shifts {
                    numerator_shift = remaining_shifts;
                }

                // Shift and update numerator.
                if n_bits > 0 {
                    // left_shift_uint192(difference.data(), numerator_shift, numerator);
                    numerator = &difference << numerator_shift;
                    n_bits += numerator_shift;
                } else {
                    // Difference is zero so no need to shift, just set to zero.
                    // set_zero_uint(uint64_count, numerator);
                    numerator.v = [0, 0, 0];
                }

                // Adjust quotient and remaining shifts as a result of shifting numerator.
                // left_shift_uint192(quotient, numerator_shift, quotient);
                quotient <<= numerator_shift;
                remaining_shifts -= numerator_shift;
            }

            // Correct numerator (which is also the remainder) for shifting of
            // denominator, unless it is just zero.
            if n_bits > 0 {
                // right_shift_uint192(numerator, denominator_shift, numerator);
                numerator >>= denominator_shift;
            }

            (quotient, numerator.v[0])
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::uint192::U192;

    #[test]
    fn test_u192_shift() {
        assert_eq!(U192 { v: [1, 1, 1] } << 8, U192 { v: [256, 256, 256] });
        assert_eq!(U192 { v: [1, 1, 1] } << 65, U192 { v: [0, 2, 2] });
        assert_eq!(U192 { v: [1, 1, 1] } << 128, U192 { v: [0, 0, 1] });
        let a = U192 { v: [1, 1, 1] };
        for i in 0..192 {
            let b = (&a << i) >> i;
            assert_eq!(b, (&b << i) >> i);
        }
    }
    #[test]
    fn test_u192_div() {
        let mut a = U192 { v: [9, 0, 1] };
        let (q, r) = a.div_u64(1 << 61);

        assert_eq!(q, U192::new_u64(1) << 67);
        assert_eq!(r, 9)
    }
    extern crate test;
    use rand::*;
    use test::Bencher;

    #[bench]
    fn bench_div(b: &mut Bencher) {
        let a = U192 { v: [14818267006119878176, 14922783034538913236, 7322974713996039426] };
        let d = 0x12345678;
        println!("{:?}", a); 

        // 5.46 ns
        b.iter(|| {
            test::black_box(a.div_u64(d));
        });
        println!("{:?}", a); 
    }
}
