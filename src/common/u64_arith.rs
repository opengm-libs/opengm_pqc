use super::primitive::mac;

/// Barrett for u64.
/// Let B = 2^64. For a module 1 < m < B, computes x mod m, where 0 < x < 2^128.
/// The reduction we used bellow is slightly different from the standard Barrett algorithm
/// in HAC 14.42.
/// Let u = [B^2 / m], where [x] = floor(x), then
/// x mod m = x - [x/m] * m = x - Q*m, where Q = [x/m]
/// let q = [x * u / B^2], then
/// Q >= q > x * (B^2/m - 1) / B^2 - 1 = x/m - x/B^2 - 1 > [x/m] - 2,
/// i.e., Q-1 <= q <= Q
/// 
/// Assume further that m < 2^63, and x = Q * m + R, then
/// x - q*m = (Q-q) * m + R <= m + R < 2m <= B, thus
/// R = (x mod B) - (q*m mod B)
pub struct BarrettU64 {
    pub m: u64,
    // u = [u0, u1] = floor(2^128/m)
    u0: u64,
    u1: u64,
}

impl BarrettU64 {
    // Precompute Barrett params for module m at most 63 bits.
    pub fn new(m: u64) -> Self {
        assert!(m >> 63 == 0);

        // 2^128 - 1 = q * value + r
        // then 2^128 = q * value + (r + 1)
        let mut q = (!0u128) / (m as u128);
        let r = (!0) - (q as u64).wrapping_mul(m) + 1;
        if r == m {
            q += 1;
        }
        BarrettU64 {
            m,
            u0: q as u64,
            u1: (q >> 64) as u64,
        }
    }

    // returns x mod m or (x mod m) + m
    fn reduce_almost(&self, x0: u64, x1: u64) -> u64 {
        // q = [x * u / B^2]
        // x * u = x0u0 + (x1u0 + u1x0)*B + u1x1*B^2
        let (_, acc1) = mac(0, x0, self.u0, 0);
        let (acc1, acc2) = mac(acc1, x0, self.u1, 0);
        let (_, t2) = mac(acc1, x1, self.u0, 0);
        let (acc2, _) = mac(acc2, x1, self.u1, t2); //acc2 = q mod B

        // result = x - q*m mod B
        x0.wrapping_sub(acc2.wrapping_mul(self.m))
    }

    #[inline]
    fn reduce_last_sub(&self, x: u64) -> u64 {
        if x >= self.m {
            x - self.m
        }else{
            x
        }
    }

    #[inline]
    pub fn reduce_u128(&self, x0: u64, x1: u64) -> u64 {
        self.reduce_last_sub(self.reduce_almost(x0, x1))
    }


    // reduce x mod m
    #[inline]
    pub fn reduce_u64(&self, x0: u64) -> u64 {
        // FIXME: How does this work?
        // q = [x0 * u / B^2]
        // x0 * u = x0u0 + u1x0 * B
        // = (a + b*B) + (c+d*B)*B
        // = (a + (b+c)*B) + d*B^2
        // (a + (b+c)*B) < (B-1) + (B-1 + B-1) * B
        // = B-1 + 2*B^2 - 2*B
        // = B^2 + (B^2 - B - 1)
        let (_, acc1) = mac(0, x0, self.u1, 0);
        let acc0 = x0 - acc1.wrapping_mul(self.m);

        self.reduce_last_sub(acc0)
    }

    #[inline]
    pub fn mul_mod(&self, a: u64, b: u64) -> u64 {
        let (a0, a1) = mac(0, a, b, 0);
        self.reduce_u128(a0, a1)
    }

    #[inline]
    fn mul_mod_almost(&self, a: u64, b: u64) -> u64 {
        let (a0, a1) = mac(0, a, b, 0);
        self.reduce_almost(a0, a1)
    }

    // returns a^e mod m, use the binary exponentiation.
    pub fn pow_mod(&self, a: u64, e: u64) -> u64 {
        let mut result = 1;
        let mut t = a;
        let mut e = e;
        while e > 0{
            if e & 1 == 1{
                result = self.mul_mod_almost(result, t)
            }
            t = self.mul_mod_almost(t,t);
            e >>= 1;
        }

        // result
        // self.reduce(result, 0)
        self.reduce_last_sub(result)
    }
}


#[inline(never)]
pub fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % (m as u128)) as u64
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use rand::thread_rng;

    use super::BarrettU64;
    use super::mul_mod;

    #[test]
    fn test_mul() {
        for _ in 0..100000 {
            let m: u64 = thread_rng().r#gen::<u64>() >> 1;
            // let m = 0x7FFFFFFFFFFFFFFF; 
            for _ in 0..1000 {
                let bar = BarrettU64::new(m);
                let a: u64 = thread_rng().r#gen();
                let b: u64 = thread_rng().r#gen();

                let x = bar.mul_mod(a, b);
                let y = (a as u128 * b as u128) % (m as u128);
                if x != y as u64 {
                    println!("{},", m);
                }
            }
        }
    }

    #[test]
    fn test_reduce_u64() {
        for _ in 0..100000 {
            let m: u64 = thread_rng().r#gen::<u64>() >> 1;
            // let m = 0x7FFFFFFFFFFFFFFF; 
            for _ in 0..1000 {
                let bar = BarrettU64::new(m);
                let a: u64 = thread_rng().r#gen::<u64>() | 1 << 63;
                let x = bar.reduce_u64(a);
                let y = bar.reduce_u128(x,0);
                if x != y as u64 {
                    println!("{},", m);
                }
            }
        }
    }

    #[test]
    fn test_pow(){
        let bar = BarrettU64::new(127);
        assert_eq!(bar.pow_mod(2, 10), 1024 % 127);
        assert_eq!(bar.pow_mod(2, 0), 1);
        assert_eq!(bar.pow_mod(2, 1), 2);
        for i in 1..100{
            assert_eq!(bar.pow_mod(2, 126*i), 1);
        }
    }

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_barrett(b: &mut Bencher) {
        let m: u64 = thread_rng().r#gen::<u64>() >> 1;
        let bar = BarrettU64::new(m);
        let x: u64 = thread_rng().r#gen();
        let y: u64 = thread_rng().r#gen();

        // 0.51 ns
        b.iter(|| {
            test::black_box(bar.mul_mod(x, y));
        });
    }
    #[bench]
    fn bench_u128(b: &mut Bencher) {
        let m: u64 = thread_rng().r#gen::<u64>() >> 1;
        let x: u64 = thread_rng().r#gen();
        let y: u64 = thread_rng().r#gen();

        // 5.46 ns
        b.iter(|| {
            test::black_box(mul_mod(x, y, m));
        });
    }
}
