use super::u64_arith::BarrettU64;

const SMALL_PRIMES: &[u64] = &[2, 3, 5, 7, 11, 13];

// returns if n is prime, n < 2^63
pub fn is_prime_u64(n: u64) -> bool {
    for p in SMALL_PRIMES {
        if n == *p {
            return true;
        }
        if n % *p == 0 {
            return false;
        }
    }
    return miller_rabin(n);
}


// Miller-Rabin probabilistic primality test, HAC 4.24
// assume n > 0
fn miller_rabin(n: u64) -> bool {
    // n - 1 = 2^s * r with r odd
    let s = (n - 1).trailing_zeros(); // s < 64
    let r = (n - 1) >> s;

    // n is even
    if s == 0 {
        return false;
    }
    let barrett = BarrettU64::new(n);

    // for all a in the range [2, min(n − 2, ⌊2(ln n)2⌋)]
    // if n < 2^64 it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if a > n - 2{
            break;
        }
        if !miller_rabin_single(&barrett, s, r, a) {
            return false;
        }
    }
    return true;
}


fn miller_rabin_single(b: &BarrettU64, s: u32, r: u64, a: u64) -> bool {
    let mut y = b.pow_mod(a, r);
    if y != 1 && y != b.m - 1 {
        let mut j = 0;
        while j <= s - 1 && y != b.m - 1 {
            y = b.mul_mod(y, y);
            if y == 1 {
                return false;
            }
            j += 1;
        }
        if y != b.m - 1 {
            return false;
        }
    }
    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prime() {
        // assert_eq!(is_prime_u64(127), true);
        let primes = [
            // 2, 3, 5, 7, 11, 13, 
            17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199,
        ];
        for p in primes {
            assert_eq!(is_prime_u64(p), true);
        }
        for i in 0..primes.len() - 1 {
            for j in i..primes.len() {
                for k in j..primes.len() {
                    assert_eq!(is_prime_u64(primes[i] * primes[j] * primes[k]), false);
                }
            }
        }
    }
}
