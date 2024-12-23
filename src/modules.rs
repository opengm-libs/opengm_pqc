use std::u64;

// modules is the mod arithmetics for integers less than 2^61.
use crate::common::*;


/// Maximum modules bit length
const MAX_MODULES_BIT:usize = 61;

#[derive(Debug, Clone)]
pub struct Modules{
    value: u64,
    // (ratio[0], ratio[1]) = 2^128 / value, ratio[2] = 2^128 mod value
    ratio: [u64;3],
    bit_count: u32,
    is_prime: bool,
}


impl Modules {
    pub fn new(value: u64) -> Modules {
        assert!( value >= 2 && value >> MAX_MODULES_BIT != 0 );
        let bit_count = value.get_msb_count();
        
        // 2^128 - 1 = q * value + r
        // then 2^128 = q * value + (r + 1)
        let mut q = (!0u128)/(value as u128);
        let mut r = (!0) - q as u64 * value + 1;
        if r < value{
            q += 1;
            r = 0;
        }

        Modules{
            value,
            ratio: [q as u64, (q >> 64) as u64, r],
            bit_count,
            is_prime: false,
        }
    }

}
