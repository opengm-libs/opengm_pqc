/// The ring Rq = Zq[x] / (x^n + 1) for q = 3329, n = 256.
/// zeta = 17 is the primitive nth root in Zq.

pub(crate) const q: u64 = 3329;
pub(crate) const n: usize = 256;


pub fn barrett_reduce_u32(x: u32) -> u16 {
    const BARRETT_PARAM: u64 = 1290167;// 2^32 / 3329

    let x = x as u64;

    let x = x - ((x as u64 * BARRETT_PARAM) >> 32) * q as u64;
    if x > q{
        (x - q) as u16
    }else{
        x as u16
    }
}


// x * y % q
#[inline(never)]
pub fn barrett_mul(x: u16, y: u16) -> u16 {
    barrett_reduce_u32(x as u32 * y as u32)
}


#[inline(never)]
pub fn mul(x: u16, y: u16) -> u16 {
    // ((x as u32 * y as u32) % q as u32) as u16
    ((x as u32 * y as u32) % q as u32) as u16
}


#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_barrett(){
        for a in 0..q{
            for b in 0..q{
                assert_eq!(a*b%q, barrett_mul(a as u16, b as u16) as u64);
            }
        }
    }

    extern crate test;
    use test::Bencher;
    #[bench]
    fn bench_barrett(b: &mut Bencher) {
        let mut x = 1111;
        let y = 2222;

        b.iter(|| {
            // 5.13 ns
            test::black_box(x = barrett_mul(x, y));
            // 4.74 ns
            // test::black_box(x = mul(x, y));
        });
    }

}