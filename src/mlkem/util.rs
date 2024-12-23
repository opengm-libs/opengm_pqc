use super::zq;


// 
pub(crate) fn compress_nieve<const d: u32>(x: u32)-> u32 {
    let y = (x << (1+d)) + zq::q as u32;
    (y / (2*zq::q as u32)) & ((1<<d)-1)
}

pub(crate) fn compress<const d: u32>(x: u32)-> u32 {
    let u = (1<<32) / zq::q;
    let y = u * x as u64 + (1<<(31-d));

    (y >> (32-d)) as u32
}



#[inline]
pub(crate) fn decompress<const d: u32>(y: u32)-> u32 {
    let x = (zq::q as u32 * y) + (1<<(d-1));
    x >> d
}


// input: B must have length 32 * d
// Elements in F are less than m = 2^d or q(d = 12),
// Each element packed to d bits, in little-endian order.
#[inline]
pub(crate) fn byte_encode<const d: u32>(B: &mut [u8], F: &[u32]){
    debug_assert!(B.len() == 32 * d as usize);

}



#[cfg(test)]
mod tests {
    use crate::mlkem::util::{compress_nieve, compress, decompress};

    #[test]
    fn test_compress(){
        const d: u32 = 10;

        for x in 0..(1<<d){
            assert_eq!(compress::<d>(x), compress_nieve::<d>(x));
        }
    }

    #[test]
    fn test_equal(){

        const d: u32 = 10;
        //compress(decompress(y)) == y for y in [0, 2^d).
        for y in 0..(1<<d){
            assert_eq!(y as u32, compress::<d>(decompress::<d>(y as u32)));
        }
    }

    extern crate test;
    use test::Bencher;
    #[bench]
    fn bench_barrett(b: &mut Bencher) {

        b.iter(|| {
            // 5.13 ns
            test::black_box(compress::<10>(1234));

            // test::black_box(compress_nieve::<10>(1234));
        });
    }

}