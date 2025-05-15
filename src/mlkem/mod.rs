mod compress_decode;
mod errors;
mod hash;
mod internal;
mod kat;
mod ntt;
mod pke;
mod reduce;
mod rq;
mod sample;

mod mlkem1024;
mod mlkem512;
mod mlkem768;

pub(crate) const N: usize = 256;
pub(crate) const Q: i16 = 3329;
pub(crate) const RQ_ELEMENT_LEN: usize = N * 12 / 8;

#[macro_export]
macro_rules! ek_len {
    ($k:expr) => {
        (384 * k + 32)
    };
}

#[macro_export]
macro_rules! dk_len {
    ($k:expr) => {
        (768 * k + 96)
    };
}

#[macro_export]
macro_rules! cipher_len {
    ($k:expr,$du:expr,$dv:expr) => {
        (32 * (du * k + dv))
    };
}
/* 
#[cfg(test)]
mod tests {
    #[test]
    fn test_mlkem512() {
        use super::mlkem512::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let ek = dk.encapsulation_key_ref();
        let (key, c) = ek.encaps(&mut rng);

        let key2 = dk.decaps(&c);

        assert_eq!(key, key2);

        let b = dk.byte_encode();
        let dk2 = DecapKey::byte_decode(&b).unwrap();
        let b2 = dk2.byte_encode();
        assert_eq!(b,b2);
    }

    #[test]
    fn test_mlkem768() {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let ek = dk.encapsulation_key_ref();
        let (key, c) = ek.encaps(&mut rng);

        let key2 = dk.decaps(&c);

        assert_eq!(key, key2);
    }

    // #[test]
    // fn test_mlkem1024() {
    //     use super::mlkem1024::*;
    //     let mut rng = rand::rng();
    //     let dk = keygen(&mut rng);
    //     let ek = dk.encapsulation_key_ref();
    //     let (key, c) = ek.encaps(&mut rng);

    //     let key2 = dk.decaps(&c);

    //     assert_eq!(key, key2);
    // }

    extern crate test;
    use rand::Rng;
    use test::Bencher;

    use crate::mlkem::{internal::{DecapKey, EncapKey}, rq::Rq, sample::sample_matrix_ntt};

    #[bench]
    fn bench_mlkem768_keygen(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();

        b.iter(|| {
            // 21,546.54 ns/iter (+/- 415.60)
            test::black_box({
                let _ = keygen(&mut rng);
            });
        });
    }

    #[bench]
    fn bench_mlkem768_dk_encode(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);

        b.iter(|| {
            // 419.38 ns/iter
            test::black_box({
                let _ = dk.byte_encode();
            });
        });
    }

    #[bench]
    fn bench_mlkem768_dk_decode(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let bytes = dk.byte_encode();

        b.iter(|| {
            // 12,944.12 ns/iter
            test::black_box({
                let _ = DecapKey::byte_decode(&bytes);
            });
        });
    }

    #[bench]
    fn bench_mlkem768_ek_encode(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let ek = dk.encapsulation_key();

        b.iter(|| {
            // 204.17 ns/iter
            test::black_box({
                let _ = ek.byte_encode();
            });
        });
    }

    #[bench]
    fn bench_mlkem768_ek_decode(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let bytes = dk.encapsulation_key_ref().byte_encode();

        b.iter(|| {
            // 10,680.42 ns/iter
            test::black_box({
                let _ = EncapKey::byte_decode(&bytes);
            });
        });
    }

    #[bench]
    fn bench_mlkem768_ek_from_bytes(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let bytes = dk.encapsulation_key_ref().bytes();
        let mut ek = EncapKey::default();

        b.iter(|| {
            //  81.74 ns/iter
            test::black_box({
                ek.from_bytes(&bytes);
            });
        });
    }

    #[bench]
    fn bench_mlkem768_dk_from_bytes(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let mut dk = keygen(&mut rng);
        let bytes = dk.bytes();

        b.iter(|| {
            // 106.39 ns/iter 
            test::black_box({
                dk.from_bytes(&bytes);
            });
        });
    }

    #[bench]
    fn bench_mlkem768_encap(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let ek = dk.encapsulation_key_ref();

        b.iter(|| {
            // 8,572.68 ns/iter
            test::black_box({
                let (_, _) = ek.encaps(&mut rng);
            });
        });
    }

    #[bench]
    fn bench_mlkem768_decap(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let dk = keygen(&mut rng);
        let ek = dk.encapsulation_key_ref();
        let (_, c) = ek.encaps(&mut rng);

        b.iter(|| {
            // 13,695.71 ns/iter
            test::black_box({
                let _ = dk.decaps(&c);
            });
        });
    }

    #[bench]
    fn bench_sample_a(b: &mut Bencher) {
        use super::mlkem768::*;
        let mut rng = rand::rng();
        let rho = rng.random();
        let mut a = [[Rq::default();k];k];
        b.iter(|| {
            // 8,053.30 ns/iter 
            test::black_box({
                sample_matrix_ntt(&mut a, &rho);
            });
        });
    }
}

*/