mod compress_decode;
mod errors;
mod hash;
// mod mlkem512;
mod mlkem768;
// mod mlkem1024;
mod ntt;
mod pke;
mod rq;
mod sample;
mod reduce;
mod internal;


pub(crate) const N: usize = 256;
pub(crate) const Q: i16 = 3329;
pub(crate) const RQ_ELEMENT_LEN: usize = N * 12 / 8;

#[macro_export]
macro_rules! ek_len {
    ($k:expr) => {
        (384*k+32)
    };
}

#[macro_export]
macro_rules! dk_len {
    ($k:expr) => {
        (768*k+96)
    };
}

#[macro_export]
macro_rules! cipher_len {
    ($k:expr,$du:expr,$dv:expr) => {
        (32 * (du*k+dv))
    };
}




#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::mlkem768;

    #[test]
    fn test_mlkem768() {
        let dk = mlkem768::keygen();
        let ek = dk.encapsulation_key_ref();
        let (k,c) = ek.encaps();

        let kk = dk.decaps(&c);
        
        assert_eq!(k,kk);
    }

    #[test]
    fn test_mlkem768_2() {
        // save dz in the card as decapsulation key.
        let dz = rand::rng().random();

        let dk = mlkem768::DecapsulationKey::from_randomness(&dz);
        let ek = dk.encapsulation_key_ref();

        let (k,c) = ek.encaps();
        let kk = dk.decaps(&c);
        assert_eq!(k,kk);
    }

}