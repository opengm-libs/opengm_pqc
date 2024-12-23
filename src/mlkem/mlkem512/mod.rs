mod pke;

use rand::Rng;
use super::Result;

const PARAM_K:usize = 2;
const PARAM_ETA1:usize = 3;
const PARAM_ETA2:usize = 2;
const PARAM_DU:usize = 10;
const PARAM_DV:usize = 4;

const EK_LEN:usize = 384*PARAM_K + 32;
const DK_LEN:usize = 768*PARAM_K + 96;

pub struct EK{
    k: Vec<u8>,
}

pub struct DK{
    k: Vec<u8>,
}

pub struct CipherText{

}


pub fn key_gen(rng: impl Rng)-> Result<(EK, DK)> {

    todo!()
}


pub fn encaps(ek: &EK, rng: impl Rng) -> Result<([u8;32],CipherText)>{
    todo!()
}

pub fn decaps(dk: &DK, c: &CipherText) -> Result<[u8;32]>{
    todo!()
}