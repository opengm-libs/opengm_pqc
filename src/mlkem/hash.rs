use crate::sha3::{self, Hash, XOF};




/// The hash function H: B^* -> B^32
#[allow(non_snake_case)]
#[inline]
pub(crate) fn H(s: &[u8]) -> [u8;32]{
    let mut h = sha3::new256();
    h.write(s);
    h.sum()
}


/// The hash function J: B^* -> B^32
#[allow(non_snake_case)]
#[inline]
pub(crate) fn J(in1: &[u8], in2: &[u8]) -> [u8;32]{
    let mut z = [0;32];
    let mut h = sha3::new_shake256();
    h.absorb(in1).absorb(in2).squeeze(&mut z);
    z
}


/// The hash function G: B^* -> B^32 x B^32
#[allow(non_snake_case)]
#[inline]
pub(crate) fn G(out1: &mut [u8], out2:&mut [u8], in1: &[u8], in2:&[u8]){
    let mut d = sha3::new512();
    d.write(in1);
    d.write(in2);
    d.read( out1);
    d.read(out2);
}

