use crate::sha3::{self, SHAKE, XOF};

#[inline]
#[allow(non_snake_case)]
pub(crate) fn G(out:&mut [u8], b: &[u8]){
    sha3::new_shake128().absorb(b).squeeze(out);
}

#[inline]
#[allow(non_snake_case)]
pub(crate) fn H(out: &mut [u8], b: &[u8]){
    sha3::new_shake256().absorb(b).squeeze(out);
}

pub(crate) fn new_h() -> SHAKE<32> {
    sha3::new_shake256()
}

pub(crate) fn new_g() -> SHAKE<16> {
    sha3::new_shake128()
}