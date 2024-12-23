


/// The hash function H: B^* -> B^32
pub(crate) fn hash_h(_s: &[u8]) -> [u8;32]{

    todo!()
}


/// The hash function J: B^* -> B^32
pub(crate) fn hash_j(_s: &[u8]) -> [u8;32]{

    todo!()
}


/// The hash function G: B^* -> B^32 x B^32
pub(crate) fn hash_g(_c: &[u8]) -> ([u8;32], [u8;32]){

    todo!()
}


pub(crate) trait XOF {
    fn init(&mut self) -> &mut Self;

    fn absorb(&mut self, str: &[u8]) -> &mut Self;

    fn squeeze(&mut self, z: &mut [u8])-> &mut Self;
}
