use super::{sponge::Digest, Hash, XOF};


#[derive(Clone)]
pub struct SHAKE<const N:usize>{
    d: Digest::<N>
}


impl<const N: usize> Hash<N> for SHAKE<N> {
    fn reset(&mut self) {
        self.d.reset();
    }

    fn write(&mut self, p: &[u8]) {
        self.d.write(p);
    }

    fn sum_into(&self, digest: &mut [u8]) {
        self.d.sum_into(digest);
    }

    fn sum(&self) -> [u8; N] {
        self.d.sum()
    }

    // BlockSize returns the rate of sponge underlying this hash function.
    fn block_size(&self) -> usize {
        self.d.block_size()
    }
    // Size returns the output size of the hash function in bytes.
    fn size(&self) -> usize {
        self.d.size()
    }
}

impl<const N: usize> SHAKE<N> {
    pub fn read(&mut self, buf: &mut [u8]){
        self.d.read(buf);
    }

    pub fn new(ds: u8)-> Self{
        SHAKE { d: Digest::new(ds) }
    }
}


impl<const N:usize> XOF for SHAKE<N>{
    fn init(&mut self) -> &mut Self {
        self.reset();
        self
    }

    fn absorb(&mut self, str: &[u8]) -> &mut Self {
        self.write(str);
        self
    }

    fn squeeze(&mut self, z: &mut [u8])-> &mut Self {
        self.read(z);
        self
    }
}