use super::{sponge::Digest, Hash, XOF};


#[derive(Clone)]
pub struct SHAKE<const N:usize>{
    d: Digest::<N>
}

impl<const N: usize> SHAKE<N> {
    pub fn reset(&mut self) {
        self.d.reset();
    }

    pub fn write(&mut self, p: &[u8]) {
        self.d.write(p);
    }

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