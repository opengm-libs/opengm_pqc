pub use sponge::Digest;
pub use shake::SHAKE;

mod keccakf;
mod sponge;
mod shake;


pub trait XOF {
    fn init(&mut self) -> &mut Self;

    fn absorb(&mut self, str: &[u8]) -> &mut Self;

    fn squeeze(&mut self, z: &mut [u8])-> &mut Self;
}

pub trait Hash<const DIGEST_SIZE:usize> {
    fn reset(&mut self);
    
    fn write(&mut self, data: &[u8]);

    fn sum_into(&self, digest: &mut [u8]);
    
    fn sum(&self)->[u8; DIGEST_SIZE]{
        let mut digest = [0; DIGEST_SIZE];
        self.sum_into(&mut digest);
        digest
    }

    fn block_size(&self)-> usize;
    fn size(&self) -> usize;
}


const dsbyteSHA3: u8 = 0b00000110;
const dsbyteShake: u8 = 0b00011111;

pub fn new512() -> Digest<64> {
    Digest::new(dsbyteSHA3)
}

pub fn new384() -> Digest<48> {
    Digest::new(dsbyteSHA3)
}
pub fn new256() -> Digest<32> {
    Digest::new(dsbyteSHA3)
}
pub fn new224() -> Digest<24> {
    Digest::new(dsbyteSHA3)
}


pub fn new_shake128()-> SHAKE<16> {
    SHAKE::new(dsbyteShake)
}

// NewShake256 creates a new SHAKE256 XOF.
pub fn new_shake256() -> SHAKE<32> {
    SHAKE::new(dsbyteShake)
}

#[cfg(test)]
mod tests {

    use super::*;
    use hex_literal::*;

    #[test]
    fn test_sha3() {
        let mut data = [0; 100];
        for i in 0..100 {
            data[i] = i as u8;
        }

        let mut h = new512();
        h.write(&data);
        let out = h.sum();
        let expect = hex!(
            "6286a3e2a02236f45739be74f1d1d83cc55c7dca0018f852ac52b5f5ed9b3d1728fa4eb2087e87f16fbbdd64abef783f1953f20d06cf271b8f2fce2a3beb76ff"
        );
        assert_eq!(out, expect);

        let mut h = new256();
        h.write(&data);
        let out = h.sum();
        let expect = hex!("8c46d8901ae6919eb001cd4a9907a22aaa47954630099a473d2d5336ea7689e1");
        assert_eq!(out, expect);
    }

    #[test]
    fn test_shake() {
        let mut data = [0; 100];
        for i in 0..100 {
            data[i] = i as u8;
        }
        let expect = hex!("04eba30b78550ee461bb4d591d2b3667eb844002eee5a1c7199f7d0420385f1118a36dbd5ab19739eea2d2e1789008f9492302b3115e36f47e838c8af0eb8e93569815cad998deced9bfb064bed1fcb8b2c14b7847a95d8ac3eb63a30b6289d96fc855394727560b201e074063a595c9e41af091362e55fc1e8b13c0a920ae83961e4664f9a1235d4d0f4ea2c93c89f7f84808ac943d1a3d927b64b40bf33d470b42601eff17c0b62e032cb102eacda8392d75641d8e3c4b27d0a9487d6ad7b04ca47079a459a643");

        let mut h = new_shake128();
        h.write(&data);
        let mut buf = [0; 100];
        h.read(&mut buf);
        assert_eq!(buf, expect[..100]);
                
        h.read(&mut buf);
        assert_eq!(buf, expect[100..]); 
    }
}
