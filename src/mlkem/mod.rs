
mod mlkem512;
mod zq;
mod util;
mod hash;
mod ntt;

type Zq = u16;

#[allow(non_camel_case_types)]
pub enum ML_KEM_Param{
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024, 
}

pub struct KEM{
    k: usize,
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
}

pub struct Error{
}

pub type Result<T> = core::result::Result<T, Error>;