use thiserror;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ByteDecode overflow")]
    ByteDecodeOverflow,

    #[error("decode DecapKey error")]
    DecapKeyDecodeError,
}
pub type Result<T> = core::result::Result<T, Error>;

