use thiserror;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ByteDecode overflow")]
    ByteDecodeOverflow,

    #[error("decode DecapKey error")]
    DecapKeyDecodeError,


    #[error("mldsa tpc: server check failed")]
    TPCServerCheckFailed,
}
pub type Result<T> = core::result::Result<T, Error>;

