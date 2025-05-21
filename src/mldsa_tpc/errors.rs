use thiserror;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("mldsa tpc: server check failed")]
    TPCServerCheckFailed,

        #[error("mldsa tpc: public key unmatch")]
    TPCPublicKeyUnMatch,

}
pub type Result<T> = core::result::Result<T, Error>;

