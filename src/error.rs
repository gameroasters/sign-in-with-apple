//! Convenience types for lib specific error handling
#![allow(clippy::pub_enum_variant_names)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Header algorithm unspecified")]
    HeaderAlgorithmUnspecified,
    #[error("Apple Keys Error")]
    KeysError,
    #[error("Key ID not found")]
    KidNotFound,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Iss claim mismatch")]
    IssClaimMismatch,
    #[error("Client ID mismatch")]
    ClientIdMismatch,
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("serde_json error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("hyper error: {0}")]
    HyperError(#[from] hyper::Error),
    #[error("http error: {0}")]
    HttpError(#[from] hyper::http::Error),
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;
