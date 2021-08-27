//! Convenience types for lib specific error handling

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error("Header algorithm unspecified")]
	HeaderAlgorithmUnspecified,
	#[error("Apple Keys Error")]
	AppleKeys,
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
	SerdeJson(#[from] serde_json::Error),
	#[error("hyper error: {0}")]
	Hyper(#[from] hyper::Error),
	#[error("http error: {0}")]
	Http(#[from] hyper::http::Error),
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;
