use serde::{Deserialize, Serialize};

pub const APPLE_PUB_KEYS: &str = "https://appleid.apple.com/auth/keys";
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyComponents {
    pub kty: String,   // "RSA"
    pub kid: String,   // "eXaunmL"
    pub r#use: String, // "sig"
    pub alg: String,   // "RS256"
    pub n: String,     // "4dGQ7bQK8LgILOdL..."
    pub e: String,     // "AQAB"
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: i32,
    pub iat: i32,
    pub sub: String,
    pub c_hash: String,
    pub email: String,
    pub email_verified: String,
    pub auth_time: i32,
}
