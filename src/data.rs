use serde::{Deserialize, Deserializer, Serialize};

pub const APPLE_PUB_KEYS: &str =
	"https://appleid.apple.com/auth/keys";
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

/// see https://developer.apple.com/documentation/sign_in_with_apple/processing_changes_for_sign_in_with_apple_accounts
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsServer2Server {
	pub iss: String,
	pub aud: String,
	pub exp: i32,
	pub iat: i32,
	pub jti: String,
	/// Note that this is documented different to how it is sent.
	/// see https://developer.apple.com/forums/thread/655485
	#[serde(deserialize_with = "deserialize_events")]
	pub events: ClaimsServer2ServerEvent,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsServer2ServerEvent {
	#[serde(rename = "type")]
	pub event_type: String,
	pub sub: String,
	pub event_time: i64,
	pub email: Option<String>,
	pub is_private_email: Option<String>,
}

// The signature of a deserialize_with function must follow the pattern:
//
//    fn deserialize<'de, D>(D) -> Result<T, D::Error>
//    where
//        D: Deserializer<'de>
//
// although it may also be generic over the output types T.
pub fn deserialize_events<'de, D>(
	deserializer: D,
) -> Result<ClaimsServer2ServerEvent, D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let events: ClaimsServer2ServerEvent =
		serde_json::from_str(s.as_str())
			.map_err(serde::de::Error::custom)?;
	Ok(events)
}
