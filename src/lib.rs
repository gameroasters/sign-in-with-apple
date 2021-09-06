#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::perf)]
#![deny(clippy::nursery)]
#![deny(clippy::match_like_matches_macro)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

mod data;
mod error;

pub use data::{Claims, ClaimsServer2Server};
pub use error::Error;

use data::{KeyComponents, APPLE_ISSUER, APPLE_PUB_KEYS};
use error::Result;
use hyper::{body, Body, Client, Request};
use hyper_tls::HttpsConnector;
use jsonwebtoken::{
	self, decode, decode_header, DecodingKey, TokenData, Validation,
};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

//TODO: put verification into a struct and only fetch apple keys once in the beginning
async fn fetch_apple_keys() -> Result<HashMap<String, KeyComponents>>
{
	let https = HttpsConnector::new();
	let client = Client::builder().build::<_, hyper::Body>(https);

	let req = Request::builder()
		.method("GET")
		.uri(APPLE_PUB_KEYS)
		.body(Body::from(""))?;

	let resp = client.request(req).await?;
	let buf = body::to_bytes(resp).await?;

	let mut resp: HashMap<String, Vec<KeyComponents>> =
		serde_json::from_slice(&buf)?;

	resp.remove("keys").map_or(Err(Error::AppleKeys), |res| {
		Ok(res
			.into_iter()
			.map(|val| (val.kid.clone(), val))
			.collect::<HashMap<String, KeyComponents>>())
	})
}

/// decoe token with optional expiry validation
pub async fn decode_token<T: DeserializeOwned>(
	token: String,
	ignore_expire: bool,
) -> Result<TokenData<T>> {
	let header = decode_header(token.as_str())?;

	let kid = match header.kid {
		Some(k) => k,
		None => return Err(Error::KidNotFound),
	};

	let pubkeys = fetch_apple_keys().await?;

	let pubkey = match pubkeys.get(&kid) {
		Some(key) => key,
		None => return Err(Error::KeyNotFound),
	};

	let mut val = Validation::new(header.alg);
	val.validate_exp = !ignore_expire;
	let token_data = decode::<T>(
		token.as_str(),
		&DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e),
		&val,
	)?;

	Ok(token_data)
}

pub async fn validate(
	client_id: String,
	token: String,
	ignore_expire: bool,
) -> Result<TokenData<Claims>> {
	let token_data =
		decode_token::<Claims>(token, ignore_expire).await?;

	//TODO: can this be validated alread in `decode_token`?
	if token_data.claims.iss != APPLE_ISSUER {
		return Err(Error::IssClaimMismatch);
	}

	if token_data.claims.sub != client_id {
		return Err(Error::ClientIdMismatch);
	}
	Ok(token_data)
}

#[cfg(test)]
mod tests {
	use crate::{decode_token, validate, ClaimsServer2Server, Error};

	#[tokio::test]
	async fn validate_test() -> std::result::Result<(), Error> {
		let user_token =
			"001026.16112b36378440d995af22b268f00984.1744";
		let token = "eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MTQ1MTc1OTQsImlhdCI6MTYxNDQzMTE5NCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiJNNVVDdW5GdTFKNjdhdVE2LXEta093IiwiZW1haWwiOiJ6ZGZ1N2p0dXVzQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNjE0NDMxMTk0LCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.GuMJfVbnEvqppwwHFZjn3GDJtB4c4rl7C4PZzyDsdyiuXcFcXq52Ti0WSJBsqtfyT2dXvYxVxebHtONSQha_9DiM5qfYTZbpDDlIXrOMy1fkfStocold_wHWavofIpoJQVUMj45HLHtjixiNE903Pho6eY2UjEUjB3aFe8txuFIMv2JsaMCYzG4-e632FKBn63SroCkLc-8b4EVV4iYqnC5AfZArXhVjUevhhlaBH0E8Az2OGEe74U2WgBvMXEilmd62Ek-uInnrpJRgYQfYXvehQ1yT3aMiIgJICTQFMDdL1KAvs6mc081lNJLFYvViWlMH-Y7E5ajtUiMApiNYsg";

		let result =
			validate(user_token.to_string(), token.to_string(), true)
				.await?;

		assert_eq!(result.claims.sub, user_token);
		assert_eq!(result.claims.aud, "com.gameroasters.stack4");

		Ok(())
	}

	#[tokio::test]
	async fn validate_no_email() {
		let token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MzA4Mjc4MzAsImlhdCI6MTYzMDc0MTQzMCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiI0QjZKWTU4TmstVUJsY3dMa2VLc2lnIiwiYXV0aF90aW1lIjoxNjMwNzQxNDMwLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.iW0xk__fPD0mlh9UU-vh9VnR8yekWq64sl5re5d7UmDJxb1Fzk1Kca-hkA_Ka1LhSmKADdFW0DYEZhckqh49DgFtFdx6hM9t7guK3yrvBglhF5LAyb8NR028npxioLTTIgP_aR6Bpy5AyLQrU-yYEx2WTPYV5ln9n8vW154gZKRyl2KBlj9fS11BL_X1UFbFrL21GG_iPbB4qt5ywwTPoJ-diGN5JQzP5fk4yU4e4YmHhxJrT0NTTux2mB3lGJLa6YN-JYe_BuVV9J-sg_2r_ugTOUp3xQpfntu8xgQrY5W0oPxAPM4sibNLsye2kgPYYxfRYowc0JIjOcOd_JHDbQ";

		validate(
			"001026.16112b36378440d995af22b268f00984.1744".into(),
			token.to_string(),
			true,
		)
		.await
		.unwrap();
	}

	#[tokio::test]
	async fn test_server_to_server_payload() {
		let token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MzAxNzE4MTIsImlhdCI6MTYzMDA4NTQxMiwianRpIjoiQjk0T2REMDNwRnNhWWFOLUZ0djdtQSIsImV2ZW50cyI6IntcInR5cGVcIjpcImVtYWlsLWRpc2FibGVkXCIsXCJzdWJcIjpcIjAwMTAyNi4xNjExMmIzNjM3ODQ0MGQ5OTVhZjIyYjI2OGYwMDk4NC4xNzQ0XCIsXCJldmVudF90aW1lXCI6MTYzMDA4NTQwMzY0OCxcImVtYWlsXCI6XCJ6ZGZ1N2p0dXVzQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbVwiLFwiaXNfcHJpdmF0ZV9lbWFpbFwiOlwidHJ1ZVwifSJ9.SSdUM88GHqrS0QXHtaehbPxLQkAB3s1-qzcy3i2iRoSCzDhA1Q3o_FhiCbqOsbiPDOQ9aA1Z8-oAz1p3-TMfHy6QdIs1vLxBmNTe5IazNJw_7wwDZG2nr-bsKPUQldE--tK1EUFXQqQxQbfjJJE0JFEwPib2rmnb-t0mRopKMx2wg3CUlI64BHI2O8giGCbWB7UbJs2BpcUuapVShCIR7Eqxy0_ud81CUDjKzZK2CcmSRGDIk8g9pRqOHmPUFMOrDjj6_hUR9mf-xCrCedoC9f05z_yKD026A4gWGFn4pxTP8-uDTRPxcONax_vnQHBUDigYi8HXuzWorTx2ORPjaw";

		let result = decode_token::<ClaimsServer2Server>(
			token.to_string(),
			true,
		)
		.await
		.unwrap();

		assert_eq!(result.claims.aud, "com.gameroasters.stack4");
		assert_eq!(
			result.claims.events.sub,
			"001026.16112b36378440d995af22b268f00984.1744"
		);

		println!("{:?}", result);
	}
}
