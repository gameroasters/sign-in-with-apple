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

pub use error::Error;

use data::{Claims, KeyComponents, APPLE_ISSUER, APPLE_PUB_KEYS};
use error::Result;
use hyper::{body, Body, Client, Request};
use hyper_tls::HttpsConnector;
use jsonwebtoken::{self, decode, decode_header, DecodingKey, TokenData, Validation};
use std::collections::HashMap;

//TODO: put verification into a struct and only fetch apple keys once in the beginning
async fn fetch_apple_keys() -> Result<HashMap<String, KeyComponents>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let req = Request::builder()
        .method("GET")
        .uri(APPLE_PUB_KEYS)
        .body(Body::from(""))?;

    let resp = client.request(req).await?;
    let buf = body::to_bytes(resp).await?;

    let mut resp: HashMap<String, Vec<KeyComponents>> = serde_json::from_slice(&buf)?;

    resp.remove("keys").map_or(Err(Error::AppleKeys), |res| {
        Ok(res
            .into_iter()
            .map(|val| (val.kid.clone(), val))
            .collect::<HashMap<String, KeyComponents>>())
    })
}

pub async fn validate(
    client_id: String,
    token: String,
    ignore_expire: bool,
) -> Result<TokenData<Claims>> {
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
    let token_data = decode::<Claims>(
        token.as_str(),
        &DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e),
        &val,
    )?;

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
    use crate::{validate, Error};

    #[tokio::test]
    async fn validate_test() -> std::result::Result<(), Error> {
        let user_token = "001026.16112b36378440d995af22b268f00984.1744";
        let token = "eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmdhbWVyb2FzdGVycy5zdGFjazQiLCJleHAiOjE2MTQ1MTc1OTQsImlhdCI6MTYxNDQzMTE5NCwic3ViIjoiMDAxMDI2LjE2MTEyYjM2Mzc4NDQwZDk5NWFmMjJiMjY4ZjAwOTg0LjE3NDQiLCJjX2hhc2giOiJNNVVDdW5GdTFKNjdhdVE2LXEta093IiwiZW1haWwiOiJ6ZGZ1N2p0dXVzQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNjE0NDMxMTk0LCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.GuMJfVbnEvqppwwHFZjn3GDJtB4c4rl7C4PZzyDsdyiuXcFcXq52Ti0WSJBsqtfyT2dXvYxVxebHtONSQha_9DiM5qfYTZbpDDlIXrOMy1fkfStocold_wHWavofIpoJQVUMj45HLHtjixiNE903Pho6eY2UjEUjB3aFe8txuFIMv2JsaMCYzG4-e632FKBn63SroCkLc-8b4EVV4iYqnC5AfZArXhVjUevhhlaBH0E8Az2OGEe74U2WgBvMXEilmd62Ek-uInnrpJRgYQfYXvehQ1yT3aMiIgJICTQFMDdL1KAvs6mc081lNJLFYvViWlMH-Y7E5ajtUiMApiNYsg";

        let result = validate(user_token.to_string(), token.to_string(), true).await?;
        println!("{:?}", result);
        Ok(())
    }
}
