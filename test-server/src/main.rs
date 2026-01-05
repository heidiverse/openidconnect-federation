use std::{collections::HashMap, sync::LazyLock};

use axum::{
    Router,
    extract::Query,
    http::{HeaderMap, HeaderName},
    routing::get,
};
use heidi_jwt::{Jwk, JwkSet, JwsHeader, chrono::Duration, jwt::creator::JwtCreator};
use openidconnect_federation::models::{EntityConfig, EntityStatement};

static KEYS: LazyLock<HashMap<String, Jwk>> = LazyLock::new(|| {
    let leaf: Jwk = serde_json::from_str(include_str!("../leaf.json")).unwrap();
    let intermediate: Jwk = serde_json::from_str(include_str!("../intermediate.json")).unwrap();
    let root: Jwk = serde_json::from_str(include_str!("../root.json")).unwrap();
    HashMap::from([
        ("leaf".to_string(), leaf),
        ("intermediate".to_string(), intermediate),
        ("root".to_string(), root),
    ])
});

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/.well-known/openid-federation", get(leaf_ec))
        .nest("/intermediate", intermediate_router())
        .nest("/root", root_router());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn intermediate_router() -> Router {
    Router::new()
        .route("/.well-known/openid-federation", get(intermediate_ec))
        .route("/fetch-subordinate", get(fetch_subordinate))
}

fn root_router() -> Router {
    Router::new().route("/.well-known/openid-federation", get(root_ec))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FetchSubordinateRequest {
    #[serde(rename = "sub")]
    subject: String,
}

async fn leaf_ec() -> ([(HeaderName, &'static str); 1], String) {
    todo! {}
}

async fn intermediate_ec() -> ([(HeaderName, &'static str); 1], String) {
    todo! {}
}
async fn root_ec() -> ([(HeaderName, &'static str); 1], String) {
    todo! {}
}

async fn fetch_subordinate(
    Query(subject): Query<FetchSubordinateRequest>,
) -> Result<([(HeaderName, &'static str); 1], String), String> {
    match subject.subject.as_str() {
        "http://localhost:3000" => {
            let mut subject_keys = JwkSet::new();
            let mut pub_key = KEYS["leaf"].to_public_key().unwrap();
            pub_key.set_key_id(KEYS["leaf"].key_id().unwrap());
            subject_keys.push_key(pub_key);
            let ec = EntityStatement {
                iss: "http://localhost:3000/intermediate".to_string(),
                sub: "http://localhost:3000".to_string(),
                iat: 0,
                exp: 0,
                jwks: heidi_jwt::models::JwkSet(subject_keys),
                metadata: None,
                ..Default::default()
            };
            let signer = heidi_jwt::ES256
                .signer_from_jwk(&KEYS["intermediate"])
                .unwrap();
            let mut jws_header = JwsHeader::new();
            jws_header.set_algorithm(heidi_jwt::ES256.name());
            jws_header.set_token_type("entity-statement+jwt");
            jws_header.set_key_id(KEYS["intermediate"].key_id().unwrap());
            let ec = ec
                .create_jwt(&jws_header, None, Duration::minutes(5), &signer)
                .unwrap();
            Ok((
                [(
                    "Content-Type".parse().unwrap(),
                    "application/entity-statement+jwt",
                )],
                ec,
            ))
        }
        "http://localhost:3000/intermediate" => {
            let mut subject_keys = JwkSet::new();
            let mut pub_key = KEYS["intermediate"].to_public_key().unwrap();
            pub_key.set_key_id(KEYS["intermediate"].key_id().unwrap());
            subject_keys.push_key(pub_key);
            let ec = EntityStatement {
                iss: "http://localhost:3000/root".to_string(),
                sub: "http://localhost:3000/intermediate".to_string(),
                iat: 0,
                exp: 0,
                jwks: heidi_jwt::models::JwkSet(subject_keys),
                metadata: None,
                ..Default::default()
            };
            let signer = heidi_jwt::ES256.signer_from_jwk(&KEYS["root"]).unwrap();
            let mut jws_header = JwsHeader::new();
            jws_header.set_algorithm(heidi_jwt::ES256.name());
            jws_header.set_token_type("entity-statement+jwt");
            jws_header.set_key_id(KEYS["root"].key_id().unwrap());
            let ec = ec
                .create_jwt(&jws_header, None, Duration::minutes(5), &signer)
                .unwrap();
            Ok((
                [(
                    "Content-Type".parse().unwrap(),
                    "application/entity-statement+jwt",
                )],
                ec,
            ))
        }
        _ => return Err("Invalid subject".to_string()),
    }
}
