use std::{collections::HashMap, sync::LazyLock};

use axum::{Router, extract::Query, http::HeaderName, routing::get};
use heidi_jwt::{
    Jwk, JwkSet, JwsHeader,
    chrono::Duration,
    jwt::{Jwt, creator::JwtCreator},
};
use openidconnect_federation::models::{EntityStatement, EntityStatementBuilder};
use serde_json::json;

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
    Router::new()
        .route("/.well-known/openid-federation", get(root_ec))
        .route("/fetch-subordinate", get(fetch_subordinate))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FetchSubordinateRequest {
    #[serde(rename = "sub")]
    subject: String,
}

async fn leaf_ec() -> ([(HeaderName, &'static str); 1], String) {
    println!("fetching leaf ec");
    let mut subject_keys = JwkSet::new();
    let mut pub_key = KEYS["leaf"].to_public_key().unwrap();
    pub_key.set_key_id(KEYS["leaf"].key_id().unwrap());
    subject_keys.push_key(pub_key);
    let ec = EntityStatement {
        iss: "http://localhost:3000".to_string(),
        sub: "http://localhost:3000".to_string(),
        iat: 0,
        exp: 0,
        jwks: heidi_jwt::models::JwkSet(subject_keys),
        metadata: None,
        authority_hints: Some(vec!["http://localhost:3000/intermediate".to_string()]),
        ..Default::default()
    };
    let signer = heidi_jwt::ES256.signer_from_jwk(&KEYS["leaf"]).unwrap();
    let mut jws_header = JwsHeader::new();
    jws_header.set_algorithm(heidi_jwt::ES256.name());
    jws_header.set_token_type("entity-statement+jwt");
    jws_header.set_key_id(KEYS["leaf"].key_id().unwrap());
    let ec = ec
        .create_jwt(
            &jws_header,
            Some("http://localhost:3000"),
            Duration::minutes(5),
            &signer,
        )
        .unwrap();
    (
        [(
            "Content-Type".parse().unwrap(),
            "application/entity-statement+jwt",
        )],
        ec,
    )
}

async fn intermediate_ec() -> ([(HeaderName, &'static str); 1], String) {
    println!("fetching intermediate ec");
    let mut subject_keys = JwkSet::new();
    let mut pub_key = KEYS["intermediate"].to_public_key().unwrap();
    pub_key.set_key_id(KEYS["intermediate"].key_id().unwrap());
    subject_keys.push_key(pub_key);
    let federation_entity = json!({ "federation_fetch_endpoint" : "http://localhost:3000/intermediate/fetch-subordinate" }).into();
    let metadata = HashMap::from([("federation_entity".to_string(), federation_entity)]);
    let ec = EntityStatementBuilder::new()
        .iss("http://localhost:3000/intermediate".to_string())
        .sub("http://localhost:3000/intermediate".to_string())
        .jwks(heidi_jwt::models::JwkSet(subject_keys))
        .metadata(Some(metadata))
        .authority_hints(Some(vec!["http://localhost:3000/root".to_string()]))
        .build();

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
    (
        [(
            "Content-Type".parse().unwrap(),
            "application/entity-statement+jwt",
        )],
        ec,
    )
}
async fn root_ec() -> ([(HeaderName, &'static str); 1], String) {
    println!("fetching root ec");
    let federation_entity =
        json!({ "federation_fetch_endpoint" : "http://localhost:3000/root/fetch-subordinate" })
            .into();
    let metadata = HashMap::from([("federation_entity".to_string(), federation_entity)]);

    let ec = create_entity_config("http://localhost:3000/root", metadata, None, &KEYS["root"]);
    (
        [(
            "Content-Type".parse().unwrap(),
            "application/entity-statement+jwt",
        )],
        ec,
    )
}

async fn fetch_subordinate(
    Query(subject): Query<FetchSubordinateRequest>,
) -> Result<([(HeaderName, &'static str); 1], String), String> {
    println!("Fetching subordinate entity for {}", subject.subject);
    match subject.subject.as_str() {
        "http://localhost:3000" => {
            let ec = create_subordinate_statement(
                "http://localhost:3000",
                "http://localhost:3000/intermediate",
                None,
                &KEYS["leaf"],
                &KEYS["intermediate"],
            );
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

fn create_entity_config(
    sub: &str,
    metadata: HashMap<String, openidconnect_federation::models::transformer::Value>,
    authority: Option<String>,
    key: &Jwk,
) -> String {
    let mut subject_keys = JwkSet::new();
    let mut pub_key = key.to_public_key().unwrap();
    if let Some(key_id) = key.key_id() {
        pub_key.set_key_id(key_id);
    }
    subject_keys.push_key(pub_key);
    let mut ec = EntityStatementBuilder::new()
        .iss(sub.to_string())
        .sub(sub.to_string())
        .jwks(heidi_jwt::models::JwkSet(subject_keys))
        .metadata(Some(metadata));
    if let Some(authority) = authority {
        ec = ec.authority_hints(Some(vec![authority]));
    }
    let ec = ec.build();
    let signer = heidi_jwt::ES256.signer_from_jwk(key).unwrap();
    let mut jws_header = JwsHeader::new();
    jws_header.set_algorithm(heidi_jwt::ES256.name());
    jws_header.set_token_type("entity-statement+jwt");
    jws_header.set_key_id(key.key_id().unwrap());
    ec.create_jwt(&jws_header, Some(sub), Duration::minutes(5), &signer)
        .unwrap()
}

fn create_subordinate_statement(
    sub: &str,
    iss: &str,
    metadata: Option<HashMap<String, openidconnect_federation::models::transformer::Value>>,
    subject_key: &Jwk,
    issuer_key: &Jwk,
) -> String {
    let mut subject_keys = JwkSet::new();
    let mut pub_key = subject_key.to_public_key().unwrap();
    if let Some(key_id) = subject_key.key_id() {
        pub_key.set_key_id(key_id);
    }
    subject_keys.push_key(pub_key);

    let metadata = metadata.unwrap_or_default();
    let es = EntityStatementBuilder::new()
        .iss(iss.to_string())
        .sub(sub.to_string())
        .jwks(heidi_jwt::models::JwkSet(subject_keys))
        .metadata(Some(metadata))
        .build();
    let signer = heidi_jwt::ES256.signer_from_jwk(issuer_key).unwrap();
    let mut jws_header = JwsHeader::new();
    jws_header.set_algorithm(heidi_jwt::ES256.name());
    jws_header.set_token_type("entity-statement+jwt");
    jws_header.set_key_id(issuer_key.key_id().unwrap());
    es.create_jwt(&jws_header, Some(iss), Duration::minutes(5), &signer)
        .unwrap()
}
