use std::{collections::HashMap, sync::LazyLock};

use axum::{
    Router,
    extract::{Query, State},
    http::HeaderName,
    routing::get,
};
use heidi_jwt::{Jwk, JwkSet, JwsHeader, chrono::Duration, jwt::creator::JwtCreator};
use openidconnect_federation::models::{EntityStatementBuilder, transformer::Value};
use serde_json::json;

static PARTIES: LazyLock<HashMap<String, FederationParty>> = LazyLock::new(|| {
    let leaf: Jwk = serde_json::from_str(include_str!("../leaf.json")).unwrap();
    let intermediate: Jwk = serde_json::from_str(include_str!("../intermediate.json")).unwrap();
    let root: Jwk = serde_json::from_str(include_str!("../root.json")).unwrap();
    let leaf_party = FederationParty {
        keys: {
            let mut set = JwkSet::new();
            set.push_key(leaf);
            set
        },
        authorities: Some(vec!["http://localhost:3000/intermediate".to_string()]),
        subject: String::from("http://localhost:3000"),
        metadata: {
            let mut metadata = HashMap::new();
            let federation_entity = json!({
                "organization_name" : "Leaf"
            });
            metadata.insert("federation_entity".to_string(), federation_entity.into());
            metadata
        },
        subordinates: HashMap::new(),
    };
    let intermediate_party = FederationParty {
        keys: {
            let mut set = JwkSet::new();
            set.push_key(intermediate);
            set
        },
        authorities: Some(vec!["http://localhost:3000/root".to_string()]),
        subject: String::from("http://localhost:3000/intermediate"),
        metadata: {
            let mut metadata = HashMap::new();
            let federation_entity = json!({
                "organization_name" : "Intermediate",
                "federation_fetch_endpoint" : "http://localhost:3000/intermediate/fetch-subordinate"
            });
            metadata.insert("federation_entity".to_string(), federation_entity.into());
            metadata
        },
        subordinates: {
            let mut map = HashMap::new();
            map.insert("http://localhost:3000".to_string(), leaf_party.clone());
            map
        },
    };
    HashMap::from([
        ("http://localhost:3000".to_string(), leaf_party),
        (
            "http://localhost:3000/intermediate".to_string(),
            intermediate_party.clone(),
        ),
        (
            "http://localhost:3000/root".to_string(),
            FederationParty {
                keys: {
                    let mut set = JwkSet::new();
                    set.push_key(root);
                    set
                },
                authorities: None,
                subject: String::from("http://localhost:3000/root"),
                metadata: {
                    let mut metadata = HashMap::new();
                    let federation_entity = json!({
                        "organization_name" : "Root Trust!!",
                        "federation_fetch_endpoint" : "http://localhost:3000/root/fetch-subordinate"
                    });
                    metadata.insert("federation_entity".to_string(), federation_entity.into());
                    metadata
                },
                subordinates: {
                    let mut map = HashMap::new();
                    map.insert(
                        "http://localhost:3000/intermediate".to_string(),
                        intermediate_party,
                    );
                    map
                },
            },
        ),
    ])
});

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/.well-known/openid-federation", get(entity_config))
        .with_state(PARTIES["http://localhost:3000"].clone())
        .nest(
            "/intermediate",
            federation_router("http://localhost:3000/intermediate"),
        )
        .nest("/root", federation_router("http://localhost:3000/root"));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn federation_router(sub: &str) -> Router {
    Router::new()
        .route("/.well-known/openid-federation", get(entity_config))
        .route("/fetch-subordinate", get(fetch_subordinate))
        .with_state(PARTIES[sub].clone())
}

#[derive(Clone, Debug)]
pub struct FederationParty {
    keys: JwkSet,
    authorities: Option<Vec<String>>,
    subject: String,
    metadata: HashMap<String, Value>,
    subordinates: HashMap<String, FederationParty>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FetchSubordinateRequest {
    #[serde(rename = "sub")]
    subject: String,
}

async fn entity_config(
    State(entity): State<FederationParty>,
) -> ([(HeaderName, &'static str); 1], String) {
    let ec = create_entity_config(
        &entity.subject,
        entity.metadata.clone(),
        entity.authorities.map(|a| a.first().unwrap().to_string()),
        entity.keys.keys().first().unwrap().clone(),
    );
    (
        [(
            "Content-Type".parse().unwrap(),
            "application/entity-statement+jwt",
        )],
        ec,
    )
}

async fn fetch_subordinate(
    State(entity): State<FederationParty>,
    Query(subject): Query<FetchSubordinateRequest>,
) -> Result<([(HeaderName, &'static str); 1], String), String> {
    if entity.subordinates.len() == 0 {
        return Err("No subordinate entities found".to_string());
    }
    println!(
        "Fetching subordinate entity for {} [{}]",
        subject.subject, entity.subject
    );
    let ec = create_subordinate_statement(
        &subject.subject,
        &entity.subject,
        None,
        entity.subordinates[subject.subject.as_str()]
            .keys
            .keys()
            .first()
            .unwrap(),
        entity.keys.keys().first().unwrap(),
    );
    Ok((
        [(
            "Content-Type".parse().unwrap(),
            "application/entity-statement+jwt",
        )],
        ec,
    ))
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
