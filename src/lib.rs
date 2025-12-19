/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

use std::str::FromStr;

use heidi_jwt::jwt::Jwt;
use serde::{Serialize, de::DeserializeOwned};

use crate::models::{
    errors::{FederationError, InternetError, JwsError},
    trust_chain::FederationRelation,
};

pub mod models;
pub mod policy;
pub type DefaultFederationRelation = FederationRelation;
pub trait FetchConfig {
    const VERIFY_TLS: bool;
}

pub struct DefaultConfig;
pub struct NoVerifyConfig;

impl FetchConfig for DefaultConfig {
    const VERIFY_TLS: bool = true;
}
impl FetchConfig for NoVerifyConfig {
    const VERIFY_TLS: bool = false;
}

pub fn fetch_jwt<T, Config>(url: &str) -> Result<Jwt<T>, FederationError>
where
    T: Serialize + DeserializeOwned + std::fmt::Debug,
    Config: FetchConfig,
{
    let mut client = reqwest::blocking::Client::builder();
    if Config::VERIFY_TLS {
        client = client.danger_accept_invalid_certs(false);
    }
    let client = client.build().unwrap();
    let response = client
        .get(url)
        .send()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?
        .error_for_status()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    let text = response
        .text()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    Jwt::from_str(&text).map_err(|e| FederationError::Jws(JwsError::InvalidFormat(format!("{e}"))))
}
pub async fn fetch_jwt_async<
    T: Serialize + DeserializeOwned + std::fmt::Debug,
    Config: FetchConfig,
>(
    url: &str,
) -> Result<Jwt<T>, FederationError> {
    let mut client = reqwest::Client::builder();
    if Config::VERIFY_TLS {
        client = client.danger_accept_invalid_certs(false);
    }
    let client = client.build().unwrap();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?
        .error_for_status()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    let text = response
        .text()
        .await
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    Jwt::from_str(&text).map_err(|e| FederationError::Jws(JwsError::InvalidFormat(format!("{e}"))))
}

#[cfg(test)]
mod tests {
    use heidi_jwt::{
        Jwk, JwsHeader, JwsSigner,
        chrono::Duration,
        jwt::{
            Jwt,
            creator::{JwtCreator, Signer},
        },
    };
    use petgraph::algo::astar;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tracing::{debug, level_filters::LevelFilter};
    use tracing_subscriber::{FmtSubscriber, fmt::format::FmtSpan};

    use crate::{
        DefaultConfig, DefaultFederationRelation,
        models::{
            self, EntityConfig, EntityStatement,
            trust_chain::{TrustAnchor, TrustStore},
        },
        policy::operators::Policy,
    };

    #[test]
    fn test_trust_chain_builder() {
        // let subscriber = FmtSubscriber::builder()
        //     .with_line_number(true)
        //     .with_max_level(LevelFilter::DEBUG)
        //     .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        //     .pretty()
        //     .finish();
        // let _ = tracing::subscriber::set_global_default(subscriber);
        debug!("Test Started");
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let mut trust_chain = DefaultFederationRelation::from_trust_chain(&chain).unwrap();
        let errors = trust_chain.build_trust().err();
        debug!(error = ?errors, "Test Ended");
    }
    #[test]
    fn test_sunet() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let jwt = chain.first().unwrap();
        let ec = jwt.parse::<Jwt<EntityStatement>>().unwrap();
        let config = EntityConfig::TrustAnchor(ec);
        println!("{:?}", config.verify());
    }

    #[test]
    fn refresh() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let jwt = chain.first().unwrap();
        let ec = jwt.parse::<Jwt<EntityStatement>>().unwrap();
        let mut config = EntityConfig::TrustAnchor(ec);
        println!("{}", config.payload_unverified().insecure().exp());
        config.refresh::<DefaultConfig>().unwrap();
        println!("{}", config.payload_unverified().insecure().exp());
    }
    #[test]
    fn fetch_from_url() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let issuer = "https://heidi-issuer-ws-dev.ubique.ch/zvv/c";
        let mut trust_chain = DefaultFederationRelation::new_from_url(issuer).unwrap();
        let res = trust_chain.build_trust();
        debug!(error = ?res, "[build_trust]");
        let res = trust_chain.verify();
        debug!(error = ?res, "[verify_trust]");
    }

    #[test]
    fn fetch_from_url_procivis() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::INFO)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        // let issuer = "https://procivis.sandbox.findy.fi/ssi/openid4vci/final-1.0/df0fc41b-f631-4f3c-b4ba-6b9e13c75e54";
        let issuer = "https://issuer.waltid.dev.findy.fi/draft13";
        let mut trust_chain = DefaultFederationRelation::new_from_url(issuer).unwrap();
        let res = trust_chain.build_trust();
        debug!(error = ?res, "[build_trust]");
        let res = trust_chain.verify();
        debug!(error = ?res, "[verify_trust]");
    }

    #[test]
    fn create_statements() {
        // let subscriber = FmtSubscriber::builder()
        //     .with_line_number(true)
        //     .with_max_level(LevelFilter::INFO)
        //     .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        //     .pretty()
        //     .finish();
        // let _ = tracing::subscriber::set_global_default(subscriber);
        let root_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let root_jwk = root_key.to_jwk_key_pair();
        println!("create ec");
        let (root_jwt, root_signer) =
            create_ec("root", &Value::Null, &Value::Null, &root_jwk, &Value::Null);

        let root2_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let root2_jwk = root2_key.to_jwk_key_pair();
        println!("create ec");
        let (root2_jwt, root2_signer) = create_ec(
            "root2",
            &Value::Null,
            &Value::Null,
            &root2_jwk,
            &Value::Null,
        );
        println!("create intermediate2");
        let (intermediate2_jwt, intermediate2_key) = create_statement(
            "root",
            "intermediate2",
            &Value::Null,
            &json!({
                "openid_provider": {
                  "id_token_signing_alg_values_supported": {
                    "add": ["RS256", "RS384", "RS512"]
                  },
                },
            }),
            &root_signer,
        );
        let intermediate2_signer = heidi_jwt::ES256
            .signer_from_jwk(&intermediate2_key)
            .unwrap();

        // let mitm_signer = heidi_jwt::ES256.signer_from_jwk(&mitm_key).unwrap();
        let (intermediate1_jwt, intermediate1_key) = create_statement(
            "intermediate2",
            "intermediate1",
            &Value::Null,
            &Value::Null,
            &intermediate2_signer,
        );

        let (intermediate_cs, _) = create_cross_signed(
            "root2",
            "intermediate1",
            &Value::Null,
            &Value::Null,
            &root2_signer,
            &intermediate1_key,
        );

        let intermediate1_signer = heidi_jwt::ES256
            .signer_from_jwk(&intermediate1_key)
            .unwrap();
        let (leaf_sub, leaf_key) = create_statement(
            "intermediate1",
            "leaf",
            &Value::Null,
            &Value::Null,
            &intermediate1_signer,
        );

        let (leaf_ec, _) = create_ec(
            "leaf",
            &json!({ "openid_provider": {
                "issuer" : "https://test.example.com"
            } }),
            &Value::Null,
            &leaf_key,
            &json!(["intermediate1"]),
        );

        let chain = vec![
            leaf_ec,
            leaf_sub,
            intermediate1_jwt,
            intermediate_cs,
            intermediate2_jwt,
            root_jwt,
            root2_jwt,
        ];

        let mut trust_chain = DefaultFederationRelation::from_trust_cache(&chain).unwrap();

        trust_chain.build_trust().unwrap();
        trust_chain.verify().unwrap();

        // let first_anchor: TrustAnchor = TrustAnchor::Subject("root2".to_string());
        let second_anchor: TrustAnchor = TrustAnchor::Subject("root".to_string());

        let trust_store = TrustStore(vec![second_anchor]);
        let paths = trust_chain
            .find_shortest_trust_chain(Some(&trust_store))
            .unwrap();
        println!("Best path found:");
        for s in paths {
            println!("{}", s.sub());
        }

        let resolved_metadata = trust_chain.resolve_metadata(None);
        println!(
            "{}",
            serde_json::to_string_pretty(&resolved_metadata).unwrap()
        );
    }

    fn create_ec(
        iss: &str,
        metadata: &Value,
        metadata_policy: &Value,
        root_key: &Jwk,
        authority_hints: &Value,
    ) -> (String, impl JwsSigner) {
        let mut public_key = root_key.to_public_key().unwrap();
        public_key.set_key_id(format!("{}", iss));
        let mut root = json!({
            "sub" : iss,
            "jwks" : {
                "keys" : [
                    public_key
                ]
            },
            "metadata" : metadata,
            "metadata_policy" : metadata_policy
        });
        if authority_hints != &Value::Null {
            root["authority_hints"] = authority_hints.clone();
        }
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(heidi_jwt::ES256.name());
        jws_header.set_token_type("entity-statement+jwt");
        jws_header.set_key_id(public_key.key_id().unwrap());
        let new_signer = heidi_jwt::ES256.signer_from_jwk(&root_key).unwrap();

        return (
            root.create_jwt(&jws_header, Some(iss), Duration::minutes(2), &new_signer)
                .unwrap(),
            new_signer,
        );
    }
    fn create_statement(
        iss: &str,
        sub: &str,
        metadata: &Value,
        metadata_policy: &Value,
        signer: &dyn Signer,
    ) -> (String, Jwk) {
        let root_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let mut public_key = root_key.to_jwk_public_key();
        public_key.set_key_id(format!("{}", sub));
        let root = json!({
            "sub" : sub,
            "jwks" : {
                "keys" : [
                    public_key
                ]
            },
            "metadata" : metadata,
            "metadata_policy" : metadata_policy
        });
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(heidi_jwt::ES256.name());
        jws_header.set_token_type("entity-statement+jwt");
        jws_header.set_key_id(iss);

        return (
            root.create_jwt(&jws_header, Some(iss), Duration::minutes(2), signer)
                .unwrap(),
            root_key.to_jwk_key_pair(),
        );
    }
    fn create_cross_signed(
        iss: &str,
        sub: &str,
        metadata: &Value,
        metadata_policy: &Value,
        signer: &dyn Signer,
        key: &Jwk,
    ) -> (String, Jwk) {
        let mut public_key = key.to_public_key().unwrap();
        public_key.set_key_id(format!("{}", sub));
        let root = json!({
            "sub" : sub,
            "jwks" : {
                "keys" : [
                    public_key
                ]
            },
            "metadata" : metadata,
            "metadata_policy" : metadata_policy
        });
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(heidi_jwt::ES256.name());
        jws_header.set_token_type("entity-statement+jwt");
        jws_header.set_key_id(iss);

        return (
            root.create_jwt(&jws_header, Some(iss), Duration::minutes(2), signer)
                .unwrap(),
            key.clone(),
        );
    }
}
