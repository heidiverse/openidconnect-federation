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
    trust_chain::TrustChain,
};

pub mod models;
pub mod policy;
pub type DefaultTrustChain = TrustChain;
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

    use std::hash::RandomState;

    use heidi_jwt::jwt::{Jwt, creator::JwtCreator};
    use petgraph::{
        algo::{all_simple_paths, astar, dijkstra},
        visit::Visitable,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tracing::{debug, level_filters::LevelFilter};
    use tracing_subscriber::{FmtSubscriber, fmt::format::FmtSpan};

    use crate::{
        DefaultConfig, DefaultTrustChain,
        models::{self, EntityConfig, EntityStatement, trust_chain::TrustChain},
        policy::operators::Policy,
    };

    #[test]
    fn test_trust_chain_builder() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        debug!("Test Started");
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let mut trust_chain = DefaultTrustChain::from_trust_chain(&chain).unwrap();
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
    fn test_chain() {
        let chain: Vec<String> =
            serde_json::from_str(include_str!("../test_resources/figure_6_trust_chain.json"))
                .unwrap();
        let mut c = DefaultTrustChain::from_trust_chain(&chain).unwrap();
        c.build_trust().unwrap();
        // c.verify().unwrap();
        let first_anchor = Sha256::digest(c.trust_anchors.first().unwrap()).into();
        let leaf: [u8; 32] = Sha256::digest(c.leaf.entity_config.as_ref().unwrap().sub()).into();

        let paths = astar(&c.trust_graph, first_anchor, |e| e == leaf, |_| 1, |_| 0).unwrap();
        let mut metadata = c.leaf.entity_config.as_ref().unwrap().metadata().unwrap();
        let mut policy = Policy::default();
        for e in paths.1.windows(2) {
            let edge = &c.trust_graph[(e[0], e[1])];
            if let Some(md_policy) = edge.metadata_policy() {
                let md_policy: serde_json::Value = md_policy.into();
                let _ = policy.merge_with(&serde_json::from_value(md_policy).unwrap());
            }
            println!("{:?}", edge.sub());
        }
        let _ = policy.apply(&mut metadata);
        println!("\n\n\n");
        println!("{}", serde_json::to_string(&metadata).unwrap());
        println!(
            "{}",
            serde_json::to_string(&c.leaf.entity_config.unwrap().metadata().unwrap()).unwrap()
        );
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
        let mut trust_chain = DefaultTrustChain::new_from_url(issuer).unwrap();
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
        let mut trust_chain = DefaultTrustChain::new_from_url(issuer).unwrap();
        let res = trust_chain.build_trust();
        debug!(error = ?res, "[build_trust]");
        let res = trust_chain.verify();
        debug!(error = ?res, "[verify_trust]");
    }

    #[test]
    fn create_statements() {
        let root_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let public_key = root_key.to_jwk_public_key();
        let root = json!({
            "sub" : "https://trust-anchor.example.com",
            "iss" : "https://trust-anchor.example.com",
            "jwks" : {
                "keys" : [
                    public_key
                ]
            }
        });
        // root.create_jwt(header, issuer, lifetime, signer)
    }
}
