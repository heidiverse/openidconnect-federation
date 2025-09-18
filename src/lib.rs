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

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    jwt::Jwt,
    models::{
        errors::{FederationError, InternetError},
        trust_chain::TrustChain,
    },
};

pub mod jwt;
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
    Jwt::from_str(&text)
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
    Jwt::from_str(&text)
}

#[cfg(test)]
mod tests {

    use tracing::{debug, level_filters::LevelFilter};
    use tracing_subscriber::{FmtSubscriber, fmt::format::FmtSpan};

    use crate::{
        DefaultConfig, DefaultTrustChain,
        jwt::Jwt,
        models::{self, EntityConfig, EntityStatement},
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
}
