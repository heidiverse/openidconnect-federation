pub mod jwt;
pub mod models;
pub mod policy;

#[cfg(test)]
mod tests {
    use tracing::{debug, level_filters::LevelFilter};
    use tracing_subscriber::{FmtSubscriber, fmt::format::FmtSpan};

    use crate::{
        jwt::Jwt,
        models::{self, EntityConfig, EntityStatement, trust_chain::TrustChain},
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
        let mut trust_chain = TrustChain::from_trust_chain(&chain).unwrap();
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
        config.refresh().unwrap();
        println!("{}", config.payload_unverified().insecure().exp());
    }
}
