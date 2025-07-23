use tracing::instrument;

use crate::{
    jwt::{Jwt, JwtVerifier},
    models::{
        EntityConfig, EntityStatement,
        errors::{FederationError, JwsError, PayloadError, TrustChainError},
    },
};
use serde_json::Value as JsonValue;

const ENTITY_STATEMENT_TYPE: &str = "entity-statement+jwt";
const TYP_CLAIM: &str = "typ";

impl JwtVerifier<EntityStatement> for EntityStatement {
    #[instrument(skip(self, jwt), err)]
    fn verify_header(&self, jwt: &Jwt<EntityStatement>) -> Result<(), FederationError> {
        let header = jwt.header()?;
        let Some(typ) = header.claim(TYP_CLAIM) else {
            return Err(FederationError::Jws(JwsError::TypeError(
                "typ claim not found".to_string(),
            )));
        };
        let JsonValue::String(typ) = typ else {
            return Err(FederationError::Jws(JwsError::TypeError(
                "typ claim is not a string".to_string(),
            )));
        };
        if typ != ENTITY_STATEMENT_TYPE {
            return Err(FederationError::Jws(JwsError::TypeError(
                "typ claim is not 'entity-statement+jwt'".to_string(),
            )));
        }
        let Some(typ) = header.claim("kid") else {
            return Err(FederationError::Jws(JwsError::InvalidHeader(
                "kid claim not found".to_string(),
            )));
        };
        let JsonValue::String(_) = typ else {
            return Err(FederationError::Jws(JwsError::TypeError(
                "kid claim is not a string".to_string(),
            )));
        };
        Ok(())
    }
    #[instrument(skip(self, jwt), err)]
    fn verify_body(&self, jwt: &Jwt<EntityStatement>) -> Result<(), FederationError> {
        let unverified = jwt.payload_unverified();
        if unverified.insecure().authority_hints().is_some() {
            return Err(PayloadError::MissingRequiredProperty(
                "authority_hints should be none".to_string(),
            )
            .into());
        }
        if unverified.insecure().iss() == unverified.insecure().sub() {
            return Err(TrustChainError::SubjectMismatch(
                "iss and sub claims should be different if not an entity configuration".to_string(),
            )
            .into());
        }
        Ok(())
    }
}

impl JwtVerifier<EntityStatement> for EntityConfig {
    #[instrument(skip(self, jwt), err)]
    fn verify_header(&self, jwt: &Jwt<EntityStatement>) -> Result<(), FederationError> {
        let header = jwt.header()?;
        let Some(typ) = header.claim(TYP_CLAIM) else {
            return Err(JwsError::TypeError("typ claim not found".to_string()).into());
        };
        let JsonValue::String(typ) = typ else {
            return Err(JwsError::TypeError("typ claim is not a string".to_string()).into());
        };
        if typ != ENTITY_STATEMENT_TYPE {
            return Err(
                JwsError::TypeError("typ claim is not 'entity-statement+jwt'".to_string()).into(),
            );
        }
        let Some(typ) = header.claim("kid") else {
            return Err(JwsError::InvalidHeader("kid claim not found".to_string()).into());
        };
        let JsonValue::String(_) = typ else {
            return Err(JwsError::InvalidHeader("kid claim is not a string".to_string()).into());
        };
        Ok(())
    }
    #[instrument(skip(self, jwt), err)]
    fn verify_body(&self, jwt: &Jwt<EntityStatement>) -> Result<(), FederationError> {
        let unverified = jwt.payload_unverified();
        if unverified.insecure().authority_hints().is_none()
            && !matches!(self, EntityConfig::TrustAnchor(_))
        {
            return Err(PayloadError::MissingRequiredProperty(
                "authority_hints claim not found".to_string(),
            )
            .into());
        }
        if unverified.insecure().iss() != unverified.insecure().sub() {
            return Err(TrustChainError::SubjectMismatch(
                "iss and sub claims do not match".to_string(),
            )
            .into());
        }
        Ok(())
    }
}
