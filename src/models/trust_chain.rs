use std::{collections::HashMap, marker::PhantomData};

use tracing::{error, instrument};

use crate::{
    DefaultConfig, FetchConfig,
    jwt::Jwt,
    models::{
        EntityConfig, EntityStatement,
        errors::{FederationError, TrustChainError},
    },
};

#[derive(Debug, Clone)]
pub struct TrustChain<Config: FetchConfig = DefaultConfig> {
    pub leaf: Entity,
    pub trust_entities: HashMap<String, Entity>,
    phantom: PhantomData<Config>,
}

#[derive(Debug, Clone)]
pub struct Entity {
    pub entity_config: Option<EntityConfig>,
    pub subordinate_statement: Vec<Jwt<EntityStatement>>,
}

impl Entity {
    #[instrument(err, skip(self, trust_entities))]
    pub fn complete_trust(
        &mut self,
        trust_entities: &mut HashMap<String, Entity>,
    ) -> Result<(), FederationError> {
        // leaf entity needs entityconfig and subordinate statement
        let Some(leaf_ec) = self.entity_config.as_ref() else {
            return Err(TrustChainError::InvalidEntityConfig(
                "Leaf entity config not found".to_string(),
            )
            .into());
        };
        if leaf_ec.verify().is_err() {
            //TODO: refresh leaf
            error!("Leaf entity config verification failed");
        }
        // check if we have all sub statements from the authorities
        for hint in leaf_ec
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or(vec![])
        {
            if self
                .subordinate_statement
                .iter()
                .find(|stmt| stmt.payload_unverified().insecure().iss() == hint.as_str())
                .is_none()
            {
                let ec = leaf_ec.fetch_authority(&hint)?;
                let subordinate = ec.fetch_subordinate(&leaf_ec.sub())?;
                self.subordinate_statement.push(subordinate);
                let entry = trust_entities.entry(ec.sub()).or_insert(Entity {
                    entity_config: None,
                    subordinate_statement: vec![],
                });
                entry.entity_config = Some(ec);
            }
        }
        for subordinate_statement in &self.subordinate_statement {
            if leaf_ec.sub() != subordinate_statement.payload_unverified().insecure().sub() {
                return Err(TrustChainError::SubjectMismatch(
                    "Subordinate statement sub does not match".to_string(),
                )
                .into());
            }
        }
        Ok(())
    }
    pub fn verify(&self) -> Result<(), FederationError> {
        if let Some(entity_config) = self.entity_config.as_ref() {
            entity_config.verify()
        } else {
            Err(TrustChainError::InvalidEntityConfig("EntityConfig is missing".to_string()).into())
        }
    }
}

impl<Config: FetchConfig> TrustChain<Config> {
    pub fn verify(&self) -> Result<(), Vec<FederationError>> {
        // leaf needs entity config
        let mut errors = vec![];
        if let Err(e) = self.leaf.entity_config.as_ref().unwrap().verify() {
            errors.push(TrustChainError::InvalidEntityConfig(format!(
                "EntityConfigError: {e}"
            )));
        }
        let sub = self.leaf.entity_config.as_ref().unwrap();
        for sub_state in &self.leaf.subordinate_statement {
            if let Err(e) = sub_state.verify_signature(&sub.jwks()) {
                errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                    "EntityConfigError <-> Subordinate: {e}"
                )));
            }
        }
        if sub
            .payload_unverified()
            .insecure()
            .authority_hints()
            .is_none()
            && !matches!(sub, EntityConfig::TrustAnchor(_))
        {
            errors.push(TrustChainError::LeafNeedsAuthorityHints(format!(
                "EntityConfigError: Missing authority hints"
            )));
        }
        let authority_hints = sub
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or_default();
        if authority_hints.is_empty() {
            errors.push(TrustChainError::AuthorityHintsMustNotBeEmpty(format!(
                "EntityConfigError: Authority hints must not be empty"
            )));
        }
        if self.leaf.subordinate_statement.is_empty() {
            errors.push(TrustChainError::BrokenChain(format!(
                "No authority found for leaf"
            )))
        }
        // check each trust entry
        for (sub, statement) in &self.trust_entities {
            println!("Verifying trust for: {sub}");
            // if there is an entity config, verify the signature (at least)
            let is_trustanchor;
            if let Some(entity_config) = statement.entity_config.as_ref() {
                is_trustanchor = matches!(entity_config, EntityConfig::TrustAnchor(..));
                if let Err(e) = entity_config.verify() {
                    errors.push(TrustChainError::InvalidEntityConfig(format!(
                        "Error in {sub} -> {e}"
                    )));
                }
            } else {
                is_trustanchor = false;
            }
            // we for sure need a subordinate statement if we are not a trust anchor
            if statement.subordinate_statement.is_empty() && !is_trustanchor {
                errors.push(TrustChainError::BrokenChain(
                    "sub: broken trust chain".to_string(),
                ));
            }
            // check all subordinate statements of this entity (check with the issuer)
            for sub_state in &statement.subordinate_statement {
                let iss = sub_state.payload_unverified().insecure().iss();

                let Some(issuer) = self.trust_entities.get(&iss) else {
                    errors.push(TrustChainError::BrokenChain(
                        "{sub}: missing issuer {iss}".to_string(),
                    ));
                    continue;
                };

                if let Some(ec) = issuer.entity_config.as_ref() {
                    if let Err(e) = ec.verify() {
                        errors.push(TrustChainError::InvalidEntityConfig(format!(
                            "Error in issuer ec [{iss}] -> {e}"
                        )));
                    }
                    if let Err(e) = sub_state.verify_signature(&ec.jwks()) {
                        errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                            "Error in sub_state [{iss}] -> {e}"
                        )));
                    }
                    // the issuer entity config subject must be equal to the subordinate statement issuer
                    if sub_state.payload_unverified().insecure().iss() != ec.sub() {
                        errors.push(TrustChainError::SubjectMismatch(format!(
                            "Issuer mismatch in sub_state [{iss}]"
                        )));
                    }
                } else {
                    // if we don't have an entity config, check for the subordinate statement
                    let issuer_statement =
                        issuer.subordinate_statement.iter().find(|iss_sub_state| {
                            iss_sub_state.payload_unverified().insecure().sub()
                                == sub_state.payload_unverified().insecure().sub()
                        });
                    if let Some(issuer_statement) = issuer_statement {
                        if let Err(e) = sub_state.verify_signature(
                            &issuer_statement.payload_unverified().insecure().jwks(),
                        ) {
                            errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                                "Error in issuer statement [{iss}] -> {e}"
                            )));
                        }
                    } else {
                        errors.push(TrustChainError::BrokenChain(format!(
                            "Error in issuer statement [{iss}] -> missing issuer statement"
                        )));
                    }
                }
            }
        }

        if errors.is_empty() {
            return Ok(());
        }
        Err(errors.into_iter().map(|a| a.into()).collect::<Vec<_>>())
    }
    pub fn new(leaf: Entity) -> Self {
        Self {
            leaf,
            trust_entities: HashMap::new(),
            phantom: PhantomData,
        }
    }
    pub fn new_from_url(url: &str) -> Result<Self, FederationError> {
        Ok(Self {
            leaf: Entity {
                entity_config: Some(EntityConfig::load_from_url::<Config>(url)?),
                subordinate_statement: vec![],
            },
            trust_entities: HashMap::new(),
            phantom: PhantomData,
        })
    }
    #[instrument(skip(chain))]
    pub fn from_trust_chain(chain: &Vec<String>) -> Option<Self> {
        let Some(leaf) = chain.first() else {
            return None;
        };
        let Ok(leaf) = leaf.parse::<Jwt<EntityStatement>>() else {
            return None;
        };
        let Some(root) = chain.last() else {
            return None;
        };
        let Ok(root) = root.parse::<Jwt<EntityStatement>>() else {
            return None;
        };
        let mut leaf_entity = Entity {
            entity_config: Some(EntityConfig::Leaf(leaf.clone())),
            subordinate_statement: vec![],
        };

        let mut trust_entities = HashMap::new();
        println!("Leaf Sub: {}", leaf.payload_unverified().insecure().sub());
        println!("Leaf Iss: {}", leaf.payload_unverified().insecure().iss());
        for (i, jwt) in chain
            .iter()
            .skip(1)
            .take(chain.len().saturating_sub(2))
            .enumerate()
        {
            let Ok(intermediate) = jwt.parse::<Jwt<EntityStatement>>() else {
                return None;
            };
            if i == 0 {
                leaf_entity.subordinate_statement = vec![intermediate.clone()];
            } else {
                trust_entities.insert(
                    intermediate.payload_unverified().insecure().sub(),
                    Entity {
                        entity_config: None,
                        subordinate_statement: vec![intermediate],
                    },
                );
            }
        }
        trust_entities.insert(
            root.payload_unverified().insecure().sub(),
            Entity {
                entity_config: Some(EntityConfig::TrustAnchor(root)),
                subordinate_statement: vec![],
            },
        );

        Some(Self {
            leaf: Entity {
                entity_config: Some(EntityConfig::Leaf(leaf)),
                subordinate_statement: vec![],
            },
            trust_entities,
            phantom: PhantomData,
        })
    }
    #[instrument(skip(self))]
    pub fn build_trust(&mut self) -> Result<(), FederationError> {
        self.leaf.complete_trust(&mut self.trust_entities)?;
        let mut old_state = self.trust_entities.clone();
        for (sub, entity) in old_state.iter_mut() {
            entity.complete_trust(&mut self.trust_entities)?;
            *self.trust_entities.get_mut(sub).unwrap() = entity.clone();
        }
        Ok(())
    }
}
