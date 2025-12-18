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

use std::{collections::HashMap, marker::PhantomData};

use heidi_jwt::jwt::Jwt;
use petgraph::prelude::DiGraphMap;
use sha2::{Digest, Sha256};
use tracing::{error, instrument};

use crate::{
    DefaultConfig, FetchConfig,
    models::{
        EntityConfig, EntityStatement,
        errors::{FederationError, TrustChainError},
        transformer::Value,
    },
};

#[derive(Debug, Clone)]
pub struct TrustChain<Config: FetchConfig = DefaultConfig> {
    pub leaf: Entity,
    pub trust_entities: HashMap<String, Entity>,
    pub trust_anchors: Vec<String>,
    pub trust_graph: DiGraphMap<[u8; 32], EntityStatement>,
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
        trust_anchors: &mut Vec<String>,
        trust_graph: &mut DiGraphMap<[u8; 32], (EntityConfig, EntityStatement)>,
    ) -> Result<(), FederationError> {
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
        let leaf_sub_hash: [u8; 32] = Sha256::digest(leaf_ec.sub()).into();

        // check if we have all sub statements from the authorities
        for hint in leaf_ec
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or(vec![])
        {
            if !self
                .subordinate_statement
                .iter()
                .any(|stmt| stmt.payload_unverified().insecure().iss() == hint.as_str())
            {
                let ec = leaf_ec.fetch_authority(&hint)?;
                let subordinate = ec.fetch_subordinate(&leaf_ec.sub())?;
                self.subordinate_statement.push(subordinate.clone());
                let mut old_entities = trust_entities.clone();
                let entry = trust_entities.entry(ec.sub()).or_insert(Entity {
                    entity_config: None,
                    subordinate_statement: vec![],
                });
                if matches!(ec, EntityConfig::TrustAnchor(_)) {
                    trust_anchors.push(ec.sub());
                }
                let sub_hash: [u8; 32] = Sha256::digest(ec.sub()).into();

                trust_graph.add_edge(
                    sub_hash,
                    leaf_sub_hash,
                    (
                        ec.clone(),
                        subordinate.payload_unverified().insecure().clone(),
                    ),
                );
                entry.entity_config = Some(ec);
                let _ = entry.complete_trust(&mut old_entities, trust_anchors, trust_graph);
                *trust_entities = old_entities;
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
            let inner = match sub {
                EntityConfig::Leaf(jwt)
                | EntityConfig::Intermediate(jwt)
                | EntityConfig::TrustAnchor(jwt) => jwt,
            };
            if let Err(e) =
                inner.verify_signature(&sub_state.payload_unverified().insecure().jwks())
            {
                errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                    "[LEAF] EntityConfigError <-> Subordinate: {e}"
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
            errors.push(TrustChainError::LeafNeedsAuthorityHints(
                "EntityConfigError: Missing authority hints".to_string(),
            ));
        }
        let authority_hints = sub
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or_default();
        if authority_hints.is_empty() {
            errors.push(TrustChainError::AuthorityHintsMustNotBeEmpty(
                "EntityConfigError: Authority hints must not be empty".to_string(),
            ));
        }
        if self.leaf.subordinate_statement.is_empty() {
            errors.push(TrustChainError::BrokenChain(
                "No authority found for leaf".to_string(),
            ))
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
            trust_anchors: Vec::new(),
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        }
    }
    pub fn new_from_url(url: &str) -> Result<Self, FederationError> {
        Ok(Self {
            leaf: Entity {
                entity_config: Some(EntityConfig::load_from_url::<Config>(url)?),
                subordinate_statement: vec![],
            },
            trust_anchors: Vec::new(),
            trust_entities: HashMap::new(),
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        })
    }
    #[instrument(skip(chain))]
    pub fn from_trust_chain(chain: &[String]) -> Option<Self> {
        let leaf = chain.first()?;
        let mut trust_graph = DiGraphMap::new();
        let Ok(leaf) = leaf.parse::<Jwt<EntityStatement>>() else {
            return None;
        };
        let root = chain.last()?;
        let Ok(root) = root.parse::<Jwt<EntityStatement>>() else {
            return None;
        };
        let mut leaf_entity = Entity {
            entity_config: Some(EntityConfig::Leaf(leaf.clone())),
            subordinate_statement: vec![],
        };
        let leaf_sub: [u8; 32] = Sha256::digest(leaf.payload_unverified().insecure().sub()).into();

        let mut trust_entities = HashMap::new();
        println!("Leaf Sub: {}", leaf.payload_unverified().insecure().sub());
        println!("Leaf Iss: {}", leaf.payload_unverified().insecure().iss());
        let mut last_sub: [u8; 32] = [0; 32];
        for (i, jwt) in chain
            .iter()
            .skip(1)
            .take(chain.len().saturating_sub(2))
            .enumerate()
        {
            let Ok(intermediate) = jwt.parse::<Jwt<EntityStatement>>() else {
                return None;
            };
            println!("{}", intermediate.payload_unverified().insecure().sub());
            let sub = Sha256::digest(intermediate.payload_unverified().insecure().sub()).into();
            if i == 0 {
                trust_graph.add_edge(
                    sub,
                    leaf_sub,
                    intermediate.payload_unverified().insecure().clone(),
                );
                leaf_entity.subordinate_statement = vec![intermediate.clone()];
            } else {
                trust_graph.add_edge(
                    sub,
                    last_sub,
                    intermediate.payload_unverified().insecure().clone(),
                );
                trust_entities.insert(
                    intermediate.payload_unverified().insecure().sub(),
                    Entity {
                        entity_config: None,
                        subordinate_statement: vec![intermediate],
                    },
                );
            }

            last_sub = sub;
        }
        let trust_anchors = vec![root.payload_unverified().insecure().sub()];
        let root_sub = Sha256::digest(root.payload_unverified().insecure().sub()).into();
        trust_graph.add_edge(
            root_sub,
            last_sub,
            root.payload_unverified().insecure().clone(),
        );
        trust_entities.insert(
            root.payload_unverified().insecure().sub(),
            Entity {
                entity_config: Some(EntityConfig::TrustAnchor(root)),
                subordinate_statement: vec![],
            },
        );

        Some(Self {
            leaf: leaf_entity,
            trust_anchors,
            trust_entities,
            trust_graph,
            phantom: PhantomData,
        })
    }
    #[instrument(skip(self))]
    pub fn build_trust(&mut self) -> Result<(), FederationError> {
        let mut trust_anchors = vec![];
        let mut trust_graph = DiGraphMap::new();
        self.leaf.complete_trust(
            &mut self.trust_entities,
            &mut trust_anchors,
            &mut trust_graph,
        )?;

        Ok(())
    }
    #[instrument(skip(self))]
    // Resolve metadata from entity config and metadata_policies following the chains
    pub fn resolve_metadata(&self) -> HashMap<String, Value> {
        let mut metadatas = HashMap::new();
        let base_metadata =
            if let Some(md) = self.leaf.entity_config.as_ref().and_then(|a| a.metadata()) {
                md.clone()
            } else {
                Value::Object(HashMap::new())
            };

        // for anchor in &self.trust_anchors {
        //     let Ok(policy_for_anchor) = merge_policies(anchor, &self.trust_entities) else {
        //         tracing::warn!("Failed to merge policy");
        //         continue;
        //     };
        //     let mut md_clone = base_metadata.clone();
        //     if policy_for_anchor.1.apply(&mut md_clone).is_err() {
        //         tracing::warn!("Failed to apply policy");
        //         continue;
        //     }
        //     metadatas.insert(anchor.to_string(), md_clone);
        // }
        metadatas
    }
}
