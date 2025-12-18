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

use std::collections::HashMap;

use crate::{
    models::{
        EntityConfig,
        errors::{FederationError, PolicyError, TrustChainError},
        transformer::{Transformer, Value},
        trust_chain::Entity,
    },
    policy::operators::Policy,
};

pub mod operators;

// /// Merge policies starting from a trust anchor only chosing the first path
// pub fn merge_policies(
//     trust_anchor: &str,
//     trust_entities: &HashMap<String, Entity>,
// ) -> Result<(Entity, Policy), FederationError> {
//     let trust_anchor_entity =
//         trust_entities
//             .get(trust_anchor)
//             .ok_or(FederationError::TrustChain(TrustChainError::BrokenChain(
//                 format!("{} trust anchor not found", trust_anchor),
//             )))?;
//     while let Some(entity) = trust_entities.iter().find(|e| e.1.)

//     todo! {}
// }

// fn fetch_more_policy(
//     authority: &str,
//     trust_entities: &HashMap<String, Entity>,
//     policies: &mut Vec<Policy>,
//     trust_anchors: &mut Vec<Entity>,
// ) -> Result<(), FederationError> {
//     todo! {}
// }
