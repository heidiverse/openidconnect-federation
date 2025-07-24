use std::{
    collections::{HashMap, HashSet},
    hash::RandomState,
};

use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

use crate::models::{
    self,
    errors::{FederationError, PolicyError},
    transformer::{self, Value},
};

fn subset(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Array(a) = a.argument() else {
        return false;
    };
    let Value::Array(b) = b.argument() else {
        return false;
    };
    for item in b {
        if !a.contains(&item) {
            return false;
        }
    }
    true
}
fn superset(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    subset(b, a)
}
fn is_same(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    a == b
}
fn not_null(a: &PolicyOperator, _b: &PolicyOperator) -> bool {
    matches!(a.argument(), Value::Null)
}
fn other_not_null(_a: &PolicyOperator, b: &PolicyOperator) -> bool {
    matches!(b.argument(), Value::Null)
}
fn contains(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Array(a) = a.argument() else {
        return false;
    };
    a.contains(&b.argument())
}

fn contained_in(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Array(b) = b.argument() else {
        return false;
    };
    b.contains(&a.argument())
}
fn check_essential(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Boolean(b) = b.argument() else {
        return false;
    };
    if !b {
        return true;
    }
    matches!(a.argument(), Value::Null)
}

crate::operator_definitions!(
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub enum PolicyOperator {
        Value(Value::String(..) | Value::Integer(..) | Value::Float(..) | Value::Boolean(..) | Value::Array(..) ) = "value"
        // Allowed combinations
            => [Add |subset|,Default|not_null|, OneOf|contained_in|, SubsetOf|subset|, SupersetOf|superset|, Essential|check_essential|]
        // merge conditions
            ;mergable => is_same,
        Add(Value::Array(..)) = "add"
            => [Value |subset|, Default, SubsetOf|subset|, SupersetOf, Essential],
        Default(any) = "default"
            => [Value|other_not_null|, Add, OneOf, SubsetOf, SupersetOf, Essential]; mergable => is_same,
        OneOf(Value::String(..)) = "one_of"
            => [Value|contains|, Default, Essential],
        SubsetOf(Value::Array(..)) = "subset_of"
            => [Value|subset|, Add|subset|, Default, SupersetOf|superset|, Essential],
        SupersetOf(Value::Array(..)) = "superset_of"
            => [Value|superset|, Add, Default, SubsetOf|superset|, Essential],
        Essential(Value::Boolean(..)) = "essential",
    }
);

#[macro_export]
macro_rules! operator_definitions {
    ($(#[$($meta:tt)*])* $v:vis enum $name:ident {
            $(
                $(#[$($meta_var:tt)*])*
                $operator_name:ident($tokens:pat) = $value:expr $(=> [$($allowed_operator:ident$(|$($fname:ident),*|)?),*])? $(;mergable => $mergable_cond:ident)?
            ),*,
        }) => {
            $(#[$($meta)*])*
            $v enum $name {
                $(
                    $(#[$($meta_var)*])*
                    #[serde(alias = $value)]
                    $operator_name(crate::models::transformer::Value)
                ),*,
                #[serde(other)]
                Unknown
            }
            impl From<&transformer::Value> for Vec<PolicyOperator> {
                fn from(v: &transformer::Value) -> Vec<PolicyOperator> {
                    let Some(obj) = v.as_object() else {
                        return vec![];
                    };
                    let mut operators = Vec::new();
                    for (key, value) in obj {
                        match key.as_str() {
                            $($value => operators.push(PolicyOperator::$operator_name(value.clone()))),*,
                            _ => operators.push(PolicyOperator::Unknown),
                        }
                    }
                    operators
                }
            }
            impl PolicyOperator {
                pub fn argument(&self) -> crate::models::transformer::Value {
                    match self {
                        $(PolicyOperator::$operator_name(value) => value.clone()),*,
                        Self::Unknown => models::transformer::Value::Null,
                    }
                }
                pub fn valid_data_type(&self, data: &Value) -> bool {
                    match self {
                        $(PolicyOperator::$operator_name(..) => matches!(data, $tokens)),*,
                        Self::Unknown => false
                    }
                }
                pub fn can_be_combined_with(&self, other: &[PolicyOperator]) -> bool {
                    $(
                        if !other.iter().all(|o| {
                            $($mergable_cond(self, o) || )? true
                        }) {
                            return false;
                        }
                    )?
                    match self {
                        $(
                            PolicyOperator::$operator_name(base) => {
                                false $( || other.iter().all(|o| match o {
                                        $(
                                            PolicyOperator::$allowed_operator(..) $(if $($fname(self, o))&&*)? => true,
                                        )*
                                         _ => false
                                    } )
                                )? }
                        )*
                        PolicyOperator::Unknown => false
                    }
                }
                pub fn name(&self) -> &str {
                    match self {
                        $(PolicyOperator::$operator_name(..) => $value),*,
                        Self::Unknown => "Unknown",
                    }
                }
            }
        };
}

impl PolicyOperator {
    #[instrument]
    pub fn merge(&mut self, other: &PolicyOperator) -> Result<(), FederationError> {
        match self {
            PolicyOperator::Value(value) => {}
            PolicyOperator::Add(value) => {
                if let Value::Array(other) = other.argument() {
                    value.as_array_mut().unwrap().extend(other);
                }
            }
            PolicyOperator::Default(value) => {}
            PolicyOperator::OneOf(value) => {
                let Value::Array(self_array) = value else {
                    return Err(PolicyError::InvalidPolicyOperator(format!(
                        "Expected array for OneOf operator, found {:?}",
                        value
                    ))
                    .into());
                };
                let Value::Array(other_array) = other.argument() else {
                    return Err(PolicyError::InvalidPolicyOperator(format!(
                        "Expected array for OneOf operator, found {:?}",
                        other.argument()
                    ))
                    .into());
                };

                // ahm naja, could be better...
                let set: HashSet<Value> = HashSet::from_iter(self_array.clone().into_iter());
                let set2 = HashSet::from_iter(other_array.into_iter());
                let result = set.intersection(&set2).cloned().collect::<Vec<_>>();
                *self_array = result;
            }
            PolicyOperator::SubsetOf(value) => todo!(),
            PolicyOperator::SupersetOf(value) => todo!(),
            PolicyOperator::Essential(value) => todo!(),
            p => {
                warn!("{p:?} is unknown")
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy {
    #[serde(flatten)]
    pub policy_members: HashMap<String, Value>,
}

impl Policy {
    #[instrument]
    pub fn merge_with(&mut self, other: &Policy) -> Result<(), FederationError> {
        for (key, value) in other.policy_members.iter() {
            let member_policy = self
                .policy_members
                .entry(key.to_string())
                .or_insert(Value::Object(HashMap::new()));
            let other_operators: Vec<PolicyOperator> = value.into();
            let mut self_operators: Vec<PolicyOperator> = (&member_policy.clone()).into();
            for other in &other_operators {
                if !other.can_be_combined_with(&self_operators) {
                    return Err(PolicyError::PolicyMergeError(format!(
                        "Cannot merge policies with incompatible operators: {:?} and {:?}",
                        self_operators, other_operators
                    ))
                    .into());
                }
                if let Some(same_operator) = self_operators
                    .iter_mut()
                    .find(|self_ops| other.name() == self_ops.name())
                {
                    same_operator.merge(other)?;
                } else {
                    self_operators.push(other.clone());
                }
            }
            for operator in self_operators {
                member_policy
                    .as_object_mut()
                    .unwrap()
                    .insert(operator.name().to_string(), operator.argument());
            }
        }
        Ok(())
    }
    pub fn apply(&self, object: &mut Value) {
        todo! {}
    }
}

#[cfg(test)]
mod tests {

    use crate::policy::operators::{Policy, PolicyOperator};

    #[test]
    fn test_basic_policy() {
        let policy = include_str!("../../test_resources/figure_11_metadata_policy.json");
        let policy: Policy = serde_json::from_str(policy).unwrap();
        for (attr, policy) in policy.policy_members {
            let operators: Vec<PolicyOperator> = (&policy).into();
            println!("{}{:?}", attr, operators)
        }
    }
}
