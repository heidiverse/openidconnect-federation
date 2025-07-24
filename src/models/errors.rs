use crate::error_model;

crate::error_model!(
    #[derive(Debug, Clone)]
    pub enum FederationError {
        Jws(JwsError),
        TrustChain(TrustChainError),
        Internet(InternetError),
        Payload(PayloadError),
        X509(X509Error),
        Policy(PolicyError),
    }
);
error_model!(
    #[derive(Debug, Clone)]
    pub enum PolicyError {
        PolicyMergeError(String),
        InvalidPolicyOperator(String),
    }
);
error_model!(
    #[derive(Debug, Clone)]
    pub enum X509Error {
        ParseError(String),
    }
);
error_model!(
    #[derive(Debug, Clone)]
    pub enum JwsError {
        InvalidHeader(String),
        InvalidSignature(String),
        Expired(String),
        NotYetValid(String),
        KeyNotFound(String),
        TypeError(String),
        EncodingError(String),
        InvalidFormat(String),
        BodyParseError(String),
    }
);

error_model!(
    #[derive(Debug, Clone)]
    pub enum TrustChainError {
        BrokenChain(String),
        LeafCannotHaveSubordinate(String),
        InvalidEntityConfig(String),
        RootHasNoAuthority(String),
        ConfigNotSignedWithSubordinate(String),
        SubjectMismatch(String),
        LeafNeedsAuthorityHints(String),
        AuthorityHintsMustNotBeEmpty(String),
    }
);

error_model!(
    #[derive(Debug, Clone)]
    pub enum InternetError {
        InvalidResponse(String),
        TrustIssues(String),
        ParseError(String),
    }
);

error_model!(
    #[derive(Debug, Clone)]
    pub enum PayloadError {
        MissingRequiredProperty(String),
    }
);

#[macro_export]
macro_rules! error_model {

    ($(#[$($meta:tt)*])* $vis:vis enum $name:ident { $( $(#[$($meta_field:tt)*])* $field:ident(String) ),*, }) => {
        $(#[$($meta)*])*
        pub enum $name {
            $(
                $(#[$meta_field])*
                $field(String)
            ),*,
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$field(inner) => write!(f, concat!(stringify!($field), "({})"), inner)
                    ),*
                }
            }
        }
    };

    ($(#[$($meta:tt)*])* $vis:vis enum $name:ident { $( $(#[$($meta_field:tt)*])* $field:ident($inner_type:ty) ),*, }) => {
        $(#[$($meta)*])*
        pub enum $name {
            $(
                $(#[$meta_field])*
                $field($inner_type)
            ),*,
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$field(inner) => write!(f, concat!(stringify!($field), "({})"), inner)
                    ),*
                }
            }
        }
        $(
            impl From<$inner_type> for $name {
                fn from(value: $inner_type) -> Self {
                    Self::$field(value)
                }
            }
        )*
    };
}

#[cfg(test)]
mod tests {
    use crate::models::errors::{FederationError, JwsError};

    #[test]
    fn test_display() {
        let e = FederationError::Jws(JwsError::Expired("test".to_string()));
        assert_eq!(format!("{e}"), String::from("Jws(Expired(test))"))
    }
}
