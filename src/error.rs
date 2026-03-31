/// Security error types for oxirush-security.
///
/// Used for operations that can genuinely fail at runtime (e.g., invalid
/// external key material in SUCI ECIES). Internal operations on fixed-size
/// arrays use `.expect()` instead, since their sizes are compile-time guaranteed.

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("ECIES error: {0}")]
    Ecies(String),
    #[error("MAC verification failed")]
    MacMismatch,
}
