//! Storage error models and typed failure representations.

use sentinel_core::alert::AlertStatus;
use sentinel_core::error::DomainError;
use thiserror::Error;

/// Strongly typed errors produced by persistent storage operations, repository queries,
/// migrations, and transaction management.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Underlying SQLite or SQLx engine error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Database schema migration error.
    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// JSON serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Domain model invariant violation during entity reconstitution.
    #[error("domain invariant violation: {0}")]
    Domain(#[from] DomainError),

    /// Database constraint violation (e.g., active alert fingerprint conflict or foreign key violation).
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    /// Target database record was not found.
    #[error("record not found: {0}")]
    RecordNotFound(String),

    /// Prohibited alert triage lifecycle transition.
    #[error("invalid alert status transition from '{from}' to '{to}'")]
    InvalidStatusTransition {
        /// Current lifecycle status of the alert.
        from: AlertStatus,
        /// Attempted target lifecycle status.
        to: AlertStatus,
    },

    /// Invalid query filter or bounded pagination parameter.
    #[error("invalid query parameter: {0}")]
    InvalidParameter(String),

    /// Transaction execution or rollback failure.
    #[error("transaction error: {0}")]
    Transaction(String),

    /// Retention cleanup failure.
    #[error("retention execution error: {0}")]
    Retention(String),

    /// Operating system I/O error (e.g. data directory creation).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
