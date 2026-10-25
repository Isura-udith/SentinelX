//! Application error types and frontend boundary mappings.

use serde::Serialize;
use thiserror::Error;

/// Frontend-safe error representation.
#[derive(Debug, Error, Serialize)]
#[serde(tag = "type", content = "message")]
pub enum AppError {
    /// Validation error when user input fails constraints.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Entity requested was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Database or storage error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Telemetry collector or pipeline error.
    #[error("Collector error: {0}")]
    Collector(String),

    /// Detection engine or rule error.
    #[error("Detection error: {0}")]
    Detection(String),

    /// Internal application failure.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sentinel_storage::StorageError> for AppError {
    fn from(err: sentinel_storage::StorageError) -> Self {
        match err {
            sentinel_storage::StorageError::RecordNotFound(msg) => Self::NotFound(msg),
            sentinel_storage::StorageError::InvalidParameter(msg) => Self::Validation(msg),
            sentinel_storage::StorageError::InvalidStatusTransition { from, to } => {
                Self::Validation(format!("Invalid status transition from {from:?} to {to:?}"))
            }
            sentinel_storage::StorageError::Domain(e) => Self::Validation(e.to_string()),
            sentinel_storage::StorageError::ConstraintViolation(msg) => Self::Validation(msg),
            sentinel_storage::StorageError::Database(ref e) => {
                tracing::error!(error = %e, "Internal database error occurred");
                Self::Storage(
                    "A database error occurred. See diagnostic logs for details.".to_string(),
                )
            }
            sentinel_storage::StorageError::Io(ref e) => {
                tracing::error!(error = %e, "Internal storage I/O error occurred");
                Self::Storage(
                    "A storage filesystem I/O error occurred. See diagnostic logs for details."
                        .to_string(),
                )
            }
            other => {
                tracing::error!(error = %other, "Storage subsystem error occurred");
                Self::Storage(
                    "A storage error occurred. See diagnostic logs for details.".to_string(),
                )
            }
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!(error = %err, "Internal application error occurred");
        Self::Internal(
            "An unexpected internal application error occurred. See diagnostic logs for details."
                .to_string(),
        )
    }
}
