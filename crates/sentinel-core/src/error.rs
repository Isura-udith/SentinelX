//! Domain errors for SentinelX core models and configurations.

use std::fmt;
use thiserror::Error;

/// Domain error representing validation or invariant violations across the core domain model.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    /// Provided event ID string was malformed or empty.
    #[error("invalid event ID: {0}")]
    InvalidEventId(String),

    /// Provided alert ID string was malformed or empty.
    #[error("invalid alert ID: {0}")]
    InvalidAlertId(String),

    /// Provided rule ID was empty or blank.
    #[error("invalid rule ID: rule ID cannot be empty or whitespace")]
    EmptyRuleId,

    /// Port number is invalid (e.g., port 0 is reserved and invalid in normal TCP/UDP communication).
    #[error("invalid port: port 0 is reserved and not allowed for connection observations")]
    InvalidPort,

    /// Process ID exceeds the valid system range.
    #[error("invalid process ID: {0} exceeds valid operating system limit")]
    InvalidProcessId(u32),

    /// Observation timestamp is in the future beyond acceptable clock drift.
    #[error("invalid timestamp: observation timestamp {timestamp} is in the future")]
    FutureTimestamp {
        /// The timestamp that was rejected.
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Metadata entry exceeds maximum permissible key or value length.
    #[error(
        "metadata entry length exceeded: key '{key}' ({key_len} bytes) or value ({val_len} bytes) exceeds limit"
    )]
    MetadataEntryTooLong {
        /// Metadata key that was rejected.
        key: String,
        /// Length of the key in bytes.
        key_len: usize,
        /// Length of the value in bytes.
        val_len: usize,
    },

    /// Metadata exceeds maximum number of allowed key-value entries.
    #[error("metadata entry count {count} exceeds maximum allowed limit of {max}")]
    MetadataTooManyEntries {
        /// Number of entries provided.
        count: usize,
        /// Maximum allowed entries.
        max: usize,
    },

    /// Alert observation time range is inverted (first observed is after last observed).
    #[error("invalid alert time range: first observed ({first}) is after last observed ({last})")]
    InvertedAlertTimeRange {
        /// First observation timestamp.
        first: chrono::DateTime<chrono::Utc>,
        /// Last observation timestamp.
        last: chrono::DateTime<chrono::Utc>,
    },

    /// Alert title was empty or blank.
    #[error("invalid alert title: title cannot be empty or whitespace")]
    EmptyAlertTitle,

    /// Alert explanation was empty or blank.
    #[error("invalid alert explanation: explanation cannot be empty or whitespace")]
    EmptyAlertExplanation,

    /// Alert was constructed without any supporting evidence event IDs.
    #[error("invalid alert: at least one evidence event ID must be provided")]
    EmptyAlertEvidence,

    /// Observation count is lower than the number of supporting evidence IDs.
    #[error("observation count {count} is less than evidence count {evidence_count}")]
    ObservationCountMismatch {
        /// Total observation count.
        count: usize,
        /// Evidence event count.
        evidence_count: usize,
    },

    /// Nested configuration error.
    #[error("configuration error: {0}")]
    Configuration(#[from] ConfigError),
}

/// Errors occurring during detection configuration validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Distinct port threshold is zero.
    #[error("distinct port threshold must be greater than zero")]
    ZeroPortThreshold,

    /// Observation window duration is zero or negative.
    #[error("observation window duration must be strictly positive")]
    ZeroWindowDuration,

    /// Maximum batch size is zero.
    #[error("maximum batch size must be greater than zero")]
    ZeroBatchSize,

    /// Maximum evidence IDs per alert is zero.
    #[error("maximum evidence IDs per alert must be greater than zero")]
    ZeroMaxEvidenceIds,

    /// Threshold arithmetic overflowed.
    #[error("arithmetic overflow while calculating threshold: {description}")]
    ThresholdOverflow {
        /// Description of the threshold calculation that overflowed.
        description: &'static str,
    },
}

impl fmt::Display for ConfigErrorSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Helper wrapper for formatted error display where needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrorSummary(pub String);
