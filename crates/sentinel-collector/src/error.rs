//! Error types for the SentinelX telemetry collection subsystem.

use sentinel_core::error::DomainError;
use thiserror::Error;

/// Errors that can occur during telemetry collection, normalization, and scheduling.
#[derive(Debug, Error)]
pub enum CollectorError {
    /// The target platform is not supported for native telemetry collection.
    #[error("unsupported operating system for native collection: {0}")]
    UnsupportedPlatform(String),

    /// A native operating system API call returned a failure status code.
    #[error("native API failure: error code {code} (0x{code:08X}) - {message}")]
    NativeApiFailure {
        /// Native error code returned by the OS (e.g., Win32 WIN32_ERROR).
        code: u32,
        /// Human-readable explanation of the error.
        message: String,
    },

    /// Buffer allocation for native table retrieval failed or exceeded limits.
    #[error("failed to allocate buffer for native table: requested {requested_bytes} bytes")]
    BufferAllocationFailure {
        /// Number of bytes requested.
        requested_bytes: usize,
    },

    /// The native table data returned by the OS was malformed or corrupted.
    #[error("invalid native table data: {0}")]
    InvalidTableData(String),

    /// The specified polling configuration or interval is invalid.
    #[error("invalid polling configuration: {reason}")]
    InvalidPollingInterval {
        /// Explanation of why the interval was rejected.
        reason: String,
    },

    /// Normalization of a native or raw record into a domain event failed.
    #[error("record normalization failure: {0}")]
    NormalizationFailed(String),

    /// Controlled failure injected by a mock or simulated collector during tests.
    #[error("mock collector simulated failure: {0}")]
    MockFailure(String),

    /// Collector is uninitialized or in standby state.
    #[error("collector uninitialized or in standby: {0}")]
    Uninitialized(String),

    /// Domain invariant failure during event creation.
    #[error("domain invariant violation: {0}")]
    Domain(#[from] DomainError),
}
