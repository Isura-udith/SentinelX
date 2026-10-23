//! # SentinelX Core
//!
//! `sentinel-core` defines the foundational domain models, strongly typed identifiers,
//! protocol enumerations, security alert schemas, configuration policies, and domain
//! error types for SentinelX.
//!
//! ## Architectural Boundaries
//! This crate is intentionally decoupled from concrete I/O, database systems, Windows
//! API calls, network capture interfaces, or user-interface frameworks. It provides a pure,
//! deterministic foundation that higher-level crates (`sentinel-detection`, collectors,
//! persistence layers, and client dashboards) can rely upon without cyclic dependencies.
//!
//! ## Modules
//! - [`event`]: Network connection snapshots, protocols, metadata, and event identifiers.
//! - [`alert`]: Security alerts, severity scales, lifecycle statuses, and rule identifiers.
//! - [`config`]: Detection configurations and threshold validation.
//! - [`error`]: Domain error types and invariant failure definitions.

pub mod alert;
pub mod config;
pub mod error;
pub mod event;

pub use alert::{AlertId, AlertSeverity, AlertStatus, RuleId, SecurityAlert, SecurityAlertBuilder};
pub use config::DetectionConfig;
pub use error::{ConfigError, DomainError};
pub use event::{
    EventId, EventMetadata, NetworkEvent, NetworkEventBuilder, NetworkProtocol, ProcessId,
    TelemetrySource,
};
