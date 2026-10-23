//! Persistent storage, database migrations, transactional repositories,
//! and data retention management for SentinelX.
//!
//! # Architecture & Defensive Design
//! SentinelX uses an embedded SQLite database as its local persistence layer.
//! The storage subsystem is strictly decoupled from telemetry collection and analytical detection rules:
//! - **Decoupled Repositories**: Detection rules never issue direct SQL queries. Storage operations
//!   are mediated exclusively via strongly typed repositories ([`EventRepository`], [`AlertRepository`],
//!   [`AuditLogRepository`], and [`RetentionManager`]).
//! - **Transactional Safety**: Telemetry batches and alert correlation updates execute inside ACID transactions.
//! - **Evidence Preservation**: Network events referenced as supporting evidence in [`AlertRepository`]
//!   are preserved across retention cycles to protect forensic integrity.
//! - **WAL Mode & Busy Timeout**: Embedded SQLite connections are configured with Write-Ahead Logging (WAL)
//!   and a 5-second busy timeout to maximize concurrent read/write throughput without blocking.

pub mod alerts;
pub mod audit;
pub mod database;
pub mod error;
pub mod events;
pub mod retention;

pub use alerts::{
    AlertCorrelationCandidate, AlertQueryFilter, AlertRepository, CorrelationOutcome,
    PersistedAlert,
};
pub use audit::{AuditEntry, AuditLogRepository, AuditQueryFilter};
pub use database::{Database, DatabaseConfig};
pub use error::StorageError;
pub use events::{BatchInsertResult, EventQueryFilter, EventRepository, PersistedEvent};
pub use retention::{RetentionManager, RetentionPolicy, RetentionReport};
