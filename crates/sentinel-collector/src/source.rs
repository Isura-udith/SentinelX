//! Telemetry collector trait definition and collection batch metadata.

use crate::error::CollectorError;
use crate::normalize::SkipReason;
use chrono::{DateTime, Utc};
use sentinel_core::event::{NetworkEvent, TelemetrySource};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Metadata describing the execution performance and yield of a single collection cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionMetadata {
    /// UTC timestamp when collection started.
    pub start_time: DateTime<Utc>,
    /// UTC timestamp when collection and normalization completed.
    pub end_time: DateTime<Utc>,
    /// Wall-clock latency of the collection cycle.
    pub duration: Duration,
    /// Total raw records observed from the platform collector.
    pub raw_records_observed: usize,
    /// Number of normalized [`NetworkEvent`] instances produced.
    pub normalized_events_produced: usize,
    /// Number of raw records skipped during normalization.
    pub records_skipped: usize,
    /// Summary of reasons for skipped records.
    pub skip_reasons: Vec<SkipReason>,
}

/// A batch of normalized events accompanied by execution metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionBatch {
    /// Normalized events ready for evaluation by the detection engine.
    pub events: Vec<NetworkEvent>,
    /// Metadata describing the collection cycle.
    pub metadata: CollectionMetadata,
}

impl CollectionBatch {
    /// Constructs a new [`CollectionBatch`].
    #[must_use]
    pub fn new(events: Vec<NetworkEvent>, metadata: CollectionMetadata) -> Self {
        Self { events, metadata }
    }
}

/// Abstract contract for telemetry collectors.
///
/// Implementations provide connection snapshot observations from either real operating system
/// APIs or simulated development fixtures.
pub trait TelemetryCollector: Send + Sync {
    /// Returns the human-readable display name of the collector.
    fn name(&self) -> &str;

    /// Returns the telemetry source identifier corresponding to this collector.
    fn source(&self) -> TelemetrySource;

    /// Executes a single collection snapshot cycle.
    ///
    /// # Errors
    /// Returns [`CollectorError`] if the underlying collection operation encounters an unrecoverable failure.
    fn collect(&mut self) -> Result<CollectionBatch, CollectorError>;
}

/// Standby collector placeholder used during internal thread ownership transfers.
/// Never produces synthetic telemetry.
#[derive(Debug, Default)]
pub struct StandbyCollector;

impl TelemetryCollector for StandbyCollector {
    fn name(&self) -> &'static str {
        "StandbyCollector"
    }

    fn source(&self) -> TelemetrySource {
        TelemetrySource::WindowsTcpSnapshot
    }

    fn collect(&mut self) -> Result<CollectionBatch, CollectorError> {
        Err(CollectorError::Uninitialized(
            "Standby collector cannot execute collection".to_string(),
        ))
    }
}

impl fmt::Display for CollectionMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Collection: {} raw -> {} normalized ({} skipped) in {:?}",
            self.raw_records_observed,
            self.normalized_events_produced,
            self.records_skipped,
            self.duration
        )
    }
}
