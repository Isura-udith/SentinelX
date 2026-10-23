//! Collection statistics tracking for the telemetry subsystem.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Comprehensive runtime statistics tracking telemetry collection cycles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionStats {
    /// Total number of collection attempts initiated.
    pub total_attempts: u64,
    /// Number of collection cycles that completed successfully.
    pub successful_cycles: u64,
    /// Number of collection cycles that encountered fatal errors.
    pub failed_cycles: u64,
    /// Total raw socket / connection records observed across all cycles.
    pub raw_records_observed: u64,
    /// Total normalized [`sentinel_core::NetworkEvent`] instances produced.
    pub normalized_events_produced: u64,
    /// Total records skipped during normalization (e.g. listening sockets, reserved ports).
    pub records_skipped: u64,
    /// Total security alerts generated from collected events.
    pub alerts_generated: u64,
    /// Timestamp of the last successful collection cycle.
    pub last_successful_at: Option<DateTime<Utc>>,
    /// Duration of the most recently executed collection cycle.
    pub most_recent_duration: Option<Duration>,
}

impl CollectionStats {
    /// Creates a new, zeroed statistics tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the successful completion of a collection cycle.
    pub fn record_success(
        &mut self,
        raw_observed: usize,
        events_produced: usize,
        skipped: usize,
        duration: Duration,
    ) {
        self.total_attempts = self.total_attempts.saturating_add(1);
        self.successful_cycles = self.successful_cycles.saturating_add(1);
        self.raw_records_observed = self
            .raw_records_observed
            .saturating_add(raw_observed as u64);
        self.normalized_events_produced = self
            .normalized_events_produced
            .saturating_add(events_produced as u64);
        self.records_skipped = self.records_skipped.saturating_add(skipped as u64);
        self.last_successful_at = Some(Utc::now());
        self.most_recent_duration = Some(duration);
    }

    /// Records a failed collection attempt.
    pub fn record_failure(&mut self, duration: Duration) {
        self.total_attempts = self.total_attempts.saturating_add(1);
        self.failed_cycles = self.failed_cycles.saturating_add(1);
        self.most_recent_duration = Some(duration);
    }

    /// Records alerts generated from evaluated batches.
    pub fn record_alerts(&mut self, alert_count: usize) {
        self.alerts_generated = self.alerts_generated.saturating_add(alert_count as u64);
    }
}

impl fmt::Display for CollectionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Collection Statistics:")?;
        writeln!(f, "  Total Cycles Attempted   : {}", self.total_attempts)?;
        writeln!(f, "  Successful Cycles        : {}", self.successful_cycles)?;
        writeln!(f, "  Failed Cycles            : {}", self.failed_cycles)?;
        writeln!(
            f,
            "  Raw Records Observed     : {}",
            self.raw_records_observed
        )?;
        writeln!(
            f,
            "  Normalized Events        : {}",
            self.normalized_events_produced
        )?;
        writeln!(f, "  Records Skipped          : {}", self.records_skipped)?;
        writeln!(f, "  Security Alerts Emitted  : {}", self.alerts_generated)?;
        let last_time = self
            .last_successful_at
            .map_or_else(|| "Never".to_string(), |t| t.to_rfc3339());
        writeln!(f, "  Last Successful Cycle    : {last_time}")?;
        let duration_str = self
            .most_recent_duration
            .map_or_else(|| "N/A".to_string(), |d| format!("{d:?}"));
        write!(f, "  Most Recent Cycle Latency: {duration_str}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_recording() {
        let mut stats = CollectionStats::new();
        assert_eq!(stats.total_attempts, 0);

        stats.record_success(100, 80, 20, Duration::from_millis(15));
        assert_eq!(stats.total_attempts, 1);
        assert_eq!(stats.successful_cycles, 1);
        assert_eq!(stats.failed_cycles, 0);
        assert_eq!(stats.raw_records_observed, 100);
        assert_eq!(stats.normalized_events_produced, 80);
        assert_eq!(stats.records_skipped, 20);
        assert!(stats.last_successful_at.is_some());
        assert_eq!(stats.most_recent_duration, Some(Duration::from_millis(15)));

        stats.record_failure(Duration::from_millis(5));
        assert_eq!(stats.total_attempts, 2);
        assert_eq!(stats.successful_cycles, 1);
        assert_eq!(stats.failed_cycles, 1);

        stats.record_alerts(3);
        assert_eq!(stats.alerts_generated, 3);
    }
}
