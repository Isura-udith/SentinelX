//! Telemetry collection scheduling, detection engine integration, and graceful shutdown orchestration.

use anyhow::{Context, Result, bail};
use sentinel_collector::error::CollectorError;
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_collector::source::{CollectionBatch, StandbyCollector, TelemetryCollector};
use sentinel_collector::stats::CollectionStats;
use sentinel_collector::windows_tcp::WindowsTcpCollector;
use sentinel_core::alert::SecurityAlert;
use sentinel_detection::engine::DetectionEngine;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};

/// Minimum allowed polling interval to prevent excessive CPU / API thrashing.
pub const MIN_POLLING_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum allowed polling interval (1 hour).
pub const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(3600);

/// Telemetry collection source mode.
#[derive(Debug, Clone)]
pub enum CollectorMode {
    /// Live native Windows IP Helper TCP table snapshot (`GetExtendedTcpTable`).
    LiveWindowsTcp,
    /// Deterministic mock collector with designated scenario.
    Mock(MockScenario),
}

/// Configuration settings governing the telemetry scheduling loop.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Polling interval between snapshot collection cycles.
    pub polling_interval: Duration,
    /// Maximum number of collection cycles to execute before terminating (None = run indefinitely).
    pub max_cycles: Option<usize>,
    /// Source mode (Live Windows TCP table or Mock).
    pub mode: CollectorMode,
}

impl SchedulerConfig {
    /// Constructs a validated [`SchedulerConfig`].
    ///
    /// # Errors
    /// Returns an error if the polling interval is less than 100ms or greater than 1 hour.
    pub fn new(
        polling_interval: Duration,
        max_cycles: Option<usize>,
        mode: CollectorMode,
    ) -> Result<Self> {
        if polling_interval < MIN_POLLING_INTERVAL {
            bail!(
                "Polling interval {polling_interval:?} is too short (minimum allowed: {MIN_POLLING_INTERVAL:?})"
            );
        }
        if polling_interval > MAX_POLLING_INTERVAL {
            bail!(
                "Polling interval {polling_interval:?} exceeds maximum allowed limit of {MAX_POLLING_INTERVAL:?}"
            );
        }
        Ok(Self {
            polling_interval,
            max_cycles,
            mode,
        })
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            polling_interval: Duration::from_secs(2),
            max_cycles: Some(3), // Default demo runs 3 cycles
            mode: CollectorMode::LiveWindowsTcp,
        }
    }
}

/// Orchestrates repeated telemetry collection cycles, passes normalized observations to the
/// detection engine, records runtime statistics, and supports clean cancellation.
pub struct TelemetryScheduler {
    config: SchedulerConfig,
    engine: DetectionEngine,
    collector: Box<dyn TelemetryCollector>,
    stats: CollectionStats,
    shutdown_flag: Arc<AtomicBool>,
}

impl TelemetryScheduler {
    /// Initializes a new scheduler with the designated configuration and detection engine.
    ///
    /// # Errors
    /// Returns an error if configuration validation fails.
    pub fn new(config: SchedulerConfig, engine: DetectionEngine) -> Result<Self> {
        let collector: Box<dyn TelemetryCollector> = match &config.mode {
            CollectorMode::LiveWindowsTcp => Box::new(WindowsTcpCollector::new()),
            CollectorMode::Mock(scenario) => Box::new(MockCollector::for_scenario(scenario)),
        };

        Ok(Self {
            config,
            engine,
            collector,
            stats: CollectionStats::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Returns a handle that can be used to trigger graceful cancellation from another task or signal handler.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_flag)
    }

    /// Returns a reference to the accumulated collection statistics.
    #[must_use]
    pub const fn stats(&self) -> &CollectionStats {
        &self.stats
    }

    /// Executes the collection loop until `max_cycles` is reached or cancellation is requested.
    ///
    /// The blocking native Windows API call is dispatched using [`tokio::task::spawn_blocking`]
    /// so the Tokio async executor thread pool is never stalled.
    pub async fn run(&mut self) -> Result<Vec<SecurityAlert>> {
        info!(
            interval = ?self.config.polling_interval,
            max_cycles = ?self.config.max_cycles,
            collector = %self.collector.name(),
            "Starting SentinelX telemetry collection loop"
        );

        let mut interval_timer = tokio::time::interval(self.config.polling_interval);
        // Ensure initial tick does not execute immediately before configuration is ready:
        interval_timer.tick().await;

        let mut accumulated_alerts = Vec::new();
        let mut cycle = 0;

        loop {
            // Check shutdown signal:
            if self.shutdown_flag.load(Ordering::Relaxed) {
                info!("Shutdown signal received; exiting collection loop");
                break;
            }

            cycle += 1;
            info!(cycle, "--- Starting telemetry collection cycle ---");

            // Execute collection in a blocking task to prevent stalling Tokio runtime worker threads:
            // We take temporary ownership of the collector box across the blocking boundary.
            let mut collector = std::mem::replace(&mut self.collector, Box::new(StandbyCollector));
            let collection_start = std::time::Instant::now();

            let collection_result: Result<CollectionBatch, CollectorError> =
                tokio::task::spawn_blocking(move || {
                    let res = collector.collect();
                    (res, collector)
                })
                .await
                .map(|(res, returned_collector)| {
                    self.collector = returned_collector;
                    res
                })
                .context("tokio worker thread panicked during native collection")?;

            let cycle_duration = collection_start.elapsed();

            match collection_result {
                Ok(batch) => {
                    self.stats.record_success(
                        batch.metadata.raw_records_observed,
                        batch.metadata.normalized_events_produced,
                        batch.metadata.records_skipped,
                        batch.metadata.duration,
                    );

                    info!(
                        raw = batch.metadata.raw_records_observed,
                        normalized = batch.metadata.normalized_events_produced,
                        skipped = batch.metadata.records_skipped,
                        duration = ?batch.metadata.duration,
                        "Telemetry snapshot collected successfully"
                    );

                    // Pass normalized events into detection engine:
                    match self.engine.process_batch(&batch.events) {
                        Ok(mut alerts) => {
                            let alert_count = alerts.len();
                            self.stats.record_alerts(alert_count);

                            if alert_count > 0 {
                                warn!(alert_count, "Security alerts generated during cycle");
                                accumulated_alerts.append(&mut alerts);
                            } else {
                                info!("No security alerts generated during cycle");
                            }
                        }
                        Err(engine_err) => {
                            error!(
                                ?engine_err,
                                "Detection engine failed evaluating event batch"
                            );
                        }
                    }
                }
                Err(err) => {
                    self.stats.record_failure(cycle_duration);
                    warn!(?err, "Telemetry collection cycle failed; applying backoff");
                }
            }

            // Check if finite cycle count reached:
            if self.config.max_cycles.is_some_and(|max| cycle >= max) {
                let max = self.config.max_cycles.unwrap_or(0);
                info!(cycle, max, "Configured maximum collection cycles completed");
                break;
            }

            // Wait for next timer tick or cancellation:
            tokio::select! {
                _ = interval_timer.tick() => {}
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C detected; initiating graceful shutdown");
                    self.shutdown_flag.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }

        info!("Collection scheduler completed all cycles");
        Ok(accumulated_alerts)
    }
}
