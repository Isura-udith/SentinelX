//! Deterministic mock telemetry collector for development and automated testing.

use crate::error::CollectorError;
use crate::normalize::{RawTcpRecord, TcpState, normalize_batch};
use crate::source::{CollectionBatch, CollectionMetadata, TelemetryCollector};
use chrono::Utc;
use sentinel_core::event::TelemetrySource;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Pre-configured traffic patterns for deterministic mock testing.
#[derive(Debug, Clone)]
pub enum MockScenario {
    /// Simulates a single source contacting multiple distinct remote TCP ports (port sweep).
    PortSweep {
        /// Source IP performing the sweep.
        scanner_ip: IpAddr,
        /// Remote destination ports swept.
        ports: Vec<u16>,
    },

    /// Simulates repeated connections from a single source to the same remote port (deduplication test).
    RepeatedPort {
        /// Source IP polling the port.
        source_ip: IpAddr,
        /// Single destination port targeted repeatedly.
        target_port: u16,
        /// Number of duplicate connections.
        count: usize,
    },

    /// Simulates ordinary established web client connections.
    NormalTraffic,

    /// Simulates mixed telemetry containing scanners, pollers, listening sockets, and IPv6 endpoints.
    Mixed,

    /// Produces an empty snapshot (zero records observed).
    Empty,

    /// Injects an explicit list of raw records.
    Custom(Vec<RawTcpRecord>),
}

/// A deterministic collector implementation that produces pre-configured or queued records
/// without generating any real network traffic.
#[derive(Debug)]
pub struct MockCollector {
    name: String,
    source: TelemetrySource,
    queued_batches: VecDeque<Vec<RawTcpRecord>>,
    fail_next: Option<String>,
}

impl MockCollector {
    /// Creates a [`MockCollector`] configured for a single scenario.
    #[must_use]
    pub fn for_scenario(scenario: &MockScenario) -> Self {
        let records = Self::build_scenario_records(scenario);
        let mut queued = VecDeque::new();
        queued.push_back(records);
        Self {
            name: "MockCollector".to_string(),
            source: TelemetrySource::SyntheticSimulator,
            queued_batches: queued,
            fail_next: None,
        }
    }

    /// Creates a [`MockCollector`] with an explicit sequence of batches for multi-cycle polling tests.
    #[must_use]
    pub fn for_sequence(batches: Vec<Vec<RawTcpRecord>>) -> Self {
        Self {
            name: "MockSequenceCollector".to_string(),
            source: TelemetrySource::SyntheticSimulator,
            queued_batches: VecDeque::from(batches),
            fail_next: None,
        }
    }

    /// Creates an empty mock collector.
    #[must_use]
    pub fn new() -> Self {
        Self::for_scenario(&MockScenario::Empty)
    }

    /// Queues a controlled failure on the next collection attempt.
    pub fn inject_failure(&mut self, message: impl Into<String>) {
        self.fail_next = Some(message.into());
    }

    /// Adds a batch of raw records to the collection queue.
    pub fn enqueue_batch(&mut self, batch: Vec<RawTcpRecord>) {
        self.queued_batches.push_back(batch);
    }

    /// Generates raw test records corresponding to a designated scenario.
    #[must_use]
    pub fn build_scenario_records(scenario: &MockScenario) -> Vec<RawTcpRecord> {
        match scenario {
            MockScenario::PortSweep { scanner_ip, ports } => ports
                .iter()
                .enumerate()
                .map(|(i, &port)| RawTcpRecord {
                    local_addr: *scanner_ip,
                    local_port: 50000 + (i as u16),
                    remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                    remote_port: port,
                    state: TcpState::SynSent,
                    owning_pid: Some(4040),
                })
                .collect(),

            MockScenario::RepeatedPort {
                source_ip,
                target_port,
                count,
            } => (0..*count)
                .map(|i| RawTcpRecord {
                    local_addr: *source_ip,
                    local_port: 51000 + (i as u16),
                    remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                    remote_port: *target_port,
                    state: TcpState::Established,
                    owning_pid: Some(5050),
                })
                .collect(),

            MockScenario::NormalTraffic => vec![
                RawTcpRecord {
                    local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                    local_port: 52001,
                    remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                    remote_port: 80,
                    state: TcpState::Established,
                    owning_pid: Some(1111),
                },
                RawTcpRecord {
                    local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                    local_port: 52002,
                    remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                    remote_port: 443,
                    state: TcpState::Established,
                    owning_pid: Some(1111),
                },
            ],

            MockScenario::Mixed => {
                let mut records = Vec::new();
                // 1. Scanner host (192.0.2.10) sweeping 6 ports:
                for (i, &port) in [22, 80, 443, 8080, 8443, 9000].iter().enumerate() {
                    records.push(RawTcpRecord {
                        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                        local_port: 53000 + (i as u16),
                        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                        remote_port: port,
                        state: TcpState::Established,
                        owning_pid: Some(2222),
                    });
                }
                // 2. Poller host (198.51.100.25) repeating port 443:
                for i in 0..8 {
                    records.push(RawTcpRecord {
                        local_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)),
                        local_port: 54000 + (i as u16),
                        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)),
                        remote_port: 443,
                        state: TcpState::Established,
                        owning_pid: Some(3333),
                    });
                }
                // 3. Listening socket (to verify skipped record counting):
                records.push(RawTcpRecord {
                    local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    local_port: 8080,
                    remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    remote_port: 0,
                    state: TcpState::Listen,
                    owning_pid: Some(4),
                });
                // 4. IPv6 established connection:
                records.push(RawTcpRecord {
                    local_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    local_port: 55555,
                    remote_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    remote_port: 443,
                    state: TcpState::Established,
                    owning_pid: None, // Missing optional PID
                });
                records
            }

            MockScenario::Empty => Vec::new(),
            MockScenario::Custom(records) => records.clone(),
        }
    }
}

impl Default for MockCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryCollector for MockCollector {
    fn name(&self) -> &str {
        &self.name
    }

    fn source(&self) -> TelemetrySource {
        self.source
    }

    fn collect(&mut self) -> Result<CollectionBatch, CollectorError> {
        let start_instant = Instant::now();
        let start_time = Utc::now();

        // Check if a controlled failure was injected:
        if let Some(msg) = self.fail_next.take() {
            return Err(CollectorError::MockFailure(msg));
        }

        // Dequeue next batch, or return an empty batch if queue is exhausted:
        let raw_records = self.queued_batches.pop_front().unwrap_or_default();
        let raw_count = raw_records.len();

        let (events, skipped) = normalize_batch(raw_records, self.source, start_time);
        let normalized_count = events.len();
        let skipped_count = skipped.len();
        let skip_reasons = skipped.into_iter().map(|(_, reason)| reason).collect();

        let end_time = Utc::now();
        let duration = start_instant.elapsed();

        let metadata = CollectionMetadata {
            start_time,
            end_time,
            duration,
            raw_records_observed: raw_count,
            normalized_events_produced: normalized_count,
            records_skipped: skipped_count,
            skip_reasons,
        };

        Ok(CollectionBatch::new(events, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_port_sweep_scenario() {
        let scanner_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        let ports = vec![21, 22, 80, 443, 8080];
        let mut collector = MockCollector::for_scenario(&MockScenario::PortSweep {
            scanner_ip,
            ports: ports.clone(),
        });

        let batch = collector.collect().expect("collection succeeds");
        assert_eq!(batch.metadata.raw_records_observed, 5);
        assert_eq!(batch.metadata.normalized_events_produced, 5);
        assert_eq!(batch.metadata.records_skipped, 0);
        assert_eq!(batch.events.len(), 5);
        assert_eq!(batch.events[0].source_ip, Some(scanner_ip));
    }

    #[test]
    fn test_mock_mixed_scenario_skips_listening() {
        let mut collector = MockCollector::for_scenario(&MockScenario::Mixed);
        let batch = collector.collect().expect("collection succeeds");

        // Mixed contains: 6 scanner + 8 poller + 1 listen + 1 ipv6 = 16 raw records
        assert_eq!(batch.metadata.raw_records_observed, 16);
        // The 1 listening socket must be skipped
        assert_eq!(batch.metadata.records_skipped, 1);
        assert_eq!(batch.metadata.normalized_events_produced, 15);
    }

    #[test]
    fn test_mock_injected_failure() {
        let mut collector = MockCollector::new();
        collector.inject_failure("simulated network collector fault");

        let result = collector.collect();
        assert!(matches!(result, Err(CollectorError::MockFailure(msg)) if msg.contains("fault")));

        // After failure is consumed, subsequent call returns empty batch normally:
        let second_result = collector.collect();
        assert!(second_result.is_ok());
    }

    #[test]
    fn test_mock_sequence_progression() {
        let batch1 = vec![RawTcpRecord {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            local_port: 50001,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            remote_port: 80,
            state: TcpState::Established,
            owning_pid: Some(10),
        }];
        let batch2 = vec![];

        let mut collector = MockCollector::for_sequence(vec![batch1, batch2]);

        let res1 = collector.collect().expect("batch 1 succeeds");
        assert_eq!(res1.events.len(), 1);

        let res2 = collector.collect().expect("batch 2 succeeds");
        assert_eq!(res2.events.len(), 0);
    }
}
