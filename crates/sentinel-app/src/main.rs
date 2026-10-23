//! SentinelX Command-Line Demonstration Application.
//!
//! Demonstrates the Phase 1 analytical pipeline using deterministic synthetic telemetry.
//!
//! # Operational Notice
//! **ALL INPUT DATA IS SYNTHETIC FOR DEMONSTRATION PURPOSES.**
//! No real network traffic is collected, captured, or transmitted.
//! Administrator privileges are neither required nor requested.

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use sentinel_core::config::DetectionConfig;
use sentinel_core::event::{NetworkEvent, NetworkEventBuilder, NetworkProtocol, TelemetrySource};
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::PortScanRule;
use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Generates a deterministic synthetic demonstration dataset representing diverse network patterns.
///
/// Uses standard documentation-only IP prefixes (RFC 5737):
/// - `192.0.2.0/24` (TEST-NET-1)
/// - `198.51.100.0/24` (TEST-NET-2)
fn generate_synthetic_dataset() -> Result<Vec<NetworkEvent>> {
    let now = Utc::now();
    let mut events = Vec::new();

    // Host A (Scanner): 192.0.2.10 sweeps 12 distinct common service ports
    let scanner_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let sweep_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080];
    for (i, &dest_port) in sweep_ports.iter().enumerate() {
        let event = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now + Duration::milliseconds((i * 150) as i64),
        )
        .with_source_ip(scanner_ip)
        .with_source_port(49152 + (i as u16))
        .with_destination_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        .with_destination_port(dest_port)
        .build()
        .context("failed building scanner synthetic event")?;
        events.push(event);
    }

    // Host B (Repeated Poller): 198.51.100.25 polls port 443 repeatedly (12 times)
    let poller_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25));
    for i in 0..12 {
        let event = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now + Duration::milliseconds(2000 + (i * 200) as i64),
        )
        .with_source_ip(poller_ip)
        .with_source_port(51000 + (i as u16))
        .with_destination_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        .with_destination_port(443)
        .build()
        .context("failed building poller synthetic event")?;
        events.push(event);
    }

    // Host C (Normal Web Client): 192.0.2.50 connects to ports 80 and 443
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    for (i, &port) in [80, 443].iter().enumerate() {
        let event = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now + Duration::milliseconds(5000 + (i * 300) as i64),
        )
        .with_source_ip(client_ip)
        .with_source_port(52000 + (i as u16))
        .with_destination_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)))
        .with_destination_port(port)
        .build()
        .context("failed building web client synthetic event")?;
        events.push(event);
    }

    // Host D (Partial Telemetry): Incomplete events with missing optional fields
    let partial_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    let partial_event_1 = NetworkEventBuilder::new(
        TelemetrySource::SyntheticSimulator,
        NetworkProtocol::Tcp,
        now + Duration::milliseconds(6000),
    )
    .with_source_ip(partial_ip)
    // Destination port is intentionally omitted (None)
    .build()
    .context("failed building partial event 1")?;
    events.push(partial_event_1);

    let partial_event_2 = NetworkEventBuilder::new(
        TelemetrySource::SyntheticSimulator,
        NetworkProtocol::Udp,
        now + Duration::milliseconds(6500),
    )
    // Source IP is intentionally omitted (None)
    .with_destination_port(53)
    .build()
    .context("failed building partial event 2")?;
    events.push(partial_event_2);

    Ok(events)
}

/// Initializes structured console logging with environment filter support (`RUST_LOG`).
fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

fn run() -> Result<()> {
    init_logging();

    println!("================================================================================");
    println!("                           SENTINELX DEFENSIVE MONITOR                          ");
    println!("                Phase 1: Foundation and Domain Model Demonstration              ");
    println!("================================================================================");
    println!(" Operational Notice:");
    println!(" * ALL INPUT DATA IS ENTIRELY SYNTHETIC FOR DEMONSTRATION PURPOSES.");
    println!(" * Documentation test address ranges (192.0.2.0/24, 198.51.100.0/24) are used.");
    println!(" * No real network sockets are monitored; administrator rights are not needed.");
    println!("================================================================================\n");

    info!("Initializing SentinelX detection engine with demonstration configuration...");

    // Demonstration configuration:
    // Threshold set to 5 distinct destination ports to showcase alert triggers.
    let mut config = DetectionConfig::default();
    config.distinct_port_threshold = 5;
    config.max_evidence_ids_per_alert = 20;

    let rule =
        PortScanRule::new(config.clone()).context("failed to initialize PortScanRule NET-001")?;
    let engine = DetectionEngine::new(config)
        .context("failed to initialize DetectionEngine")?
        .with_rule(Box::new(rule));

    info!("Generating deterministic synthetic network connection observations...");
    let events =
        generate_synthetic_dataset().context("failed to generate synthetic telemetry dataset")?;
    let total_observations = events.len();
    info!(
        total_observations,
        "Synthetic dataset generated successfully"
    );

    info!("Executing detection engine across event batch...");
    let alerts = engine
        .process_batch(&events)
        .context("detection engine batch processing failed")?;
    let total_alerts = alerts.len();
    info!(total_alerts, "Batch processing complete");

    println!("\n--------------------------------------------------------------------------------");
    println!("                              EXECUTION SUMMARY                                 ");
    println!("--------------------------------------------------------------------------------");
    println!("Total observations processed : {total_observations}");
    println!("Total security alerts emitted: {total_alerts}");
    println!("--------------------------------------------------------------------------------\n");

    if alerts.is_empty() {
        println!("No security alerts were generated for the current observation batch.");
    } else {
        println!("Generated Security Alerts:");
        for (idx, alert) in alerts.iter().enumerate() {
            let alert_num = idx + 1;
            println!("\n[Alert #{alert_num}]");
            println!("  Alert ID           : {}", alert.id);
            println!("  Rule ID            : {}", alert.rule_id);
            println!("  Severity           : {}", alert.severity);
            println!("  Title              : {}", alert.title);
            let src_str = alert
                .source_ip
                .map_or_else(|| "Unknown".to_string(), |ip| ip.to_string());
            println!("  Source Address     : {src_str}");
            println!("  Supporting Events  : {}", alert.observation_count);
            println!("  Evidence IDs Count : {}", alert.evidence_event_ids.len());
            println!(
                "  Time Range (UTC)   : {} -> {}",
                alert.first_observed_at, alert.last_observed_at
            );
            println!("  Triage Status      : {}", alert.status);
            println!("  Explanation        :\n    {}", alert.explanation);
        }
    }

    println!("\n================================================================================");
    println!(" Demonstration completed successfully without errors.");
    println!("================================================================================");

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("\n[FATAL ERROR]: {err:?}");
            ExitCode::FAILURE
        }
    }
}
