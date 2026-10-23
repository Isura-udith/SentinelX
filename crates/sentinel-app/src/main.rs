//! SentinelX Command-Line Application: Windows Telemetry & Detection Monitor.
//!
//! Demonstrates Phase 2 live Windows TCP snapshot telemetry collection, normalization,
//! asynchronous scheduling, and analytical rule evaluation.
//!
//! # Operational Notice
//! - Operates in **read-only mode** using user-mode Windows IP Helper APIs (`GetExtendedTcpTable`).
//! - Requires **no administrator privileges** and **no kernel drivers**.
//! - Modifies **no network configurations, firewall rules, or socket connections**.

pub mod telemetry;

use anyhow::{Context, Result};
use sentinel_collector::mock::MockScenario;
use sentinel_collector::stats::CollectionStats;
use sentinel_core::alert::SecurityAlert;
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::PortScanRule;
use std::process::ExitCode;
use std::time::Duration;
use telemetry::{CollectorMode, SchedulerConfig, TelemetryScheduler};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Parsed CLI configuration options.
#[derive(Debug, Clone)]
struct CliConfig {
    use_mock: bool,
    interval_ms: u64,
    max_cycles: Option<usize>,
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

/// Parses command line arguments, returning `None` if help was printed and the app should exit.
fn parse_cli_args(args: &[String]) -> Result<Option<CliConfig>> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("SentinelX Defensive Network Monitor - Phase 2");
        println!();
        println!("Usage: sentinel-app [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --mock               Run using deterministic in-memory mock collector");
        println!(
            "  --interval-ms <ms>   Polling interval in milliseconds [default: 1000] (min: 100, max: 3600000)"
        );
        println!(
            "  --max-cycles <num>   Maximum collection cycles to run before exiting [default: 3]"
        );
        println!("  --continuous         Run continuously until Ctrl+C is pressed");
        println!("  -h, --help           Show this help message");
        return Ok(None);
    }

    let mut interval_ms = 1000u64;
    let mut max_cycles = Some(3usize);
    let mut use_mock = !cfg!(target_os = "windows");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mock" => use_mock = true,
            "--continuous" => max_cycles = None,
            "--interval-ms" if i + 1 < args.len() => {
                interval_ms = args[i + 1]
                    .parse()
                    .context("invalid integer value for --interval-ms")?;
                i += 1;
            }
            "--max-cycles" if i + 1 < args.len() => {
                let parsed: usize = args[i + 1]
                    .parse()
                    .context("invalid integer value for --max-cycles")?;
                max_cycles = Some(parsed);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    Ok(Some(CliConfig {
        use_mock,
        interval_ms,
        max_cycles,
    }))
}

/// Prints operational startup banner and security disclosures.
fn print_banner(use_mock: bool) {
    println!("================================================================================");
    println!("                           SENTINELX DEFENSIVE MONITOR                          ");
    println!("             Phase 2: Windows 11 Telemetry Subsystem & Detection Engine         ");
    println!("================================================================================");
    println!(" Operational Notice:");
    if use_mock {
        println!(" * Telemetry Mode: DETERMINISTIC MOCK COLLECTOR (--mock or non-Windows host).");
        println!(" * Uses documentation test address ranges (192.0.2.0/24, 198.51.100.0/24).");
    } else {
        println!(" * Telemetry Mode: LIVE WINDOWS TCP SNAPSHOT (IP Helper API).");
        println!(" * Querying native host TCP table via GetExtendedTcpTable in read-only mode.");
    }
    println!(" * No administrator privileges required; standard user permissions sufficient.");
    println!(" * Network sockets are neither modified, redirected, nor terminated.");
    println!("================================================================================\n");
}

/// Prints diagnostic execution statistics and detected security alerts.
fn print_execution_summary(stats: &CollectionStats, alerts: &[SecurityAlert]) {
    println!("\n--------------------------------------------------------------------------------");
    println!("                              EXECUTION SUMMARY                                 ");
    println!("--------------------------------------------------------------------------------");
    print!("{stats}");
    println!("\n--------------------------------------------------------------------------------");

    if alerts.is_empty() {
        println!("\nNo security alerts were generated for the observed connection snapshots.");
        println!("(Connections observed were within normal baseline distinct-port thresholds.)");
    } else {
        println!("\nGenerated Security Alerts ({}):", alerts.len());
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
    println!(" Phase 2 demonstration completed successfully without errors.");
    println!("================================================================================");
}

#[tokio::main]
async fn run() -> Result<()> {
    init_logging();

    let args: Vec<String> = std::env::args().collect();
    let Some(cli_cfg) = parse_cli_args(&args)? else {
        return Ok(());
    };

    print_banner(cli_cfg.use_mock);

    info!("Initializing SentinelX detection engine with demonstration threshold configuration...");
    let mut config = DetectionConfig::default();
    config.distinct_port_threshold = 5;
    config.max_evidence_ids_per_alert = 20;

    let rule =
        PortScanRule::new(config.clone()).context("failed to initialize PortScanRule NET-001")?;
    let engine = DetectionEngine::new(config)
        .context("failed to initialize DetectionEngine")?
        .with_rule(Box::new(rule));

    let collector_mode = if cli_cfg.use_mock {
        CollectorMode::Mock(MockScenario::Mixed)
    } else {
        CollectorMode::LiveWindowsTcp
    };

    let scheduler_config = SchedulerConfig::new(
        Duration::from_millis(cli_cfg.interval_ms),
        cli_cfg.max_cycles,
        collector_mode,
    )
    .context("invalid scheduler configuration")?;

    let mut scheduler = TelemetryScheduler::new(scheduler_config, engine)
        .context("failed to initialize telemetry scheduler")?;

    info!("Starting telemetry collection and detection pipeline...");
    let alerts = scheduler
        .run()
        .await
        .context("scheduler execution failed")?;

    print_execution_summary(scheduler.stats(), &alerts);

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
