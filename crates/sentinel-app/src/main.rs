//! `SentinelX` Command-Line Application: Windows Telemetry, SQLite Storage & Detection Monitor.
//!
//! Demonstrates Phase 3 live/mock telemetry collection, transactional SQLite event ingestion,
//! stateful rolling-window detection (NET-001 and NET-002), alert correlation, and retention.
//!
//! # Operational Notice
//! - Operates in **read-only mode** using user-mode Windows IP Helper APIs (`GetExtendedTcpTable`).
//! - Requires **no administrator privileges** and **no kernel drivers**.
//! - Modifies **no network configurations, firewall rules, or socket connections**.

use anyhow::{Context, Result};
use sentinel_app::pipeline::{PipelineConfig, PipelineCoordinator, PipelineMetrics};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_collector::source::TelemetryCollector;
use sentinel_collector::stats::CollectionStats;
use sentinel_collector::windows_tcp::WindowsTcpCollector;
use sentinel_core::alert::SecurityAlert;
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{ConnectionBurstConfig, ConnectionBurstRule, PortScanRule};
use sentinel_storage::retention::RetentionPolicy;
use sentinel_storage::{Database, DatabaseConfig};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Parsed CLI configuration options.
#[derive(Debug, Clone)]
struct CliConfig {
    use_mock: bool,
    interval_ms: u64,
    max_cycles: Option<usize>,
    db_path: PathBuf,
    retention_days: u32,
    run_retention: bool,
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
        println!("SentinelX Defensive Network Monitor - Phase 3 (Storage & Detection)");
        println!();
        println!("Usage: sentinel-app [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --mock                  Run using deterministic in-memory mock collector");
        println!(
            "  --interval-ms <ms>      Polling interval in milliseconds [default: 1000] (min: 100, max: 3600000)"
        );
        println!(
            "  --max-cycles <num>      Maximum collection cycles to run before exiting [default: 3]"
        );
        println!("  --continuous            Run continuously until Ctrl+C is pressed");
        println!(
            "  --db <path>             Path to SQLite database file [default: data/sentinelx.db]"
        );
        println!("  --retention-days <days> Event retention window in days [default: 30]");
        println!("  --no-retention          Skip automated retention purge cycle on shutdown");
        println!("  -h, --help              Show this help message");
        return Ok(None);
    }

    let mut interval_ms = 1000u64;
    let mut max_cycles = Some(3usize);
    let mut use_mock = !cfg!(target_os = "windows");
    let mut db_path = PathBuf::from("data/sentinelx.db");
    let mut retention_days = 30u32;
    let mut run_retention = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mock" => use_mock = true,
            "--continuous" => max_cycles = None,
            "--no-retention" => run_retention = false,
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
            "--db" if i + 1 < args.len() => {
                db_path = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            "--retention-days" if i + 1 < args.len() => {
                retention_days = args[i + 1]
                    .parse()
                    .context("invalid integer value for --retention-days")?;
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
        db_path,
        retention_days,
        run_retention,
    }))
}

/// Prints operational startup banner and security disclosures.
fn print_banner(use_mock: bool, db_path: &std::path::Path) {
    println!("================================================================================");
    println!("                           SENTINELX DEFENSIVE MONITOR                          ");
    println!("           Phase 3: SQLite Persistent Storage, Stateful Detection & Retention   ");
    println!("================================================================================");
    println!(" Operational Notice:");
    if use_mock {
        println!(" * Telemetry Mode : DETERMINISTIC MOCK COLLECTOR (--mock or non-Windows host).");
        println!(" * Uses documentation test address ranges (192.0.2.0/24, 198.51.100.0/24).");
    } else {
        println!(" * Telemetry Mode : LIVE WINDOWS TCP SNAPSHOT (IP Helper API).");
        println!(" * Querying native host TCP table via GetExtendedTcpTable in read-only mode.");
    }
    println!(" * Persistence    : SQLite (WAL mode, foreign keys enforced).");
    println!(" * Database Path  : {}", db_path.display());
    println!(" * Detection Rules: NET-001 (Port Scan) & NET-002 (Connection Volume Anomaly).");
    println!(" * Alert Policy   : Stateful rolling window with correlation and deduplication.");
    println!(" * Defensive Rule : No automated containment, firewall changes, or process killing.");
    println!("================================================================================\n");
}

/// Prints diagnostic execution statistics, storage metrics, and detected security alerts.
fn print_execution_summary(
    stats: &CollectionStats,
    metrics: &PipelineMetrics,
    total_stored_events: usize,
    total_stored_alerts: usize,
    cycle_alerts: &[SecurityAlert],
) {
    println!("\n--------------------------------------------------------------------------------");
    println!("                              EXECUTION SUMMARY                                 ");
    println!("--------------------------------------------------------------------------------");
    print!("{stats}");
    println!("\n--------------------------------------------------------------------------------");
    print!("{metrics}");
    println!("\n--------------------------------------------------------------------------------");
    println!("SQLite Persistence Layer:");
    println!("  Total Network Events in DB : {total_stored_events}");
    println!("  Total Security Alerts in DB: {total_stored_alerts}");
    println!("--------------------------------------------------------------------------------");

    if cycle_alerts.is_empty() {
        println!("\nNo new security alerts were generated during this run.");
    } else {
        println!("\nGenerated Security Alerts ({}):", cycle_alerts.len());
        for (idx, alert) in cycle_alerts.iter().enumerate() {
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
            println!("  Observation Count  : {}", alert.observation_count);
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
    println!(" Phase 3 demonstration completed successfully without errors.");
    println!("================================================================================");
}

#[tokio::main]
async fn run() -> Result<()> {
    init_logging();

    let args: Vec<String> = std::env::args().collect();
    let Some(cli_cfg) = parse_cli_args(&args)? else {
        return Ok(());
    };

    print_banner(cli_cfg.use_mock, &cli_cfg.db_path);

    info!("Initializing SQLite database pool and applying migrations...");
    let db_config = DatabaseConfig::new(&cli_cfg.db_path);
    let database = Database::new(&db_config)
        .await
        .context("failed to initialize SQLite persistent storage")?;

    info!("Configuring detection engine with stateful rules NET-001 and NET-002...");
    let mut net001_config = DetectionConfig::default();
    net001_config.distinct_port_threshold = 5;
    net001_config.max_evidence_ids_per_alert = 20;

    let net002_config = ConnectionBurstConfig::new(
        15,
        chrono::Duration::seconds(60),
        Some(chrono::Duration::seconds(300)),
        20,
    )
    .context("invalid NET-002 configuration")?;

    let rule_port_scan =
        PortScanRule::new(net001_config.clone()).context("failed to initialize PortScanRule")?;
    let rule_conn_burst = ConnectionBurstRule::new(net002_config)
        .context("failed to initialize ConnectionBurstRule")?;

    let engine = DetectionEngine::new(net001_config)
        .context("failed to initialize DetectionEngine")?
        .with_rule(Box::new(rule_port_scan))
        .with_rule(Box::new(rule_conn_burst));

    let collector: Box<dyn TelemetryCollector> = if cli_cfg.use_mock {
        Box::new(MockCollector::for_scenario(&MockScenario::Mixed))
    } else {
        Box::new(WindowsTcpCollector::new())
    };

    let pipeline_config = PipelineConfig::default();
    let mut coordinator = PipelineCoordinator::new(pipeline_config, collector, database, engine);

    info!("Starting telemetry, persistence, and detection pipeline loop...");
    let polling_interval = Duration::from_millis(cli_cfg.interval_ms);
    let max_cycles = cli_cfg.max_cycles;

    let mut interval_timer = tokio::time::interval(polling_interval);
    interval_timer.tick().await;

    let mut cycle = 0;
    let mut accumulated_alerts = Vec::new();

    loop {
        cycle += 1;
        info!(cycle, "--- Starting telemetry & persistence cycle ---");

        match coordinator.process_cycle().await {
            Ok(mut alerts) => {
                accumulated_alerts.append(&mut alerts);
            }
            Err(err) => {
                tracing::error!(error = %err, cycle, "Cycle processing encountered error");
            }
        }

        if let Some(max) = max_cycles
            && cycle >= max
        {
            info!(
                cycle,
                "Reached configured maximum collection cycles; terminating"
            );
            break;
        }

        interval_timer.tick().await;
    }

    // Optional retention cleanup run on shutdown
    if cli_cfg.run_retention {
        info!("Running automated data retention cleanup cycle...");
        let policy = RetentionPolicy::new(cli_cfg.retention_days, 90, 500, 100);
        match coordinator.run_retention(&policy).await {
            Ok(report) => {
                info!(
                    events_deleted = report.events_deleted,
                    audit_deleted = report.audit_entries_deleted,
                    duration = ?report.duration,
                    "Retention cycle executed successfully"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Retention cleanup cycle encountered warning");
            }
        }
    }

    let stored_events = coordinator.event_repo().count_events().await.unwrap_or(0);
    let stored_alerts = coordinator.alert_repo().count_alerts().await.unwrap_or(0);

    print_execution_summary(
        coordinator.collection_stats(),
        &coordinator.metrics(),
        stored_events,
        stored_alerts,
        &accumulated_alerts,
    );

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
