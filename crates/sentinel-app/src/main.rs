//! `SentinelX` Desktop Application: Windows Telemetry, SQLite Storage & Defensive Threat Detection.
//!
//! Provides the Tauri 2 desktop dashboard application and preserves optional CLI execution.

#![allow(missing_docs)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use anyhow::{Context, Result};
use sentinel_app::commands::*;
use sentinel_app::pipeline::{PipelineConfig, PipelineCoordinator};
use sentinel_app::state::{AppSettings, AppState, default_database_path, settings_file_path};
use sentinel_collector::mock::{MockCollector, MockScenario};
use sentinel_collector::source::TelemetryCollector;
use sentinel_collector::windows_tcp::WindowsTcpCollector;
use sentinel_core::config::DetectionConfig;
use sentinel_detection::engine::DetectionEngine;
use sentinel_detection::rules::{ConnectionBurstConfig, ConnectionBurstRule, PortScanRule};
use sentinel_storage::retention::RetentionPolicy;
use sentinel_storage::{Database, DatabaseConfig};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Parsed CLI configuration options.
#[derive(Debug, Clone)]
struct CliConfig {
    is_cli_mode: bool,
    use_mock: bool,
    interval_ms: u64,
    max_cycles: Option<usize>,
    db_path: PathBuf,
    retention_days: u32,
    run_retention: bool,
}

/// Initializes structured logging.
fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .compact();

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}

/// Parses command line arguments.
fn parse_cli_args(args: &[String]) -> Result<Option<CliConfig>> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("SentinelX Defensive Network Monitor & Desktop Dashboard");
        println!();
        println!("Usage: sentinel-app [OPTIONS]");
        println!();
        println!("Options:");
        println!(
            "  --cli                   Run in headless CLI monitoring mode instead of desktop GUI"
        );
        println!("  --mock                  Run using deterministic in-memory mock collector");
        println!("  --interval-ms <ms>      Polling interval in milliseconds [default: 1000]");
        println!(
            "  --max-cycles <num>      Maximum collection cycles to run before exiting (CLI mode)"
        );
        println!("  --continuous            Run continuously until Ctrl+C is pressed (CLI mode)");
        println!("  --db <path>             Path to SQLite database file");
        println!("  --retention-days <days> Event retention window in days [default: 30]");
        println!("  --no-retention          Skip automated retention purge cycle on shutdown");
        println!("  -h, --help              Show this help message");
        return Ok(None);
    }

    let is_cli_mode = args.iter().any(|a| a == "--cli");
    let mut interval_ms = 1000u64;
    let mut max_cycles = if is_cli_mode { Some(3usize) } else { None };
    let mut use_mock = !cfg!(target_os = "windows");
    let mut db_path = default_database_path();
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
        is_cli_mode,
        use_mock,
        interval_ms,
        max_cycles,
        db_path,
        retention_days,
        run_retention,
    }))
}

/// Loads persistent settings from disk or constructs defaults.
fn load_or_create_settings(db_path: PathBuf, use_mock: bool) -> AppSettings {
    let path = settings_file_path();
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(mut settings) = serde_json::from_str::<AppSettings>(&content) {
                if use_mock {
                    settings.is_demo_mode = true;
                }
                return settings;
            }
        }
    }

    let mut settings = AppSettings::default();
    settings.database_path = db_path.to_string_lossy().to_string();
    if use_mock {
        settings.is_demo_mode = true;
    }
    settings
}

/// Builds initial detection engine with NET-001 and NET-002 rules.
fn build_initial_detection_engine() -> Result<DetectionEngine> {
    let mut net001_config = DetectionConfig::default();
    net001_config.distinct_port_threshold = 10;
    net001_config.max_evidence_ids_per_alert = 20;

    let net002_config = ConnectionBurstConfig::new(
        20,
        chrono::Duration::seconds(60),
        Some(chrono::Duration::seconds(300)),
        50,
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

    Ok(engine)
}

/// Runs CLI mode (for backward compatibility and automated test pipeline).
async fn run_cli(cli_cfg: CliConfig) -> Result<()> {
    info!("Running SentinelX in CLI monitoring mode");
    let db_config = DatabaseConfig::new(&cli_cfg.db_path);
    let database = Database::new(&db_config)
        .await
        .context("failed to initialize SQLite persistent storage")?;

    let engine = build_initial_detection_engine()?;
    let collector: Box<dyn TelemetryCollector> = if cli_cfg.use_mock {
        Box::new(MockCollector::for_scenario(&MockScenario::Mixed))
    } else {
        Box::new(WindowsTcpCollector::new())
    };

    let pipeline_config = PipelineConfig::default();
    let mut coordinator = PipelineCoordinator::new(pipeline_config, collector, database, engine);

    let polling_interval = Duration::from_millis(cli_cfg.interval_ms);
    let mut interval_timer = tokio::time::interval(polling_interval);
    interval_timer.tick().await;

    let mut cycle = 0;
    let mut accumulated_alerts = Vec::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C interrupt received; initiating graceful shutdown");
                break;
            }
            _ = interval_timer.tick() => {
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

                if let Some(max) = cli_cfg.max_cycles {
                    if cycle >= max {
                        info!(
                            cycle,
                            "Reached configured maximum collection cycles; exiting"
                        );
                        break;
                    }
                }
            }
        }
    }

    if cli_cfg.run_retention {
        let policy = RetentionPolicy::new(cli_cfg.retention_days, 90, 500, 100);
        let _ = coordinator.run_retention(&policy).await;
    }

    println!(
        "\nCLI execution completed successfully (alerts detected: {}).",
        accumulated_alerts.len()
    );
    Ok(())
}

fn main() -> ExitCode {
    init_logging();

    let args: Vec<String> = std::env::args().collect();
    let cli_cfg = match parse_cli_args(&args) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[ERROR]: {err}");
            return ExitCode::FAILURE;
        }
    };

    if cli_cfg.is_cli_mode {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("[FATAL]: Failed to initialize Tokio runtime: {e}");
                return ExitCode::FAILURE;
            }
        };

        return match rt.block_on(run_cli(cli_cfg)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("[FATAL ERROR]: {err:?}");
                ExitCode::FAILURE
            }
        };
    }

    // Launch Tauri 2 Desktop Application
    let settings = load_or_create_settings(cli_cfg.db_path.clone(), cli_cfg.use_mock);
    let db_path = PathBuf::from(&settings.database_path);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[FATAL]: Failed to create Tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let app_state = match rt.block_on(async {
        let db_config = DatabaseConfig::new(&db_path);
        let database = Database::new(&db_config)
            .await
            .context("failed to initialize SQLite database")?;

        let engine = build_initial_detection_engine()?;
        let collector: Box<dyn TelemetryCollector> = if settings.is_demo_mode {
            Box::new(MockCollector::for_scenario(&MockScenario::Mixed))
        } else {
            Box::new(WindowsTcpCollector::new())
        };

        let pipeline_config = PipelineConfig::default();
        let coordinator =
            PipelineCoordinator::new(pipeline_config, collector, database.clone(), engine);

        AppState::new(database, coordinator, settings)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("[FATAL]: Failed to initialize application state: {err}");
            return ExitCode::FAILURE;
        }
    };

    let state_for_setup = Arc::clone(&app_state);
    let state_for_window = Arc::clone(&app_state);

    let result = tauri::Builder::default()
        .manage(app_state)
        .setup(move |app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                state_for_setup.set_app_handle(handle).await;
            });
            Ok(())
        })
        .on_window_event(move |_window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed = event
            {
                state_for_window
                    .shutdown_flag
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                info!("Window close requested; signaled graceful background shutdown");
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_system_status,
            get_dashboard_summary,
            query_network_events,
            get_network_event_details,
            query_security_alerts,
            get_security_alert_details,
            get_alert_evidence,
            acknowledge_alert,
            resolve_alert,
            get_detection_rules,
            update_detection_rule,
            get_telemetry_status,
            start_telemetry,
            stop_telemetry,
            get_audit_history,
            get_application_settings,
            update_application_settings,
            get_system_diagnostics,
        ])
        .run(tauri::generate_context!());

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[FATAL TAURI ERROR]: {err}");
            ExitCode::FAILURE
        }
    }
}
