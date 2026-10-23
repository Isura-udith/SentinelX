//! # SentinelX Telemetry Collector Subsystem
//!
//! `sentinel-collector` provides local network connection table collection, normalization,
//! and statistics tracking for SentinelX.
//!
//! ## Key Capabilities
//! - [`WindowsTcpCollector`]: Read-only, user-mode Windows IP Helper integration querying
//!   IPv4 and IPv6 TCP connection tables (`GetExtendedTcpTable`) with safe memory boundary validation.
//! - [`MockCollector`]: Deterministic synthetic collector for development, scenario testing,
//!   and multi-cycle polling verification without external network traffic.
//! - [`TelemetryCollector`]: Extensible trait abstracting connection observation providers.
//! - [`CollectionStats`]: Runtime statistics tracking collection cycle counts, raw observations,
//!   normalization yield, and alert generation.
//! - [`normalize`]: Safe transformation of native operating system records to [`sentinel_core::NetworkEvent`]
//!   with endianness decoding, TCP state tracking, and explicit skip policies.

#![allow(unsafe_code)]

pub mod error;
pub mod mock;
pub mod normalize;
pub mod source;
pub mod stats;
pub mod windows_tcp;

pub use error::CollectorError;
pub use mock::{MockCollector, MockScenario};
pub use normalize::{
    RawTcpRecord, SkipReason, TcpState, decode_ipv4_addr, decode_ipv6_addr, decode_tcp_port,
    normalize_batch, normalize_tcp_record,
};
pub use source::{CollectionBatch, CollectionMetadata, TelemetryCollector};
pub use stats::CollectionStats;
pub use windows_tcp::WindowsTcpCollector;
