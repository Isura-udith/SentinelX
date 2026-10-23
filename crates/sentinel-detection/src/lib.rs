//! # SentinelX Detection Engine & Rules
//!
//! `sentinel-detection` implements the core analytical detection engine and security rules
//! for SentinelX.
//!
//! ## Key Capabilities
//! - [`DetectionEngine`]: Orchestrates batch evaluation across registered rules, enforces
//!   bounded processing limits, and guarantees deterministic alert ordering.
//! - [`DetectionRule`]: Extensible trait for adding specialized analytical detection rules.
//! - [`PortScanRule`]: Rule `NET-001` detecting port sweep reconnaissance while accounting
//!   for legitimate administrative scanner behaviors.

pub mod engine;
pub mod rules;

pub use engine::{DetectionEngine, DetectionError, DetectionRule};
pub use rules::port_scan::{PortScanRule, RULE_ID_NET_001, RULE_NAME_NET_001};
