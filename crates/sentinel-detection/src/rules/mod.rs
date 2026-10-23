//! Detection rules module for SentinelX.
//!
//! Contains implementations of individual detection rules conforming to [`crate::engine::DetectionRule`].

pub mod connection_burst;
pub mod port_scan;

pub use connection_burst::{
    ConnectionBurstConfig, ConnectionBurstRule, RULE_ID_NET_002, RULE_NAME_NET_002,
};
pub use port_scan::{PortScanRule, RULE_ID_NET_001, RULE_NAME_NET_001};
