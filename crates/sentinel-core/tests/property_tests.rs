//! Property-based tests for SentinelX Core domain models and invariants.

use chrono::{Duration, Utc};
use proptest::prelude::*;
use sentinel_core::alert::{AlertSeverity, RuleId, SecurityAlertBuilder};
use sentinel_core::config::DetectionConfig;
use sentinel_core::error::ConfigError;
use sentinel_core::event::{
    EventId, EventMetadata, MAX_METADATA_KEY_LEN, MAX_METADATA_VALUE_LEN, NetworkEventBuilder,
    NetworkProtocol, ProcessId, TelemetrySource,
};
use std::net::{IpAddr, Ipv4Addr};

proptest! {
    /// Invariant: Valid IPv4 addresses and non-zero ports always construct a valid NetworkEvent.
    #[test]
    fn prop_network_event_valid_ports(
        a in 1u8..=254,
        b in 0u8..=254,
        c in 0u8..=254,
        d in 1u8..=254,
        src_port in 1u16..=65535,
        dst_port in 1u16..=65535,
    ) {
        let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        let event = NetworkEventBuilder::new(TelemetrySource::SyntheticSimulator, NetworkProtocol::Tcp, Utc::now())
            .with_source_ip(ip)
            .with_source_port(src_port)
            .with_destination_port(dst_port)
            .build();

        prop_assert!(event.is_ok());
        let event = event.unwrap();
        prop_assert_eq!(event.source_port, Some(src_port));
        prop_assert_eq!(event.destination_port, Some(dst_port));
    }

    /// Invariant: Port 0 must ALWAYS be rejected for either source or destination.
    #[test]
    fn prop_network_event_zero_port_rejected(
        is_src in any::<bool>(),
        other_port in 1u16..=65535,
    ) {
        let mut builder = NetworkEventBuilder::new(TelemetrySource::SyntheticSimulator, NetworkProtocol::Tcp, Utc::now());
        if is_src {
            builder = builder.with_source_port(0).with_destination_port(other_port);
        } else {
            builder = builder.with_source_port(other_port).with_destination_port(0);
        }

        prop_assert!(builder.build().is_err());
    }

    /// Invariant: Metadata key/value length limits are strictly enforced.
    #[test]
    fn prop_metadata_bounds_check(
        key in "[a-zA-Z0-9_]{1,70}",
        val in "[a-zA-Z0-9_]{1,300}",
    ) {
        let mut meta = EventMetadata::new();
        let result = meta.insert(key.clone(), val.clone());

        if key.len() > MAX_METADATA_KEY_LEN || val.len() > MAX_METADATA_VALUE_LEN {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_ok());
            prop_assert_eq!(meta.get(&key), Some(val.as_str()));
        }
    }

    /// Invariant: Process IDs beyond MAX_PROCESS_ID are always rejected.
    #[test]
    fn prop_process_id_validation(pid in any::<u32>()) {
        let result = ProcessId::new(pid);
        if pid > sentinel_core::event::MAX_PROCESS_ID {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap().as_u32(), pid);
        }
    }

    /// Invariant: Inverted alert time ranges are strictly rejected.
    #[test]
    fn prop_alert_inverted_time_rejected(delta_seconds in 1i64..=100_000) {
        let base = Utc::now();
        let first = base;
        let last = base - Duration::seconds(delta_seconds);
        let rule_id = RuleId::new("NET-001").unwrap();

        let alert_res = SecurityAlertBuilder::new(
            rule_id,
            AlertSeverity::Medium,
            "Title",
            "Explanation",
            first,
            last,
        )
        .with_evidence_ids(vec![EventId::new()])
        .with_observation_count(1)
        .build();

        prop_assert!(alert_res.is_err());
    }

    /// Invariant: Checked threshold arithmetic correctly catches overflows for high thresholds.
    #[test]
    fn prop_config_arithmetic_overflow(threshold in 16_384u16..=u16::MAX) {
        // Any threshold >= 16384 * 4 >= 65536 > u16::MAX must fail checked arithmetic.
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = threshold;
        let res = config.validate();
        let is_overflow = matches!(res, Err(ConfigError::ThresholdOverflow { .. }));
        prop_assert!(is_overflow);
    }
}
