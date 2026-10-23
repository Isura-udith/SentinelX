//! Property-based tests for SentinelX detection rules and engine invariants.

use chrono::{Duration, Utc};
use proptest::prelude::*;
use sentinel_core::config::DetectionConfig;
use sentinel_core::event::{NetworkEvent, NetworkEventBuilder, NetworkProtocol, TelemetrySource};
use sentinel_detection::engine::DetectionRule;
use sentinel_detection::rules::PortScanRule;
use std::net::{IpAddr, Ipv4Addr};

// Strategy to generate arbitrary valid test events for a specific source IP and destination port.
fn make_event(ip: IpAddr, port: u16, offset_secs: i64) -> NetworkEvent {
    let ts = Utc::now() + Duration::seconds(offset_secs);
    NetworkEventBuilder::new(
        TelemetrySource::SyntheticSimulator,
        NetworkProtocol::Tcp,
        ts,
    )
    .with_source_ip(ip)
    .with_destination_port(port)
    .build()
    .expect("valid event")
}

proptest! {
    /// Invariant 1: Adding duplicate observations of an already observed destination port
    /// NEVER increases the distinct-port count and does NOT cause an alert if distinct ports < threshold.
    #[test]
    fn prop_duplicate_ports_never_inflate_distinct_count(
        target_port in 1u16..=1000,
        duplicate_count in 2usize..=50,
    ) {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 2; // threshold requires at least 2 distinct ports
        let rule = PortScanRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let events: Vec<NetworkEvent> = (0..duplicate_count)
            .map(|i| make_event(ip, target_port, i as i64))
            .collect();

        let alerts = rule.evaluate(&events).unwrap();
        // Since only 1 distinct port was contacted, no alert must ever be generated!
        prop_assert!(alerts.is_empty(), "Duplicate ports generated unexpected alert");
    }

    /// Invariant 2: Reordering (permuting) the input events does not alter the logical detection outcome
    /// (same source IPs alerted, same alert count, same distinct port count).
    #[test]
    fn prop_input_permutation_invariance(
        ports in prop::collection::hash_set(1u16..=100, 3..=10),
    ) {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 3;
        let rule_fwd = PortScanRule::new(config.clone()).unwrap();
        let rule_rev = PortScanRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        let port_vec: Vec<u16> = ports.into_iter().collect();

        // Forward sequence
        let events_fwd: Vec<NetworkEvent> = port_vec
            .iter()
            .enumerate()
            .map(|(i, &p)| make_event(ip, p, i as i64))
            .collect();

        // Reversed sequence
        let mut events_rev = events_fwd.clone();
        events_rev.reverse();

        let alerts_fwd = rule_fwd.evaluate(&events_fwd).unwrap();
        let alerts_rev = rule_rev.evaluate(&events_rev).unwrap();

        prop_assert_eq!(alerts_fwd.len(), alerts_rev.len());
        if !alerts_fwd.is_empty() {
            prop_assert_eq!(alerts_fwd[0].source_ip, alerts_rev[0].source_ip);
            prop_assert_eq!(alerts_fwd[0].severity, alerts_rev[0].severity);
            prop_assert_eq!(alerts_fwd[0].observation_count, alerts_rev[0].observation_count);
        }
    }

    /// Invariant 3: Events from independent source IPs are strictly partitioned and never merged.
    #[test]
    fn prop_independent_source_ips_never_merged(
        host_a_last_octet in 1u8..=100,
        host_b_last_octet in 101u8..=200,
    ) {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 4; // requires 4 distinct ports per host
        let rule = PortScanRule::new(config).unwrap();

        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host_a_last_octet));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host_b_last_octet));

        // Host A contacts 2 ports: 80, 443
        // Host B contacts 2 ports: 8080, 8443
        // Combined distinct ports across both is 4, but individually neither crosses threshold 4!
        let events = vec![
            make_event(ip_a, 80, 0),
            make_event(ip_a, 443, 1),
            make_event(ip_b, 8080, 2),
            make_event(ip_b, 8443, 3),
        ];

        let alerts = rule.evaluate(&events).unwrap();
        prop_assert!(alerts.is_empty(), "Independent IPs were erroneously aggregated");
    }

    /// Invariant 4: Empty input always produces exactly 0 alerts.
    #[test]
    fn prop_empty_input_produces_zero_alerts(_dummy in any::<u8>()) {
        let rule = PortScanRule::new(DetectionConfig::default()).unwrap();
        let alerts = rule.evaluate(&[]).unwrap();
        prop_assert!(alerts.is_empty());
    }

    /// Invariant 5: Idempotency — evaluating identical inputs multiple times produces equivalent alerts.
    #[test]
    fn prop_evaluation_idempotency(port_count in 1usize..=12) {
        let mut config = DetectionConfig::default();
        config.distinct_port_threshold = 5;
        let rule1 = PortScanRule::new(config.clone()).unwrap();
        let rule2 = PortScanRule::new(config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
        let events: Vec<NetworkEvent> = (1..=port_count)
            .map(|p| make_event(ip, p as u16, p as i64))
            .collect();

        let run1 = rule1.evaluate(&events).unwrap();
        let run2 = rule2.evaluate(&events).unwrap();

        prop_assert_eq!(run1.len(), run2.len());
        if !run1.is_empty() {
            prop_assert_eq!(run1[0].source_ip, run2[0].source_ip);
            prop_assert_eq!(run1[0].severity, run2[0].severity);
            prop_assert_eq!(run1[0].observation_count, run2[0].observation_count);
        }
    }
}
