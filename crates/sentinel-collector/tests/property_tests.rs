//! Property-based tests for SentinelX telemetry normalization and decoding invariants.

use chrono::Utc;
use proptest::prelude::*;
use sentinel_collector::normalize::{
    RawTcpRecord, SkipReason, TcpState, decode_ipv4_addr, decode_tcp_port, normalize_tcp_record,
};
use sentinel_core::event::TelemetrySource;
use std::net::{IpAddr, Ipv4Addr};

proptest! {
    /// Invariant: Port decoding from network byte order matches native u16::from_be.
    #[test]
    fn prop_port_decoding_roundtrip(port in 1u16..=65535) {
        let net_order_bytes = port.to_be_bytes();
        let raw_val = u16::from_ne_bytes(net_order_bytes) as u32;
        let decoded = decode_tcp_port(raw_val);
        prop_assert_eq!(decoded, port);
    }

    /// Invariant: IPv4 decoding from network byte order matches native Ipv4Addr construction.
    #[test]
    fn prop_ipv4_decoding_roundtrip(
        a in 0u8..=255,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
    ) {
        let expected = Ipv4Addr::new(a, b, c, d);
        let net_order_bytes = [a, b, c, d];
        let raw_val = u32::from_ne_bytes(net_order_bytes);
        let decoded = decode_ipv4_addr(raw_val);
        prop_assert_eq!(decoded, expected);
    }

    /// Invariant: Any record with remote port 0 or state Listen is always skipped with ListeningSocket.
    #[test]
    fn prop_listening_socket_always_skipped(
        is_listen_state in any::<bool>(),
        local_port in 1u16..=65535,
        remote_port in any::<u16>(),
    ) {
        let state = if is_listen_state { TcpState::Listen } else { TcpState::Established };
        let actual_remote_port = if is_listen_state { 0 } else { remote_port };

        let record = RawTcpRecord {
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port,
            remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: actual_remote_port,
            state,
            owning_pid: Some(4),
        };

        let result = normalize_tcp_record(record, TelemetrySource::WindowsTcpSnapshot, Utc::now());
        if state == TcpState::Listen || actual_remote_port == 0 {
            prop_assert_eq!(result.unwrap_err(), SkipReason::ListeningSocket);
        }
    }

    /// Invariant: Valid non-zero ports and established states always produce a valid NetworkEvent.
    #[test]
    fn prop_valid_records_always_normalize(
        local_port in 1u16..=65535,
        remote_port in 1u16..=65535,
        pid in 1u32..=4_194_304,
    ) {
        let record = RawTcpRecord {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            local_port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            remote_port,
            state: TcpState::Established,
            owning_pid: Some(pid),
        };

        let result = normalize_tcp_record(record, TelemetrySource::WindowsTcpSnapshot, Utc::now());
        prop_assert!(result.is_ok());
        let event = result.unwrap();
        prop_assert_eq!(event.source_port, Some(local_port));
        prop_assert_eq!(event.destination_port, Some(remote_port));
        prop_assert_eq!(event.process_id.map(|p| p.as_u32()), Some(pid));
    }
}
