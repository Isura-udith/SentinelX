//! Normalization logic transforming raw TCP table observations into domain events.
//!
//! # Endpoint Distinction
//! In Windows IP Helper TCP table observations:
//! - **Local Endpoint** (`dwLocalAddr` / `dwLocalPort`): The local socket interface on the host.
//!   Mapped to [`sentinel_core::NetworkEvent::source_ip`] and [`sentinel_core::NetworkEvent::source_port`].
//! - **Remote Endpoint** (`dwRemoteAddr` / `dwRemotePort`): The peer socket interface of the connection.
//!   Mapped to [`sentinel_core::NetworkEvent::destination_ip`] and [`sentinel_core::NetworkEvent::destination_port`].
//!
//! # Byte Order Conversion
//! The Windows IP Helper API stores IPv4 addresses and TCP ports in **network byte order (big-endian)**:
//! - Ports are stored in the lower 16 bits of a 32-bit integer: `u16::from_be((dwPort & 0xFFFF) as u16)`.
//! - IPv4 addresses are stored as 32-bit network-order integers: `Ipv4Addr::from(u32::from_be(dwAddr))`.
//! - IPv6 addresses are stored as 16-byte byte arrays in network byte order: `Ipv6Addr::from(ucAddr)`.
//! - Process IDs (`dwOwningPid`) and TCP States (`dwState`) are in **host byte order**.

use chrono::{DateTime, Utc};
use sentinel_core::error::DomainError;
use sentinel_core::event::{
    EventMetadata, NetworkEvent, NetworkEventBuilder, NetworkProtocol, ProcessId, TelemetrySource,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Standard TCP connection state representations matching Windows `MIB_TCP_STATE_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    /// Socket is closed and not in use.
    Closed,
    /// Listening for incoming connection requests.
    Listen,
    /// SYN packet sent; waiting for matching connection request.
    SynSent,
    /// SYN packet received and acknowledged; waiting for ACK.
    SynReceived,
    /// Connection is open and data transfer can occur.
    Established,
    /// Waiting for a connection termination request from remote TCP.
    FinWait1,
    /// Waiting for a connection termination request from remote TCP after local FIN ACKed.
    FinWait2,
    /// Waiting for a connection termination request from the local user.
    CloseWait,
    /// Waiting for connection termination request acknowledgment from remote TCP.
    Closing,
    /// Waiting for an acknowledgment of the connection termination request previously sent to remote TCP.
    LastAck,
    /// Waiting for enough time to pass to ensure remote TCP received acknowledgment of its termination request.
    TimeWait,
    /// Transmission Control Block is deleted.
    DeleteTcb,
    /// Non-standard or unknown state code.
    Unknown(u32),
}

impl TcpState {
    /// Constructs a [`TcpState`] from a native Windows `MIB_TCP_STATE_*` integer code.
    #[must_use]
    pub const fn from_raw(state: u32) -> Self {
        match state {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            other => Self::Unknown(other),
        }
    }

    /// Returns the standard text name of the TCP state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::DeleteTcb => "DELETE_TCB",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Raw, unnormalized snapshot record extracted from the platform TCP table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTcpRecord {
    /// Local IP address.
    pub local_addr: IpAddr,
    /// Local TCP port.
    pub local_port: u16,
    /// Remote IP address.
    pub remote_addr: IpAddr,
    /// Remote TCP port.
    pub remote_port: u16,
    /// TCP connection state.
    pub state: TcpState,
    /// Owning operating system Process ID, if supplied by the table variant.
    pub owning_pid: Option<u32>,
}

/// Explicit reasons why a raw TCP connection record was skipped during normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    /// Listening socket (`MIB_TCP_STATE_LISTEN`) with remote port 0.
    ///
    /// Listening sockets represent local service bindings awaiting connections,
    /// rather than active connection observations.
    ListeningSocket,

    /// Local port is 0, which is invalid in TCP communication.
    InvalidLocalPort(u16),

    /// Remote port is 0 on a non-listening connection record.
    InvalidRemotePort(u16),

    /// Operating system Process ID exceeds supported system range.
    InvalidProcessId(u32),

    /// Underlying domain model rejected the event during validation.
    DomainValidationFailure(String),
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListeningSocket => write!(f, "listening socket endpoint (remote port is 0)"),
            Self::InvalidLocalPort(p) => write!(f, "invalid local port: {p}"),
            Self::InvalidRemotePort(p) => write!(f, "invalid remote port: {p}"),
            Self::InvalidProcessId(pid) => write!(f, "invalid process ID: {pid}"),
            Self::DomainValidationFailure(msg) => write!(f, "domain validation failed: {msg}"),
        }
    }
}

/// Normalizes a single raw TCP record into a validated [`NetworkEvent`].
///
/// # Normalization Policy
/// 1. Sockets in `LISTEN` state (remote port 0) are skipped with [`SkipReason::ListeningSocket`].
/// 2. Records with local port 0 or non-listening remote port 0 are skipped with [`SkipReason::InvalidLocalPort`]
///    or [`SkipReason::InvalidRemotePort`].
/// 3. TCP state is preserved in structured metadata (`tcp_state`).
/// 4. Process IDs are mapped to [`ProcessId`] if provided and valid.
///
/// # Errors
/// Returns [`SkipReason`] when a record cannot or should not be transformed into a connection event.
pub fn normalize_tcp_record(
    raw: RawTcpRecord,
    source: TelemetrySource,
    timestamp: DateTime<Utc>,
) -> Result<NetworkEvent, SkipReason> {
    // 1. Listening socket policy check:
    if raw.state == TcpState::Listen || raw.remote_port == 0 {
        return Err(SkipReason::ListeningSocket);
    }

    // 2. Local port validation:
    if raw.local_port == 0 {
        return Err(SkipReason::InvalidLocalPort(raw.local_port));
    }

    // 3. Process ID conversion:
    let process_id = if let Some(pid) = raw.owning_pid {
        Some(ProcessId::new(pid).map_err(|_| SkipReason::InvalidProcessId(pid))?)
    } else {
        None
    };

    // 4. Attach TCP state to metadata:
    let mut metadata = EventMetadata::new();
    let _ = metadata.insert("tcp_state", raw.state.as_str());

    // 5. Construct NetworkEvent using validated builder:
    let mut builder = NetworkEventBuilder::new(source, NetworkProtocol::Tcp, timestamp)
        .with_source_ip(raw.local_addr)
        .with_source_port(raw.local_port)
        .with_destination_ip(raw.remote_addr)
        .with_destination_port(raw.remote_port)
        .with_metadata(metadata);

    if let Some(pid) = process_id {
        builder = builder.with_process_id(pid);
    }

    builder
        .build()
        .map_err(|e: DomainError| SkipReason::DomainValidationFailure(e.to_string()))
}

/// Normalizes a batch of raw records, returning both successfully normalized events
/// and records that were skipped along with their skip reasons.
pub fn normalize_batch(
    records: Vec<RawTcpRecord>,
    source: TelemetrySource,
    timestamp: DateTime<Utc>,
) -> (Vec<NetworkEvent>, Vec<(RawTcpRecord, SkipReason)>) {
    let mut events = Vec::with_capacity(records.len());
    let mut skipped = Vec::new();

    for record in records {
        match normalize_tcp_record(record, source, timestamp) {
            Ok(event) => events.push(event),
            Err(reason) => skipped.push((record, reason)),
        }
    }

    (events, skipped)
}

/// Helper to decode native IPv4 address from network byte order integer.
#[must_use]
pub fn decode_ipv4_addr(dw_addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(dw_addr))
}

/// Helper to decode native TCP port from lower 16 bits in network byte order.
#[must_use]
pub fn decode_tcp_port(dw_port: u32) -> u16 {
    u16::from_be((dw_port & 0xFFFF) as u16)
}

/// Helper to decode native IPv6 address from network byte order byte array.
#[must_use]
pub fn decode_ipv6_addr(bytes: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_established_record() {
        let raw = RawTcpRecord {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            remote_port: 443,
            state: TcpState::Established,
            owning_pid: Some(1234),
        };

        let now = Utc::now();
        let event = normalize_tcp_record(raw, TelemetrySource::WindowsTcpSnapshot, now)
            .expect("should normalize");

        assert_eq!(event.protocol, NetworkProtocol::Tcp);
        assert_eq!(event.source, TelemetrySource::WindowsTcpSnapshot);
        assert_eq!(
            event.source_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(event.source_port, Some(54321));
        assert_eq!(
            event.destination_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        );
        assert_eq!(event.destination_port, Some(443));
        assert_eq!(event.process_id.map(|p| p.as_u32()), Some(1234));
        assert_eq!(event.metadata.get("tcp_state"), Some("ESTABLISHED"));
    }

    #[test]
    fn test_listening_socket_skipped() {
        let raw = RawTcpRecord {
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 80,
            remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            state: TcpState::Listen,
            owning_pid: Some(4),
        };

        let res = normalize_tcp_record(raw, TelemetrySource::WindowsTcpSnapshot, Utc::now());
        assert_eq!(res.unwrap_err(), SkipReason::ListeningSocket);
    }

    #[test]
    fn test_invalid_local_port_zero() {
        let raw = RawTcpRecord {
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 0,
            remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: 8080,
            state: TcpState::Established,
            owning_pid: Some(100),
        };

        let res = normalize_tcp_record(raw, TelemetrySource::WindowsTcpSnapshot, Utc::now());
        assert_eq!(res.unwrap_err(), SkipReason::InvalidLocalPort(0));
    }

    #[test]
    fn test_ipv4_and_port_byte_order_decoding() {
        // IP 192.0.2.1 in network byte order: bytes [192, 0, 2, 1]
        // On little endian (x86), as u32 integer: 0x010200C0
        let raw_ip_int: u32 = u32::from_ne_bytes([192, 0, 2, 1]);
        let decoded_ip = decode_ipv4_addr(raw_ip_int);
        assert_eq!(decoded_ip, Ipv4Addr::new(192, 0, 2, 1));

        // Port 443 (0x01BB) in network byte order: bytes [0x01, 0xBB]
        let raw_port_int: u32 = u16::from_ne_bytes([0x01, 0xBB]) as u32;
        let decoded_port = decode_tcp_port(raw_port_int);
        assert_eq!(decoded_port, 443);
    }

    #[test]
    fn test_ipv6_normalization() {
        let raw = RawTcpRecord {
            local_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            local_port: 40000,
            remote_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            remote_port: 8443,
            state: TcpState::Established,
            owning_pid: Some(888),
        };

        let event = normalize_tcp_record(raw, TelemetrySource::WindowsTcpSnapshot, Utc::now())
            .expect("ipv6 normalizes");
        assert_eq!(event.source_ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(event.destination_port, Some(8443));
    }
}
