//! Network event domain model, protocols, telemetry sources, and bounded metadata.
//!
//! # Conceptual Model
//! A [`NetworkEvent`] represents an **instantaneous connection observation** — a point-in-time
//! snapshot of an observed network connection or socket state captured by a telemetry source.
//!
//! **Important Distinction**:
//! A connection snapshot is **not** a continuous packet capture or complete lifecycle log.
//! Ephemeral or short-lived connections that start and terminate between capture sampling
//! intervals may not be captured in snapshot telemetry. This distinction is critical for
//! defensive detection engineering: detection rules must operate on discrete samples rather
//! than assuming unbroken session visibility.

use crate::error::DomainError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use uuid::Uuid;

/// Maximum number of metadata key-value entries permitted per event.
pub const MAX_METADATA_ENTRIES: usize = 16;
/// Maximum length in bytes for any metadata key.
pub const MAX_METADATA_KEY_LEN: usize = 64;
/// Maximum length in bytes for any metadata value.
pub const MAX_METADATA_VALUE_LEN: usize = 256;
/// Maximum realistic process ID limit on Windows operating systems (Windows limits PIDs to multiples of 4 up to ~4M).
pub const MAX_PROCESS_ID: u32 = 4_194_304;

/// Strongly typed, unique identifier for a [`NetworkEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(Uuid);

impl EventId {
    /// Generates a new random (v4) `EventId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates an `EventId` from an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID reference.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for EventId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Strongly typed process identifier for an operating system process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessId(u32);

impl ProcessId {
    /// Creates a validated `ProcessId`.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidProcessId`] if the PID exceeds the supported operating system range.
    pub fn new(pid: u32) -> Result<Self, DomainError> {
        if pid > MAX_PROCESS_ID {
            return Err(DomainError::InvalidProcessId(pid));
        }
        Ok(Self(pid))
    }

    /// Returns the raw numeric PID value.
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transport-layer network protocol observed during telemetry capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetworkProtocol {
    /// Transmission Control Protocol (connection-oriented transport).
    Tcp,
    /// User Datagram Protocol (connectionless transport).
    Udp,
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

/// Telemetry source origin identifier describing how the event was observed.
///
/// These identifiers specify source provenance for auditability and validation.
/// Operating system collectors are deferred to future development phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetrySource {
    /// Synthetic test generator used for deterministic verification and demonstrations.
    SyntheticSimulator,
    /// Periodic snapshot of active Windows TCP table connections (e.g., GetExtendedTcpTable).
    WindowsTcpSnapshot,
    /// Windows event telemetry (e.g., Event Tracing for Windows or Security Event Log).
    WindowsEventTelemetry,
    /// Bounded packet metadata inspection (e.g., filter driver or lightweight capture).
    PacketMetadata,
}

impl fmt::Display for TelemetrySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyntheticSimulator => write!(f, "synthetic_simulator"),
            Self::WindowsTcpSnapshot => write!(f, "windows_tcp_snapshot"),
            Self::WindowsEventTelemetry => write!(f, "windows_event_telemetry"),
            Self::PacketMetadata => write!(f, "packet_metadata"),
        }
    }
}

/// Structured, size-bounded key-value metadata container for contextual telemetry fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMetadata {
    entries: BTreeMap<String, String>,
}

impl EventMetadata {
    /// Creates an empty metadata container.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts a key-value pair, enforcing size and entry count limits.
    ///
    /// # Errors
    /// Returns [`DomainError::MetadataTooManyEntries`] if the entry count limit is reached,
    /// or [`DomainError::MetadataEntryTooLong`] if the key or value exceeds allowed byte limits.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), DomainError> {
        let key = key.into();
        let value = value.into();

        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_METADATA_ENTRIES {
            return Err(DomainError::MetadataTooManyEntries {
                count: self.entries.len() + 1,
                max: MAX_METADATA_ENTRIES,
            });
        }

        if key.len() > MAX_METADATA_KEY_LEN || value.len() > MAX_METADATA_VALUE_LEN {
            return Err(DomainError::MetadataEntryTooLong {
                key_len: key.len(),
                val_len: value.len(),
                key,
            });
        }

        self.entries.insert(key, value);
        Ok(())
    }

    /// Retrieves a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Returns the number of metadata entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Checks if metadata container is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// A validated, normalized network connection observation.
///
/// Represents an instantaneous snapshot of a network connection or packet observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Unique event identifier.
    pub id: EventId,
    /// UTC timestamp when the observation was recorded.
    pub timestamp: DateTime<Utc>,
    /// Telemetry source origin.
    pub source: TelemetrySource,
    /// Transport network protocol.
    pub protocol: NetworkProtocol,
    /// Optional source IP address.
    pub source_ip: Option<IpAddr>,
    /// Optional source port (1..=65535).
    pub source_port: Option<u16>,
    /// Optional destination IP address.
    pub destination_ip: Option<IpAddr>,
    /// Optional destination port (1..=65535).
    pub destination_port: Option<u16>,
    /// Optional process identifier responsible for the connection.
    pub process_id: Option<ProcessId>,
    /// Bounded, structured metadata.
    pub metadata: EventMetadata,
}

impl NetworkEvent {
    /// Validates the internal consistency and boundary constraints of the event.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidPort`] if port 0 is used,
    /// or other domain errors if bounds are violated.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.source_port == Some(0) || self.destination_port == Some(0) {
            return Err(DomainError::InvalidPort);
        }
        if let Some(pid) = self.process_id
            && pid.as_u32() > MAX_PROCESS_ID
        {
            return Err(DomainError::InvalidProcessId(pid.as_u32()));
        }
        if self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(DomainError::MetadataTooManyEntries {
                count: self.metadata.len(),
                max: MAX_METADATA_ENTRIES,
            });
        }
        Ok(())
    }
}

/// Builder for constructing and validating [`NetworkEvent`] instances safely.
#[derive(Debug, Clone)]
pub struct NetworkEventBuilder {
    id: EventId,
    timestamp: DateTime<Utc>,
    source: TelemetrySource,
    protocol: NetworkProtocol,
    source_ip: Option<IpAddr>,
    source_port: Option<u16>,
    destination_ip: Option<IpAddr>,
    destination_port: Option<u16>,
    process_id: Option<ProcessId>,
    metadata: EventMetadata,
}

impl NetworkEventBuilder {
    /// Starts building a new [`NetworkEvent`] with required core fields.
    #[must_use]
    pub fn new(
        source: TelemetrySource,
        protocol: NetworkProtocol,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            id: EventId::new(),
            timestamp,
            source,
            protocol,
            source_ip: None,
            source_port: None,
            destination_ip: None,
            destination_port: None,
            process_id: None,
            metadata: EventMetadata::new(),
        }
    }

    /// Sets an explicit event ID.
    #[must_use]
    pub fn with_id(mut self, id: EventId) -> Self {
        self.id = id;
        self
    }

    /// Sets the source IP address.
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the optional source IP address.
    #[must_use]
    pub fn with_opt_source_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.source_ip = ip;
        self
    }

    /// Sets the source port.
    #[must_use]
    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Sets the optional source port.
    #[must_use]
    pub fn with_opt_source_port(mut self, port: Option<u16>) -> Self {
        self.source_port = port;
        self
    }

    /// Sets the destination IP address.
    #[must_use]
    pub fn with_destination_ip(mut self, ip: IpAddr) -> Self {
        self.destination_ip = Some(ip);
        self
    }

    /// Sets the optional destination IP address.
    #[must_use]
    pub fn with_opt_destination_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.destination_ip = ip;
        self
    }

    /// Sets the destination port.
    #[must_use]
    pub fn with_destination_port(mut self, port: u16) -> Self {
        self.destination_port = Some(port);
        self
    }

    /// Sets the optional destination port.
    #[must_use]
    pub fn with_opt_destination_port(mut self, port: Option<u16>) -> Self {
        self.destination_port = port;
        self
    }

    /// Sets the process ID.
    #[must_use]
    pub fn with_process_id(mut self, pid: ProcessId) -> Self {
        self.process_id = Some(pid);
        self
    }

    /// Sets the optional process ID.
    #[must_use]
    pub fn with_opt_process_id(mut self, pid: Option<ProcessId>) -> Self {
        self.process_id = pid;
        self
    }

    /// Sets metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: EventMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Validates and constructs the [`NetworkEvent`].
    ///
    /// # Errors
    /// Returns [`DomainError`] if any validation rule fails.
    pub fn build(self) -> Result<NetworkEvent, DomainError> {
        let event = NetworkEvent {
            id: self.id,
            timestamp: self.timestamp,
            source: self.source,
            protocol: self.protocol,
            source_ip: self.source_ip,
            source_port: self.source_port,
            destination_ip: self.destination_ip,
            destination_port: self.destination_port,
            process_id: self.process_id,
            metadata: self.metadata,
        };
        event.validate()?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_event_builder_valid() {
        let now = Utc::now();
        let event = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now,
        )
        .with_source_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .with_source_port(49152)
        .with_destination_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        .with_destination_port(443)
        .build()
        .expect("valid event");

        assert_eq!(event.protocol, NetworkProtocol::Tcp);
        assert_eq!(event.source, TelemetrySource::SyntheticSimulator);
        assert_eq!(event.destination_port, Some(443));
    }

    #[test]
    fn test_event_invalid_port_zero() {
        let now = Utc::now();
        let result = NetworkEventBuilder::new(
            TelemetrySource::SyntheticSimulator,
            NetworkProtocol::Tcp,
            now,
        )
        .with_destination_port(0)
        .build();

        assert_eq!(result.unwrap_err(), DomainError::InvalidPort);
    }

    #[test]
    fn test_metadata_bounds() {
        let mut meta = EventMetadata::new();
        for i in 0..MAX_METADATA_ENTRIES {
            meta.insert(format!("key_{i}"), format!("val_{i}"))
                .expect("insert within bound");
        }
        let overflow_res = meta.insert("extra_key", "extra_val");
        assert!(matches!(
            overflow_res,
            Err(DomainError::MetadataTooManyEntries { .. })
        ));
    }

    #[test]
    fn test_serde_roundtrip() {
        let now = Utc::now();
        let event = NetworkEventBuilder::new(
            TelemetrySource::WindowsTcpSnapshot,
            NetworkProtocol::Udp,
            now,
        )
        .with_source_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .with_source_port(53)
        .build()
        .expect("valid event");

        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: NetworkEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, deserialized);
    }
}
