//! Native Windows TCP connection table collector using IP Helper API (`GetExtendedTcpTable`).
//!
//! # Defensive Security & Privilege Notice
//! This collector operates entirely in read-only mode using user-mode Windows IP Helper
//! APIs. It requires **no administrator privileges** for standard TCP table queries,
//! **no kernel drivers**, and **no packet filtering drivers**.
//!
//! # Telemetry Limitations
//! - Sockets in `LISTEN` state do not represent active peer-to-peer connections and are
//!   categorized as listening endpoints.
//! - Transient, sub-millisecond connections that open and close between polling cycles
//!   will not be captured in snapshot telemetry.
//! - UDP endpoints and raw packet payloads are outside the scope of this collector.

use crate::error::CollectorError;
use crate::normalize::{
    RawTcpRecord, TcpState, decode_ipv4_addr, decode_ipv6_addr, decode_tcp_port, normalize_batch,
};
use crate::source::{CollectionBatch, CollectionMetadata, TelemetryCollector};
use chrono::Utc;
use sentinel_core::event::TelemetrySource;
use std::time::Instant;
use tracing::{debug, info, instrument, warn};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Maximum retry attempts when native table size expands during collection sampling.
const MAX_BUFFER_RETRIES: usize = 3;
/// Maximum number of records accepted from native TCP table snapshot to prevent memory exhaustion.
pub const MAX_SNAPSHOT_RECORDS: usize = 50_000;

/// Native Windows TCP connection table snapshot collector.
#[derive(Debug)]
pub struct WindowsTcpCollector {
    name: String,
    source: TelemetrySource,
}

impl Default for WindowsTcpCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsTcpCollector {
    /// Constructs a new [`WindowsTcpCollector`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "WindowsTcpCollector".to_string(),
            source: TelemetrySource::WindowsTcpSnapshot,
        }
    }

    /// Queries the native Windows IPv4 and IPv6 TCP tables using `GetExtendedTcpTable`.
    #[cfg(target_os = "windows")]
    fn fetch_raw_tables() -> Result<Vec<RawTcpRecord>, CollectorError> {
        let mut records = Vec::new();

        // 1. Fetch IPv4 TCP table:
        debug!("Fetching native Windows IPv4 TCP table (AF_INET)...");
        let ipv4_records = Self::query_extended_table_ipv4()?;
        debug!(count = ipv4_records.len(), "IPv4 records retrieved");
        records.extend(ipv4_records);

        // 2. Fetch IPv6 TCP table:
        debug!("Fetching native Windows IPv6 TCP table (AF_INET6)...");
        match Self::query_extended_table_ipv6() {
            Ok(ipv6_records) => {
                debug!(count = ipv6_records.len(), "IPv6 records retrieved");
                records.extend(ipv6_records);
            }
            Err(err) => {
                // If IPv6 is disabled on the host, log warning and continue with IPv4.
                warn!(
                    ?err,
                    "IPv6 TCP table query returned non-fatal error; continuing with IPv4"
                );
            }
        }

        Ok(records)
    }

    /// Helper for IPv4 `GetExtendedTcpTable` query.
    #[cfg(target_os = "windows")]
    #[allow(clippy::too_many_lines)]
    fn query_extended_table_ipv4() -> Result<Vec<RawTcpRecord>, CollectorError> {
        let mut buffer_size: u32 = 0;

        // Step 1: Initial call to determine required buffer size.
        // SAFETY:
        // Passing null pointer with buffer_size = 0. According to GetExtendedTcpTable documentation,
        // it fails with ERROR_INSUFFICIENT_BUFFER and sets buffer_size to required byte count.
        let mut ret = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &raw mut buffer_size,
                0, // bOrder = FALSE
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        let mut buffer: Vec<u8>;
        let mut attempts = 0;

        loop {
            if ret != ERROR_INSUFFICIENT_BUFFER && ret != NO_ERROR {
                return Err(CollectorError::NativeApiFailure {
                    code: ret,
                    message: format!(
                        "GetExtendedTcpTable (IPv4 sizing) returned Win32 error {ret}"
                    ),
                });
            }

            buffer = vec![0u8; buffer_size as usize];

            // SAFETY:
            // buffer has been allocated with at least buffer_size bytes.
            // GetExtendedTcpTable writes up to buffer_size bytes into buffer.as_mut_ptr().
            ret = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast(),
                    &raw mut buffer_size,
                    0,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if ret == NO_ERROR {
                break;
            }

            if ret == ERROR_INSUFFICIENT_BUFFER && attempts < MAX_BUFFER_RETRIES {
                attempts += 1;
                debug!(
                    attempts,
                    buffer_size, "TCP table expanded; retrying allocation"
                );
                continue;
            }

            return Err(CollectorError::NativeApiFailure {
                code: ret,
                message: format!("GetExtendedTcpTable (IPv4 fetch) returned Win32 error {ret}"),
            });
        }

        // Validate buffer boundary:
        // Table layout: dwNumEntries: u32, followed by array of MIB_TCPROW_OWNER_PID.
        let header_size = std::mem::size_of::<u32>();
        if buffer.len() < header_size {
            return Err(CollectorError::InvalidTableData(
                "IPv4 TCP table buffer smaller than header".to_string(),
            ));
        }

        // SAFETY:
        // We verified buffer.len() >= size_of::<u32>(). read_unaligned prevents alignment faults.
        let num_entries =
            unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
        if num_entries > MAX_SNAPSHOT_RECORDS {
            return Err(CollectorError::InvalidTableData(format!(
                "IPv4 TCP table entries ({num_entries}) exceeds maximum safety bound of {MAX_SNAPSHOT_RECORDS}"
            )));
        }
        let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

        let expected_size = header_size
            .checked_add(num_entries.checked_mul(row_size).ok_or_else(|| {
                CollectorError::InvalidTableData(
                    "integer overflow calculating row table size".to_string(),
                )
            })?)
            .ok_or_else(|| {
                CollectorError::InvalidTableData(
                    "integer overflow calculating total table size".to_string(),
                )
            })?;

        if buffer.len() < expected_size {
            return Err(CollectorError::InvalidTableData(format!(
                "IPv4 TCP table buffer ({} bytes) smaller than required rows ({} bytes)",
                buffer.len(),
                expected_size
            )));
        }

        let mut records = Vec::with_capacity(num_entries);

        // SAFETY:
        // Buffer verified to hold expected_size bytes. read_unaligned safely copies each row.
        unsafe {
            let base_ptr = buffer
                .as_ptr()
                .add(header_size)
                .cast::<MIB_TCPROW_OWNER_PID>();
            for i in 0..num_entries {
                let row_ptr = base_ptr.add(i);
                let row = std::ptr::read_unaligned(row_ptr);

                records.push(RawTcpRecord {
                    local_addr: std::net::IpAddr::V4(decode_ipv4_addr(row.dwLocalAddr)),
                    local_port: decode_tcp_port(row.dwLocalPort),
                    remote_addr: std::net::IpAddr::V4(decode_ipv4_addr(row.dwRemoteAddr)),
                    remote_port: decode_tcp_port(row.dwRemotePort),
                    state: TcpState::from_raw(row.dwState),
                    owning_pid: Some(row.dwOwningPid),
                });
            }
        }

        Ok(records)
    }

    /// Helper for IPv6 `GetExtendedTcpTable` query.
    #[cfg(target_os = "windows")]
    #[allow(clippy::too_many_lines)]
    fn query_extended_table_ipv6() -> Result<Vec<RawTcpRecord>, CollectorError> {
        let mut buffer_size: u32 = 0;

        // Step 1: Initial call to determine required buffer size.
        // SAFETY:
        // Passing null pointer with buffer_size = 0. According to GetExtendedTcpTable documentation,
        // it fails with ERROR_INSUFFICIENT_BUFFER and sets buffer_size to required byte count.
        let mut ret = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &raw mut buffer_size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        let mut buffer: Vec<u8>;
        let mut attempts = 0;

        loop {
            if ret != ERROR_INSUFFICIENT_BUFFER && ret != NO_ERROR {
                return Err(CollectorError::NativeApiFailure {
                    code: ret,
                    message: format!(
                        "GetExtendedTcpTable (IPv6 sizing) returned Win32 error {ret}"
                    ),
                });
            }

            buffer = vec![0u8; buffer_size as usize];

            // SAFETY:
            // buffer has been allocated with at least buffer_size bytes.
            // GetExtendedTcpTable writes up to buffer_size bytes into buffer.as_mut_ptr().
            ret = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast(),
                    &raw mut buffer_size,
                    0,
                    AF_INET6 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if ret == NO_ERROR {
                break;
            }

            if ret == ERROR_INSUFFICIENT_BUFFER && attempts < MAX_BUFFER_RETRIES {
                attempts += 1;
                debug!(
                    attempts,
                    buffer_size, "IPv6 TCP table expanded; retrying allocation"
                );
                continue;
            }

            return Err(CollectorError::NativeApiFailure {
                code: ret,
                message: format!("GetExtendedTcpTable (IPv6 fetch) returned Win32 error {ret}"),
            });
        }

        let header_size = std::mem::size_of::<u32>();
        if buffer.len() < header_size {
            return Err(CollectorError::InvalidTableData(
                "IPv6 TCP table buffer smaller than header".to_string(),
            ));
        }

        // SAFETY:
        // Buffer verified to hold header_size bytes. read_unaligned prevents alignment faults.
        let num_entries =
            unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
        if num_entries > MAX_SNAPSHOT_RECORDS {
            return Err(CollectorError::InvalidTableData(format!(
                "IPv6 TCP table entries ({num_entries}) exceeds maximum safety bound of {MAX_SNAPSHOT_RECORDS}"
            )));
        }
        let row_size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();

        let expected_size = header_size
            .checked_add(num_entries.checked_mul(row_size).ok_or_else(|| {
                CollectorError::InvalidTableData(
                    "integer overflow in IPv6 row table size".to_string(),
                )
            })?)
            .ok_or_else(|| {
                CollectorError::InvalidTableData(
                    "integer overflow in IPv6 total table size".to_string(),
                )
            })?;

        if buffer.len() < expected_size {
            return Err(CollectorError::InvalidTableData(format!(
                "IPv6 TCP table buffer ({} bytes) smaller than required rows ({} bytes)",
                buffer.len(),
                expected_size
            )));
        }

        let mut records = Vec::with_capacity(num_entries);

        // SAFETY:
        // Buffer verified to hold expected_size bytes. read_unaligned safely copies each row.
        unsafe {
            let base_ptr = buffer
                .as_ptr()
                .add(header_size)
                .cast::<MIB_TCP6ROW_OWNER_PID>();
            for i in 0..num_entries {
                let row_ptr = base_ptr.add(i);
                let row = std::ptr::read_unaligned(row_ptr);

                records.push(RawTcpRecord {
                    local_addr: std::net::IpAddr::V6(decode_ipv6_addr(row.ucLocalAddr)),
                    local_port: decode_tcp_port(row.dwLocalPort),
                    remote_addr: std::net::IpAddr::V6(decode_ipv6_addr(row.ucRemoteAddr)),
                    remote_port: decode_tcp_port(row.dwRemotePort),
                    state: TcpState::from_raw(row.dwState),
                    owning_pid: Some(row.dwOwningPid),
                });
            }
        }

        Ok(records)
    }

    /// Non-Windows platform fallback.
    #[cfg(not(target_os = "windows"))]
    fn fetch_raw_tables() -> Result<Vec<RawTcpRecord>, CollectorError> {
        Err(CollectorError::UnsupportedPlatform(
            "Native TCP connection table collection via IP Helper API is only supported on Windows"
                .to_string(),
        ))
    }
}

impl TelemetryCollector for WindowsTcpCollector {
    fn name(&self) -> &str {
        &self.name
    }

    fn source(&self) -> TelemetrySource {
        self.source
    }

    #[instrument(skip(self), name = "windows_tcp_collect")]
    fn collect(&mut self) -> Result<CollectionBatch, CollectorError> {
        let start_instant = Instant::now();
        let start_time = Utc::now();

        info!("Initiating native Windows TCP connection table snapshot");
        let raw_records = Self::fetch_raw_tables()?;
        let raw_count = raw_records.len();
        debug!(
            raw_records = raw_count,
            "Raw TCP connection records retrieved from OS"
        );

        let (events, skipped) = normalize_batch(raw_records, self.source, start_time);
        let normalized_count = events.len();
        let skipped_count = skipped.len();
        let skip_reasons = skipped.into_iter().map(|(_, reason)| reason).collect();

        let end_time = Utc::now();
        let duration = start_instant.elapsed();

        info!(
            raw_records = raw_count,
            normalized_events = normalized_count,
            skipped_records = skipped_count,
            latency = ?duration,
            "Native Windows TCP table collection completed"
        );

        let metadata = CollectionMetadata {
            start_time,
            end_time,
            duration,
            raw_records_observed: raw_count,
            normalized_events_produced: normalized_count,
            records_skipped: skipped_count,
            skip_reasons,
        };

        Ok(CollectionBatch::new(events, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_tcp_collector_creation() {
        let collector = WindowsTcpCollector::new();
        assert_eq!(collector.name(), "WindowsTcpCollector");
        assert_eq!(collector.source(), TelemetrySource::WindowsTcpSnapshot);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_native_windows_collection_live() {
        let mut collector = WindowsTcpCollector::new();
        let result = collector.collect();
        assert!(
            result.is_ok(),
            "Native Windows TCP collection should succeed as standard user"
        );

        let batch = result.unwrap();
        // A live Windows workstation routinely has active TCP connections and listening endpoints:
        assert!(
            batch.metadata.raw_records_observed > 0,
            "Expected at least 1 TCP connection on host"
        );
        assert!(
            batch.metadata.duration.as_millis() < 5000,
            "Collection latency should be fast"
        );
    }
}
