# Windows TCP Telemetry Specification: SentinelX

## 1. Overview & Operational Philosophy

SentinelX Phase 2 introduces a native Windows telemetry collector designed to observe local TCP connection states on **Windows 11** systems.

The collector operates with the following design constraints:
- **Strictly Read-Only**: Sockets are neither modified, redirected, filtered, nor terminated.
- **Unprivileged Operation**: Operates entirely within standard user permissions (`SeDebugPrivilege` or Administrator rights are **not** required).
- **Non-Invasive**: Requires no kernel drivers, no packet capture drivers (such as Npcap or WinPcap), and no modifications to Windows Defender Firewall.
- **Defensive Boundary**: Native Windows FFI operations are isolated behind a small, heavily validated interface with robust buffer boundary checks.

---

## 2. Native Windows API Architecture

### 2.1 The IP Helper API (`GetExtendedTcpTable`)

To inspect local TCP connection tables, SentinelX queries the documented Windows IP Helper function:

```c
DWORD GetExtendedTcpTable(
  [out]     PVOID           pTcpTable,
  [in, out] PDWORD          pdwSize,
  [in]      BOOL            bOrder,
  [in]      ULONG           ulAf,
  [in]      TCP_TABLE_CLASS TableClass,
  [in]      ULONG           Reserved
);
```

SentinelX targets `TableClass = TCP_TABLE_OWNER_PID_ALL`, allowing user-mode enumeration of all active TCP connections along with the owning process identifier (`dwOwningPid`).

### 2.2 Table Formats

SentinelX supports both IPv4 and IPv6 network stacks:

| Address Family | WinSock Constant | Native Table Structure | Row Structure |
| :--- | :--- | :--- | :--- |
| **IPv4** | `AF_INET` | `MIB_TCPTABLE_OWNER_PID` | `MIB_TCPROW_OWNER_PID` |
| **IPv6** | `AF_INET6` | `MIB_TCP6TABLE_OWNER_PID` | `MIB_TCP6ROW_OWNER_PID` |

### 2.3 Dynamic Buffer Sizing & Race Handling

Because network connections are dynamically created and destroyed by active processes, the required buffer size can fluctuate between the initial sizing query and the data retrieval query.

SentinelX implements a two-pass retry loop:
1. SentinelX issues an initial call passing `pTcpTable = NULL` and `&raw mut buffer_size`. The API returns `ERROR_INSUFFICIENT_BUFFER` (Win32 error `122`) and populates `buffer_size` with the byte count needed.
2. A contiguous byte buffer `Vec<u8>` is allocated with the requested capacity.
3. SentinelX issues a second call passing `buffer.as_mut_ptr().cast()`.
4. If a burst of new connections causes the second call to also return `ERROR_INSUFFICIENT_BUFFER`, SentinelX retries up to `MAX_BUFFER_RETRIES` (3 attempts), re-querying the increased size.
5. If the OS returns an unexpected status code (e.g., access denied or invalid parameter), collection fails explicitly with `CollectorError::NativeApiFailure` and does **not** panic or emit a misleading empty snapshot.

---

## 3. Memory Safety & Unsafe Code Isolation

### 3.1 Unsafe Boundaries
All Windows API calls and raw pointer manipulations are confined to a single file:
[`crates/sentinel-collector/src/windows_tcp.rs`](../crates/sentinel-collector/src/windows_tcp.rs).

In contrast, `sentinel-core` and `sentinel-detection` enforce `#![forbid(unsafe_code)]`.

### 3.2 Pointer Alignment & `read_unaligned`
The native Windows structures `MIB_TCPTABLE_OWNER_PID` and `MIB_TCP6TABLE_OWNER_PID` consist of a 32-bit entry count `dwNumEntries` followed immediately by a variable-length array of row structs. Casting raw byte pointers directly to struct pointers can violate CPU alignment requirements on certain architectures or trip Rust compiler lints (`clippy::cast_ptr_alignment`).

SentinelX resolves this by using:
```rust
let row = std::ptr::read_unaligned(row_ptr);
```
`std::ptr::read_unaligned` safely performs an alignment-safe byte copy into typed Rust memory before accessing fields.

### 3.3 Boundary and Size Validation
Before reading rows from the buffer, SentinelX calculates:
$$\text{expected\_size} = \text{header\_size} + (\text{num\_entries} \times \text{row\_size})$$
using checked arithmetic (`checked_mul` and `checked_add`). If `buffer.len() < expected_size` or an integer overflow occurs, the raw data is rejected with `CollectorError::InvalidTableData`.

---

## 4. Fields Collected & Byte-Order Normalization

### 4.1 Field Mapping

| Native Field | Native Type | Byte Order | Normalized Domain Model Field |
| :--- | :--- | :--- | :--- |
| `dwLocalAddr` / `ucLocalAddr` | `DWORD` / `[u8; 16]` | Big-Endian (Network) | `NetworkEvent.source_ip` (`std::net::IpAddr`) |
| `dwLocalPort` | `DWORD` | Big-Endian (Network) | `NetworkEvent.source_port` (`u16`) |
| `dwRemoteAddr` / `ucRemoteAddr` | `DWORD` / `[u8; 16]` | Big-Endian (Network) | `NetworkEvent.destination_ip` (`std::net::IpAddr`) |
| `dwRemotePort` | `DWORD` | Big-Endian (Network) | `NetworkEvent.destination_port` (`u16`) |
| `dwState` | `DWORD` | Native Host | `NetworkEvent.metadata["tcp_state"]` (`TcpState`) |
| `dwOwningPid` | `DWORD` | Native Host | `NetworkEvent.process_id` (`ProcessId`) |

### 4.2 Endianness Conversion
The Windows IP Helper API stores IP addresses and port numbers in **network byte order (big-endian)**:
- **IPv4 Address**: Read as a 32-bit word, converted using `u32::from_be(dw_addr)` and decoded to `Ipv4Addr`.
- **TCP Ports**: The port number is stored in the lower 16 bits of the `DWORD` in network byte order. Decoded using `(dw_port as u16).to_be()`.
- **IPv6 Address**: Represented as a 16-byte array `[u8; 16]` in network order; mapped directly to `Ipv6Addr::from(uc_addr)`.

### 4.3 TCP Connection State Mapping
The native `dwState` field is mapped to SentinelX's validated `TcpState` enum:

| Win32 Constant | Value | Mapped `TcpState` | Description |
| :--- | :--- | :--- | :--- |
| `MIB_TCP_STATE_CLOSED` | 1 | `Closed` | Socket is closed |
| `MIB_TCP_STATE_LISTEN` | 2 | `Listen` | Listening for incoming connections |
| `MIB_TCP_STATE_SYN_SENT` | 3 | `SynSent` | Active open; SYN packet sent |
| `MIB_TCP_STATE_SYN_RCVD` | 4 | `SynReceived` | SYN received, ACK sent |
| `MIB_TCP_STATE_ESTAB` | 5 | `Established` | Connection fully established |
| `MIB_TCP_STATE_FIN_WAIT1` | 6 | `FinWait1` | Socket closing; FIN sent |
| `MIB_TCP_STATE_FIN_WAIT2` | 7 | `FinWait2` | Awaiting remote FIN |
| `MIB_TCP_STATE_CLOSE_WAIT` | 8 | `CloseWait` | Remote closed; waiting for local close |
| `MIB_TCP_STATE_CLOSING` | 9 | `Closing` | Mutual FIN exchange |
| `MIB_TCP_STATE_LAST_ACK` | 10 | `LastAck` | Awaiting final ACK |
| `MIB_TCP_STATE_TIME_WAIT` | 11 | `TimeWait` | Waiting for old packets to expire |
| `MIB_TCP_STATE_DELETE_TCB` | 12 | `DeleteTcb` | Deleting Transmission Control Block |

---

## 5. Normalization Policies & Skipped Records

Not every record in the OS TCP table represents an active network communication between two distinct hosts. SentinelX enforces explicit normalization policies:

### 5.1 Listening Sockets (`SkipReason::ListeningSocket`)
In Windows TCP tables, sockets in the `Listen` state have:
- `remote_addr = 0.0.0.0` (or `::`)
- `remote_port = 0`

Because `NetworkEvent` models communications with non-zero source and destination endpoints, sockets in `TcpState::Listen` or sockets with `remote_port == 0` are **skipped**. They are recorded in `CollectionStats.records_skipped` with `SkipReason::ListeningSocket`.

### 5.2 Invalid Endpoints (`SkipReason::InvalidLocalPort` / `SkipReason::InvalidRemotePort`)
If a record contains `local_port == 0` or an invalid port outside `1..=65535`, it is rejected.

---

## 6. Snapshot Collection Limitations

SentinelX's Phase 2 TCP snapshot collector is a **point-in-time state inspector**, not a continuous packet capture system or intrusion detection driver. Analysts must understand its inherent limitations:

1. **Transient Connection Blindspots**: Connections established and torn down between polling intervals (e.g., short-lived DNS-over-TCP queries or rapid port probes) may not appear in the snapshot.
2. **No Failed TCP Handshakes**: Failed connection attempts (`SYN` without answer or `RST` responses) may not register as established rows in the IP Helper table.
3. **No UDP Telemetry**: `GetExtendedTcpTable` only exposes TCP. UDP endpoint tracking requires `GetExtendedUdpTable` (planned for future phases).
4. **No Packet Payload or Headers**: Telemetry is purely metadata (IP, port, state, PID). No payload bytes, HTTP headers, or TLS certificates are collected.
5. **Repeated Observations of Persistent Connections**: Long-lived connections (e.g., active database connections, SSH sessions, browser HTTP/2 keep-alives) will be observed in every consecutive snapshot cycle.
   - In Phase 2 (prior to SQLite persistent deduplication in Phase 3), if a single local source maintains concurrent connections to more than `distinct_port_threshold` remote ports, repeated snapshots will generate alerts for each snapshot.
6. **Localhost IPC Sweep Detections**: High-volume local inter-process communication (e.g., developer IDEs, language servers, microservice sidecars) contacting numerous localhost loopback ports will trigger detection rules if the threshold is configured lower than the local software baseline.
