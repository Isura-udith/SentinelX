//! Network event persistence, transactional batched ingestion, and bounded querying.

use crate::error::StorageError;
use chrono::{DateTime, Utc};
use sentinel_core::event::{
    EventId, EventMetadata, NetworkEvent, NetworkProtocol, ProcessId, TelemetrySource,
};
use sqlx::{Row, SqlitePool};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

/// Default page limit for querying persisted events.
pub const DEFAULT_EVENT_QUERY_LIMIT: usize = 100;
/// Maximum allowed page limit to prevent excessive memory consumption.
pub const MAX_EVENT_QUERY_LIMIT: usize = 1000;

/// Bounded query filter parameters for retrieving persisted network events.
#[derive(Debug, Clone, Default)]
pub struct EventQueryFilter {
    /// Optional filter for source IP address.
    pub source_ip: Option<IpAddr>,
    /// Optional filter for destination IP address.
    pub destination_ip: Option<IpAddr>,
    /// Optional filter for protocol.
    pub protocol: Option<NetworkProtocol>,
    /// Optional filter for telemetry source.
    pub source: Option<TelemetrySource>,
    /// Optional search text matching address, protocol, or source.
    pub search_text: Option<String>,
    /// Optional filter for destination port.
    pub destination_port: Option<u16>,
    /// Optional start boundary for event observation time (inclusive).
    pub start_time: Option<DateTime<Utc>>,
    /// Optional end boundary for event observation time (inclusive).
    pub end_time: Option<DateTime<Utc>>,
    /// Page size limit (enforced between 1 and `MAX_EVENT_QUERY_LIMIT`).
    pub limit: usize,
    /// Offset for pagination.
    pub offset: usize,
    /// Whether to sort in descending chronological order (newest first).
    pub sort_desc: bool,
}

impl EventQueryFilter {
    /// Creates a query filter with default bounded pagination limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limit: DEFAULT_EVENT_QUERY_LIMIT,
            ..Default::default()
        }
    }

    /// Sets the maximum number of items to return, clamped to `MAX_EVENT_QUERY_LIMIT`.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, MAX_EVENT_QUERY_LIMIT);
        self
    }

    /// Sets the query offset for pagination.
    #[must_use]
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Filters by source IP address.
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Filters by destination IP address.
    #[must_use]
    pub fn with_destination_ip(mut self, ip: IpAddr) -> Self {
        self.destination_ip = Some(ip);
        self
    }

    /// Filters by protocol.
    #[must_use]
    pub fn with_protocol(mut self, protocol: NetworkProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Filters by telemetry source.
    #[must_use]
    pub fn with_source(mut self, source: TelemetrySource) -> Self {
        self.source = Some(source);
        self
    }

    /// Filters with free-text search.
    #[must_use]
    pub fn with_search_text(mut self, text: impl Into<String>) -> Self {
        self.search_text = Some(text.into());
        self
    }

    /// Filters by destination port.
    #[must_use]
    pub fn with_destination_port(mut self, port: u16) -> Self {
        self.destination_port = Some(port);
        self
    }

    /// Filters by observation time range.
    #[must_use]
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Sets chronological sort direction.
    #[must_use]
    pub fn with_sort_desc(mut self, sort_desc: bool) -> Self {
        self.sort_desc = sort_desc;
        self
    }
}

/// A persisted network event record, containing the normalized domain event
/// along with the storage ingestion timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedEvent {
    /// Normalized network event domain model.
    pub event: NetworkEvent,
    /// UTC timestamp recorded when the event was committed to persistent storage.
    pub ingested_at: DateTime<Utc>,
}

/// Outcome statistics for a batched event ingestion operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchInsertResult {
    /// Number of new event records successfully inserted.
    pub inserted_count: usize,
    /// Number of duplicate event IDs ignored.
    pub duplicate_count: usize,
}

/// Repository providing persistent CRUD operations, transactional batch ingestion,
/// and bounded queries over network events in SQLite.
#[derive(Debug, Clone)]
pub struct EventRepository {
    pool: SqlitePool,
}

impl EventRepository {
    /// Creates an `EventRepository` backed by the provided SQLite connection pool.
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Inserts a single validated event into the database.
    ///
    /// If an event with the same ID already exists, the operation is an idempotent no-op.
    ///
    /// # Errors
    /// Returns [`StorageError::Domain`] if event validation fails, or [`StorageError::Database`]
    /// on database errors.
    #[instrument(skip(self, event), fields(event_id = %event.id))]
    pub async fn insert_event(&self, event: &NetworkEvent) -> Result<bool, StorageError> {
        event.validate().map_err(StorageError::Domain)?;
        let now = Utc::now();
        let inserted = Self::insert_event_row(&self.pool, event, now).await?;
        Ok(inserted)
    }

    /// Inserts a batch of network events inside a single database transaction.
    ///
    /// If any event in the batch violates domain validation or encounters a database error,
    /// the entire transaction is rolled back and no events from the batch are committed.
    /// Duplicate event IDs are skipped idempotently (`INSERT OR IGNORE`).
    ///
    /// # Errors
    /// Returns [`StorageError`] if validation fails or the transaction encounters an error.
    #[instrument(skip(self, events), fields(batch_size = events.len()))]
    pub async fn insert_events_batch(
        &self,
        events: &[NetworkEvent],
    ) -> Result<BatchInsertResult, StorageError> {
        if events.is_empty() {
            return Ok(BatchInsertResult::default());
        }

        // Validate all events upfront before beginning the transaction
        for event in events {
            event.validate().map_err(StorageError::Domain)?;
        }

        let now = Utc::now();
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;

        let mut inserted_count = 0;
        let mut duplicate_count = 0;

        for event in events {
            let row_inserted = Self::insert_event_row(&mut *tx, event, now).await?;
            if row_inserted {
                inserted_count += 1;
            } else {
                duplicate_count += 1;
            }
        }

        tx.commit().await.map_err(StorageError::Database)?;

        debug!(
            inserted = inserted_count,
            duplicates = duplicate_count,
            "Committed batch event ingestion transaction"
        );

        Ok(BatchInsertResult {
            inserted_count,
            duplicate_count,
        })
    }

    /// Helper executing a parameterized `INSERT OR IGNORE` for a single event on an executor.
    async fn insert_event_row<'e, E>(
        executor: E,
        event: &NetworkEvent,
        ingested_at: DateTime<Utc>,
    ) -> Result<bool, StorageError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let id_str = event.id.to_string();
        let observed_at_str = event.timestamp.to_rfc3339();
        let source_str = event.source.to_string();
        let protocol_str = event.protocol.to_string();
        let source_ip_str = event.source_ip.as_ref().map(ToString::to_string);
        let source_port_val = event.source_port.map(i64::from);
        let dest_ip_str = event.destination_ip.as_ref().map(ToString::to_string);
        let dest_port_val = event.destination_port.map(i64::from);
        let pid_val = event.process_id.map(|p| i64::from(p.as_u32()));

        let metadata_map: BTreeMap<&str, &str> = event.metadata.iter().collect();
        let metadata_json = serde_json::to_string(&metadata_map)?;
        let ingested_at_str = ingested_at.to_rfc3339();

        let query = sqlx::query(
            r"
            INSERT OR IGNORE INTO events (
                id, observed_at, source, protocol, source_ip, source_port,
                destination_ip, destination_port, process_id, metadata_json, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(id_str)
        .bind(observed_at_str)
        .bind(source_str)
        .bind(protocol_str)
        .bind(source_ip_str)
        .bind(source_port_val)
        .bind(dest_ip_str)
        .bind(dest_port_val)
        .bind(pid_val)
        .bind(metadata_json)
        .bind(ingested_at_str);

        let result = query.execute(executor).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Fetches a single event by its unique identifier.
    ///
    /// # Errors
    /// Returns [`StorageError::Database`] on SQL failure or [`StorageError::Domain`] if
    /// stored data violates domain constraints.
    #[instrument(skip(self), fields(event_id = %id))]
    pub async fn get_event_by_id(
        &self,
        id: EventId,
    ) -> Result<Option<PersistedEvent>, StorageError> {
        let id_str = id.to_string();
        let row = sqlx::query(
            r"
            SELECT id, observed_at, source, protocol, source_ip, source_port,
                   destination_ip, destination_port, process_id, metadata_json, ingested_at
            FROM events
            WHERE id = ?
            ",
        )
        .bind(id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let event = Self::map_event_row(&row)?;
                let ingested_at_str: String = row.try_get("ingested_at")?;
                let ingested_at = DateTime::parse_from_rfc3339(&ingested_at_str)
                    .map_err(|e| {
                        StorageError::InvalidParameter(format!("invalid ingested_at: {e}"))
                    })?
                    .with_timezone(&Utc);

                Ok(Some(PersistedEvent { event, ingested_at }))
            }
            None => Ok(None),
        }
    }

    /// Queries events matching the bounded filter criteria.
    ///
    /// Results are returned in ascending chronological order of observation timestamp.
    ///
    /// # Errors
    /// Returns [`StorageError`] on query failure.
    #[instrument(skip(self))]
    pub async fn query_events(
        &self,
        filter: &EventQueryFilter,
    ) -> Result<Vec<PersistedEvent>, StorageError> {
        let limit = if filter.limit == 0 {
            DEFAULT_EVENT_QUERY_LIMIT
        } else {
            filter.limit.clamp(1, MAX_EVENT_QUERY_LIMIT)
        };

        let mut sql = String::from(
            r"
            SELECT id, observed_at, source, protocol, source_ip, source_port,
                   destination_ip, destination_port, process_id, metadata_json, ingested_at
            FROM events
            WHERE 1=1
            ",
        );

        #[derive(Debug)]
        enum SqlParam {
            Text(String),
            Int(i64),
        }

        let mut params: Vec<SqlParam> = Vec::new();

        if let Some(src_ip) = filter.source_ip {
            sql.push_str(" AND source_ip = ?");
            params.push(SqlParam::Text(src_ip.to_string()));
        }

        if let Some(dst_ip) = filter.destination_ip {
            sql.push_str(" AND destination_ip = ?");
            params.push(SqlParam::Text(dst_ip.to_string()));
        }

        if let Some(proto) = filter.protocol {
            sql.push_str(" AND protocol = ?");
            params.push(SqlParam::Text(proto.to_string()));
        }

        if let Some(src) = filter.source {
            sql.push_str(" AND source = ?");
            params.push(SqlParam::Text(src.to_string()));
        }

        if let Some(ref text) = filter.search_text {
            sql.push_str(" AND (source_ip LIKE ? OR destination_ip LIKE ? OR id LIKE ?)");
            let pattern = format!("%{text}%");
            params.push(SqlParam::Text(pattern.clone()));
            params.push(SqlParam::Text(pattern.clone()));
            params.push(SqlParam::Text(pattern));
        }

        if let Some(dst_port) = filter.destination_port {
            sql.push_str(" AND destination_port = ?");
            params.push(SqlParam::Int(i64::from(dst_port)));
        }

        if let Some(start) = filter.start_time {
            sql.push_str(" AND observed_at >= ?");
            params.push(SqlParam::Text(start.to_rfc3339()));
        }

        if let Some(end) = filter.end_time {
            sql.push_str(" AND observed_at <= ?");
            params.push(SqlParam::Text(end.to_rfc3339()));
        }

        if filter.sort_desc {
            sql.push_str(" ORDER BY observed_at DESC LIMIT ? OFFSET ?");
        } else {
            sql.push_str(" ORDER BY observed_at ASC LIMIT ? OFFSET ?");
        }

        let mut query = sqlx::query(&sql);
        for param in params {
            query = match param {
                SqlParam::Text(s) => query.bind(s),
                SqlParam::Int(i) => query.bind(i),
            };
        }
        query = query
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .bind(i64::try_from(filter.offset).unwrap_or(0));

        let rows = query.fetch_all(&self.pool).await?;
        let mut results = Vec::with_capacity(rows.len());

        for row in rows {
            let event = Self::map_event_row(&row)?;
            let ingested_at_str: String = row.try_get("ingested_at")?;
            let ingested_at = DateTime::parse_from_rfc3339(&ingested_at_str)
                .map_err(|e| StorageError::InvalidParameter(format!("invalid ingested_at: {e}")))?
                .with_timezone(&Utc);

            results.push(PersistedEvent { event, ingested_at });
        }

        Ok(results)
    }

    /// Counts events matching the bounded filter criteria.
    ///
    /// # Errors
    /// Returns [`StorageError`] on query failure.
    #[instrument(skip(self))]
    pub async fn count_matching_events(
        &self,
        filter: &EventQueryFilter,
    ) -> Result<usize, StorageError> {
        let mut sql = String::from("SELECT COUNT(*) FROM events WHERE 1=1");

        #[derive(Debug)]
        enum SqlParam {
            Text(String),
            Int(i64),
        }

        let mut params: Vec<SqlParam> = Vec::new();

        if let Some(src_ip) = filter.source_ip {
            sql.push_str(" AND source_ip = ?");
            params.push(SqlParam::Text(src_ip.to_string()));
        }

        if let Some(dst_ip) = filter.destination_ip {
            sql.push_str(" AND destination_ip = ?");
            params.push(SqlParam::Text(dst_ip.to_string()));
        }

        if let Some(proto) = filter.protocol {
            sql.push_str(" AND protocol = ?");
            params.push(SqlParam::Text(proto.to_string()));
        }

        if let Some(src) = filter.source {
            sql.push_str(" AND source = ?");
            params.push(SqlParam::Text(src.to_string()));
        }

        if let Some(ref text) = filter.search_text {
            sql.push_str(" AND (source_ip LIKE ? OR destination_ip LIKE ? OR id LIKE ?)");
            let pattern = format!("%{text}%");
            params.push(SqlParam::Text(pattern.clone()));
            params.push(SqlParam::Text(pattern.clone()));
            params.push(SqlParam::Text(pattern));
        }

        if let Some(dst_port) = filter.destination_port {
            sql.push_str(" AND destination_port = ?");
            params.push(SqlParam::Int(i64::from(dst_port)));
        }

        if let Some(start) = filter.start_time {
            sql.push_str(" AND observed_at >= ?");
            params.push(SqlParam::Text(start.to_rfc3339()));
        }

        if let Some(end) = filter.end_time {
            sql.push_str(" AND observed_at <= ?");
            params.push(SqlParam::Text(end.to_rfc3339()));
        }

        let mut query = sqlx::query_scalar::<_, i64>(&sql);
        for param in params {
            query = match param {
                SqlParam::Text(s) => query.bind(s),
                SqlParam::Int(i) => query.bind(i),
            };
        }

        let count = query.fetch_one(&self.pool).await?;
        Ok(count.max(0) as usize)
    }

    /// Returns the count of events observed at or after the given `since` timestamp.
    ///
    /// # Errors
    /// Returns [`StorageError::Database`] on SQL query failure.
    pub async fn count_events_since(&self, since: DateTime<Utc>) -> Result<usize, StorageError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE observed_at >= ?")
            .bind(since.to_rfc3339())
            .fetch_one(&self.pool)
            .await?;
        Ok(count.max(0) as usize)
    }

    /// Returns the total count of network events currently stored in the database.
    ///
    /// # Errors
    /// Returns [`StorageError::Database`] on SQL query failure.
    pub async fn count_events(&self) -> Result<usize, StorageError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.max(0) as usize)
    }

    /// Deletes expired events older than `cutoff` in a single bounded batch,
    /// strictly preserving any events that are linked as forensic evidence in `alert_events`.
    ///
    /// Returns the number of events deleted.
    ///
    /// # Errors
    /// Returns [`StorageError::Database`] on deletion failure.
    #[instrument(skip(self), fields(cutoff = %cutoff.to_rfc3339(), max_delete))]
    pub async fn delete_expired_events(
        &self,
        cutoff: DateTime<Utc>,
        max_delete: usize,
    ) -> Result<usize, StorageError> {
        let cutoff_str = cutoff.to_rfc3339();
        let limit = max_delete.clamp(1, 10_000) as i64;

        // Subquery ensures events linked to any security alerts are never deleted.
        let result = sqlx::query(
            r"
            DELETE FROM events
            WHERE id IN (
                SELECT id FROM events
                WHERE observed_at < ?
                  AND id NOT IN (SELECT event_id FROM alert_events)
                LIMIT ?
            )
            ",
        )
        .bind(cutoff_str)
        .bind(limit)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected() as usize;
        debug!(deleted, "Deleted expired events batch");
        Ok(deleted)
    }

    /// Maps a SQLite row into a validated [`NetworkEvent`] domain object.
    fn map_event_row(row: &sqlx::sqlite::SqliteRow) -> Result<NetworkEvent, StorageError> {
        let id_str: String = row.try_get("id")?;
        let uuid = Uuid::parse_str(&id_str)
            .map_err(|e| StorageError::InvalidParameter(format!("invalid event id: {e}")))?;
        let id = EventId::from_uuid(uuid);

        let observed_at_str: String = row.try_get("observed_at")?;
        let timestamp = DateTime::parse_from_rfc3339(&observed_at_str)
            .map_err(|e| StorageError::InvalidParameter(format!("invalid observed_at: {e}")))?
            .with_timezone(&Utc);

        let source_str: String = row.try_get("source")?;
        let source = match source_str.as_str() {
            "windows_tcp_snapshot" => TelemetrySource::WindowsTcpSnapshot,
            "synthetic_simulator" => TelemetrySource::SyntheticSimulator,
            "windows_event_telemetry" => TelemetrySource::WindowsEventTelemetry,
            "packet_metadata" => TelemetrySource::PacketMetadata,
            other => {
                warn!(
                    source = other,
                    "Unknown telemetry source; defaulting to SyntheticSimulator"
                );
                TelemetrySource::SyntheticSimulator
            }
        };

        let protocol_str: String = row.try_get("protocol")?;
        let protocol = match protocol_str.as_str() {
            "TCP" => NetworkProtocol::Tcp,
            "UDP" => NetworkProtocol::Udp,
            other => {
                return Err(StorageError::InvalidParameter(format!(
                    "unknown network protocol '{other}'"
                )));
            }
        };

        let source_ip: Option<IpAddr> =
            match row.try_get::<Option<String>, _>("source_ip")? {
                Some(src_ip_str) => Some(IpAddr::from_str(&src_ip_str).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid source_ip: {e}"))
                })?),
                None => None,
            };

        let source_port: Option<u16> = match row.try_get::<Option<i64>, _>("source_port")? {
            Some(p) => Some(u16::try_from(p).map_err(|e| {
                StorageError::InvalidParameter(format!("invalid source_port {p}: {e}"))
            })?),
            None => None,
        };

        let destination_ip: Option<IpAddr> =
            match row.try_get::<Option<String>, _>("destination_ip")? {
                Some(dst_ip_str) => Some(IpAddr::from_str(&dst_ip_str).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid destination_ip: {e}"))
                })?),
                None => None,
            };

        let destination_port: Option<u16> =
            match row.try_get::<Option<i64>, _>("destination_port")? {
                Some(p) => Some(u16::try_from(p).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid destination_port {p}: {e}"))
                })?),
                None => None,
            };

        let process_id: Option<ProcessId> = match row.try_get::<Option<i64>, _>("process_id")? {
            Some(pid) => {
                let pid_u32 = u32::try_from(pid).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid process_id {pid}: {e}"))
                })?;
                Some(ProcessId::new(pid_u32).map_err(|e| {
                    StorageError::InvalidParameter(format!("invalid process_id: {e}"))
                })?)
            }
            None => None,
        };

        let metadata_json: String = row.try_get("metadata_json")?;
        let metadata_map: BTreeMap<String, String> = serde_json::from_str(&metadata_json)?;
        let mut metadata = EventMetadata::new();
        for (k, v) in metadata_map {
            metadata.insert(k, v).map_err(StorageError::Domain)?;
        }

        let event = NetworkEvent {
            id,
            timestamp,
            source,
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            process_id,
            metadata,
        };

        event.validate().map_err(StorageError::Domain)?;
        Ok(event)
    }
}
