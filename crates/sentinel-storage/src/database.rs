//! Database connection lifecycle, connection pooling, SQLite PRAGMA configuration,
//! and schema migration orchestration.

use crate::error::StorageError;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, info, instrument};

/// Default busy timeout for SQLite connections to wait before reporting a lock error.
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum concurrent connection pool size for local embedded operations.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;

/// Configuration options for initializing the SQLite database pool and schema.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Filesystem path to the SQLite database file.
    pub database_path: PathBuf,
    /// Maximum number of concurrent connections in the connection pool.
    pub max_connections: u32,
    /// Maximum time to wait for a database lock before returning busy error.
    pub busy_timeout: Duration,
    /// Whether to automatically create the database file and parent directories if missing.
    pub create_if_missing: bool,
    /// Whether to execute embedded SQLx migrations automatically on pool initialization.
    pub run_migrations: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("data/sentinelx.db"),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            create_if_missing: true,
            run_migrations: true,
        }
    }
}

impl DatabaseConfig {
    /// Creates a database configuration pointing to the specified database file path.
    #[must_use]
    pub fn new(database_path: impl Into<PathBuf>) -> Self {
        Self {
            database_path: database_path.into(),
            ..Default::default()
        }
    }

    /// Sets the maximum connection pool size.
    #[must_use]
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the busy timeout duration.
    #[must_use]
    pub fn with_busy_timeout(mut self, timeout: Duration) -> Self {
        self.busy_timeout = timeout;
        self
    }

    /// Toggles whether migrations run during initialization.
    #[must_use]
    pub fn with_migrations(mut self, run: bool) -> Self {
        self.run_migrations = run;
        self
    }
    /// Validates database configuration parameters and path safety.
    ///
    /// # Errors
    /// Returns [`StorageError::InvalidParameter`] if path is empty, contains null bytes,
    /// or if connection pool limits are invalid.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.database_path.as_os_str().is_empty() {
            return Err(StorageError::InvalidParameter(
                "Database path cannot be empty".to_string(),
            ));
        }

        let path_str = self.database_path.to_string_lossy();
        if path_str.contains('\0') {
            return Err(StorageError::InvalidParameter(
                "Database path contains invalid null byte".to_string(),
            ));
        }

        if self.max_connections == 0 {
            return Err(StorageError::InvalidParameter(
                "max_connections must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Central database abstraction managing the underlying SQLite connection pool,
/// active migrations, and transaction lifecycles.
#[derive(Debug, Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Connects to a SQLite database with the given configuration, enforces WAL mode,
    /// turns on foreign key enforcement on every connection, and applies migrations.
    ///
    /// # Errors
    /// Returns [`StorageError::InvalidParameter`] if config validation fails,
    /// [`StorageError::Io`] if directory creation fails, [`StorageError::Database`]
    /// if connection establishment fails, or [`StorageError::Migration`] if schema
    /// migrations fail.
    #[instrument(skip(config), fields(db_path = %config.database_path.display()))]
    pub async fn new(config: &DatabaseConfig) -> Result<Self, StorageError> {
        config.validate()?;

        if config.create_if_missing
            && let Some(parent) = config.database_path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            info!(dir = %parent.display(), "Creating database parent directory");
            std::fs::create_dir_all(parent)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let connect_opts = SqliteConnectOptions::new()
            .filename(&config.database_path)
            .create_if_missing(config.create_if_missing)
            .foreign_keys(true)
            .busy_timeout(config.busy_timeout)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);

        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .connect_with(connect_opts)
            .await?;

        let db = Self { pool };

        if config.run_migrations {
            db.migrate().await?;
        }

        info!("Database initialized and configured successfully");
        Ok(db)
    }

    /// Initializes a transient in-memory database with shared cache and migrations applied.
    /// Suitable for unit tests and isolated property testing.
    ///
    /// # Errors
    /// Returns [`StorageError`] if migration or connection fails.
    pub async fn in_memory() -> Result<Self, StorageError> {
        let uri = format!("file:mem_{}?mode=memory&cache=shared", uuid::Uuid::new_v4());
        let connect_opts = SqliteConnectOptions::from_str(&uri)?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(DEFAULT_BUSY_TIMEOUT);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_opts)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Initializes a temporary file-backed database in an isolated directory.
    ///
    /// # Errors
    /// Returns [`StorageError`] if creation or migrations fail.
    pub async fn from_file(path: &Path) -> Result<Self, StorageError> {
        let config = DatabaseConfig::new(path);
        Self::new(&config).await
    }

    /// Executes embedded SQLx schema migrations against the connection pool.
    ///
    /// # Errors
    /// Returns [`StorageError::Migration`] if migration SQL scripts encounter errors.
    #[instrument(skip(self))]
    pub async fn migrate(&self) -> Result<(), StorageError> {
        debug!("Applying embedded database migrations...");
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(StorageError::Migration)?;
        debug!("Embedded database migrations applied successfully");
        Ok(())
    }

    /// Returns a reference to the inner SQLx SQLite connection pool.
    #[must_use]
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Gracefully closes all idle connections in the pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
