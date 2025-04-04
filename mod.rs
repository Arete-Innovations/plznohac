pub mod db;
pub mod enrichers;
pub mod macros;
pub mod middleware;
pub mod models;

pub use db::*;
pub use enrichers::*;
pub use macros::*;
pub use middleware::*;
pub use models::*;

use crate::cata_log;
use crate::services::sparks::registry::Spark;
use chrono::Utc;
use rocket::{Build, Rocket};
use serde_json::Value;
use std::sync::OnceLock;

pub static SECURITY_INSTANCE: OnceLock<PlzNoHac> = OnceLock::new();

// Create a wrapper for PlzNoHac that implements the Spark trait
struct PlzNoHacSpark {
    inner: PlzNoHac,
}

impl PlzNoHacSpark {
    fn new() -> Self {
        Self { inner: PlzNoHac::new() }
    }
}

impl Spark for PlzNoHacSpark {
    fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner.initialize().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let _ = SECURITY_INSTANCE.set(self.inner.clone());
        cata_log!(Info, "PlzNoHac spark initialized successfully");
        Ok(())
    }

    fn attach_to_rocket(&self, rocket: Rocket<Build>) -> Rocket<Build> {
        cata_log!(Info, "Attaching PlzNoHac spark to Rocket");
        rocket.attach(middleware::PlzNoHacMiddleware::attach(self.inner.clone())).manage(self.inner.clone())
    }

    fn name(&self) -> &str {
        "plznohac"
    }
}

// Export a function to create the spark
pub fn create_spark() -> Box<dyn crate::services::sparks::registry::Spark> {
    Box::new(PlzNoHacSpark::new())
}

/// Identity context for security events
///
/// Represents user or system identity data in a flexible JSON format
#[derive(Debug, Clone)]
pub struct IdentityContext {
    pub data: Value,
}

impl IdentityContext {
    /// Create a new identity context with given JSON data
    pub fn new(data: Value) -> Self {
        Self { data }
    }

    /// Convert identity to JSON representation
    pub fn to_json(&self) -> Value {
        self.data.clone()
    }
}

/// Main entry point for PlzNoHac security spark
///
/// This struct provides the main interface for interacting with the security system.
/// Initialize it once at application startup and use it throughout the app.
///
/// # Configuration
///
/// This spark supports the following configuration options that can be set in Catalyst.toml:
///
/// ```toml
/// [spark.plznohac]
/// enable_real_time_alerts = false  # Enable real-time alerts for critical events
/// log_level = "info"               # Logging level (trace, debug, info, warning, error)
/// max_event_retention_days = 90    # How many days to retain security events
/// ```
///
/// Configuration is loaded from multiple sources with the following priority:
/// 1. Catalyst.toml spark section
/// 2. Environment variables (PLZNOHAC_ENABLE_ALERTS, PLZNOHAC_LOG_LEVEL, etc.)
/// 3. Default values
#[derive(Clone)]
pub struct PlzNoHac {
    config: SecurityConfig,
    initialized: bool,
}

impl PlzNoHac {
    /// Create a new PlzNoHac instance with configuration loaded from Catalyst.toml
    ///
    /// This is the recommended way to initialize the spark. It will:
    /// 1. Load configuration from Catalyst.toml [spark.plznohac] section
    /// 2. Fall back to environment variables if config options aren't in TOML
    /// 3. Use sensible defaults for any values not specified
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut security = PlzNoHac::new();
    /// security.initialize()?;
    /// ```
    pub fn new() -> Self {
        let config = Self::load_config();
        Self { config, initialized: false }
    }

    /// Create a new PlzNoHac instance with the given configuration
    pub fn with_config(config: SecurityConfig) -> Self {
        Self { config, initialized: false }
    }

    /// Load configuration from Catalyst.toml and environment variables
    fn load_config() -> SecurityConfig {
        use std::env;

        // Load and parse Catalyst.toml
        let toml_config = Self::parse_catalyst_toml();

        // Build config with cascading priority: toml -> env -> defaults
        SecurityConfig {
            database_url: env::var("PLZNOHAC_DATABASE_URL").expect("PLZNOHAC_DATABASE_URL must be set"),
            log_file_path: env::var("PLZNOHAC_LOG_FILE_PATH").ok(),
            enable_real_time_alerts: Self::get_config_bool(&toml_config, "enable_real_time_alerts", "PLZNOHAC_ENABLE_ALERTS", false),
            log_level: Self::get_config_string(&toml_config, "log_level", "PLZNOHAC_LOG_LEVEL", "info"),
            max_event_retention_days: Self::get_config_integer(&toml_config, "max_event_retention_days", "PLZNOHAC_RETENTION_DAYS", 90) as u32,
        }
    }

    /// Parse Catalyst.toml file
    fn parse_catalyst_toml() -> Option<toml::Value> {
        use std::fs;

        let config_path = "Catalyst.toml";
        let config_str = fs::read_to_string(config_path).unwrap_or_else(|_| {
            cata_log!(Warning, "Could not find Catalyst.toml, using default configuration");
            String::new()
        });

        if !config_str.is_empty() {
            match toml::from_str::<toml::Value>(&config_str) {
                Ok(config) => Some(config),
                Err(e) => {
                    cata_log!(Error, format!("Failed to parse Catalyst.toml: {}", e));
                    None
                }
            }
        } else {
            None
        }
    }

    /// Helper to get a boolean config value with fallback to environment and default
    fn get_config_bool(toml_config: &Option<toml::Value>, key: &str, env_key: &str, default: bool) -> bool {
        use std::env;

        toml_config
            .as_ref()
            .and_then(|c| c.get("spark"))
            .and_then(|s| s.get("plznohac"))
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| env::var(env_key).unwrap_or_else(|_| default.to_string()).parse().unwrap_or(default))
    }

    /// Helper to get a string config value with fallback to environment and default
    fn get_config_string(toml_config: &Option<toml::Value>, key: &str, env_key: &str, default: &str) -> String {
        use std::env;

        if let Some(val) = toml_config.as_ref().and_then(|c| c.get("spark")).and_then(|s| s.get("plznohac")).and_then(|p| p.get(key)).and_then(|v| v.as_str()) {
            return val.to_string();
        }

        if let Ok(val) = env::var(env_key) {
            return val;
        }

        default.to_string()
    }

    /// Helper to get an integer config value with fallback to environment and default
    fn get_config_integer(toml_config: &Option<toml::Value>, key: &str, env_key: &str, default: i64) -> i64 {
        use std::env;

        toml_config
            .as_ref()
            .and_then(|c| c.get("spark"))
            .and_then(|s| s.get("plznohac"))
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| env::var(env_key).unwrap_or_else(|_| default.to_string()).parse().unwrap_or(default))
    }

    /// Initialize the security system
    ///
    /// This method sets up the database connection and runs migrations.
    /// It must be called before any other methods.
    pub fn initialize(&mut self) -> Result<(), SecurityError> {
        cata_log!(Info, "Initializing PlzNoHac security system...");

        // Initialize the database connection pool
        db::initialize_pool(Some(&self.config.database_url))?;

        // Run migrations to ensure the database schema is up to date
        db::run_migrations()?;

        self.initialized = true;
        cata_log!(Info, "PlzNoHac security system initialized successfully");
        Ok(())
    }

    /// Record a security event
    ///
    /// This is the core method to record any security event with arbitrary data.
    ///
    /// # Arguments
    /// * `event_type` - The type of security event
    /// * `severity` - The severity level of the event
    /// * `description` - Human-readable description of the event
    /// * `data` - Arbitrary JSON data to store with the event (identities, context, etc)
    /// * `network` - Optional network context (IP, user agent)
    ///
    /// # Returns
    /// * `Result<(), SecurityError>` - Success or error
    pub fn emit(&self, event_type: SecurityEventType, severity: SecurityEventSeverity, description: &str, data: Value, network: Option<NetworkContext>) -> Result<(), SecurityError> {
        if !self.initialized {
            return Err(SecurityError::ConfigurationError("Security system not initialized. Call initialize() first.".to_string()));
        }

        cata_log!(Debug, format!("Emitting security event: {:?} - {}", &event_type, description));

        let final_data = match data {
            Value::Object(_) => data,
            _ => {
                let mut map = serde_json::Map::new();
                map.insert("value".to_string(), data);
                Value::Object(map)
            }
        };

        let mut event = SecurityEvent {
            event_type: event_type.clone(), // Clone to keep the original value
            severity,
            timestamp: Utc::now(),
            source_ip: None,
            description: description.to_string(),
            data: final_data,
        };

        if let Some(mut network_ctx) = network {
            event.source_ip = network_ctx.ip_address.take();

            if let Some(user_agent) = network_ctx.user_agent.as_ref() {
                if let Value::Object(ref mut map) = event.data {
                    let mut network_obj = serde_json::Map::new();
                    network_obj.insert("user_agent".to_string(), Value::String(user_agent.clone()));

                    if let Some(ip) = &event.source_ip {
                        network_obj.insert("ip_address".to_string(), Value::String(ip.clone()));
                    }

                    map.insert("network".to_string(), Value::Object(network_obj));
                }
            }
        }

        db::store_event(&event)
    }

    /// Query security events based on filters
    ///
    /// # Arguments
    /// * `filter` - EventFilter with various criteria to filter results
    ///
    /// # Returns
    /// * `Result<Vec<SecurityEvent>, SecurityError>` - List of matching events or error
    pub fn query(&self, filter: EventFilter) -> Result<Vec<SecurityEvent>, SecurityError> {
        if !self.initialized {
            return Err(SecurityError::ConfigurationError("Security system not initialized. Call initialize() first.".to_string()));
        }

        let filter_desc = format!("{:?}", filter);
        cata_log!(Debug, format!("Querying security events with filter: {}", filter_desc));

        let events = db::query_security_events(&filter)?;

        cata_log!(Debug, format!("Found {} security events matching filter", events.len()));
        Ok(events)
    }

    /// Helper to create a NetworkContext from an HTTP request
    pub fn network_from_request<'r>(request: &'r rocket::Request<'r>) -> NetworkContext {
        NetworkContext {
            ip_address: request.client_ip().map(|ip| ip.to_string()),
            user_agent: request.headers().get_one("User-Agent").map(String::from),
        }
    }

    /// Helper to extract JSON data from a request
    pub fn json_from_request<'r>(request: &'r rocket::Request<'r>) -> Value {
        let mut data = serde_json::Map::new();

        // Add HTTP method
        data.insert("method".to_string(), Value::String(request.method().to_string()));

        // Add URI path
        data.insert("uri".to_string(), Value::String(request.uri().to_string()));

        // Add headers of interest
        let headers_of_interest = ["Origin", "Referer", "Content-Type", "Accept", "Accept-Language"];

        let mut headers_map = serde_json::Map::new();
        for header in &headers_of_interest {
            if let Some(value) = request.headers().get_one(header) {
                headers_map.insert(header.to_string(), Value::String(value.to_string()));
            }
        }

        data.insert("headers".to_string(), Value::Object(headers_map));

        Value::Object(data)
    }
}

/// Network context for security events
///
/// Contains information about the request's network origin, including
/// IP address and user agent string
pub struct NetworkContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}
