use chrono::{DateTime, Utc};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

pub static SECURITY_POOL: OnceLock<Pool<ConnectionManager<PgConnection>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub database_url: String,
    pub log_file_path: Option<String>,
    pub enable_real_time_alerts: bool,
    pub log_level: String,
    pub max_event_retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthFailure,
    TokenTampering,
    UnauthorizedAccess,
    SuspiciousActivity,
    DataAccess,
    AdminAction,
    ConfigurationChange,
    RateLimitExceeded,
    BruteForceAttempt,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: SecurityEventSeverity,
    pub timestamp: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub description: String,
    pub data: Value,
}

#[derive(Debug)]
pub enum SecurityError {
    DatabaseError(String),
    ConfigurationError(String),
    EventProcessingError(String),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            SecurityError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            SecurityError::EventProcessingError(msg) => write!(f, "Event processing error: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

#[derive(Debug)]
pub struct EventFilter {
    pub event_types: Option<Vec<SecurityEventType>>,
    pub severity_min: Option<SecurityEventSeverity>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub source_ip: Option<String>,
    pub contains_data: Option<(String, String)>,
    pub limit: Option<usize>,
}

impl EventFilter {
    pub fn new() -> Self {
        Self {
            event_types: None,
            severity_min: None,
            from_date: None,
            to_date: None,
            source_ip: None,
            contains_data: None,
            limit: Some(100),
        }
    }

    /// Filter for a specific event type
    pub fn with_event_type(mut self, event_type: SecurityEventType) -> Self {
        match &mut self.event_types {
            Some(types) => types.push(event_type),
            None => self.event_types = Some(vec![event_type]),
        }
        self
    }

    /// Filter by minimum severity
    pub fn with_min_severity(mut self, severity: SecurityEventSeverity) -> Self {
        self.severity_min = Some(severity);
        self
    }

    /// Filter by date range
    pub fn with_date_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from_date = Some(from);
        self.to_date = Some(to);
        self
    }

    /// Filter by source IP
    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Filter by JSON data field
    pub fn with_data_field(mut self, key: &str, value: &str) -> Self {
        self.contains_data = Some((key.to_string(), value.to_string()));
        self
    }

    /// Set result limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

