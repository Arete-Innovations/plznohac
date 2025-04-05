use crate::cata_log;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Cookie, Status};
use rocket::{Data, Request, Response};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{PlzNoHac, SecurityEventSeverity, SecurityEventType};
use crate::secure_log;

/// Recent authentication attempts tracking for brute force detection
#[derive(Default)]
struct AuthAttempts {
    /// IP address to failed attempt count mapping
    ip_attempts: HashMap<String, Vec<Instant>>,
    /// Username/ID to failed attempt count mapping
    user_attempts: HashMap<String, Vec<Instant>>,
}

impl AuthAttempts {
    fn record_attempt(&mut self, ip: Option<String>, user_id: Option<String>) {
        let now = Instant::now();

        // Record IP-based attempts
        if let Some(ip_addr) = ip {
            let attempts = self.ip_attempts.entry(ip_addr).or_insert_with(Vec::new);
            attempts.push(now);

            // Clean old attempts (older than 30 minutes)
            attempts.retain(|time| now.duration_since(*time) < Duration::from_secs(30 * 60));
        }

        // Record user-based attempts
        if let Some(uid) = user_id {
            let attempts = self.user_attempts.entry(uid).or_insert_with(Vec::new);
            attempts.push(now);

            // Clean old attempts (older than 30 minutes)
            attempts.retain(|time| now.duration_since(*time) < Duration::from_secs(30 * 60));
        }
    }

    fn get_ip_attempts(&self, ip: &str) -> usize {
        self.ip_attempts.get(ip).map_or(0, |a| a.len())
    }

    fn get_user_attempts(&self, user_id: &str) -> usize {
        self.user_attempts.get(user_id).map_or(0, |a| a.len())
    }
}

/// PlzNoHac middleware (fairing) for Rocket
///
/// This fairing automatically monitors requests and responses
/// for suspicious activities and logs security events through the PlzNoHac system.
///
/// The middleware detects:
/// - Suspicious URL patterns (like path traversal attempts)
/// - Unusually large request payloads
/// - Access denied (403) responses
/// - Suspicious 404 patterns that might indicate scanning
/// - JWT authentication failures and token tampering
/// - Brute force login attempts
/// - Session anomalies and cookie manipulation
#[derive(Clone)]
pub struct PlzNoHacMiddleware {
    /// Reference to the security system
    security: PlzNoHac,
    /// Track recent authentication attempts for brute force detection
    auth_attempts: Arc<Mutex<AuthAttempts>>,
}

impl PlzNoHacMiddleware {
    /// Create a new middleware with a reference to the security system
    pub fn new(security: PlzNoHac) -> Self {
        Self {
            security,
            auth_attempts: Arc::new(Mutex::new(AuthAttempts::default())),
        }
    }

    /// Register this middleware with Rocket
    pub fn attach(security: PlzNoHac) -> impl Fairing {
        cata_log!(Info, "Attaching PlzNoHac middleware to Rocket");
        Self::new(security)
    }

    /// Check if a path is potentially suspicious
    ///
    /// Certain path patterns like directory traversal attempts or
    /// accessing sensitive files are considered suspicious
    fn is_suspicious_path(&self, path: &str) -> bool {
        path.contains("../")
            || path.contains("/.git")
            || path.contains("/etc/")
            || path.contains("/proc/")
            || path.contains("/sys/")
            || path.contains("/.env")
            || path.contains(".bak")
            || path.contains(".config")
            || path.contains("/.ssh/")
            || path.contains("wp-admin")
            || path.contains("phpMyAdmin")
            || path.contains(".htaccess")
            || path.contains("admin.php")
            || path.contains(".passwd")
    }

    /// Check if path is likely a protected route that requires JWT authentication
    fn is_protected_route(&self, path: &str) -> bool {
        // Add patterns based on your application's routes
        // Typically admin routes and API endpoints are protected
        path.starts_with("/admin")
            || path.starts_with("/api")
            || path.starts_with("/dashboard")
            || path.starts_with("/user")
            || path.starts_with("/settings")
            || path.starts_with("/private")
            // Exclude common public paths
            && !path.starts_with("/public")
            && !path.starts_with("/assets")
            && !path.starts_with("/auth/login")
            && !path.starts_with("/auth/register")
    }

    /// Check for JWT-related issues in the request
    fn check_for_jwt_anomalies(&self, request: &Request<'_>) -> Option<(SecurityEventType, SecurityEventSeverity, String, serde_json::Value)> {
        let cookies = request.cookies();

        // Check if this is a protected route that should have JWT
        let path = request.uri().path().as_str();
        if !self.is_protected_route(path) {
            return None;
        }

        // Check for missing tokens on protected routes
        let token = cookies.get("token");
        let user_id = cookies.get("user_id");

        if token.is_none() && user_id.is_none() {
            // No authentication cookies at all on protected route
            return Some((
                SecurityEventType::AuthFailure,
                SecurityEventSeverity::Low,
                "JWT missing on protected route".to_string(),
                json!({
                    "path": path,
                    "method": request.method().to_string(),
                    "missing": ["token", "user_id"]
                }),
            ));
        } else if token.is_none() && user_id.is_some() {
            // User ID present but token missing - potentially suspicious
            return Some((
                SecurityEventType::TokenTampering,
                SecurityEventSeverity::Medium,
                "User ID cookie present but JWT token missing".to_string(),
                json!({
                    "path": path,
                    "method": request.method().to_string(),
                    "user_id": user_id.unwrap().value(),
                }),
            ));
        } else if token.is_some() && user_id.is_none() {
            // Token present but user ID missing - potentially suspicious
            return Some((
                SecurityEventType::TokenTampering,
                SecurityEventSeverity::Medium,
                "JWT token present but user ID cookie missing".to_string(),
                json!({
                    "path": path,
                    "method": request.method().to_string(),
                }),
            ));
        }

        // Both cookies present - check if we should do deep inspection
        // This would be a more complex JWT validation

        None
    }

    /// Check for potential brute force attacks based on history
    fn check_brute_force(&self, request: &Request<'_>) -> Option<(SecurityEventType, SecurityEventSeverity, String, serde_json::Value)> {
        // Get IP address
        let ip = request.client_ip().map(|ip| ip.to_string());

        // Check if this is a login route
        let path = request.uri().path().as_str();
        if !path.contains("/auth/login") && !path.contains("/login") && !path.contains("/signin") {
            return None;
        }

        // Get any potential user identifier from the request
        let user_id = if let Some(cookie) = request.cookies().get("user_id") { Some(cookie.value().to_string()) } else { None };

        if let Some(ip_addr) = &ip {
            let attempts = {
                let guard = self.auth_attempts.lock().unwrap();
                guard.get_ip_attempts(ip_addr)
            };

            // Check if IP has too many attempts
            if attempts >= 10 {
                return Some((
                    SecurityEventType::BruteForceAttempt,
                    SecurityEventSeverity::High,
                    format!("Possible brute force attack: {} failed login attempts from IP", attempts),
                    json!({
                        "ip": ip_addr,
                        "attempts": attempts,
                        "path": path,
                    }),
                ));
            }
        }

        if let Some(uid) = &user_id {
            let attempts = {
                let guard = self.auth_attempts.lock().unwrap();
                guard.get_user_attempts(uid)
            };

            // Check if user has too many attempts
            if attempts >= 5 {
                return Some((
                    SecurityEventType::BruteForceAttempt,
                    SecurityEventSeverity::High,
                    format!("Possible brute force attack: {} failed login attempts for user", attempts),
                    json!({
                        "user_id": uid,
                        "attempts": attempts,
                        "path": path,
                    }),
                ));
            }
        }

        None
    }

    /// Analyzes a 401/403 response to determine the specific JWT failure reason
    fn analyze_jwt_failure(&self, request: &Request<'_>, status: Status) -> (SecurityEventType, SecurityEventSeverity, String, serde_json::Value) {
        let path = request.uri().path().as_str();
        let cookies = request.cookies();

        // Default event type and message
        let mut event_type = SecurityEventType::AuthFailure;
        let mut severity = SecurityEventSeverity::Medium;
        let mut message = "Authentication failure".to_string();
        let mut data = json!({
            "path": path,
            "method": request.method().to_string(),
            "status_code": status.code,
        });

        // Check cookies to diagnose the issue
        let has_token = cookies.get("token").is_some();
        let has_user_id = cookies.get("user_id").is_some();

        if status == Status::Unauthorized {
            // 401 Unauthorized typically means no token or expired token
            if !has_token && !has_user_id {
                message = "No authentication credentials provided".to_string();
                severity = SecurityEventSeverity::Low;
            } else if !has_token && has_user_id {
                message = "JWT token missing but user ID present".to_string();
                event_type = SecurityEventType::TokenTampering;
            } else {
                message = "JWT token likely expired".to_string();
            }
        } else if status == Status::Forbidden {
            // 403 Forbidden typically means invalid token or token-user mismatch
            if has_token && has_user_id {
                let user_id = cookies.get("user_id").unwrap().value();
                message = "JWT validation failed".to_string();
                event_type = SecurityEventType::TokenTampering;
                data = json!({
                    "path": path,
                    "method": request.method().to_string(),
                    "status_code": status.code,
                    "user_id": user_id,
                    "reason": "Token validation failed or user ID mismatch"
                });
                severity = SecurityEventSeverity::High;
            } else {
                message = "Access forbidden - insufficient permissions".to_string();
            }
        }

        // Record this failed attempt for brute force detection
        if let Some(ip) = request.client_ip().map(|ip| ip.to_string()) {
            let user_id = cookies.get("user_id").map(|c| c.value().to_string());

            // Record the attempt in our tracking
            let mut guard = self.auth_attempts.lock().unwrap();
            guard.record_attempt(Some(ip), user_id);
        }

        (event_type, severity, message, data)
    }
}

#[rocket::async_trait]
impl Fairing for PlzNoHacMiddleware {
    fn info(&self) -> Info {
        Info {
            name: "PlzNoHac Security Monitor",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let path = request.uri().path().as_str();

        // Original suspicious path detection
        if self.is_suspicious_path(path) {
            secure_log!(
                request,
                SuspiciousActivity,
                High,
                "Suspicious path detected in request",
                json!({
                    "method": request.method().to_string(),
                    "uri": request.uri().to_string(),
                    "path": path
                })
            );
        }

        // Original large payload detection
        if let Some(content_length) = request.headers().get_one("Content-Length") {
            if let Ok(size) = content_length.parse::<u64>() {
                if size > 10_000_000 {
                    secure_log!(
                        request,
                        SuspiciousActivity,
                        Medium,
                        "Unusually large payload detected",
                        json!({
                            "path": request.uri().path().as_str(),
                            "method": request.method().as_str(),
                            "content_length": size,
                        })
                    );
                }
            }
        }

        // NEW: Check for JWT anomalies
        if let Some((event_type, severity, message, data)) = self.check_for_jwt_anomalies(request) {
            // Use the specific event type and severity based on the values
            match event_type {
                SecurityEventType::AuthFailure => secure_log!(request, AuthFailure, Medium, &message, data),
                SecurityEventType::TokenTampering => secure_log!(request, TokenTampering, High, &message, data),
                SecurityEventType::SuspiciousActivity => secure_log!(request, SuspiciousActivity, Medium, &message, data),
                _ => secure_log!(request, SuspiciousActivity, Low, &message, data),
            }
        }

        // NEW: Check for brute force attempts
        if let Some((event_type, severity, message, data)) = self.check_brute_force(request) {
            // For brute force we know it's always a BruteForceAttempt type
            secure_log!(request, BruteForceAttempt, High, &message, data);
        }

        // NEW: Scan for cookie manipulation
        let cookies = request.cookies();
        if let Some(token_cookie) = cookies.get("token") {
            // Check for cookie suspicious patterns that indicate tampering
            let token_value = token_cookie.value();

            // Simple heuristics for obviously tampered tokens
            if token_value.len() < 20 {
                // Real JWTs are much longer
                secure_log!(
                    request,
                    TokenTampering,
                    High,
                    "Suspiciously short JWT token",
                    json!({
                        "path": path,
                        "token_length": token_value.len()
                    })
                );
            } else if !token_value.contains('.') {
                // JWTs have a format with dots (header.payload.signature)
                secure_log!(
                    request,
                    TokenTampering,
                    High,
                    "Malformed JWT token structure",
                    json!({
                        "path": path,
                    })
                );
            } else if token_value.matches('.').count() != 2 {
                // JWTs should have exactly 2 dots
                secure_log!(
                    request,
                    TokenTampering,
                    High,
                    "Incorrect JWT token format",
                    json!({
                        "path": path,
                        "dot_count": token_value.matches('.').count()
                    })
                );
            }
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let status = response.status();
        let path = request.uri().path().as_str();

        // NEW: Enhanced JWT authentication failure analysis
        if (status == Status::Unauthorized || status == Status::Forbidden) && self.is_protected_route(path) {
            let (event_type, severity, message, data) = self.analyze_jwt_failure(request, status);

            // Use the specific event type
            match event_type {
                SecurityEventType::AuthFailure => secure_log!(request, AuthFailure, Medium, &message, data),
                SecurityEventType::TokenTampering => secure_log!(request, TokenTampering, High, &message, data),
                SecurityEventType::BruteForceAttempt => secure_log!(request, BruteForceAttempt, High, &message, data),
                _ => secure_log!(request, SuspiciousActivity, Medium, &message, data),
            }
        }
        // Original forbidden response detection
        else if status == Status::Forbidden {
            secure_log!(
                request,
                UnauthorizedAccess,
                Medium,
                "Access forbidden response",
                json!({
                    "path": path,
                    "method": request.method().as_str(),
                    "status": status.code,
                })
            );
        }

        // Original not found detection
        if status == Status::NotFound {
            if self.is_suspicious_path(path) {
                secure_log!(
                    request,
                    SuspiciousActivity,
                    Low,
                    "Suspicious resource not found",
                    json!({
                        "path": path,
                        "method": request.method().as_str(),
                        "status": status.code,
                    })
                );
            }
        }
    }
}
