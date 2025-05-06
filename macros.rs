#[macro_export]
macro_rules! security_event {
    ($plznohac:expr, $event_type:ident, $severity:ident, $description:expr, $data:expr) => {{
        $plznohac.emit(
            $crate::services::sparks::plznohac::SecurityEventType::$event_type,
            $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
            $description,
            $data,
            None,
        )
    }};
    ($plznohac:expr, $event_type:ident, $severity:ident, $description:expr, $data:expr, $network:expr) => {{
        $plznohac.emit(
            $crate::services::sparks::plznohac::SecurityEventType::$event_type,
            $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
            $description,
            $data,
            $network,
        )
    }};
    ($plznohac:expr, custom = $custom_type:expr, $severity:ident, $description:expr, $data:expr) => {{
        $plznohac.emit(
            $crate::services::sparks::plznohac::SecurityEventType::Custom($custom_type.to_string()),
            $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
            $description,
            $data,
            None,
        )
    }};
}

/// Main security event logging macro with automatic context extraction
///
/// This macro simplifies security event logging by automatically handling common use cases:
/// - Retrieves the PlzNoHac instance from Rocket's state
/// - Creates NetworkContext from the request when available
/// - Extracts relevant information for properly formatting the event
///
/// # Basic usage with request context:
/// ```ignore
/// secure_log!(request, TokenTampering, High, "JWT validation failed", json!({
///     "error": "invalid signature",
///     "tampering_type": "invalid_signature"
/// }));
/// ```
///
/// # Usage without request context (from global instance):
/// ```ignore
/// secure_log!(TokenTampering, High, "Suspicious activity detected", json!({
///     "activity": "repeated failed logins",
///     "username": username
/// }));
/// ```
#[macro_export]
macro_rules! secure_log {
    // With request - extracts PlzNoHac and NetworkContext automatically
    ($request:expr, $event_type:ident, $severity:ident, $description:expr, $data:expr) => {{
        if let Some(sec) = $request.rocket().state::<$crate::services::sparks::plznohac::PlzNoHac>() {
            // Create context information by copying what we need from the request
            let ip_address = $request.client_ip().map(|ip| ip.to_string());
            let user_agent = $request.headers().get_one("User-Agent").map(|s| s.to_string());
            let network_context = $crate::services::sparks::plznohac::NetworkContext { ip_address, user_agent };

            let _ = sec.emit(
                $crate::services::sparks::plznohac::SecurityEventType::$event_type,
                $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
                $description,
                $data,
                Some(network_context),
            );
        }
    }};

    // Without request - uses global instance when available
    ($event_type:ident, $severity:ident, $description:expr, $data:expr) => {{
        if let Some(sec) = $crate::middleware::jwt::SECURITY_INSTANCE.get() {
            let _ = sec.emit(
                $crate::services::sparks::plznohac::SecurityEventType::$event_type,
                $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
                $description,
                $data,
                None,
            );
        }
    }};

    // Custom event type with request context
    ($request:expr, custom = $custom_type:expr, $severity:ident, $description:expr, $data:expr) => {{
        if let Some(sec) = $request.rocket().state::<$crate::services::sparks::plznohac::PlzNoHac>() {
            // Create context information by copying what we need from the request
            let ip_address = $request.client_ip().map(|ip| ip.to_string());
            let user_agent = $request.headers().get_one("User-Agent").map(|s| s.to_string());
            let network_context = $crate::services::sparks::plznohac::NetworkContext { ip_address, user_agent };

            let _ = sec.emit(
                $crate::services::sparks::plznohac::SecurityEventType::Custom($custom_type.to_string()),
                $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
                $description,
                $data,
                Some(network_context),
            );
        }
    }};

    // Custom event type without request context
    (custom = $custom_type:expr, $severity:ident, $description:expr, $data:expr) => {{
        if let Some(sec) = $crate::middleware::jwt::SECURITY_INSTANCE.get() {
            let _ = sec.emit(
                $crate::services::sparks::plznohac::SecurityEventType::Custom($custom_type.to_string()),
                $crate::services::sparks::plznohac::SecurityEventSeverity::$severity,
                $description,
                $data,
                None,
            );
        }
    }};
}
