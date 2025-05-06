use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::request::Outcome;
use rocket::Request;
use std::net::IpAddr;

use crate::services::sparks::plznohac::enrichers::ContextEnricher;
use crate::services::sparks::plznohac::SecurityEvent;
use serde_json::Value;

pub struct HttpRequestEnricher<'r> {
    request: &'r Request<'r>,
}

impl<'r> HttpRequestEnricher<'r> {
    pub fn new(request: &'r Request<'r>) -> Self {
        Self { request }
    }

    pub fn to_network_context(&self) -> crate::services::sparks::plznohac::NetworkContext {
        crate::services::sparks::plznohac::NetworkContext {
            ip_address: self.request.client_ip().map(|ip| ip.to_string()),
            user_agent: self.request.headers().get_one("User-Agent").map(String::from),
        }
    }
}

impl<'r> ContextEnricher for HttpRequestEnricher<'r> {
    fn enrich(&self, event: &mut SecurityEvent) {
        // Extract IP address if not already set
        if event.source_ip.is_none() {
            if let Some(ip) = self.request.client_ip() {
                event.source_ip = Some(ip.to_string());
            }
        }

        // Make sure data is an object before we try to insert into it
        if !matches!(event.data, Value::Object(_)) {
            event.data = Value::Object(serde_json::Map::new());
        }

        if let Value::Object(ref mut map) = event.data {
            // Extract user agent
            if let Some(user_agent) = self.request.headers().get_one("User-Agent") {
                map.insert("user_agent".to_string(), Value::String(user_agent.to_string()));
            }

            // Add resource (URI)
            map.insert("resource".to_string(), Value::String(self.request.uri().to_string()));

            // Method
            map.insert("http_method".to_string(), Value::String(self.request.method().to_string()));

            // Headers (selected ones that might be security-relevant)
            if let Some(origin) = self.request.headers().get_one("Origin") {
                map.insert("origin".to_string(), Value::String(origin.to_string()));
            }

            if let Some(referrer) = self.request.headers().get_one("Referer") {
                map.insert("referrer".to_string(), Value::String(referrer.to_string()));
            }

            // Create an http context object to keep things organized
            let mut http_map = serde_json::Map::new();
            http_map.insert("method".to_string(), Value::String(self.request.method().to_string()));
            http_map.insert("uri".to_string(), Value::String(self.request.uri().to_string()));

            // Add headers of interest (avoid adding too many headers)
            let mut headers_map = serde_json::Map::new();
            let headers_of_interest = ["User-Agent", "Origin", "Referer", "Content-Type", "Accept", "Accept-Language"];

            for &name in &headers_of_interest {
                if let Some(value) = self.request.headers().get_one(name) {
                    headers_map.insert(name.to_string(), Value::String(value.to_string()));
                }
            }

            http_map.insert("headers".to_string(), Value::Object(headers_map));
            map.insert("http".to_string(), Value::Object(http_map));
        }
    }
}
