use crate::services::sparks::plznohac::enrichers::ContextEnricher;
use crate::services::sparks::plznohac::IdentityContext;
use crate::services::sparks::plznohac::SecurityEvent;
use serde_json::Value;

pub struct IdentityEnricher {
    identity: IdentityContext,
}

impl IdentityEnricher {
    pub fn new(identity: IdentityContext) -> Self {
        Self { identity }
    }
}

impl ContextEnricher for IdentityEnricher {
    fn enrich(&self, event: &mut SecurityEvent) {
        if let Value::Object(ref mut map) = event.data {
            map.insert("identity".to_string(), self.identity.to_json());
        }
    }
}
