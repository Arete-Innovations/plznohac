pub mod http;
pub mod user;

pub use http::*;
pub use user::*;

use crate::services::sparks::plznohac::SecurityEvent;

pub trait ContextEnricher {
    fn enrich(&self, event: &mut SecurityEvent);
}

pub struct EnrichmentChain {
    enrichers: Vec<Box<dyn ContextEnricher>>,
}

impl EnrichmentChain {
    pub fn new() -> Self {
        Self { enrichers: Vec::new() }
    }

    pub fn add<T: ContextEnricher + 'static>(&mut self, enricher: T) {
        self.enrichers.push(Box::new(enricher));
    }

    pub fn enrich(&self, event: &mut SecurityEvent) {
        for enricher in &self.enrichers {
            enricher.enrich(event);
        }
    }
}

