CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    source_ip VARCHAR(45) NULL,
    description TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_event_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_source_ip ON security_events(source_ip) WHERE source_ip IS NOT NULL;

-- Create GIN index on data for faster JSON querying
CREATE INDEX idx_security_events_data ON security_events USING GIN (data);

COMMENT ON TABLE security_events IS 'Stores security-related events for audit and monitoring';