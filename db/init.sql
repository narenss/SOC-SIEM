-- DIY SIEM — alert store (applied on first Postgres container init only)

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    summary TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    graylog_message_id TEXT,
    mitre_technique TEXT
);

CREATE TABLE IF NOT EXISTS alert_explanations (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    explanation TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts (rule_name);
CREATE INDEX IF NOT EXISTS idx_alert_explanations_alert_id ON alert_explanations (alert_id);
