-- ============================================================
-- Claroty VPC Integration - PostgreSQL Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Assets table (enrichment layer)
CREATE TABLE IF NOT EXISTS assets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_key       TEXT NOT NULL UNIQUE,   -- IP or Claroty asset_id
    ip_address      TEXT,
    mac_address     TEXT,
    hostname        TEXT,
    manufacturer    TEXT,
    model           TEXT,
    asset_type      TEXT,                   -- OT / IT / IoT
    zone            TEXT,
    site            TEXT,
    os              TEXT,
    firmware        TEXT,
    source          TEXT NOT NULL,          -- claroty | nessus | manual
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerabilities canonical table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_key       TEXT NOT NULL,
    cve             TEXT,
    cwe             TEXT,
    plugin_id       TEXT,
    title           TEXT,
    description     TEXT,
    severity        TEXT,                   -- critical | high | medium | low | info
    cvss_score      NUMERIC(4,1),
    cvss_vector     TEXT,
    status          TEXT DEFAULT 'open',    -- open | closed | accepted | false_positive | duplicate
    source          TEXT NOT NULL,          -- claroty | nessus | pits
    source_id       TEXT,                   -- original ID in source system
    pits_id         TEXT,                   -- PITS confirmation ID
    pits_status     TEXT,                   -- confirmed | closed | false_positive | accepted_risk
    remediation     TEXT,
    first_detected  TIMESTAMPTZ DEFAULT NOW(),
    last_updated    TIMESTAMPTZ DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(asset_key, cve, source)
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve        ON vulnerabilities(cve);
CREATE INDEX IF NOT EXISTS idx_vulns_asset      ON vulnerabilities(asset_key);
CREATE INDEX IF NOT EXISTS idx_vulns_status     ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulns_severity   ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_source     ON vulnerabilities(source);
CREATE INDEX IF NOT EXISTS idx_vulns_pits_id    ON vulnerabilities(pits_id);

-- PITS confirmed vulnerabilities
CREATE TABLE IF NOT EXISTS pits_vulns (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pits_id         TEXT UNIQUE NOT NULL,
    cve             TEXT,
    asset_key       TEXT,
    status          TEXT,   -- confirmed | closed | false_positive | accepted_risk
    confirmed_by    TEXT,
    confirmed_at    TIMESTAMPTZ,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pits_cve     ON pits_vulns(cve);
CREATE INDEX IF NOT EXISTS idx_pits_status  ON pits_vulns(status);

-- Uploaded cloud / VPC / security reports
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS report_uploads (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upload_name     TEXT NOT NULL,
    filename        TEXT NOT NULL,
    uploaded_by     TEXT,
    report_scope    TEXT,
    source_kind     TEXT,
    sheet_count     INTEGER DEFAULT 0,
    record_count    INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS report_records (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upload_id       UUID NOT NULL REFERENCES report_uploads(id) ON DELETE CASCADE,
    row_number      INTEGER NOT NULL,
    sheet_name      TEXT,
    dns_name        TEXT,
    netbios_name    TEXT,
    asset_key       TEXT,
    ip_address      TEXT,
    agent_id        TEXT,
    hostname        TEXT,
    cve             TEXT,
    severity        TEXT,
    status          TEXT,
    score           NUMERIC(6,2),
    port            INTEGER,
    protocol        TEXT,
    plugin_id       TEXT,
    plugin_name     TEXT,
    plugin_direct_output TEXT,
    solution        TEXT,
    vpc_solution    TEXT,
    description     TEXT,
    synopsis        TEXT,
    see_also        TEXT,
    title           TEXT,
    cloud_provider  TEXT,
    report_family   TEXT,
    report_scope    TEXT,
    owner           TEXT,
    environment     TEXT,
    subscription    TEXT,
    account         TEXT,
    region          TEXT,
    time_elapsed_from_discovery TEXT,
    first_discovered DATE,
    last_seen       DATE,
    seconds_count   BIGINT,
    remediation     TEXT,
    due_date        DATE,
    raw_data        JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_report_records_upload_id ON report_records(upload_id);
CREATE INDEX IF NOT EXISTS idx_report_records_cve ON report_records(cve);
CREATE INDEX IF NOT EXISTS idx_report_records_severity ON report_records(severity);
CREATE INDEX IF NOT EXISTS idx_report_records_status ON report_records(status);
CREATE INDEX IF NOT EXISTS idx_report_records_cloud_provider ON report_records(cloud_provider);

-- ETL run log
CREATE TABLE IF NOT EXISTS etl_runs (
    id          SERIAL PRIMARY KEY,
    source      TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    records     INTEGER DEFAULT 0,
    status      TEXT DEFAULT 'running',   -- running | success | error
    error_msg   TEXT
);
