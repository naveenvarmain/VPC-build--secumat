-- ============================================================
-- Claroty VPC Integration - Deduplication Views
-- ============================================================

-- Unified vulnerabilities materialized view
-- Merges Claroty + Nessus + PITS with deduplication logic
CREATE MATERIALIZED VIEW IF NOT EXISTS unified_vulnerabilities AS
WITH base AS (
    SELECT
        v.asset_key,
        v.cve,
        v.cwe,
        v.title,
        v.description,
        v.severity,
        v.cvss_score,
        v.status,
        v.source,
        v.source_id,
        v.pits_id,
        v.pits_status,
        v.remediation,
        v.first_detected,
        v.last_updated,
        v.closed_at,
        -- Row number per (asset, CVE) ordered by CVSS desc → pick highest
        ROW_NUMBER() OVER (
            PARTITION BY v.asset_key, COALESCE(v.cve, v.plugin_id)
            ORDER BY v.cvss_score DESC NULLS LAST, v.last_updated DESC
        ) AS rn,
        -- Aggregate all sources for this (asset, CVE)
        ARRAY_AGG(v.source) OVER (
            PARTITION BY v.asset_key, COALESCE(v.cve, v.plugin_id)
        ) AS all_sources
    FROM vulnerabilities v
),
pits_override AS (
    SELECT
        b.*,
        p.status  AS pits_override_status,
        p.confirmed_by,
        p.confirmed_at
    FROM base b
    LEFT JOIN pits_vulns p
        ON p.cve = b.cve
        AND (p.asset_key = b.asset_key OR p.asset_key IS NULL)
    WHERE b.rn = 1
)
SELECT
    gen_random_uuid()                       AS unified_id,
    p.asset_key,
    p.cve,
    p.cwe,
    p.title,
    p.description,
    p.severity,
    p.cvss_score,
    -- PITS is the truth source for status
    CASE
        WHEN p.pits_override_status = 'closed'           THEN 'closed'
        WHEN p.pits_override_status = 'false_positive'   THEN 'false_positive'
        WHEN p.pits_override_status = 'accepted_risk'    THEN 'accepted_risk'
        WHEN p.pits_override_status = 'confirmed'        THEN 'confirmed_open'
        WHEN p.status IN ('closed', 'fixed')             THEN 'closed'
        ELSE 'open'
    END                                     AS final_status,
    p.pits_override_status                  AS pits_status,
    p.confirmed_by                          AS pits_confirmed_by,
    p.confirmed_at                          AS pits_confirmed_at,
    p.remediation,
    ARRAY(SELECT DISTINCT unnest(p.all_sources)) AS sources,
    CASE WHEN array_length(ARRAY(SELECT DISTINCT unnest(p.all_sources)), 1) > 1
         THEN TRUE ELSE FALSE END           AS is_duplicate,
    p.first_detected,
    p.last_updated,
    p.closed_at,
    -- Asset type derived from source
    CASE WHEN 'claroty' = ANY(p.all_sources) THEN 'OT/ICS' ELSE 'IT' END AS asset_type
FROM pits_override p
WITH DATA;

-- Indexes on the materialized view
CREATE UNIQUE INDEX IF NOT EXISTS uidx_unified_asset_cve
    ON unified_vulnerabilities(asset_key, cve);

CREATE INDEX IF NOT EXISTS idx_unified_status
    ON unified_vulnerabilities(final_status);

CREATE INDEX IF NOT EXISTS idx_unified_severity
    ON unified_vulnerabilities(severity);

CREATE INDEX IF NOT EXISTS idx_unified_asset_type
    ON unified_vulnerabilities(asset_type);

-- Refresh function (call from ETL after each run)
CREATE OR REPLACE FUNCTION refresh_unified_vulns()
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY unified_vulnerabilities;
END;
$$;

-- Summary stats view (for dashboard)
CREATE OR REPLACE VIEW vuln_summary AS
SELECT
    final_status,
    severity,
    asset_type,
    COUNT(*)                            AS total,
    COUNT(*) FILTER (WHERE is_duplicate) AS duplicates
FROM unified_vulnerabilities
GROUP BY final_status, severity, asset_type;

-- Top CVEs view
CREATE OR REPLACE VIEW top_cves AS
SELECT
    cve,
    MAX(cvss_score)     AS max_cvss,
    MAX(severity)       AS severity,
    COUNT(*)            AS affected_assets,
    COUNT(*) FILTER (WHERE final_status = 'open') AS open_count
FROM unified_vulnerabilities
WHERE cve IS NOT NULL
GROUP BY cve
ORDER BY max_cvss DESC NULLS LAST, affected_assets DESC;
