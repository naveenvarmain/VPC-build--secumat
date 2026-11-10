"""
claroty_etl.py - Extract vulnerabilities from Claroty CTD API → PostgreSQL
"""
import os
import logging
import requests
from db import get_connection, log_etl_start, log_etl_end

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CLAROTY_BASE_URL = os.environ.get("CLAROTY_BASE_URL", "https://claroty.example.com")
CLAROTY_API_TOKEN = os.environ.get("CLAROTY_API_TOKEN", "")

HEADERS = {
    "Authorization": f"Bearer {CLAROTY_API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Map Claroty severity strings to canonical
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def fetch_claroty_assets():
    """Fetch all assets from Claroty CTD."""
    try:
        resp = requests.get(
            f"{CLAROTY_BASE_URL}/api/v1/assets",
            headers=HEADERS,
            timeout=60,
            verify=True,
        )
        resp.raise_for_status()
        return resp.json().get("data", resp.json() if isinstance(resp.json(), list) else [])
    except Exception as e:
        logger.warning(f"Could not fetch assets: {e}")
        return []


def fetch_claroty_vulnerabilities():
    """Fetch all vulnerabilities from Claroty CTD."""
    resp = requests.get(
        f"{CLAROTY_BASE_URL}/api/v1/vulnerabilities",
        headers=HEADERS,
        timeout=120,
        verify=True,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", data if isinstance(data, list) else [])


def upsert_asset(conn, asset: dict):
    """Upsert a single Claroty asset."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets
                (asset_key, ip_address, mac_address, hostname, manufacturer, model,
                 asset_type, zone, site, os, firmware, source, last_seen)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'claroty',NOW())
            ON CONFLICT (asset_key) DO UPDATE
            SET ip_address   = EXCLUDED.ip_address,
                hostname     = EXCLUDED.hostname,
                manufacturer = EXCLUDED.manufacturer,
                model        = EXCLUDED.model,
                zone         = EXCLUDED.zone,
                last_seen    = NOW(),
                updated_at   = NOW()
            """,
            (
                asset.get("id", asset.get("ip_address", "")),
                asset.get("ip_address"),
                asset.get("mac_address"),
                asset.get("name"),
                asset.get("vendor", asset.get("manufacturer")),
                asset.get("model"),
                asset.get("type", "OT"),
                asset.get("zone"),
                asset.get("site"),
                asset.get("os"),
                asset.get("firmware_version"),
            ),
        )


def upsert_vulnerability(conn, vuln: dict):
    """Upsert a single Claroty vulnerability."""
    severity_raw = str(vuln.get("severity", "")).lower()
    severity = SEVERITY_MAP.get(severity_raw, "low")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO vulnerabilities
                (asset_key, cve, cwe, title, description, severity, cvss_score, cvss_vector,
                 status, source, source_id, remediation, first_detected, last_updated)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'claroty',%s,%s,
                    COALESCE(%s, NOW()), NOW())
            ON CONFLICT (asset_key, cve, source) DO UPDATE
            SET severity     = EXCLUDED.severity,
                cvss_score   = EXCLUDED.cvss_score,
                status       = EXCLUDED.status,
                last_updated = NOW()
            """,
            (
                vuln.get("asset_id", vuln.get("asset_key", "")),
                vuln.get("cve_id", vuln.get("cve")),
                vuln.get("cwe_id", vuln.get("cwe")),
                vuln.get("title", vuln.get("name")),
                vuln.get("description"),
                severity,
                vuln.get("cvss_score", vuln.get("score")),
                vuln.get("cvss_vector"),
                vuln.get("status", "open"),
                str(vuln.get("id", "")),
                vuln.get("remediation", vuln.get("fix_text")),
                vuln.get("first_detected", vuln.get("created_at")),
            ),
        )


def run():
    conn = get_connection()
    run_id = log_etl_start(conn, "claroty")
    count = 0
    try:
        logger.info("Fetching Claroty assets...")
        assets = fetch_claroty_assets()
        for asset in assets:
            upsert_asset(conn, asset)
        conn.commit()
        logger.info(f"Upserted {len(assets)} Claroty assets")

        logger.info("Fetching Claroty vulnerabilities...")
        vulns = fetch_claroty_vulnerabilities()
        for vuln in vulns:
            upsert_vulnerability(conn, vuln)
        conn.commit()
        count = len(vulns)
        logger.info(f"Upserted {count} Claroty vulnerabilities")
        log_etl_end(conn, run_id, count, "success")
    except Exception as e:
        conn.rollback()
        logger.error(f"Claroty ETL failed: {e}", exc_info=True)
        log_etl_end(conn, run_id, count, "error", str(e))
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    run()
