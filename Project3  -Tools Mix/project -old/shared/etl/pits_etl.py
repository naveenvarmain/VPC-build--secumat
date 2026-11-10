"""
pits_etl.py - Ingest PITS confirmed/closed vulnerability data → PostgreSQL
Supports CSV feed or REST API
"""
import os
import csv
import json
import logging
import requests
from db import get_connection, log_etl_start, log_etl_end

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PITS_FEED_CSV = os.environ.get("PITS_FEED_CSV", "./data/pits_vulns.csv")
PITS_API_URL  = os.environ.get("PITS_API_URL", "")
PITS_API_TOKEN = os.environ.get("PITS_API_TOKEN", "")


def load_from_csv(path: str) -> list:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def load_from_api() -> list:
    resp = requests.get(
        PITS_API_URL,
        headers={"Authorization": f"Bearer {PITS_API_TOKEN}"},
        timeout=60,
        verify=True,
    )
    resp.raise_for_status()
    return resp.json()


def upsert_pits_vuln(conn, row: dict):
    """Upsert PITS record and propagate status to vulnerabilities table."""
    pits_id  = row.get("pits_id", row.get("id", ""))
    cve      = row.get("cve", row.get("CVE", ""))
    asset_key = row.get("asset_key", row.get("ip_address", row.get("IP", "")))
    status   = str(row.get("status", row.get("Status", "confirmed"))).lower()
    confirmed_by = row.get("confirmed_by", row.get("ConfirmedBy", ""))
    confirmed_at = row.get("confirmed_at", row.get("ConfirmedAt", None)) or None
    notes    = row.get("notes", row.get("Notes", ""))

    with conn.cursor() as cur:
        # Upsert PITS record
        cur.execute(
            """
            INSERT INTO pits_vulns
                (pits_id, cve, asset_key, status, confirmed_by, confirmed_at, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (pits_id) DO UPDATE
            SET status       = EXCLUDED.status,
                confirmed_by = EXCLUDED.confirmed_by,
                confirmed_at = EXCLUDED.confirmed_at,
                notes        = EXCLUDED.notes,
                updated_at   = NOW()
            """,
            (pits_id, cve, asset_key, status, confirmed_by, confirmed_at, notes),
        )

        # Propagate PITS status back to vulnerabilities table
        if cve:
            cur.execute(
                """
                UPDATE vulnerabilities
                SET pits_id     = %s,
                    pits_status = %s,
                    status      = CASE WHEN %s = 'closed' THEN 'closed' ELSE status END,
                    closed_at   = CASE WHEN %s = 'closed' AND closed_at IS NULL THEN NOW() ELSE closed_at END,
                    last_updated = NOW()
                WHERE cve = %s
                  AND (%s = '' OR asset_key = %s)
                """,
                (pits_id, status, status, status, cve, asset_key, asset_key),
            )


def run():
    conn = get_connection()
    run_id = log_etl_start(conn, "pits")
    count = 0
    try:
        if PITS_API_URL:
            logger.info(f"Loading PITS data from API: {PITS_API_URL}")
            rows = load_from_api()
        else:
            logger.info(f"Loading PITS data from CSV: {PITS_FEED_CSV}")
            rows = load_from_csv(PITS_FEED_CSV)

        for row in rows:
            upsert_pits_vuln(conn, row)
            count += 1

        conn.commit()
        logger.info(f"Processed {count} PITS records")
        log_etl_end(conn, run_id, count, "success")
    except Exception as e:
        conn.rollback()
        logger.error(f"PITS ETL failed: {e}", exc_info=True)
        log_etl_end(conn, run_id, count, "error", str(e))
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    run()
