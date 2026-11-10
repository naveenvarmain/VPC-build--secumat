"""
nessus_etl.py - Extract vulnerabilities from Nessus REST API → PostgreSQL
"""
import os
import logging
import requests
import urllib3
from db import get_connection, log_etl_start, log_etl_end

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NESSUS_BASE_URL = os.environ.get("NESSUS_BASE_URL", "https://nessus.example.com:8834")
NESSUS_USERNAME = os.environ.get("NESSUS_USERNAME", "admin")
NESSUS_PASSWORD = os.environ.get("NESSUS_PASSWORD", "")

SEVERITY_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def nessus_login() -> str:
    resp = requests.post(
        f"{NESSUS_BASE_URL}/session",
        json={"username": NESSUS_USERNAME, "password": NESSUS_PASSWORD},
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["token"]


def nessus_logout(token: str):
    try:
        requests.delete(
            f"{NESSUS_BASE_URL}/session",
            headers={"X-Cookie": f"token={token}"},
            verify=False,
            timeout=10,
        )
    except Exception:
        pass


def fetch_scans(token: str) -> list:
    resp = requests.get(
        f"{NESSUS_BASE_URL}/scans",
        headers={"X-Cookie": f"token={token}"},
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("scans", [])


def fetch_scan_vulnerabilities(token: str, scan_id: int) -> list:
    resp = requests.get(
        f"{NESSUS_BASE_URL}/scans/{scan_id}",
        headers={"X-Cookie": f"token={token}"},
        verify=False,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    hosts = data.get("hosts", [])
    vulns = []
    for host in hosts:
        host_id = host.get("host_id")
        host_ip = host.get("hostname", host.get("host-ip", ""))
        host_resp = requests.get(
            f"{NESSUS_BASE_URL}/scans/{scan_id}/hosts/{host_id}",
            headers={"X-Cookie": f"token={token}"},
            verify=False,
            timeout=30,
        )
        host_resp.raise_for_status()
        for item in host_resp.json().get("vulnerabilities", []):
            item["_host_ip"] = host_ip
            vulns.append(item)
    return vulns


def fetch_plugin_details(token: str, plugin_id: int) -> dict:
    try:
        resp = requests.get(
            f"{NESSUS_BASE_URL}/plugins/plugin/{plugin_id}",
            headers={"X-Cookie": f"token={token}"},
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def upsert_vulnerability(conn, vuln: dict, plugin_details: dict):
    severity_num = vuln.get("severity", 0)
    severity = SEVERITY_MAP.get(int(severity_num), "low")

    attrs = plugin_details.get("attributes", {})
    cve_list = attrs.get("cve", [])
    cve = cve_list[0] if cve_list else None
    cvss = attrs.get("cvss3_base_score") or attrs.get("cvss_base_score")
    cvss_vector = attrs.get("cvss3_vector") or attrs.get("cvss_vector")
    description = attrs.get("description", vuln.get("plugin_name", ""))
    remediation = attrs.get("solution")
    cwe_list = attrs.get("cwe", [])
    cwe = cwe_list[0] if cwe_list else None

    asset_key = vuln.get("_host_ip", "")
    plugin_id = str(vuln.get("plugin_id", ""))

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO vulnerabilities
                (asset_key, cve, cwe, plugin_id, title, description, severity,
                 cvss_score, cvss_vector, status, source, source_id, remediation, last_updated)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'open','nessus',%s,%s, NOW())
            ON CONFLICT (asset_key, cve, source) DO UPDATE
            SET severity     = EXCLUDED.severity,
                cvss_score   = EXCLUDED.cvss_score,
                plugin_id    = EXCLUDED.plugin_id,
                last_updated = NOW()
            """,
            (
                asset_key,
                cve,
                cwe,
                plugin_id,
                vuln.get("plugin_name"),
                description,
                severity,
                float(cvss) if cvss else None,
                cvss_vector,
                plugin_id,
                remediation,
            ),
        )


def run():
    conn = get_connection()
    run_id = log_etl_start(conn, "nessus")
    token = None
    count = 0
    try:
        logger.info("Logging into Nessus...")
        token = nessus_login()

        logger.info("Fetching Nessus scans...")
        scans = fetch_scans(token)
        logger.info(f"Found {len(scans)} scans")

        for scan in scans:
            scan_id = scan.get("id")
            if not scan_id:
                continue
            logger.info(f"Processing scan {scan_id}: {scan.get('name', '')}")
            vulns = fetch_scan_vulnerabilities(token, scan_id)
            for vuln in vulns:
                plugin_id = vuln.get("plugin_id")
                plugin_details = fetch_plugin_details(token, plugin_id) if plugin_id else {}
                upsert_vulnerability(conn, vuln, plugin_details)
                count += 1
            conn.commit()

        logger.info(f"Upserted {count} Nessus vulnerabilities")
        log_etl_end(conn, run_id, count, "success")
    except Exception as e:
        conn.rollback()
        logger.error(f"Nessus ETL failed: {e}", exc_info=True)
        log_etl_end(conn, run_id, count, "error", str(e))
        raise
    finally:
        if token:
            nessus_logout(token)
        conn.close()


if __name__ == "__main__":
    run()
