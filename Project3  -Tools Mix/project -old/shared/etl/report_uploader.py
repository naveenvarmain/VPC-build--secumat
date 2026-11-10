"""
report_uploader.py - Upload cloud/VPC/security reports into PostgreSQL.

Supports CSV and Excel input, normalizes common columns, and stores both the raw
rows and a dashboard-ready normalized representation.
"""
import argparse
import csv
import io
import json
import logging
import os
import re
from datetime import date, datetime

import psycopg2
import psycopg2.extras


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

POSTGRES_CONFIG = {
    "dbname": os.environ.get("POSTGRES_DB", "vuln_db"),
    "user": os.environ.get("POSTGRES_USER", "vuln_user"),
    "password": os.environ.get("POSTGRES_PASSWORD", "StrongPassword123!"),
    "host": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
    "port": int(os.environ.get("POSTGRES_PORT", 5432)),
}

HEADER_ALIASES = {
    "asset_key": ["asset_key", "assetkey", "asset id", "asset", "host", "hostname", "device", "resource", "resource name"],
    "dns_name": ["dns name", "dns", "hostname", "host", "fqdn"],
    "netbios_name": ["netbios name", "netbios", "computer name"],
    "ip_address": ["ip", "ipaddress", "ip address", "ipv4", "address"],
    "agent_id": ["agent id", "agentid", "agent"],
    "hostname": ["hostname", "host name"],
    "cve": ["cve", "cve id", "vulnerability id"],
    "severity": ["severity", "sev", "risk level", "risk", "priority"],
    "status": ["status", "state", "finding status", "remediation status", "ticket status"],
    "score": ["score", "cvss", "cvss score", "risk score", "finding score"],
    "title": ["title", "vulnerability", "finding", "issue", "name", "plugin name"],
    "port": ["port"],
    "protocol": ["protocol"],
    "plugin_id": ["plugin id", "pluginid"],
    "plugin_name": ["plugin name", "plugin"],
    "plugin_direct_output": ["plugin direct output", "plugin output", "plugin direct output"],
    "solution": ["solution", "fix", "recommendation", "resolution"],
    "vpc_solution": ["vpc solution", "vpc solution"],
    "description": ["description", "details", "issue description"],
    "synopsis": ["synopsis", "short description", "summary"],
    "see_also": ["see also", "references", "reference"],
    "owner": ["owner", "team", "assigned to", "assignee", "responsible"],
    "environment": ["environment", "env", "scope", "platform"],
    "cloud_provider": ["cloud provider", "provider", "cloud", "platform provider", "account type"],
    "subscription": ["subscription", "subscription id", "subscription name"],
    "account": ["account", "account id", "project", "tenant"],
    "region": ["region", "availability zone", "zone", "location"],
    "report_family": ["report type", "report family", "report", "feed", "source"],
    "report_scope": ["report scope", "scope type", "target type"],
    "time_elapsed_from_discovery": ["time elapsed from discovery", "time elapsed", "elapsed"],
    "first_discovered": ["first discovered", "first discovery", "discovery date"],
    "last_seen": ["last seen", "last seen date", "last detected"],
    "seconds_count": ["seconds_count", "seconds count", "duration seconds"],
    "remediation": ["remediation", "recommendation", "fix", "resolution", "action"],
    "due_date": ["due date", "duedate", "target date", "deadline", "sla due"],
}

REPORT_SCHEMA_SQL = """
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
"""


def get_connection():
    return psycopg2.connect(cursor_factory=psycopg2.extras.RealDictCursor, **POSTGRES_CONFIG)


def normalize_text(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def canonical_header(header):
    normalized = normalize_text(header)
    for canonical, aliases in HEADER_ALIASES.items():
        if normalized == normalize_text(canonical):
            return canonical
        if normalized in {normalize_text(alias) for alias in aliases}:
            return canonical
    return None


def normalize_severity(value):
    token = normalize_text(value)
    if token in {"critical", "sev1"}:
        return "critical"
    if token in {"high", "sev2"}:
        return "high"
    if token in {"medium", "med", "sev3"}:
        return "medium"
    if token in {"low", "sev4"}:
        return "low"
    if token in {"info", "informational"}:
        return "info"
    return token or None


def normalize_status(value):
    token = normalize_text(value)
    if token in {"open", "active", "unresolved", "pending"}:
        return "open"
    if token in {"closed", "fixed", "resolved", "remediated"}:
        return "closed"
    if token in {"acceptedrisk", "riskaccepted", "accepted"}:
        return "accepted_risk"
    if token in {"falsepositive", "fp", "notanissue"}:
        return "false_positive"
    if token in {"confirmedopen", "confirmed", "verifiedopen"}:
        return "confirmed_open"
    return token or None


def parse_number(value):
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).replace(",", "").strip())
    except Exception:
        return None


def parse_date(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        return None


def infer_scope(filename, row):
    tokens = " ".join([filename or "", row.get("report_family") or "", row.get("cloud_provider") or "", row.get("environment") or ""]).lower()
    if "vpc" in tokens:
        return "vpc"
    if any(token in tokens for token in ("cloud", "aws", "azure", "gcp", "oracle", "ibm", "alibaba")):
        return "cloud"
    return row.get("report_scope") or "mixed"


def infer_cloud_provider(filename, row):
    candidates = [row.get("cloud_provider"), row.get("environment"), row.get("report_family"), filename]
    joined = " ".join(str(item or "") for item in candidates).lower()
    if "aws" in joined:
        return "aws"
    if "azure" in joined or "microsoft" in joined:
        return "azure"
    if "gcp" in joined or "google" in joined:
        return "gcp"
    if "oracle" in joined:
        return "oracle"
    if "alibaba" in joined:
        return "alibaba"
    if "vpc" in joined:
        return "vpc"
    return row.get("cloud_provider") or None


def ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute(REPORT_SCHEMA_SQL)
    conn.commit()


def parse_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row_number, raw_row in enumerate(reader, start=2):
            yield "CSV", row_number, raw_row


def parse_excel(path):
    try:
        from openpyxl import load_workbook
        import io
    except Exception:
        raise RuntimeError("Excel support requires openpyxl to be installed")

    wb = load_workbook(path, read_only=True, data_only=True)
    for sheet in wb.worksheets:
        rows = sheet.iter_rows(values_only=True)
        try:
            headers = [str(h).strip() if h is not None else "" for h in next(rows)]
        except StopIteration:
            continue
        for row_number, row_values in enumerate(rows, start=2):
            raw_row = {headers[idx]: row_values[idx] for idx in range(min(len(headers), len(row_values))) if headers[idx]}
            if not any(value not in (None, "") for value in raw_row.values()):
                continue
            yield sheet.title, row_number, raw_row


def normalize_row(raw_row, filename, sheet_name, row_number):
    extracted = {}
    raw_payload = {}
    for key, value in raw_row.items():
        if key is None:
            continue
        key_text = str(key).strip()
        raw_payload[key_text] = value
        canonical = canonical_header(key_text)
        if canonical and value not in (None, ""):
            extracted[canonical] = value

    extracted["asset_key"] = extracted.get("asset_key") or extracted.get("ip_address") or extracted.get("hostname")
    extracted["severity"] = normalize_severity(extracted.get("severity"))
    extracted["status"] = normalize_status(extracted.get("status"))
    extracted["score"] = parse_number(extracted.get("score"))
    extracted["port"] = parse_number(extracted.get("port"))
    extracted["seconds_count"] = parse_number(extracted.get("seconds_count"))
    extracted["due_date"] = parse_date(extracted.get("due_date"))
    extracted["first_discovered"] = parse_date(extracted.get("first_discovered"))
    extracted["last_seen"] = parse_date(extracted.get("last_seen"))
    extracted["cloud_provider"] = infer_cloud_provider(filename, extracted)
    extracted["report_scope"] = infer_scope(filename, extracted)
    extracted["report_family"] = extracted.get("report_family") or extracted["report_scope"]

    return {
        "row_number": row_number,
        "sheet_name": sheet_name,
        "dns_name": extracted.get("dns_name"),
        "netbios_name": extracted.get("netbios_name"),
        "asset_key": extracted.get("asset_key"),
        "ip_address": extracted.get("ip_address"),
        "agent_id": extracted.get("agent_id"),
        "hostname": extracted.get("hostname"),
        "cve": extracted.get("cve"),
        "severity": extracted.get("severity"),
        "status": extracted.get("status"),
        "score": extracted.get("score"),
        "title": extracted.get("title"),
        "port": extracted.get("port"),
        "protocol": extracted.get("protocol"),
        "plugin_id": extracted.get("plugin_id"),
        "plugin_name": extracted.get("plugin_name"),
        "plugin_direct_output": extracted.get("plugin_direct_output"),
        "solution": extracted.get("solution"),
        "vpc_solution": extracted.get("vpc_solution"),
        "description": extracted.get("description"),
        "synopsis": extracted.get("synopsis"),
        "see_also": extracted.get("see_also"),
        "cloud_provider": extracted.get("cloud_provider"),
        "report_family": extracted.get("report_family"),
        "report_scope": extracted.get("report_scope"),
        "owner": extracted.get("owner"),
        "environment": extracted.get("environment"),
        "subscription": extracted.get("subscription"),
        "account": extracted.get("account"),
        "region": extracted.get("region"),
        "time_elapsed_from_discovery": extracted.get("time_elapsed_from_discovery"),
        "first_discovered": extracted.get("first_discovered"),
        "last_seen": extracted.get("last_seen"),
        "seconds_count": extracted.get("seconds_count"),
        "remediation": extracted.get("remediation"),
        "due_date": extracted.get("due_date"),
        "raw_data": raw_payload,
    }


def load_rows(path):
    filename = os.path.basename(path)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "csv":
        iterator = parse_csv(path)
    elif ext in {"xlsx", "xlsm", "xls"}:
        iterator = parse_excel(path)
    else:
        raise ValueError("Only CSV, XLSX, XLSM, and XLS files are supported")

    rows = []
    for sheet_name, row_number, raw_row in iterator:
        rows.append(normalize_row(raw_row, filename, sheet_name, row_number))
    return rows


def save_upload(conn, file_name, upload_name, uploaded_by, rows):
    with conn.cursor() as cur:
        first_row = rows[0] if rows else {}
        cur.execute(
            """
            INSERT INTO report_uploads (upload_name, filename, uploaded_by, report_scope, source_kind, sheet_count, record_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                upload_name,
                file_name,
                uploaded_by,
                first_row.get("report_scope") or infer_scope(file_name, first_row),
                first_row.get("cloud_provider") or infer_cloud_provider(file_name, first_row),
                len({row.get("sheet_name") for row in rows}) if rows else 0,
                len(rows),
            ),
        )
        upload_id = cur.fetchone()["id"]

        for row in rows:
            cur.execute(
                """
                INSERT INTO report_records (
                    upload_id, row_number, sheet_name, dns_name, netbios_name, asset_key,
                    ip_address, agent_id, hostname, cve, severity, status, score, port,
                    protocol, plugin_id, plugin_name, plugin_direct_output, solution,
                    vpc_solution, description, synopsis, see_also, title, cloud_provider,
                    report_family, report_scope, owner, environment, subscription, account,
                    region, time_elapsed_from_discovery, first_discovered, last_seen,
                    seconds_count, remediation, due_date, raw_data
                ) VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    upload_id,
                    row["row_number"],
                    row["sheet_name"],
                    row["dns_name"],
                    row["netbios_name"],
                    row["asset_key"],
                    row["ip_address"],
                    row["agent_id"],
                    row["hostname"],
                    row["cve"],
                    row["severity"],
                    row["status"],
                    row["score"],
                    row["port"],
                    row["protocol"],
                    row["plugin_id"],
                    row["plugin_name"],
                    row["plugin_direct_output"],
                    row["solution"],
                    row["vpc_solution"],
                    row["description"],
                    row["synopsis"],
                    row["see_also"],
                    row["title"],
                    row["cloud_provider"],
                    row["report_family"],
                    row["report_scope"],
                    row["owner"],
                    row["environment"],
                    row["subscription"],
                    row["account"],
                    row["region"],
                    row["time_elapsed_from_discovery"],
                    row["first_discovered"],
                    row["last_seen"],
                    row["seconds_count"],
                    row["remediation"],
                    row["due_date"],
                    psycopg2.extras.Json(row["raw_data"]),
                ),
            )

    conn.commit()
    return upload_id


def main():
    parser = argparse.ArgumentParser(description="Upload Excel or CSV report data into the dashboard database")
    parser.add_argument("file", help="Path to CSV or Excel file")
    parser.add_argument("--upload-name", default=None, help="Friendly upload name")
    parser.add_argument("--uploaded-by", default=None, help="Uploader identity")
    args = parser.parse_args()

    file_path = os.path.abspath(args.file)
    upload_name = args.upload_name or os.path.splitext(os.path.basename(file_path))[0]
    uploaded_by = args.uploaded_by or os.environ.get("USER") or os.environ.get("USERNAME") or "cli-user"

    conn = get_connection()
    try:
        ensure_schema(conn)
        rows = load_rows(file_path)
        if len(rows) > 5000:
            raise ValueError("Upload too large. Limit to 5000 rows per file.")

        upload_id = save_upload(conn, os.path.basename(file_path), upload_name, uploaded_by, rows)
        print(json.dumps({
            "status": "success",
            "upload_id": str(upload_id),
            "file": os.path.basename(file_path),
            "rows_loaded": len(rows),
        }, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()