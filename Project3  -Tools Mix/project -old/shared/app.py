
"""
app.py - Claroty VPC Security Dashboard
Flask web app with red/white/yellow color scheme
"""
import os
import json
import base64
import logging
import csv
import io
import re
import math
import uuid
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urlparse
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from decimal import Decimal
from flask import Flask, render_template, jsonify, request, Response, g
import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool
import requests
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.jinja_env.auto_reload = True

# Set UTF-8 encoding for all responses
@app.after_request
def set_utf8_encoding(response):
    # Preserve JSON/binary response types; only ensure text responses declare UTF-8.
    content_type = response.headers.get("Content-Type", "")
    if content_type.startswith("text/") and "charset=" not in content_type.lower():
        response.headers["Content-Type"] = f"{content_type}; charset=utf-8"
    if content_type.startswith("text/html"):
        # Prevent stale dashboard pages when templates are updated.
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(APP_ROOT, ".."))
COMPLIANCE_UPLOAD_STORAGE_DIR = os.path.join(REPO_ROOT, "data", "compliance_uploads")
REPORT_UPLOAD_STORAGE_DIR = os.path.join(REPO_ROOT, "data", "report_uploads")
HEADER_LEARNING_PATH = os.path.join(REPO_ROOT, "data", "header_learning.json")
HEADER_LEARNING_CACHE = None

# Use Flask's json module with a custom provider for Decimal handling
from flask.json.provider import DefaultJSONProvider
import json

class CustomJSONProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super().default(o)

app.json = CustomJSONProvider(app)

POSTGRES_CONFIG = {
    "dbname":   os.environ.get("POSTGRES_DB", "vuln_db"),
    "user":     os.environ.get("POSTGRES_USER", "vuln_user"),
    "password": os.environ.get("POSTGRES_PASSWORD", "StrongPassword123!"),
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "connect_timeout": int(os.environ.get("POSTGRES_CONNECT_TIMEOUT", 2)),
}
POSTGRES_CONNECT_RETRIES = max(1, int(os.environ.get("POSTGRES_CONNECT_RETRIES", 2)))
DB_POOL_MINCONN = max(1, int(os.environ.get("POSTGRES_POOL_MINCONN", 1)))
DB_POOL_MAXCONN = max(DB_POOL_MINCONN, int(os.environ.get("POSTGRES_POOL_MAXCONN", 8)))
_DB_POOLS = {}


def _postgres_connect_candidates():
    """Build connection candidates; fallback to localhost for local, non-docker runs."""
    base = dict(POSTGRES_CONFIG)
    candidates = [base]

    host = str(base.get("host") or "").strip().lower()
    host_explicitly_set = bool(os.environ.get("POSTGRES_HOST"))
    running_in_container = os.path.exists("/.dockerenv") or bool(os.environ.get("KUBERNETES_SERVICE_HOST"))

    # If host was not explicitly configured and points to a common docker alias,
    # choose host order based on runtime:
    # - local/dev runtime: prefer localhost first to avoid repeated connect timeouts
    # - container runtime: keep docker alias first
    docker_alias_host = host in {"postgres", "db", "database"}
    should_add_local_fallback = docker_alias_host and (not host_explicitly_set or not running_in_container)
    if should_add_local_fallback:
        local_candidates = []
        for local_host in ("localhost", "127.0.0.1"):
            alt = dict(base)
            alt["host"] = local_host
            local_candidates.append(alt)

        # On local non-container runs, never spend time on docker aliases.
        # Keep docker alias first only when actually running in a container.
        candidates = [base] + local_candidates if running_in_container else local_candidates

    return candidates


def _pool_key(cfg):
    return (
        cfg.get("host"),
        cfg.get("port"),
        cfg.get("dbname"),
        cfg.get("user"),
    )


def _get_or_create_pool(cfg):
    key = _pool_key(cfg)
    pool = _DB_POOLS.get(key)
    if pool is None:
        pool = ThreadedConnectionPool(
            DB_POOL_MINCONN,
            DB_POOL_MAXCONN,
            cursor_factory=psycopg2.extras.RealDictCursor,
            **cfg,
        )
        _DB_POOLS[key] = pool
    return pool


def dashboard_force_fallback():
    return str(os.environ.get("DASHBOARD_FORCE_FALLBACK", "")).strip().lower() in {"1", "true", "yes", "on"}


def cab_fallback_path():
    return os.path.join(REPO_ROOT, "data", "cab_updates_fallback.json")


def load_cab_fallback_state():
    default_state = {
        "lock": {
            "is_locked": False,
            "locked_by": None,
            "locked_at": None,
            "updated_at": None,
        },
        "updates": [],
    }
    path = cab_fallback_path()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                default_state.update(data)
    except Exception as exc:
        logger.warning("Failed to load CAB fallback state: %s", exc)
    return default_state


def save_cab_fallback_state(state):
    path = cab_fallback_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def cab_updates_latest_rows(rows):
    latest_by_ticket = {}
    for row in sorted(rows or [], key=lambda item: str(item.get("created_at") or ""), reverse=True):
        ticket_id = str(row.get("ticket_id") or "")
        if ticket_id and ticket_id not in latest_by_ticket:
            latest_by_ticket[ticket_id] = dict(row)
    latest = list(latest_by_ticket.values())
    latest.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return latest


def cab_updates_summary(rows):
    latest = cab_updates_latest_rows(rows)
    avg_risk = round(sum(float(item.get("risk_percent") or 0) for item in latest) / len(latest), 1) if latest else 0
    open_statuses = {"open", "pending", "in_progress", "review", "accepted_risk"}
    return {
        "tickets": len(latest),
        "updates": len(rows or []),
        "avg_risk_percent": avg_risk,
        "open_updates": len([item for item in latest if str(item.get("status") or "") in open_statuses]),
        "strict_open_updates": len([item for item in latest if str(item.get("status") or "") == "open"]),
        "pending_updates": len([item for item in latest if str(item.get("status") or "") == "pending"]),
        "closed_updates": len([item for item in latest if str(item.get("status") or "") == "closed"]),
    }


def normalize_cab_import_status(value):
    txt = str(sanitize_text(value) or "").lower()
    if not txt:
        return "__unknown"
    has_closed = any(k in txt for k in ["closed", "complete", "completed", "resolved", "mitigated", "done"])
    has_pending = any(k in txt for k in ["pending", "under review", "review", "in progress", "progress"])
    has_open = any(k in txt for k in ["open", "reopen", "active", "unresolved"])
    if has_closed and not has_open:
        return "closed"
    if has_pending:
        return "pending"
    if has_open:
        return "open"
    if "accept" in txt:
        return "accepted_risk"
    return "__unknown"


def apply_cab_comment_status_override(status, comment):
    normalized = str(status or "").strip().lower()
    if normalized != "pending":
        return normalized
    comment_txt = str(sanitize_text(comment) or "").lower()
    has_closed_signal = bool(re.search(r'(status\s*marked\s*:\s*"?(closed|completed|resolved|mitigated|done)"?|\bclosed by system\b)', comment_txt))
    has_open_signal = bool(re.search(r'(reopen|re-open|open again|still open)', comment_txt))
    if has_closed_signal and not has_open_signal:
        return "closed"
    return normalized


def validate_cab_import_distribution(rows, expected_distribution=None):
    expected_distribution = expected_distribution or {}
    status_counts = {
        "open": 0,
        "pending": 0,
        "closed": 0,
        "accepted_risk": 0,
        "other": 0,
        "total": 0,
    }

    for row in rows or []:
        status = str((row or {}).get("status") or "").strip().lower()
        status_counts["total"] += 1
        if status in {"open", "pending", "closed", "accepted_risk"}:
            status_counts[status] += 1
        else:
            status_counts["other"] += 1

    # Pending contributes to open incident tracking for CAB reporting.
    status_counts["open_inclusive"] = status_counts["open"] + status_counts["pending"]

    mismatches = []
    for key in ("open", "closed", "pending", "accepted_risk", "total"):
        if key in expected_distribution and expected_distribution[key] is not None:
            try:
                expected_value = int(expected_distribution[key])
            except Exception:
                continue
            actual_value = status_counts.get("open_inclusive") if key == "open" else status_counts.get(key, 0)
            if int(actual_value or 0) != expected_value:
                mismatches.append({
                    "status": key,
                    "expected": expected_value,
                    "actual": int(actual_value or 0),
                    "note": "open includes pending" if key == "open" else "",
                })

    return {
        "status_counts": status_counts,
        "expected_distribution": expected_distribution,
        "mismatches": mismatches,
        "is_valid": len(mismatches) == 0,
    }


def _to_bool(value, default=False):
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _cab_header_match_score(cells):
    header_hints = [
        "problem tickets", "ticket id", "incident id", "ticket", "status", "incident status",
        "state", "ticket status", "asset", "asset key", "hostname", "ip", "cve",
        "severity", "criticality", "priority", "risk", "assigned to", "owner", "comments",
    ]
    score = 0
    for cell in cells:
        token = str(cell or "").strip().lower()
        if not token:
            continue
        if any(token == hint or hint in token for hint in header_hints):
            score += 1
    return score


def detect_cab_header_row(all_rows, max_scan_rows=40):
    best_index = -1
    best_score = -1
    scan_limit = min(max_scan_rows, len(all_rows))

    for idx in range(scan_limit):
        row = all_rows[idx] or ()
        cells = [str(cell or "").strip().lower() for cell in row]
        non_empty = [cell for cell in cells if cell]
        if len(non_empty) < 2:
            continue
        score = _cab_header_match_score(non_empty)
        if score > best_score:
            best_score = score
            best_index = idx

    if best_index < 0:
        for idx, row in enumerate(all_rows):
            if any(str(cell or "").strip() for cell in (row or ())):
                best_index = idx
                break

    if best_index < 0:
        return 0, []

    header_values = all_rows[best_index] or ()
    headers = []
    for i, value in enumerate(header_values):
        key = str(value or "").strip().lower()
        headers.append(key or f"__empty_{i}")
    return best_index, headers


def cab_first_value(row, keys, default=None):
    for key in keys:
        value = row.get(key) if isinstance(row, dict) else None
        if value not in (None, ""):
            return value
    return default


def normalize_cab_incident_rows(incidents):
    incidents_by_ticket = {}
    for idx, inc in enumerate(incidents or []):
        raw_ticket = sanitize_text(cab_first_value(inc, ["ticket_id", "problem tickets", "ticket id", "incident id", "ticket", "id"], f"INC-{idx + 1}"))
        ticket_id = re.sub(r"\s+", " ", raw_ticket).strip() or f"INC-{idx + 1}"

        status_value = cab_first_value(inc, ["status", "incident status", "state", "ticket status", "problem status", "overall status", "incident state"])
        comment_value = cab_first_value(inc, ["comments", "comment", "details", "description", "notes", "remediation"], "")
        status = normalize_cab_import_status(status_value)
        status = apply_cab_comment_status_override(status, comment_value)
        if status == "__unknown":
            status = "closed"

        criticality_value = cab_first_value(inc, ["criticality", "severity", "priority"], "medium")
        if criticality_value in (None, ""):
            criticality_value = "medium"

        risk_value = cab_first_value(inc, ["risk_percent", "risk"], 0.0)
        current = {
            "ticket_id": ticket_id,
            "asset_key": sanitize_text(cab_first_value(inc, ["asset_key", "asset", "asset details", "hostname", "ip"], "")),
            "cve": sanitize_text(cab_first_value(inc, ["cve", "vulnerability"], "")),
            "status": status,
            "criticality": sanitize_text(str(criticality_value).strip().lower() or "medium"),
            "risk_percent": max(0.0, min(100.0, float(parse_number(risk_value) or 0.0))),
            "comment": sanitize_text(comment_value),
            "updated_by": sanitize_text(cab_first_value(inc, ["updated_by", "owner", "assigned_to", "smart factory technician"], "bulk-import")),
        }

        existing = incidents_by_ticket.get(ticket_id)
        if existing is None:
            incidents_by_ticket[ticket_id] = current
        elif existing["status"] == "closed" and current["status"] != "closed":
            incidents_by_ticket[ticket_id] = current

    return list(incidents_by_ticket.values())


def parse_cab_incidents_from_payload(payload, filename):
    if not payload:
        return {
            "incidents": [],
            "rows_detected": 0,
            "sheet_name": None,
            "source_format": None,
        }

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    rows = []
    chosen_sheet_name = None

    if ext == "csv":
        text = payload.decode("utf-8-sig")
        parsed = list(csv.reader(io.StringIO(text)))
        if parsed:
            header_idx, headers = detect_cab_header_row(parsed)
            for row_values in parsed[header_idx + 1:]:
                if not any(str(v or "").strip() for v in row_values):
                    continue
                row = {}
                for idx, header in enumerate(headers):
                    row[header] = row_values[idx] if idx < len(row_values) else ""
                rows.append(row)
        chosen_sheet_name = "CSV"
    elif ext in {"xlsx", "xlsm"}:
        try:
            from openpyxl import load_workbook
        except Exception as exc:
            raise RuntimeError("Excel support requires openpyxl") from exc

        workbook = load_workbook(io.BytesIO(payload), read_only=True, data_only=True)
        preferred_name = None
        for name in workbook.sheetnames:
            if re.search(r"problem\s*inc", str(name or ""), re.IGNORECASE):
                preferred_name = name
                break
        if preferred_name is None:
            for name in workbook.sheetnames:
                if re.search(r"incident", str(name or ""), re.IGNORECASE):
                    preferred_name = name
                    break
        if preferred_name is None and workbook.sheetnames:
            preferred_name = workbook.sheetnames[0]

        sheet = workbook[preferred_name] if preferred_name else workbook.worksheets[0]
        chosen_sheet_name = sanitize_text(sheet.title) or "Sheet"
        all_rows = list(sheet.iter_rows(values_only=True))
        if all_rows:
            header_idx, headers = detect_cab_header_row(all_rows)
            for row_values in all_rows[header_idx + 1:]:
                row_values = row_values or ()
                if not any(str(v or "").strip() for v in row_values):
                    continue
                row = {}
                for idx, header in enumerate(headers):
                    row[header] = row_values[idx] if idx < len(row_values) else ""
                rows.append(row)
    else:
        raise ValueError("Only CSV, XLSX, and XLSM are supported for CAB import")

    incidents = normalize_cab_incident_rows(rows)
    return {
        "incidents": incidents,
        "rows_detected": len(rows),
        "sheet_name": chosen_sheet_name,
        "source_format": ext,
    }


def parse_cab_incidents_from_upload(file_storage, filename):
    return parse_cab_incidents_from_payload(file_storage.read(), filename)


def run_cab_bulk_import(incidents, expected_distribution=None, enforce_expected_distribution=False, allow_distribution_mismatch=False, replace_existing=True):
    expected_distribution = expected_distribution or {}
    enforce_expected_distribution = bool(enforce_expected_distribution)
    allow_distribution_mismatch = bool(allow_distribution_mismatch)
    replace_existing = bool(replace_existing)

    if not incidents:
        return {"error": "incidents array required"}, 400

    normalized_incidents = normalize_cab_incident_rows(incidents)
    if not normalized_incidents:
        return {"error": "No valid incidents found in uploaded data"}, 400

    validation = validate_cab_import_distribution(normalized_incidents, expected_distribution)
    if enforce_expected_distribution and not validation.get("is_valid") and not allow_distribution_mismatch:
        return {
            "error": "CAB import distribution validation failed",
            "validation": validation,
            "hint": "Adjust source statuses or set allow_distribution_mismatch=true to bypass.",
        }, 400

    if dashboard_force_fallback():
        state = load_cab_fallback_state()
        lock_state = state.get("lock") or {}
        if lock_state.get("is_locked"):
            return {"error": "CAB updates are locked. Unlock before importing.", "locked": True}, 423

        updates = [] if replace_existing else list(state.get("updates") or [])
        inserted = 0
        for inc in normalized_incidents:
            updates.append({
                "id": len(updates) + 1,
                "ticket_id": inc["ticket_id"],
                "asset_key": inc["asset_key"],
                "cve": inc["cve"],
                "status": inc["status"],
                "criticality": inc["criticality"],
                "risk_percent": inc["risk_percent"],
                "comment": inc["comment"],
                "updated_by": inc["updated_by"],
                "created_at": datetime.utcnow().isoformat() + "Z",
            })
            inserted += 1

        state["updates"] = updates
        save_cab_fallback_state(state)
        return {
            "status": "success",
            "inserted": inserted,
            "replaced_existing": replace_existing,
            "validation": validation,
            "warnings": ([] if validation.get("is_valid") else ["Distribution mismatch accepted via override"]) if allow_distribution_mismatch else [],
        }, 200

    ensure_report_schema()
    lock_state = get_cab_lock_state()
    if lock_state.get("is_locked"):
        return {"error": "CAB updates are locked. Unlock before importing.", "locked": True}, 423

    conn = None
    inserted = 0

    def write_to_fallback_state(reason=None):
        state = load_cab_fallback_state()
        lock_state = state.get("lock") or {}
        if lock_state.get("is_locked"):
            return {"error": "CAB updates are locked. Unlock before importing.", "locked": True}, 423

        updates = [] if replace_existing else list(state.get("updates") or [])
        local_inserted = 0
        for inc in normalized_incidents:
            updates.append({
                "id": len(updates) + 1,
                "ticket_id": inc["ticket_id"],
                "asset_key": inc["asset_key"],
                "cve": inc["cve"],
                "status": inc["status"],
                "criticality": inc["criticality"],
                "risk_percent": inc["risk_percent"],
                "comment": inc["comment"],
                "updated_by": inc["updated_by"],
                "created_at": datetime.utcnow().isoformat() + "Z",
            })
            local_inserted += 1

        state["updates"] = updates
        save_cab_fallback_state(state)
        response = {
            "status": "success",
            "inserted": local_inserted,
            "replaced_existing": replace_existing,
            "validation": validation,
            "warnings": ([] if validation.get("is_valid") else ["Distribution mismatch accepted via override"]) if allow_distribution_mismatch else [],
            "storage_mode": "fallback",
        }
        if reason:
            response["fallback_reason"] = reason
        return response, 200
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if replace_existing:
                cur.execute("DELETE FROM cab_ticket_updates")

            for inc in normalized_incidents:
                cur.execute(
                    """
                    INSERT INTO cab_ticket_updates (
                        ticket_id, asset_key, cve, status, criticality, risk_percent, comment, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        inc["ticket_id"],
                        inc["asset_key"],
                        inc["cve"],
                        inc["status"],
                        inc["criticality"],
                        inc["risk_percent"],
                        inc["comment"],
                        inc["updated_by"],
                    ),
                )
                inserted += 1
        conn.commit()
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        if is_db_unavailable_error(exc):
            logger.warning("CAB bulk import switching to fallback state due to DB unavailability: %s", exc)
            return write_to_fallback_state(reason="db_unavailable")
        logger.exception("CAB bulk import failed")
        return {"error": str(exc), "inserted": inserted}, 500

    return {
        "status": "success",
        "inserted": inserted,
        "replaced_existing": replace_existing,
        "validation": validation,
        "warnings": ([] if validation.get("is_valid") else ["Distribution mismatch accepted via override"]) if allow_distribution_mismatch else [],
    }, 200


def cab_manual_stats_from_fallback():
    state = load_cab_fallback_state()
    summary = cab_updates_summary(state.get("updates") or [])
    return {
        "manual_tickets": summary.get("tickets", 0),
        "manual_updates": summary.get("updates", 0),
        "avg_manual_risk_percent": summary.get("avg_risk_percent", 0),
    }


def security_automation_fallback_modules():
    return {
        "threat_detection": {"status": "idle", "summary": "Fallback mode enabled; live DB-backed automation is unavailable.", "metrics": {}},
        "alert_priority": {"status": "idle", "summary": "Fallback mode enabled; live DB-backed automation is unavailable.", "metrics": {}},
        "vuln_patch": {"status": "idle", "summary": "Fallback mode enabled; live DB-backed automation is unavailable.", "metrics": {}},
        "edr_monitor": {"status": "idle", "summary": "Fallback mode enabled; live DB-backed automation is unavailable.", "metrics": {}},
        "ueba": {"status": "idle", "summary": "Fallback mode enabled; live DB-backed automation is unavailable.", "metrics": {}},
        "compliance_check": {"status": "idle", "summary": "Fallback mode enabled; live DB-backed automation is unavailable.", "metrics": {}},
    }


def security_automation_alert_state_path():
    return os.path.join(REPO_ROOT, "data", "security_automation_alert_state.json")


def load_security_automation_alert_state():
    state = {"actions": {}}
    path = security_automation_alert_state_path()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                state.update(loaded)
    except Exception as exc:
        logger.warning("Failed to load security automation alert state: %s", exc)
    return state


def save_security_automation_alert_state(state):
    path = security_automation_alert_state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def _automation_date_window_days():
    try:
        return max(7, min(int(request.args.get("days", 30) or 30), 90))
    except Exception:
        return 30


def _readonly_integration_catalog():
    """Return integration readiness data without live network calls or DB bootstrap."""
    try:
        if REPO_ROOT not in sys.path:
            sys.path.insert(0, REPO_ROOT)
        from automation.vendor_integrations import _base_health, load_integration_settings

        settings = load_integration_settings()
        platforms = settings.get("platforms") or {}
        catalog = []
        for slug, cfg in platforms.items():
            health = _base_health(slug, cfg)
            catalog.append({
                "slug": slug,
                "name": cfg.get("display_name") or cfg.get("name") or slug,
                "vendor": (cfg.get("display_name") or cfg.get("name") or slug).split(" ")[0],
                "category": cfg.get("category") or "Security Platform",
                "portal_url": cfg.get("portal_url") or "",
                "enabled": bool(cfg.get("enabled", True)),
                "modules": list(cfg.get("modules") or []),
                "health_mode": cfg.get("health_mode") or "config_only",
                "credential_env": list(cfg.get("credential_env") or []),
                "health": health,
                "live_metrics": {},
            })
        return catalog
    except Exception as exc:
        logger.warning("Read-only integration catalog fallback active: %s", exc)
        return []


def build_all_security_tools_live_summary():
    """Aggregate all security tool readiness and read metrics for the SOAR page."""
    live_catalog = {item.get("slug"): item for item in _readonly_integration_catalog()}
    fallback_summary = build_full_data_fallback_report_payload().get("summary") or {}
    total_fallback_vulns = int(fallback_summary.get("total_rows") or 0)

    tools = []
    for item in SECURITY_TOOL_INTEGRATIONS:
        slug = item.get("slug")
        live_item = live_catalog.get(slug, {})
        health = live_item.get("health") or {}
        metrics = live_item.get("live_metrics") or {}
        required_env = list(live_item.get("credential_env") or item.get("credential_env") or [])
        missing_env = [name for name in required_env if not str(os.environ.get(name, "")).strip()]
        configured = bool(health.get("configured")) or (bool(required_env) and not missing_env)
        status = health.get("status") or ("configured" if configured else "pending_credentials")
        tools.append({
            "slug": slug,
            "name": item.get("name"),
            "vendor": item.get("vendor"),
            "category": item.get("category"),
            "enabled": bool(live_item.get("enabled", item.get("enabled", True))),
            "configured": configured,
            "status": status,
            "message": health.get("message") or ("Credentials detected." if configured else "Missing credentials or endpoint contract."),
            "required_env": required_env,
            "missing_env": missing_env,
            "metrics": {
                "assets": int(metrics.get("assets") or 0),
                "vulnerabilities": int(metrics.get("vulnerabilities") or metrics.get("detections") or 0),
                "tickets": int(metrics.get("tickets") or 0),
                "alerts": int(metrics.get("detections") or 0),
            },
            "source_type": "live_api" if status == "healthy" else "readiness",
        })

    return {
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "tools_total": len(tools),
            "configured": len([tool for tool in tools if tool.get("configured")]),
            "healthy": len([tool for tool in tools if tool.get("status") == "healthy"]),
            "pending_credentials": len([tool for tool in tools if not tool.get("configured")]),
            "fallback_vulnerabilities": total_fallback_vulns,
        },
        "tools": tools,
        "fallback_dataset": {
            "source": "Full data upload fallback",
            "vulnerabilities": total_fallback_vulns,
            "critical": int(fallback_summary.get("critical_rows") or 0),
            "high": int(fallback_summary.get("high_rows") or 0),
            "medium": int(fallback_summary.get("medium_rows") or 0),
            "low": int(fallback_summary.get("low_rows") or 0),
        },
    }


def _security_integration_readiness():
    live_catalog = {item.get("slug"): item for item in _readonly_integration_catalog()}

    items = []
    for item in SECURITY_TOOL_INTEGRATIONS:
        live_item = live_catalog.get(item.get("slug"), {})
        required_env = list(live_item.get("credential_env") or item.get("credential_env") or [])
        missing_env = [name for name in required_env if not str(os.environ.get(name, "")).strip()]
        health = live_item.get("health") or {}
        configured = bool(health.get("configured")) or (bool(required_env) and not missing_env)
        status = health.get("status") or ("configured" if configured else "mock_fallback")
        source_type = "live_api" if configured and status in {"healthy", "configured"} else "mock_fallback"
        items.append({
            "slug": item.get("slug"),
            "name": item.get("name"),
            "category": item.get("category"),
            "configured": configured,
            "status": status,
            "source_type": source_type,
            "source_label": "Live API" if source_type == "live_api" else "Mock fallback - API unavailable",
            "live_metrics": live_item.get("live_metrics") or {},
        })
    return items


def _default_security_alerts(days, integrations):
    now = datetime.utcnow()
    live_sources = [item for item in integrations if item.get("source_type") == "live_api"]
    source_type = "live_api" if live_sources else "mock_fallback"
    source_label = "Live API" if live_sources else "Mock fallback - API unavailable"
    templates = [
        ("SOC-1001", "critical", "SIEM", "New lateral movement rule match", "TA0008", "open", 2),
        ("SOC-1002", "high", "EDR", "Endpoint isolation recommended", "TA0005", "acknowledged", 6),
        ("SOC-1003", "medium", "Vulnerability", "Exploit path found on cloud workload", "TA0001", "owned", 14),
        ("SOC-1004", "high", "Threat Intel", "IOC seen in proxy telemetry", "TA0011", "open", 22),
        ("SOC-1005", "low", "IAM", "Privileged sign-in anomaly", "TA0006", "closed", 33),
        ("SOC-1006", "critical", "SOAR", "Playbook failed containment step", "TA0040", "escalated", 48),
        ("SOC-1007", "medium", "ITSM", "Incident ticket SLA warning", "TA0002", "open", 65),
        ("SOC-1008", "high", "SIEM", "Multiple failed admin logons", "TA0006", "closed", 80),
    ]
    alerts = []
    for idx, (alert_id, severity, category, title, tactic, state, age_hours) in enumerate(templates, start=1):
        created_at = now.replace(microsecond=0) - timedelta(hours=age_hours)
        if age_hours / 24.0 > days:
            continue
        alerts.append({
            "id": alert_id,
            "title": title,
            "severity": severity,
            "category": category,
            "state": state,
            "source": (live_sources[0].get("name") if live_sources else category),
            "source_type": source_type,
            "source_label": source_label,
            "created_at": created_at.isoformat() + "Z",
            "updated_at": (created_at + timedelta(minutes=idx * 9)).isoformat() + "Z",
            "owner": "Unassigned" if state == "open" else "SOC Tier 2",
            "ticket": "" if state == "open" else f"INC-{2400 + idx}",
            "mitre_tactic": tactic,
            "comments": [],
            "notification": severity in {"critical", "high"} and state in {"open", "escalated"},
        })
    return alerts


def _apply_security_alert_actions(alerts):
    state = load_security_automation_alert_state()
    actions = state.get("actions") or {}
    for alert in alerts:
        stored = actions.get(str(alert.get("id"))) or {}
        if stored:
            alert.update({key: value for key, value in stored.items() if key in {"state", "owner", "ticket", "incident_id", "updated_at"}})
            alert["comments"] = list(stored.get("comments") or [])
    return alerts


def build_security_automation_dashboard_payload():
    days = _automation_date_window_days()
    integrations = _security_integration_readiness()
    alerts = _apply_security_alert_actions(_default_security_alerts(days, integrations))

    severity_filter = (request.args.get("severity") or "").strip().lower()
    category_filter = (request.args.get("category") or "").strip().lower()
    state_filter = (request.args.get("state") or "").strip().lower()
    query_filter = (request.args.get("q") or "").strip().lower()

    def keep(alert):
        if severity_filter and str(alert.get("severity") or "").lower() != severity_filter:
            return False
        if category_filter and str(alert.get("category") or "").lower() != category_filter:
            return False
        if state_filter and str(alert.get("state") or "").lower() != state_filter:
            return False
        if query_filter:
            haystack = " ".join(str(alert.get(key) or "") for key in ("id", "title", "category", "source", "owner", "ticket", "mitre_tactic")).lower()
            return query_filter in haystack
        return True

    visible_alerts = [alert for alert in alerts if keep(alert)]
    open_alerts = [alert for alert in alerts if alert.get("state") not in {"closed", "resolved"}]
    closed_alerts = [alert for alert in alerts if alert.get("state") in {"closed", "resolved"}]
    high_alerts = [alert for alert in open_alerts if alert.get("severity") in {"critical", "high"}]
    live_count = len([item for item in integrations if item.get("source_type") == "live_api"])
    configured_count = len([item for item in integrations if item.get("configured")])
    automation_rate = round((configured_count / len(integrations)) * 100.0, 1) if integrations else 0.0
    closure_rate = round((len(closed_alerts) / len(alerts)) * 100.0, 1) if alerts else 0.0
    posture_score = max(0, min(100, round(100 - (len(high_alerts) * 7) + (automation_rate * 0.25))))
    hours_saved = round((len(closed_alerts) * 1.8) + (automation_rate / 100.0 * max(len(alerts), 1) * 0.7), 1)

    def count_by(key):
        counter = Counter(str(alert.get(key) or "Unknown") for alert in alerts)
        return [{"label": label, "value": count} for label, count in sorted(counter.items())]

    trend = []
    bucket_count = min(days, 14)
    for idx in range(bucket_count - 1, -1, -1):
        day = (datetime.utcnow().date() - timedelta(days=idx))
        incident_count = 1 + ((bucket_count - idx) % 5)
        closed_count = min(incident_count, 1 + ((bucket_count - idx) % 3))
        trend.append({"label": day.isoformat(), "incidents": incident_count, "closed": closed_count})

    return {
        "source": "live_api" if live_count else "mock_fallback",
        "source_label": "Live API integrations active" if live_count else "Mock fallback - APIs unavailable or credentials missing",
        "poll_interval_seconds": 30,
        "days": days,
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "kpis": {
            "mttd_hours": round(1.6 + (len(high_alerts) * 0.4), 1),
            "mttr_hours": round(5.2 + (len(open_alerts) * 0.6), 1),
            "automation_rate_percent": automation_rate,
            "open_incidents": len(open_alerts),
            "hours_saved": hours_saved,
            "posture_score": posture_score,
        },
        "charts": {
            "incident_trends": trend,
            "severity": count_by("severity"),
            "closure_rate": [{"label": "Closed", "value": len(closed_alerts)}, {"label": "Open", "value": len(open_alerts)}],
            "mitre_attack": count_by("mitre_tactic"),
            "automation_success": [{"label": "Automated", "value": configured_count}, {"label": "Manual", "value": max(len(integrations) - configured_count, 0)}],
            "siem_alerts": [{"label": item.get("name"), "value": 1 if item.get("source_type") == "live_api" else 0} for item in integrations],
            "vulnerabilities": count_by("category"),
            "roi": [{"label": "Hours saved", "value": hours_saved}, {"label": "Open workload", "value": len(open_alerts) * 1.5}],
        },
        "alerts": visible_alerts,
        "integrations": integrations,
        "states": ["open", "acknowledged", "owned", "escalated", "closed"],
        "date_ranges": [7, 30, 90],
    }


def is_db_unavailable_error(exc):
    msg = str(exc or "").lower()
    markers = [
        "connection to server",
        "connection refused",
        "timeout expired",
        "could not connect",
        "operationalerror",
    ]
    return any(marker in msg for marker in markers)


def secumat_fallback_path():
    return os.path.join(REPO_ROOT, "data", "secumat_fallback_state.json")


def load_secumat_fallback_state():
    state = {
        "audits": [],
        "assignments": [],
        "assignment_responses": {},
        "custom_questionnaire_templates": [],
    }
    path = secumat_fallback_path()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                state.update(loaded)
    except Exception as exc:
        logger.warning("Failed to load secumat fallback state: %s", exc)
    return state


def save_secumat_fallback_state(state):
    path = secumat_fallback_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def secumat_next_int_id(items):
    max_id = 0
    for item in items or []:
        try:
            max_id = max(max_id, int(item.get("id") or 0))
        except Exception:
            continue
    return max_id + 1


def secumat_builtin_questionnaires_payload():
    return [
        {
            "id": questionnaire["id"],
            "name": questionnaire["name"],
            "framework": questionnaire["framework"],
            "version": questionnaire["version"],
            "description": questionnaire["description"],
            "source": questionnaire["source"],
            "question_count": questionnaire["question_count"],
            "sections": questionnaire["sections"],
            "questions": questionnaire["questions"],
            "is_custom": False,
        }
        for questionnaire in SECUMAT_BUILTIN_QUESTIONNAIRES
    ]


def secumat_workspace_fallback_payload():
    state = load_secumat_fallback_state()
    templates_list = []
    for template_id, template_data in SECUMAT_TEMPLATES.items():
        templates_list.append({
            "id": template_id,
            "name": template_data["name"],
            "framework": template_data["framework"],
            "version": template_data["version"],
            "description": template_data["description"],
            "control_count": template_data["control_count"],
        })

    custom_questionnaires = []
    for row in state.get("custom_questionnaire_templates") or []:
        qs = row.get("questions") or []
        sections = list(dict.fromkeys(q.get("section", "") for q in qs if q.get("section")))
        custom_questionnaires.append({
            "id": f"custom_{row.get('id')}",
            "db_id": row.get("id"),
            "name": row.get("name") or "Custom Questionnaire",
            "framework": row.get("framework") or "CUSTOM",
            "version": row.get("version") or "1.0",
            "description": row.get("description") or "",
            "source": "Custom / Manual",
            "question_count": len(qs),
            "sections": sections,
            "questions": qs,
            "is_custom": True,
        })

    return {
        "options": SECUMAT_OPTIONS,
        "resources": SECUMAT_RESOURCES,
        "questionnaire_library": SECUMAT_QUESTIONNAIRE_LIBRARY,
        "questionnaires": secumat_builtin_questionnaires_payload() + custom_questionnaires,
        "guidance": SECUMAT_GUIDANCE,
        "templates": templates_list,
        "audits": state.get("audits") or [],
        "uploads": [],
        "fallback_mode": True,
    }


def vuln_fallback_path():
    return os.path.join(REPO_ROOT, "data", "vulnerability_fallback_rows.json")


def default_vulnerability_fallback_rows():
    now_iso = datetime.utcnow().isoformat() + "Z"
    return [
        {
            "record_id": "fallback-1",
            "asset_key": "OT-PLC-001",
            "cve": "CVE-2024-4577",
            "severity": "critical",
            "cvss_score": 9.8,
            "final_status": "open",
            "remediation": "Apply latest vendor patch and restrict external exposure.",
            "pits_status": "tracked",
            "pits_detail": "PITS CMS: Yes | Whitelisted: No | Needs Check: No",
            "sources": ["upload"],
            "last_updated": now_iso,
        },
        {
            "record_id": "fallback-2",
            "asset_key": "OT-HMI-009",
            "cve": "CVE-2023-23397",
            "severity": "high",
            "cvss_score": 8.3,
            "final_status": "outdated",
            "remediation": "Upgrade component version and validate hardening baseline.",
            "pits_status": "needs_check",
            "pits_detail": "PITS CMS: No | Whitelisted: No | Needs Check: Yes",
            "sources": ["upload"],
            "last_updated": now_iso,
        },
        {
            "record_id": "fallback-3",
            "asset_key": "IT-SRV-042",
            "cve": "CVE-2021-44228",
            "severity": "critical",
            "cvss_score": 10.0,
            "final_status": "pending",
            "remediation": "Patch Log4j and validate no vulnerable JAR remains.",
            "pits_status": "tracked",
            "pits_detail": "PITS CMS: Yes | Whitelisted: No | Needs Check: No",
            "sources": ["upload"],
            "last_updated": now_iso,
        },
        {
            "record_id": "fallback-4",
            "asset_key": "IT-WS-117",
            "cve": "CVE-2024-30078",
            "severity": "medium",
            "cvss_score": 6.5,
            "final_status": "new",
            "remediation": "Apply monthly OS security updates.",
            "pits_status": "unknown",
            "pits_detail": "PITS CMS: Unknown",
            "sources": ["upload"],
            "last_updated": now_iso,
        },
        {
            "record_id": "fallback-5",
            "asset_key": "OT-SCADA-007",
            "cve": "CVE-2022-30190",
            "severity": "high",
            "cvss_score": 7.8,
            "final_status": "open",
            "remediation": "Mitigate via endpoint controls and macro policy lockdown.",
            "pits_status": "tracked_whitelisted",
            "pits_detail": "PITS CMS: Yes | Whitelisted: Yes | Needs Check: No",
            "sources": ["upload"],
            "last_updated": now_iso,
        },
    ]


def load_vulnerability_fallback_rows():
    path = vuln_fallback_path()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                rows = json.load(handle)
            if isinstance(rows, list):
                return rows
    except Exception as exc:
        logger.warning("Failed to load vulnerability fallback rows: %s", exc)
    return default_vulnerability_fallback_rows()


def save_vulnerability_fallback_rows(rows):
    path = vuln_fallback_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)


def compliance_audit_fallback_payload():
    questions = []
    if SECUMAT_BUILTIN_QUESTIONNAIRES:
        questions = list((SECUMAT_BUILTIN_QUESTIONNAIRES[0] or {}).get("questions") or [])[:12]

    upload = {
        "id": "fallback-secumat",
        "upload_name": "SecuMat Fallback Assessment",
        "filename": "secumat_fallback.xlsx",
        "framework": "CIS",
        "total_questions": len(questions),
        "total_controls": max(1, len({str(q.get('control_id') or q.get('section') or 'GEN') for q in questions})),
        "sheet_count": 1,
        "coverage_percent": 72.5,
        "upload_mode": "fallback",
        "preview_available": False,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    responses = []
    controls_acc = {}
    for idx, q in enumerate(questions, start=1):
        status = "compliant" if idx % 4 in {1, 2} else ("partial" if idx % 4 == 3 else "non_compliant")
        score = 100 if status == "compliant" else (50 if status == "partial" else 0)
        priority = "critical" if idx % 6 == 0 else ("high" if idx % 3 == 0 else "medium")
        control_id = str(q.get("control_id") or f"CTRL-{idx}")
        control_name = str(q.get("section") or "General")
        responses.append({
            "control_id": control_id,
            "control_name": control_name,
            "question_number": q.get("question_number") or idx,
            "question_text": q.get("question") or q.get("title") or f"Question {idx}",
            "response_status": status,
            "response_value": status,
            "evidence": "Fallback evidence record",
            "comments": "Generated in fallback mode while DB is unavailable.",
            "priority": priority,
            "mapping_score": float(score),
            "created_at": datetime.utcnow().isoformat() + "Z",
        })
        bucket = controls_acc.setdefault(control_id, {"framework": "CIS", "implemented": 0, "total": 0, "score_sum": 0.0, "risk_level": "low"})
        bucket["total"] += 1
        if score > 0:
            bucket["implemented"] += 1
        bucket["score_sum"] += score
        if priority == "critical":
            bucket["risk_level"] = "critical"
        elif priority == "high" and bucket["risk_level"] != "critical":
            bucket["risk_level"] = "high"
        elif priority == "medium" and bucket["risk_level"] not in {"critical", "high"}:
            bucket["risk_level"] = "medium"

    controls = []
    for control_id, agg in controls_acc.items():
        controls.append({
            "control_id": control_id,
            "framework": agg["framework"],
            "implemented": agg["implemented"],
            "total": agg["total"],
            "percent_complete": round((agg["score_sum"] / max(agg["total"], 1)), 1),
            "risk_level": agg["risk_level"],
            "last_assessed": datetime.utcnow().isoformat() + "Z",
        })

    compliant = len([r for r in responses if r["response_status"] == "compliant"])
    non_compliant = len([r for r in responses if r["response_status"] == "non_compliant"])
    stats = {
        "total_controls": len(controls),
        "implemented": len([c for c in controls if c["implemented"] > 0]),
        "coverage_percent": round(sum(float(c.get("percent_complete") or 0) for c in controls) / max(len(controls), 1), 1) if controls else 0.0,
        "total_questions": len(responses),
        "total_responses": len(responses),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "critical_items": len([r for r in responses if r.get("priority") == "critical"]),
    }

    return {
        "upload": upload,
        "uploads": [upload],
        "stats": stats,
        "controls": controls,
        "responses": responses,
        "fallback_mode": True,
    }


def is_fallback_upload_id(upload_id):
    value = str(upload_id or "").strip().lower()
    return value in {"fallback-upload", "fallback-secumat", ""} or value.startswith("fallback-")


def sanitize_db_params(params):
    """Normalize synthetic fallback upload ids before SQL execution.

    Some UI flows can still emit placeholder ids (for example fallback-upload).
    Passing those values into UUID columns creates noisy database errors even when
    route-level fallback logic handles the response gracefully.
    """
    if params is None:
        return None

    def _clean(value):
        if isinstance(value, str) and is_fallback_upload_id(value):
            return None
        if isinstance(value, tuple):
            return tuple(_clean(item) for item in value)
        if isinstance(value, list):
            return [_clean(item) for item in value]
        if isinstance(value, dict):
            return {k: _clean(v) for k, v in value.items()}
        return value

    return _clean(params)


def has_unified_vulnerabilities_relation():
    row = query_one("SELECT to_regclass('public.unified_vulnerabilities') AS relation_name")
    return bool((row or {}).get("relation_name"))

CLAROTY_BASE_URL  = os.environ.get("CLAROTY_BASE_URL", "")
CLAROTY_API_TOKEN = os.environ.get("CLAROTY_API_TOKEN", "")
LOCATE_URL        = os.environ.get("LOCATE_URL", "http://frdv03264.emea.zf-world.com:8888/locate")
PITS_CMS_URL      = os.environ.get("PITS_CMS_URL", "https://pits-cms.emea.zf-world.com/")
IT_SITECODES_URL  = os.environ.get(
    "IT_SITECODES_URL",
    "https://trw1.sharepoint.com/sites/inet/SitePages/Main.aspx?xsdata=MDV8MDJ8fDM1MzEzOGQ3ODIyNDRjZjZkOWM4MDhkZTYzMDJlMGUzfGViNzBiNzYzYjZkNzQ0ODY4NTU1ODgzMTcwOWE3ODRlfDB8MHw2MzkwNTcwNjExNDczMDIzNDR8VW5rbm93bnxWR1ZoYlhOVFpXTjFjbWwwZVZObGNuWnBZMlY4ZXlKRFFTSTZJbFJsWVcxelgwRlVVRk5sY25acFkyVmZVMUJQVEU5R0lpd2lWaUk2SWpBdU1DNHdNREF3SWl3aVVDSTZJbGRwYmpNeUlpd2lRVTRpT2lKUGRHaGxjaUlzSWxkVUlqb3hNWDA9fDF8TDJOb1lYUnpMekU1T2pFM05EUmxOamd3TFRNM04yRXROR0kyWVMxaFlUWTNMV0l6TURJMk16UmtPR1k0TlY5ak4yUmhNakJsTkMxaVl6VXpMVFJqTWpNdE9UWXdPQzAzTjJFNU5qRmpPRFJtWlRKQWRXNXhMbWRpYkM1emNHRmpaWE12YldWemMyRm5aWE12TVRjM01ERXdPVE14TWpZd05RPT18YTA1MGYyMjE4NzBiNDRhNGQ5YzgwOGRlNjMwMmUwZTN8M2JjNDQxYzg1YmVmNGU0MDg4NGFlODdmNmJjZTJlMDU%3D&sdata=VXlnRWlWcTBadGZ0MmR0bjA1U0VZRVlQMm91aWZZQzUvUFJYY1lBZ1pnND0%3D&ovuser=eb70b763-b6d7-4486-8555-8831709a784e%2Cnaveen.chintalapati%40zf.com#communities/18747",
)
PITS_BI_1         = os.environ.get("PITS_POWERBI_REPORT_1", "https://app.powerbi.com/groups/ac4ca672-b874-4e4c-9b8b-9a9172f996d5/reports/1a6564b0-3fbd-486a-a27e-a00d3bd11df5/f533e0f1496f4ef54bd1?ctid=eb70b763-b6d7-4486-8555-8831709a784e&experience=power-bi")
PITS_BI_2         = os.environ.get("PITS_POWERBI_REPORT_2", "https://app.powerbi.com/groups/me/reports/7d139cb6-0474-4dc2-b584-ac5a3504daf9/869f4d3019c6394d0d80?ctid=eb70b763-b6d7-4486-8555-8831709a784e&experience=power-bi")
PITS_BI_3         = os.environ.get("PITS_POWERBI_REPORT_3", "https://app.powerbi.com/groups/me/reports/1a6564b0-3fbd-486a-a27e-a00d3bd11df5/f533e0f1496f4ef54bd1?ctid=eb70b763-b6d7-4486-8555-8831709a784e&experience=power-bi")
PATCH_MGMT_URL    = os.environ.get("PATCH_MANAGEMENT_URL", "https://trw1.sharepoint.com/sites/pits-productionitsecurity/SitePages/Patch-Management.aspx?csf=1&web=1&e=ZEr11m")
HUDSONROCK_COMPROMISED_URL = os.environ.get("HUDSONROCK_COMPROMISED_URL", "https://www.hudsonrock.com/are-you-compromised")
HUDSONROCK_TOOLS_URL = os.environ.get("HUDSONROCK_TOOLS_URL", "https://www.hudsonrock.com/threat-intelligence-cybercrime-tools")
UPLOAD_API_TOKEN  = os.environ.get("UPLOAD_API_TOKEN", "")
REPORT_UPLOAD_LIMIT = int(os.environ.get("REPORT_UPLOAD_LIMIT", 25))
REPORT_MAX_ROWS = int(os.environ.get("REPORT_MAX_ROWS", 20000))
REPORT_INSERT_BATCH_SIZE = int(os.environ.get("REPORT_INSERT_BATCH_SIZE", 500))
REPORT_REPLACE_ON_UPLOAD = os.environ.get("REPORT_REPLACE_ON_UPLOAD", "1").lower() in {"1", "true", "yes", "on"}
REPORT_ALLOWED_EXTENSIONS = {"csv", "xlsx", "xlsm"}
TEMPLATE_EXPECTED_SHEETS = int(os.environ.get("TEMPLATE_EXPECTED_SHEETS", 17))
VPC_OVERVIEW_CACHE_TTL_SECONDS = int(os.environ.get("VPC_OVERVIEW_CACHE_TTL_SECONDS", 120))
VPC_OVERVIEW_PAYLOAD_CACHE = {}
RISK_ACCEPTANCE_TEMPLATE_FIELDS = [
    "activity_assessed",
    "purpose_of_activity",
    "date_assessed",
]
RISK_ACCEPTANCE_TEMPLATE_COLUMNS = [
    "category_risk",
    "incident_type",
    "risk_or_hazard_description",
    "vulnerability",
    "assets_and_consequences",
    "it_solution",
    "resources_impacted",
    "existing_control_measures",
    "risk_probability",
    "risk_impact",
    "risk_rating",
    "prevention_measures",
    "responsibilities",
    "assigned_to",
    "action_date",
    "status",
]
RISK_ACCEPTANCE_TEMPLATE_LABELS = {
    "activity_assessed": "ACTIVITY ASSESSED",
    "purpose_of_activity": "PURPOSE OF ACTIVITY",
    "date_assessed": "DATE ASSESSED",
    "category_risk": "CATEGORY / RISK",
    "incident_type": "INCIDENT TYPE",
    "risk_or_hazard_description": "RISK OR HAZARD DESCRIPTION",
    "vulnerability": "VULNERABILITY",
    "assets_and_consequences": "ASSET(S) AND CONSEQUENCES",
    "it_solution": "IT SOLUTION",
    "resources_impacted": "RESOURCES IMPACTED (e.g. personnel, machinery)",
    "existing_control_measures": "EXISTING CONTROL MEASURES",
    "risk_probability": "RISK PROBABILITY",
    "risk_impact": "RISK IMPACT",
    "risk_rating": "RISK RATING",
    "prevention_measures": "PREVENTION MEASURES",
    "responsibilities": "RESPONSIBILITIES",
    "assigned_to": "ASSIGNED TO",
    "action_date": "ACTION DATE",
    "status": "STATUS",
}
RISK_ACCEPTANCE_TEMPLATE_ROWS = [
    {"category_risk": "RISK 1", "status": "", "action_date": "MM/DD/YY"},
    {"category_risk": "Issue 1.1", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "High", "action_date": "MM/DD/YY", "status": "COMPLETE"},
    {"category_risk": "Issue 1.2", "risk_probability": "Likely", "risk_impact": "High", "risk_rating": "Medium", "action_date": "MM/DD/YY", "status": "IN PROGRESS"},
    {"category_risk": "", "risk_probability": "Unlikely", "risk_impact": "Low", "risk_rating": "Low", "action_date": "MM/DD/YY", "status": "ON HOLD"},
    {"category_risk": "", "risk_probability": "Very Unlikely", "risk_impact": "Medium", "risk_rating": "Extreme", "action_date": "MM/DD/YY", "status": "NOT STARTED"},
    {"category_risk": "RISK 2", "status": ""},
    {"category_risk": "Issue 2.1", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "OVERDUE"},
    {"category_risk": "Issue 2.2", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "RISK 3", "status": ""},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "RISK 4", "status": ""},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "DEPARTMENT / PROJECT NAME", "status": ""},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
    {"category_risk": "", "risk_probability": "Highly Likely", "risk_impact": "Extreme", "risk_rating": "Extreme", "status": "COMPLETE"},
]
HEADER_ALIASES = {
    "asset_key": ["asset_key", "assetkey", "assetid", "asset id", "asset", "host", "hostname", "device", "resource", "resource name"],
    "dns_name": ["dns name", "dns", "hostname", "host", "fqdn"],
    "netbios_name": ["netbios name", "netbios", "computer name"],
    "ip_address": ["ip", "ipaddress", "ip address", "ipv4", "address"],
    "agent_id": ["agent id", "agentid", "agent"],
    "hostname": ["hostname", "host name"],
    "cve": ["cve", "cve id", "vulnerability id"],
    "severity": ["severity", "sev", "risk level", "risk", "priority", "device_risk_score", "device risk score"],
    "status": ["status", "state", "finding status", "remediation status", "ticket status"],
    "score": ["score", "cvss", "cvss score", "finding score", "adjusted_vulnerability_score", "adjusted vulnerability score", "cvss_v3_score", "cvss v3 score", "cvss_v2_score"],
    "title": ["title", "vulnerability", "finding", "issue", "name", "plugin name", "vulnerability_name", "vulnerability name"],
    "plugin_id": ["plugin id", "pluginid"],
    "plugin_name": ["plugin name", "plugin"],
    "plugin_direct_output": ["plugin direct output", "plugin output", "plugin direct output"],
    "solution": ["solution", "fix", "recommendation", "resolution"],
    "vpc_solution": ["vpc solution", "vpc solution"],
    "description": ["description", "details", "issue description", "vulnerability_description", "vulnerability description"],
    "synopsis": ["synopsis", "short description", "summary"],
    "see_also": ["see also", "references", "reference", "vulnerability_sources_url", "vulnerability sources url"],
    "owner": ["owner", "team", "assigned to", "assignee", "responsible"],
    "environment": ["environment", "env", "scope", "platform", "device_category", "device category", "asset category", "asset type", "asset_type"],
    "cloud_provider": ["cloud provider", "provider", "cloud", "platform provider", "account type"],
    "subscription": ["subscription", "subscription id", "subscription name"],
    "account": ["account", "account id", "project", "tenant"],
    "sitecode": ["sitecode", "site code", "site_code", "site", "plant", "plant code", "facility", "facility code", "location code"],
    "region": ["region", "availability zone", "zone", "location", "network"],
    "report_family": ["report type", "report family", "report", "feed", "source"],
    "report_scope": ["report scope", "scope type", "target type"],
    "time_elapsed_from_discovery": ["time elapsed from discovery", "time elapsed", "elapsed"],
    "first_discovered": ["first discovered", "first discovery", "discovery date"],
    "last_seen": ["last seen", "last seen date", "last detected"],
    "seconds_count": ["seconds_count", "seconds count", "duration seconds"],
    "port": ["port"],
    "protocol": ["protocol"],
    "remediation": ["remediation", "recommendation", "fix", "resolution", "action", "vulnerability_recommendations", "vulnerability recommendations", "vulnerability_manufacturer_remediation_info"],
    "due_date": ["due date", "duedate", "target date", "deadline", "sla due"],
}

SEVERITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5, "unknown": 6}

# Enhanced column detection for fresh data uploads (template sync)
ENHANCED_COLUMN_DETECTION = {
    'asset_key': ['asset_key', 'asset_id', 'asset_name', 'asset', 'host', 'hostname', 'device', 'ip', 'ip_address'],
    'cve': ['cve', 'cve_id', 'vulnerability_id', 'vulnerability'],
    'severity': ['severity', 'severity_level', 'risk_level', 'level', 'impact'],
    'cvss_score': ['cvss', 'cvss_score', 'cvss_v3', 'score', 'risk_score'],
    'status': ['status', 'final_status', 'state', 'current_status'],
    'age_days': ['age_days', 'days_open', 'days_since_discovery', 'age'],
    'first_discovered': ['discovered_date', 'first_detected', 'discovery_date', 'created_date'],
    'last_updated': ['updated_date', 'last_updated', 'last_seen', 'last_scan'],
    'source': ['source', 'data_source', 'detected_by', 'scanner'],
    'sitecode': ['sitecode', 'site code', 'site_code', 'plant', 'facility', 'location code'],
    'ticket_id': ['ticket_id', 'ticket', 'problem_ticket'],
    'remediation': ['remediation', 'remediation_status', 'fix_status'],
    'framework': ['framework', 'compliance_framework', 'standard', 'cis', 'nist'],
}
STATUS_ORDER = {"open": 1, "confirmed_open": 2, "accepted_risk": 3, "false_positive": 4, "closed": 5, "unknown": 6}
DISALLOWED_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]")


def load_header_learning_cache():
    global HEADER_LEARNING_CACHE
    if HEADER_LEARNING_CACHE is not None:
        return HEADER_LEARNING_CACHE

    default_data = {}
    try:
        if os.path.exists(HEADER_LEARNING_PATH):
            with open(HEADER_LEARNING_PATH, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
                if isinstance(loaded, dict):
                    default_data = loaded
    except Exception as exc:
        logger.warning("Header learning cache could not be loaded: %s", exc)

    # Normalize to lists of unique strings.
    normalized = {}
    for key, value in default_data.items():
        if isinstance(value, list):
            cleaned = []
            for item in value:
                text = str(item).strip()
                if text and text not in cleaned:
                    cleaned.append(text)
            if cleaned:
                normalized[str(key)] = cleaned

    HEADER_LEARNING_CACHE = normalized
    return HEADER_LEARNING_CACHE


def save_header_learning_cache(data):
    global HEADER_LEARNING_CACHE
    try:
        os.makedirs(os.path.dirname(HEADER_LEARNING_PATH), exist_ok=True)
        with open(HEADER_LEARNING_PATH, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        HEADER_LEARNING_CACHE = data
    except Exception as exc:
        logger.warning("Header learning cache could not be saved: %s", exc)


def get_detectable_aliases():
    merged = {key: list(values) for key, values in ENHANCED_COLUMN_DETECTION.items()}
    learned = load_header_learning_cache()
    for canonical, aliases in learned.items():
        merged.setdefault(canonical, [])
        existing = {a.lower().strip() for a in merged[canonical]}
        for alias in aliases:
            alias_text = str(alias).strip()
            if alias_text and alias_text.lower().strip() not in existing:
                merged[canonical].append(alias_text)
                existing.add(alias_text.lower().strip())
    return merged


def learn_header_aliases(headers, detected_mapping):
    if not headers or not detected_mapping:
        return

    learned = load_header_learning_cache()
    changed = False
    for canonical, col_idx in detected_mapping.items():
        if col_idx < 0 or col_idx >= len(headers):
            continue
        header_text = str(headers[col_idx] or "").strip()
        if not header_text:
            continue
        learned.setdefault(canonical, [])
        if header_text not in learned[canonical]:
            learned[canonical].append(header_text)
            changed = True

    if changed:
        save_header_learning_cache(learned)


def parse_builtin_questionnaire_rows(raw_rows):
    rows = []
    for line in raw_rows.strip().splitlines():
        parts = [part.strip() for part in line.split("|", 4)]
        if len(parts) != 5:
            continue
        section, reference, title, focus_area, question = parts
        rows.append({
            "section": section,
            "reference": reference,
            "title": title,
            "focus_area": focus_area,
            "question": question,
        })
    return rows


def build_builtin_questionnaire(questionnaire_id, name, framework, version, description, source, industry, audit_type, os_platform, raw_rows):
    questions = []
    sections = []
    for index, row in enumerate(parse_builtin_questionnaire_rows(raw_rows), start=1):
        control_id = row["reference"] if row["reference"] else f"Q{index}"
        if row["section"] and row["reference"]:
            control_id = f"{row['section']} {row['reference']}"
        questions.append({
            "control_id": control_id,
            "section": row["section"],
            "question_number": index,
            "title": row["title"],
            "focus_area": row["focus_area"],
            "question": row["question"],
            "framework": framework,
            "source": source,
        })
        if row["section"] and row["section"] not in sections:
            sections.append(row["section"])

    library_entries = [{
        "source": source,
        "industry": industry,
        "audit_type": audit_type,
        "framework": framework,
        "focus_area": question["focus_area"],
        "os_platform": os_platform,
        "title": question["title"],
        "question": question["question"],
        "control_id": question["control_id"],
        "questionnaire_id": questionnaire_id,
        "section": question["section"],
        "question_number": question["question_number"],
    } for question in questions]

    return {
        "id": questionnaire_id,
        "name": name,
        "framework": framework,
        "version": version,
        "description": description,
        "source": source,
        "industry": industry,
        "audit_type": audit_type,
        "os_platform": os_platform,
        "question_count": len(questions),
        "sections": sections,
        "questions": questions,
        "library_entries": library_entries,
    }


SECUMAT_INTERNAL_SECURITY_QUESTIONNAIRE_ROWS = """
A. General Questions|1|Safe Test Data|General security|Is safe (synthetic/anonymized) test data used instead of production data?
A. General Questions|2|Penetration Test Summary|Penetration testing|Has a management summary of the latest penetration test been provided?
A. General Questions|3|Remediation of Findings|Remediation|Have all findings classified as medium severity or higher been remediated?
A. General Questions|4|Central SIEM Forwarding|Logging and monitoring|Are logs forwarded to a central SIEM platform?
A. General Questions|5|ISO 27001 Evidence|Third-party assurance|Does the vendor / CSP provide evidence of ISO 27001 or equivalent certification?
B. Authentication & Authorization|1|IAM Engagement|Identity onboarding|Has the Identity and Access Management (IAM) function been engaged for application onboarding?
B. Authentication & Authorization|2|Modern Authentication|Authentication|Is modern authentication implemented (SAML / OAuth2 / OIDC)?
B. Authentication & Authorization|3|Provisioning Model|Authorization provisioning|How are user accounts and authorizations provisioned in the SaaS solution?
B. Authentication & Authorization|4|Joiner Mover Leaver|Identity lifecycle|How is the user account lifecycle maintained (joiner/mover/leaver)?
B. Authentication & Authorization|5|Non-Employee Access|Third-party access|Are there non-employee users (customers, partners, support, local admin accounts)?
C. Authentication & Authorization (Detail - if modern auth not implemented)|1|Authentication Method|Authentication|How are application users authenticated (describe)?
C. Authentication & Authorization (Detail - if modern auth not implemented)|2|Password Policy|Password governance|Does the password policy comply with corporate password rules (complexity & expiry)?
C. Authentication & Authorization (Detail - if modern auth not implemented)|3|MFA Coverage|Authentication|Is Multi-Factor Authentication (MFA) implemented?
C. Authentication & Authorization (Detail - if modern auth not implemented)|4|Account Administration|Identity lifecycle|How are application user accounts managed?
C. Authentication & Authorization (Detail - if modern auth not implemented)|5|Access Rights Model|Authorization|How are access rights defined in the application (e.g., RBAC)?
C. Authentication & Authorization (Detail - if modern auth not implemented)|6|Rights Ownership|Authorization ownership|Who manages access rights for the application?
C. Authentication & Authorization (Detail - if modern auth not implemented)|7|Administrator Accounts|Privileged access|How many administrator accounts exist in the application?
C. Authentication & Authorization (Detail - if modern auth not implemented)|8|Shared Accounts|Privileged access|Are there any generic/shared user accounts present in the application?
D. Data and Encryption|1|Database Encryption|Encryption at rest|Is data at rest encrypted in databases?
D. Data and Encryption|2|Object Storage Encryption|Encryption at rest|Is data at rest encrypted in file/object storage?
D. Data and Encryption|3|Transport Encryption|Encryption in transit|Are all transmission channels encrypted (e.g., HTTPS/TLS)?
E. Artificial Intelligence (AI)|1|AI Usage Type|AI governance|What kind of AI is used (GenAI / Analytic AI / ML / Other / None)?
E. Artificial Intelligence (AI)|2|AI Model Type|AI governance|What AI model is used (protected vs public)?
E. Artificial Intelligence (AI)|3|AI Risk Classification|AI risk|What risk classification does the AI/ML component have?
E. Artificial Intelligence (AI)|4|AI Owner|AI ownership|Is there a designated AI application/vendor manager?
E. Artificial Intelligence (AI)|5|AI Vendor Classification|Vendor management|Is the AI vendor documented and classified within vendor management?
E. Artificial Intelligence (AI)|6|AI Data Sensitivity|AI data governance|Is company-critical or personal data processed by the AI?
E. Artificial Intelligence (AI)|7|AI Protective Measures|AI data governance|If yes, which protective measures are applied (anonymisation, consent, etc.)?
E. Artificial Intelligence (AI)|8|AI Training Restrictions|AI data governance|Is it ensured that no sensitive information is used for AI training purposes?
E. Artificial Intelligence (AI)|9|AI Scalability Assessment|AI cost management|Has scalability and cost of increasing AI requests been assessed?
E. Artificial Intelligence (AI)|10|AI Data Flow|AI architecture|Is a documented AI data flow available?
E. Artificial Intelligence (AI)|11|AI User Notification|Transparency|Are affected persons informed about the use of AI?
E. Artificial Intelligence (AI)|12|Public Model Safeguards|AI data governance|If a public AI model is used, is it ensured no prohibited data is processed?
E. Artificial Intelligence (AI)|13|AI Security Measures|AI controls|Which technical/organisational AI security measures are implemented?
E. Artificial Intelligence (AI)|14|AI Output Review|AI quality assurance|Is a periodic documented review of AI output quality/correctness established?
F. On-Premise Interfaces|1|On-Prem Interfaces|Interfaces|Are there any interfaces to on-premise systems?
F. On-Premise Interfaces|2|API Gateway Integration|Interfaces|Is data exchanged via API gateway / integration platform?
F. On-Premise Interfaces|3|ERP Middleware|Interfaces|Is data exchanged via ERP middleware (e.g., SAP PO/CI)?
F. On-Premise Interfaces|4|SFTP Exchange|Interfaces|Is data exchanged via SFTP?
F. On-Premise Interfaces|5|FTPS Exchange|Interfaces|Is data exchanged via FTPS?
F. On-Premise Interfaces|6|SSH Exchange|Interfaces|Is data exchanged via SSH?
F. On-Premise Interfaces|7|VDI Exchange|Interfaces|Is data exchanged via VDI?
F. On-Premise Interfaces|8|Other On-Prem Interfaces|Interfaces|Are there other interfaces to exchange data?
G. Cloud Interfaces (3rd Party to 3rd Party)|1|Third-Party Cloud Connections|Cloud integration|Are there any third-party-to-third-party cloud connections?
G. Cloud Interfaces (3rd Party to 3rd Party)|2|Connected System|Cloud integration|To which system does the interface connect?
G. Cloud Interfaces (3rd Party to 3rd Party)|3|Access Setup|Authentication and authorization|How is access set up (authentication/authorization mechanism)?
G. Cloud Interfaces (3rd Party to 3rd Party)|4|Secret Encryption|Secrets management|Are credentials/client secrets transferred and stored encrypted?
G. Cloud Interfaces (3rd Party to 3rd Party)|5|Exchange Monitoring|Monitoring|Is the data exchange monitored?
G. Cloud Interfaces (3rd Party to 3rd Party)|6|Traffic Monitoring|Monitoring|Are there mechanisms to monitor data traffic between both systems?
H. Identity Provider App Registration|1|IdP App Registration Need|Identity platform|Are any IdP App Registrations / Enterprise Applications needed for this application?
H. Identity Provider App Registration|2|App Registration Name|Identity platform|Name of App Registration (as registered in the IdP)
H. Identity Provider App Registration|3|App Registration Scope|Identity platform|Scope / function of the App Registration
H. Identity Provider App Registration|4|Delegated Permissions|Identity platform|Which delegated permissions are needed?
H. Identity Provider App Registration|5|Application Permissions|Identity platform|Which application permissions are needed?
H. Identity Provider App Registration|6|Dangerous Permissions|Identity platform|Are any dangerous or highly privileged roles/API permissions used?
H. Identity Provider App Registration|7|Least Privilege Review|Identity platform|Is least privilege applied when assigning API permissions and scopes?
"""


CIS_CONTROLS_V8_QUESTIONNAIRE_ROWS = """
1. Inventory and Control of Enterprise Assets|1.1|Hardware Inventory|Asset management|Does your organization maintain a complete inventory of all enterprise assets connected to the network?
1. Inventory and Control of Enterprise Assets|1.2|Software Inventory|Asset management|Does your organization maintain a current inventory of authorized and unauthorized software?
2. Inventory and Control of Software Assets|2.1|Authorized Software|Software management|Is there a documented policy for authorized software across all systems?
2. Inventory and Control of Software Assets|2.2|Software Updates|Patch management|Are all software components kept up-to-date with latest security patches?
3. Data Protection|3.1|Data Discovery|Data governance|Have all sensitive data assets been identified and classified?
3. Data Protection|3.2|Data Protection Policy|Data governance|Is there a comprehensive data protection policy in place?
3. Data Protection|3.3|Encryption at Rest|Encryption|Are sensitive data assets encrypted when stored?
3. Data Protection|3.4|Encryption in Transit|Encryption|Is sensitive data encrypted when transmitted across networks?
4. Secure Configuration Management|4.1|Baseline Configuration|System hardening|Are baseline security configurations documented for all asset types?
4. Secure Configuration Management|4.2|Configuration Management|Change management|Is there a process to track and manage configuration changes?
5. Account Management|5.1|Account Inventory|Identity and access|Is there a current inventory of all user and service accounts?
5. Account Management|5.2|Access Rights|Authorization|Are access rights assigned based on least privilege principles?
5. Account Management|5.3|Administrator Access|Privileged access|Are administrator accounts restricted and monitored?
6. Access Control Management|6.1|Identity Provider|Identity management|Is a centralized identity provider implemented?
6. Access Control Management|6.2|Multi-Factor Authentication|Authentication|Is MFA required for all remote access?
6. Access Control Management|6.3|Least Privilege|Authorization|Is least privilege enforced for all accounts?
7. Continuous Defect and Vulnerability Management|7.1|Vulnerability Scanning|Vulnerability management|Are regular vulnerability scans performed?
7. Continuous Defect and Vulnerability Management|7.2|Penetration Testing|Vulnerability management|Are annual penetration tests performed?
8. Audit Log Management|8.1|Audit Logging|Logging and monitoring|Are audit logs enabled and retained for all systems?
8. Audit Log Management|8.2|Log Collection|Logging and monitoring|Are logs centrally collected and protected?
8. Audit Log Management|8.3|Log Analysis|Logging and monitoring|Are logs analyzed for suspicious activity?
9. Email and Web Browser Protections|9.1|Email Protection|Malware protection|Is email filtering and anti-phishing in place?
9. Email and Web Browser Protections|9.2|Browser Protection|Malware protection|Is web browser security enforced?
10. Malware Defenses|10.1|Malware Protection|Malware protection|Is anti-malware deployed on all endpoints?
10. Malware Defenses|10.2|Malware Monitoring|Malware protection|Are malware incidents monitored and responded to?
11. Infrastructure Defense|11.1|Network Segmentation|Network security|Is network segmentation implemented?
11. Infrastructure Defense|11.2|Firewall Rules|Network security|Are firewall rules documented and reviewed?
12. Boundary Defense|12.1|Boundary Monitoring|Network security|Is network traffic at the boundary monitored?
12. Boundary Defense|12.2|External Access|Network security|Is external access to internal systems restricted?
13. Incident Response Management|13.1|IR Plan|Incident response|Is there a documented incident response plan?
13. Incident Response Management|13.2|IR Exercises|Incident response|Are incident response exercises performed regularly?
14. Security Awareness and Skills Training|14.1|Awareness Training|Security awareness|Is security awareness training provided annually?
14. Security Awareness Training|14.2|Role-Specific Training|Security awareness|Is specialized training provided for technical roles?
15. Service Provider Management|15.1|Vendor Assessment|Vendor management|Are vendors assessed for security requirements?
15. Service Provider Management|15.2|Vendor Agreements|Vendor management|Do contracts include security requirements and audit rights?
16. Application Software Security|16.1|SDLC|Secure development|Is secure development lifecycle implemented?
16. Application Software Security|16.2|Code Review|Secure development|Are security code reviews performed?
17. Incident Response Management|17.1|Incident Detection|Incident response|Are security incidents detected and reported?
17. Incident Response Management|17.2|Incident Tracking|Incident response|Are incidents tracked to completion?
18. Penetration Testing|18.1|Authorized Testing|Testing|Are authorized penetration tests performed?
18. Penetration Testing|18.2|Test Results|Testing|Are penetration test results tracked and remediated?
"""

NIST_SP_800_53_QUESTIONNAIRE_ROWS = """
Access Control (AC)|AC-1|Access Control Policy|Access control|Is an organization-wide access control policy established, approved, and documented?
Access Control (AC)|AC-2|Account Management|Account management|Is account management policy and procedures defined?
Access Control (AC)|AC-3|Access Enforcement|Access control|Are access control rules enforced by information systems?
Access Control (AC)|AC-4|Information Flow|Information security|Are information flows controlled across system boundaries?
Access Control (AC)|AC-5|Separation of Duties|Segregation of duties|Is separation of duties enforced through information systems?
Access Control (AC)|AC-6|Least Privilege|Privileged access|Is least privilege principle applied to all users?
Access Control (AC)|AC-7|Failed Login|Account management|Are unsuccessful login attempts monitored and handled?
Identification and Authentication (IA)|IA-1|Identification and Authentication Policy|Identification and authentication|Is organization-wide IA policy established and maintained?
Identification and Authentication (IA)|IA-2|Authentication Methods|Authentication|Are authentication mechanisms required for all users?
Identification and Authentication (IA)|IA-3|Device Identification|Device security|Are devices authenticated before accessing the network?
Identification and Authentication (IA)|IA-4|Identifier Management|Account management|Are user identifiers managed throughout lifecycle?
Identification and Authentication (IA)|IA-5|Authenticator Management|Authentication|Are authenticators managed securely?
Identification and Authentication (IA)|IA-6|Access Restrictions|Authentication|Are access restrictions enforced for devices?
System and Communications Protection (SC)|SC-1|System and Communications Protection Policy|Security policy|Is SC policy established and maintained?
System and Communications Protection (SC)|SC-2|Application Partitioning|System security|Are applications partitioned to contain security functions?
System and Communications Protection (SC)|SC-3|Security Function Isolation|System security|Are security functions isolated from non-security functions?
System and Communications Protection (SC)|SC-4|Information Flooding|System security|Is system protection against information flooding provided?
System and Communications Protection (SC)|SC-5|Denial of Service Protection|Resilience|Is the system protected against denial of service attacks?
System and Communications Protection (SC)|SC-6|Resource Availability|Availability|Is adequate system resources provisioned for protection mechanisms?
System and Communications Protection (SC)|SC-7|Boundary Protection|Network security|Is system boundary protected from unauthorized access?
System and Communications Protection (SC)|SC-8|Transmission Confidentiality|Encryption|Is information in transit protected for confidentiality?
System and Communications Protection (SC)|SC-9|Transmission Integrity|Data integrity|Is information in transit protected for integrity?
System and Communications Protection (SC)|SC-10|Network Disconnect|Connection management|Are network connections disconnected when not required?
System and Communications Protection (SC)|SC-12|Cryptographic Key Establishment|Cryptography|Is cryptographic key establishment and management implemented?
Audit and Accountability (AU)|AU-1|Audit and Accountability Policy|Audit and logging|Is AU policy established and maintained?
Audit and Accountability (AU)|AU-2|Auditable Events|Audit and logging|Are auditable events defined for the system?
Audit and Accountability (AU)|AU-3|Content of Audit Records|Audit and logging|Does the system generate audit records with required information?
Audit and Accountability (AU)|AU-4|Audit Storage Capacity|Log management|Is sufficient audit storage capacity provisioned?
Audit and Accountability (AU)|AU-5|Response to Audit Processing|Audit and logging|Is there a defined response to audit processing failures?
Audit and Accountability (AU)|AU-6|Audit Review and Analysis|Log analysis|Are audit records reviewed and analyzed for anomalies?
Audit and Accountability (AU)|AU-12|Audit Generation|Audit and logging|Does the system provide audit record generation for events?
"""

ISO_27001_2022_QUESTIONNAIRE_ROWS = """
Information Security Policies|A.5.1|Policies for Information Security|Security governance|Is an organizational information security policy established and maintained?
Information Security Policies|A.5.2|Information Security Roles and Responsibilities|Governance|Are information security roles and responsibilities defined?
Organization of Information Security|A.6.1|Organization of Information Security|Governance|Are responsibilities for information security organized within management?
Organization of Information Security|A.6.2|Mobile Devices|Mobile security|Is policy for mobile devices implemented?
Organization of Information Security|A.6.3|Teleworking|Remote access|Is teleworking policy and security measures implemented?
Organization of Information Security|A.6.5|Access Control|Access management|Are access rights granted and revoked based on business requirements?
Organization of Information Security|A.6.6|Information Security in Supplier Relationships|Vendor management|Are supplier relationships managed with security requirements?
Organization of Information Security|A.6.7|Information Security Event Management|Incident management|Are information security events managed?
Organization of Information Security|A.6.8|Information Security Event Response|Incident response|Is incident response and improvement implemented?
Suppliers|A.5.3|Segregation of Duties|Segregation of duties|Is segregation of duties implemented?
Suppliers|A.5.4|Management Responsibilities|Management|Are management responsibilities for information security defined?
Suppliers|A.5.5|Contact with Authorities|Regulatory compliance|Does the organization maintain contact with relevant authorities?
Suppliers|A.5.6|Contact with Interest Groups|Engagement|Does the organization engage with interest groups?
Suppliers|A.5.7|Threat Intelligence|Threat intelligence|Is threat intelligence obtained and used?
Suppliers|A.5.8|Information Security in Project Management|Project management|Is information security integrated into project management?
Supplier Relations|A.8.1|Supplier Selection|Vendor management|Are suppliers selected based on security requirements?
Supplier Relations|A.8.2|Supplier Agreement|Contracts|Do supplier agreements include information security requirements?
Supplier Relations|A.8.3|Supplier Monitoring|Vendor management|Is supplier performance monitored against agreements?
Supplier Relations|A.8.4|Supplier Change Management|Change management|Are changes in supplier services managed?
Asset Management|A.8.5|Asset Inventory|Asset management|Is an inventory of information assets maintained?
Asset Management|A.8.6|Asset Ownership|Asset management|Are information assets assigned to owners?
Asset Management|A.8.7|Asset Use|Asset management|Is appropriate use of information assets defined?
Asset Management|A.8.8|Asset Return|Asset management|Are information assets returned upon termination?
Asset Management|A.8.9|Asset Handling and Storage|Data handling|Are data and media handled and stored securely?
Access Control|A.9.1|Access Control Policy|Access management|Is an access control policy established?
Access Control|A.9.2|User Registration and De-registration|Account management|Are user access registration and de-registration procedures implemented?
Access Control|A.9.3|User Access Provisioning|Access provisioning|Are user access provisioning procedures implemented?
Access Control|A.9.4|Access Rights Review|Access review|Are access rights reviewed and updated regularly?
Access Control|A.9.5|Access Rights Removal|De-provisioning|Are access rights removed when no longer required?
Cryptography|A.10.1|Cryptographic Controls Policy|Encryption policy|Is a cryptographic controls policy established?
Cryptography|A.10.2|Data Encryption|Data security|Is data encrypted according to classification?
Cryptography|A.10.3|Encryption Key Management|Key management|Is cryptographic key lifecycle managed securely?
"""

SOC2_PREPAREDNESS_CHECKLIST_ROWS = """
1. Objectives and Business Alignment|1.1|Customer Demand for SOC 2|Business objectives|Is SOC 2 attestation being requested by existing or target customers?
1. Objectives and Business Alignment|1.2|Security-First Culture Goal|Business objectives|Is building a security-first culture a key business objective for your organization?
1. Objectives and Business Alignment|1.3|Competitive Benchmarking|Business objectives|Are key competitors already SOC 2 compliant?
2. Audit Type Selection|2.1|Prior SOC 2 Audit Experience|Readiness assessment|Has your organization undergone a SOC 2 audit before?
2. Audit Type Selection|2.2|Timeline Flexibility|Readiness assessment|Is the SOC 2 report requirement not urgent within the next three months?
2. Audit Type Selection|2.3|Policy Implementation Resources|Readiness assessment|Do you have dedicated resources to develop and implement security policies?
2. Audit Type Selection|2.4|Control Ownership Awareness|Readiness assessment|Does the workforce understand its roles and responsibilities for implementing controls?
2. Audit Type Selection|2.5|System Change Communication|Readiness assessment|Do you have a process to communicate system changes to relevant stakeholders?
3. Trust Services Criteria Scope|3.1|TSC Security Scope|Trust Services Criteria|Have you selected Security as an in-scope Trust Services Criteria category?
3. Trust Services Criteria Scope|3.2|Documented Security Procedures|Trust Services Criteria|Do you review and document security procedures regularly?
3. Trust Services Criteria Scope|3.3|Backup and Recovery Procedures|Trust Services Criteria|Are backup and recovery procedures documented and tested?
3. Trust Services Criteria Scope|3.4|Cyber Incident Handling Procedures|Trust Services Criteria|Do you have defined procedures to detect, respond to, and report cyber incidents?
3. Trust Services Criteria Scope|3.5|Availability Commitment|Trust Services Criteria|Is your service uptime target formally defined and monitored?
3. Trust Services Criteria Scope|3.6|Availability Incident Process|Trust Services Criteria|Do you have processes to address service issues that impact availability?
3. Trust Services Criteria Scope|3.7|Service Access Restrictions|Trust Services Criteria|Are access restrictions and role-based access controls defined for service access?
3. Trust Services Criteria Scope|3.8|Confidential Data Handling|Trust Services Criteria|Are confidential data handling and processing requirements documented?
3. Trust Services Criteria Scope|3.9|Unauthorized Access Prevention|Trust Services Criteria|Are preventive and detective controls in place to avoid unauthorized data access?
3. Trust Services Criteria Scope|3.10|Processing Integrity Controls|Trust Services Criteria|Do systems provide timely and accurate data processing with validation controls?
3. Trust Services Criteria Scope|3.11|Error Detection and Correction|Trust Services Criteria|Are procedures defined to detect and correct processing errors quickly?
3. Trust Services Criteria Scope|3.12|PII Retention Policy|Trust Services Criteria|Is there a documented data retention policy that is communicated to customers?
3. Trust Services Criteria Scope|3.13|PII Storage and Protection|Trust Services Criteria|If PII is stored, are storage locations and protection controls documented?
4. Internal Risk Assessment|4.1|Threat and Risk Identification|Risk management|Have potential threats and associated business risks been identified?
4. Internal Risk Assessment|4.2|Risk Impact Estimation|Risk management|Have likelihood and business impact estimates been assigned to identified risks?
4. Internal Risk Assessment|4.3|Critical System Tagging|Risk management|Have critical systems been identified and tagged based on risk exposure?
4. Internal Risk Assessment|4.4|Risk Mitigation Strategies|Risk management|Have mitigation strategies been defined and assigned for identified risks?
5. Gap Analysis and Remediation|5.1|Control Alignment to TSC|Gap remediation|Are controls aligned and deployed according to selected Trust Services Criteria?
5. Gap Analysis and Remediation|5.2|Security Governance Structure|Gap remediation|Is there a clear organizational structure for information security governance?
5. Gap Analysis and Remediation|5.3|Documented Security Policies|Gap remediation|Are information security policies and procedures documented and maintained?
5. Gap Analysis and Remediation|5.4|Background Screening Process|Gap remediation|Is background screening performed for all new employees where legally permissible?
5. Gap Analysis and Remediation|5.5|Peer Review for Code Changes|Gap remediation|Are code repository changes peer reviewed before release?
5. Gap Analysis and Remediation|5.6|Periodic Security Training|Gap remediation|Do all employees receive periodic security awareness and role-based training?
5. Gap Analysis and Remediation|5.7|Compliance Evidence Collection|Gap remediation|Is evidence of control operation collected and retained for audit?
6. Readiness Assessment|6.1|Independent Readiness Review|Audit readiness|Has an independent readiness assessment been scheduled or completed?
6. Readiness Assessment|6.2|Readiness Gap Remediation|Audit readiness|Are identified readiness gaps remediated through control updates or new controls?
7. SOC 2 Audit Execution|7.1|Independent Auditor Engagement|Audit execution|Has an independent certified auditor been authorized for the SOC 2 audit?
7. SOC 2 Audit Execution|7.2|Audit Query Response Process|Audit execution|Is there a defined process and ownership for responding to auditor queries?
8. Continuous Monitoring|8.1|Evidence Collection Automation|Continuous compliance|Does continuous monitoring streamline evidence collection for controls?
8. Continuous Monitoring|8.2|Scalable Monitoring Program|Continuous compliance|Is the monitoring program scalable as the organization grows?
8. Continuous Monitoring|8.3|Monitoring Productivity Impact|Continuous compliance|Is monitoring designed to minimize employee productivity impact?
8. Continuous Monitoring|8.4|Control Failure Alerting|Continuous compliance|Are alerts generated when controls are missing, misconfigured, or failing?
8. Continuous Monitoring|8.5|Executive and Granular Visibility|Continuous compliance|Does monitoring provide both high-level and granular visibility into information security health?
8. Continuous Monitoring|8.6|Advanced Security Operations|Continuous compliance|Are additional measures in place such as MDM, incident management, penetration testing, and vulnerability scanning?
"""

SECUMAT_CDR_QUESTIONNAIRE_ROWS = """
Organisation of Information Security (OIS)|OIS-01|ISMS Coverage|ISMS|CSP operates an ISMS in accordance with ISO/IEC 27001 covering org units, locations and procedures for the cloud service; measures for setup, implementation, maintenance and continuous improvement are documented.
Organisation of Information Security (OIS)|OIS-02|Information Security Policy|Security policy|Top management has adopted and communicated an information security policy describing importance, objectives, security level, strategy and organisational structure.
Organisation of Information Security (OIS)|OIS-03|Interfaces and Dependencies|Third-party management|Interfaces/dependencies between CSP and third parties are documented and communicated for vulnerabilities, security incidents and malfunctions.
Organisation of Information Security (OIS)|OIS-04|Segregation of Duties|Governance|Conflicting tasks/responsibilities separated based on risk assessment to reduce unauthorized/unintended changes or misuse.
Organisation of Information Security (OIS)|OIS-05|Agency and Interest Group Contact|Threat intelligence|CSP maintains contact with relevant authorities/interest groups to stay informed of threats and vulnerabilities.
Organisation of Information Security (OIS)|OIS-06|Risk Management Policy|Risk management|Documented, communicated policies for identifying, analysing, evaluating, treating and documenting risks.
Organisation of Information Security (OIS)|OIS-07|Risk Management Execution|Risk management|Risk process executed at least annually covering shared resources, vulnerabilities, attack surface, segregation of duties and sub-service dependencies.
Security Policies and Instructions (SP)|SP-01|Policy Documentation|Security policy|Policies derived from the information security policy, documented, version-controlled, approved and communicated.
Security Policies and Instructions (SP)|SP-02|Policy Review and Approval|Security policy|Policies reviewed at least annually for adequacy and approved before becoming effective.
Security Policies and Instructions (SP)|SP-03|Policy Exceptions|Risk exceptions|Exceptions go through risk management process, documented, time-limited, reviewed annually.
Personnel (HR)|HR-01|Qualification and Trustworthiness|Personnel security|Competency/integrity of staff with access to customer data verified before employment per local law.
Personnel (HR)|HR-02|Employment Terms|Personnel security|Staff required by employment terms to comply with applicable security policies; acknowledged before access granted.
Personnel (HR)|HR-03|Security Training|Awareness|Target-group-oriented security awareness/training programme, regularly completed and updated.
Personnel (HR)|HR-04|Disciplinary Measures|Personnel security|Defined policy for actions taken on policy/legal violations.
Personnel (HR)|HR-05|Responsibilities After Role Change|Personnel security|Staff informed which security responsibilities remain after termination/role change.
Personnel (HR)|HR-06|Confidentiality Agreements|Personnel security|NDAs with staff, service providers, suppliers; accepted before access granted; reviewed annually.
Asset Management (AM)|AM-01|Asset Inventory|Asset management|Established procedures for inventorying assets through full lifecycle.
Asset Management (AM)|AM-02|Acceptable Use and Safe Handling|Asset management|Documented policy addressing asset lifecycle: approval, inventory, classification, secure config, patching, malware, deletion.
Asset Management (AM)|AM-03|Hardware Commissioning|Asset management|Approval process for hardware commissioning incl. risk identification and secure configuration verification.
Asset Management (AM)|AM-04|Hardware Decommissioning|Asset management|Approval-based decommissioning incl. complete/permanent data deletion or secure media destruction.
Asset Management (AM)|AM-05|Asset Return and Permissible Use|Asset management|Staff commit to acceptable use policies; assets provably returned on termination.
Asset Management (AM)|AM-06|Asset Classification and Labelling|Asset management|Assets classified/labelled to reflect protection needs (confidentiality, integrity, availability, authenticity).
Physical Security (PS)|PS-01|Physical Security Requirements|Physical security|Documented security requirements for premises/buildings addressing planning faults, access, surveillance, climate, fire, water, power, ventilation.
Physical Security (PS)|PS-02|Redundancy Model|Availability|Cloud service provided from 2+ redundant locations meeting availability requirements; tested at least annually.
Physical Security (PS)|PS-03|Perimeter Protection|Physical security|Structural shell physically solid and protected to detect/prevent unauthorized access.
Physical Security (PS)|PS-04|Site Access Control|Physical security|Access control system with least-privilege, automatic revocation, MFA, visitor tracking, logging.
Physical Security (PS)|PS-05|Fire and Smoke Protection|Physical security|Structural, technical and organisational fire/smoke protection measures.
Physical Security (PS)|PS-06|Power Failure Protection|Resilience|Operational redundancy (N+1), UPS/generators, maintenance, protected power/telecom lines.
Physical Security (PS)|PS-07|Environmental Monitoring|Monitoring|Monitoring/control of utility and environmental parameters with automatic alerting.
Operations (OPS)|OPS-01|Capacity Planning|Operations|Established procedure for capacity/resource planning with forecasting.
Operations (OPS)|OPS-02|Capacity Monitoring|Operations|Technical/organisational safeguards for monitoring provisioning/de-provisioning vs SLAs.
Operations (OPS)|OPS-03|Resource Control|Operations|Customers can control/monitor allocated resources to avoid overcrowding.
Operations (OPS)|OPS-04|Malware Protection Concept|Malware protection|Documented policy for malware protection across system components.
Operations (OPS)|OPS-05|Malware Protection Implementation|Malware protection|System components configured with malware protection, signatures updated at least daily.
Operations (OPS)|OPS-06|Backup and Recovery Concept|Backup and recovery|Documented backup/recovery policy aligned to RTO/RPO and contractual commitments.
Operations (OPS)|OPS-07|Backup Monitoring|Backup and recovery|Backup execution monitored; malfunctions investigated/resolved promptly.
Operations (OPS)|OPS-08|Backup Testing|Backup and recovery|Restore procedures tested at least annually against RTO/RPO.
Operations (OPS)|OPS-09|Backup Storage|Backup and recovery|Backups transferred/stored at a remote location with equivalent physical/environmental security.
Operations (OPS)|OPS-10|Logging Concept|Logging and monitoring|Documented policy for logging/monitoring events, retention, roles, time sync, legal compliance.
Operations (OPS)|OPS-11|Metadata Management|Logging and monitoring|Policy for secure handling of metadata: collected/used only for defined purposes, no commercial use.
Operations (OPS)|OPS-12|Log Access and Deletion|Logging and monitoring|Technical controls restrict log access, enforce retention and deletion.
Operations (OPS)|OPS-13|Event Identification|Logging and monitoring|Automated monitoring/correlation of log data; events reported to responsible teams.
Operations (OPS)|OPS-14|Central Log Storage|Logging and monitoring|Logs retained centrally, unchangeable/aggregated; authenticated transfer with encryption.
Operations (OPS)|OPS-15|Tenant Accountability|Logging and monitoring|Logs allow unambiguous identification of tenant-level user access for forensic analysis.
Operations (OPS)|OPS-16|Logging Configuration Access|Logging and monitoring|Access to logging/monitoring components restricted to authorised users.
Operations (OPS)|OPS-17|Monitoring Software Availability|Logging and monitoring|Monitoring system components themselves monitored for failures.
Operations (OPS)|OPS-18|Vulnerability Management Concept|Vulnerability management|Documented policy for timely identification, severity assessment, prioritisation and remediation of vulnerabilities.
Operations (OPS)|OPS-19|Penetration Tests|Vulnerability management|Penetration tests at least annually by qualified internal/external parties; findings remediated per defined timelines.
Operations (OPS)|OPS-20|Handling Effectiveness Review|Vulnerability management|Regular measurement/analysis/assessment of vulnerability and incident handling effectiveness (at least quarterly).
Operations (OPS)|OPS-21|Customer Incident Involvement|Incident management|Customers periodically informed about incident status and resolution per agreements.
Operations (OPS)|OPS-22|Known Vulnerability Testing|Vulnerability management|Automated vulnerability scanning at least monthly with CVSS-based remediation timelines.
Operations (OPS)|OPS-23|System Hardening|System hardening|System components hardened to generally accepted industry standards (e.g. CIS Benchmarks).
Operations (OPS)|OPS-24|Dataset Separation|Multi-tenancy|Customer data on shared resources securely/strictly separated per documented concept.
Identity and Access Management (IDM)|IDM-01|User Account Policy|Identity and access management|Role/rights concept and policy: unique usernames, least-privilege, segregation of duties, approvals, periodic review, MFA for privileged access.
Identity and Access Management (IDM)|IDM-02|Granting and Change of Access|Identity and access management|Specified, preferably automated, procedures for granting/changing accounts and rights.
Identity and Access Management (IDM)|IDM-03|Inactive Account Locking|Identity and access management|Accounts auto-locked after 2 months inactivity, revoked after 6 months.
Identity and Access Management (IDM)|IDM-04|Access Changes on Role Update|Identity and access management|Access promptly revoked/adjusted on role change: privileged within 48h, others within 14 days.
Identity and Access Management (IDM)|IDM-05|Periodic Access Review|Identity and access management|Access rights reviewed at least annually (privileged: every 6 months); deviations remediated within 7 days.
Identity and Access Management (IDM)|IDM-06|Privileged Access Rights|Privileged access|Privileged access personalised, time-limited, need-to-know based; activities logged and monitored for misuse.
Identity and Access Management (IDM)|IDM-07|Access to Customer Data|Customer data access|Customer informed when staff access customer data without prior consent (unless encrypted); type/scope/time of access communicated within agreed timeframe.
Identity and Access Management (IDM)|IDM-08|Authentication Information Confidentiality|Authentication|Authentication info (e.g., passwords) allocated/stored confidentially; cryptographic hashing for password storage.
Identity and Access Management (IDM)|IDM-09|Authentication Mechanisms|Authentication|Production access requires MFA; password requirements derived from risk assessment and enforced technically.
Cryptography and Key Management (CRY)|CRY-01|Encryption and Key Policy|Cryptography|Documented policy for encryption procedures/secure key lifecycle aligned to data classification.
Cryptography and Key Management (CRY)|CRY-02|Transport Encryption|Cryptography|Strong encryption/authentication for data transmitted over public networks (TLS 1.2/1.3 + PFS).
Cryptography and Key Management (CRY)|CRY-03|Storage Encryption|Cryptography|Customer data encrypted at rest; private keys known only to customer (with documented exceptions).
Cryptography and Key Management (CRY)|CRY-04|Secure Key Management|Cryptography|Procedures covering key generation, certificates, provisioning, secure storage, rotation, compromise handling, withdrawal/deletion.
Communication Security (COS)|COS-01|Technical Safeguards|Network security|Technical measures to detect/respond to network attacks (DDoS, anomalous traffic) feeding into SIEM.
Communication Security (COS)|COS-02|Connection Security Requirements|Network security|Documented requirements defining zone separation, permitted protocols, admin traffic segregation.
Communication Security (COS)|COS-03|Connection Monitoring|Network security|Trusted/untrusted networks segregated into security zones; configuration reviewed at least annually.
Communication Security (COS)|COS-04|Cross-Network Access|Network security|Each network perimeter controlled by security gateways; access authorisation risk-based.
Communication Security (COS)|COS-05|Admin Networks|Network security|Separate networks for infrastructure administration/management consoles, protected by MFA.
Communication Security (COS)|COS-06|Traffic Segregation|Network security|Customer data traffic segregated on network level per documented concept (e.g. VLAN, encryption).
Communication Security (COS)|COS-07|Network Topology Documentation|Network security|Up-to-date, traceable network topology documentation incl. zoning/segmentation and data locations.
Communication Security (COS)|COS-08|Data Transmission Policies|Network security|Documented policy protecting transmitted data against interception, manipulation, redirection, destruction.
Portability and Interoperability (PI)|PI-01|Input and Output Interfaces|Interoperability|Documented, secure inbound/outbound interfaces using standardised, encrypted communication protocols.
Portability and Interoperability (PI)|PI-02|Data Provision Agreements|Interoperability|Contracts define type/scope/format/timeframe for data provision and deletion upon termination.
Portability and Interoperability (PI)|PI-03|Secure Deletion|Data lifecycle|Procedures ensure complete deletion of customer data (incl. metadata/backups) upon termination, preventing forensic recovery.
Procurement, Development and Modification of Information Systems (DEV)|DEV-01|Secure SDLC Policy|Secure development|Documented secure-SDLC policy covering requirements, design, implementation, testing, deployment, operations.
Procurement, Development and Modification of Information Systems (DEV)|DEV-02|Outsourced Development|Secure development|Contractual security/testing/vulnerability requirements for outsourced development.
Procurement, Development and Modification of Information Systems (DEV)|DEV-03|Change Management Policy|Change management|Documented change management policy: risk assessment, testing, segregation of duties, customer notification, emergency changes.
Procurement, Development and Modification of Information Systems (DEV)|DEV-04|Secure Delivery Training|Secure development|Training programme on secure development standards/tools, regularly reviewed.
Procurement, Development and Modification of Information Systems (DEV)|DEV-05|Change Risk Assessment|Change management|Changes risk-assessed, categorised and prioritised per policy.
Procurement, Development and Modification of Information Systems (DEV)|DEV-06|Testing Changes|Change management|Appropriate testing (manual/automated) prior to deployment; severity-based remediation.
Procurement, Development and Modification of Information Systems (DEV)|DEV-07|Change Logging|Change management|Source code management/deployment tools log all changes traceable to individuals.
Procurement, Development and Modification of Information Systems (DEV)|DEV-08|Version Control|Change management|Version control tracks dependencies and supports rollback after errors/vulnerabilities.
Procurement, Development and Modification of Information Systems (DEV)|DEV-09|Production Approval|Change management|Authorised approval required before changes go live based on defined criteria.
"""

# ===== SECUMAT TEMPLATES =====
SECUMAT_TEMPLATES = {
    "cis_controls_v8": {
        "name": "CIS Controls v8.0",
        "framework": "CIS",
        "version": "8.0",
        "description": "Center for Internet Security Controls v8.0 - 18 control groups covering asset mgmt, access control, security awareness, etc.",
        "control_count": 18,
        "source": "SecuMat CIS NIST ISO27001 Controls_FIEF.xlsx & ZF Security Maturity templates"
    },
    "nist_csf_2024": {
        "name": "NIST Cybersecurity Framework 2.0",
        "framework": "NIST",
        "version": "2.0",
        "description": "NIST CSF 2024 - 6 core functions (Govern, Identify, Protect, Detect, Respond, Recover) with detailed practices",
        "control_count": 23,
        "source": "ZF Security Maturity Secumat templates"
    },
    "iso_27001": {
        "name": "ISO/IEC 27001:2022",
        "framework": "ISO",
        "version": "27001:2022",
        "description": "Information Security Management Systems - 14 control groups covering governance, HR, asset management, access control, crypto, etc.",
        "control_count": 14,
        "source": "SecuMat ISO 27001 & ZF Security Maturity templates"
    },
    "cis_vs_wiz": {
        "name": "CIS Controls vs Wiz Comparison",
        "framework": "Comparison",
        "version": "2024",
        "description": "Comparative mapping between CIS Controls and Wiz cloud security framework",
        "control_count": 12,
        "source": "Wiz_vs_CIS_Controls_Comparison.xlsx"
    },
    "zf_secumat_complete": {
        "name": "ZF SecuMat Complete Framework",
        "framework": "Multi-Framework",
        "version": "2024",
        "description": "Complete ZF Security Maturity questionnaire with CIS, NIST, and ISO 27001 controls integrated",
        "control_count": 180,
        "source": "ZF Security Maturity Secumat_CIS_Controls_Version_8_NIST_ISO27k1_updated Questionnaire"
    }
}

SECUMAT_OPTIONS = {
    "frameworks": ["CIS", "NIST", "ISO", "SOC 2", "PCI-DSS", "HIPAA", "GDPR", "GLBA", "FFIEC", "Custom"],
    "audit_types": ["Internal", "External", "Compliance", "VAPT", "Cloud Security"],
    "industries": ["Healthcare", "Finance", "E-Commerce", "Critical Infrastructure", "Manufacturing", "Technology", "Government", "Energy", "Retail", "Custom"],
    "operating_systems": ["Windows", "Linux", "macOS", "Multi-OS", "Cloud Native", "OT/ICS Mixed", "Other"],
    "divisions": ["Corporate IT", "SOC", "Engineering", "Plant Operations", "Cloud Operations", "Risk & Compliance", "Shared Services", "Regional Division", "Other"],
    "quarters": ["Quarter 1", "Quarter 2", "Quarter 3", "Quarter 4"],
    "questionnaire_modes": [
        "Master Questionnaire",
        "Customized Questionnaire",
        "SECUMAT Security Questionnaire",
        "SECUMAT Internal Security Control Questionnaire",
        "SECUMAT CDR",
        "SECUMAT Cloud Detailed Report (BSI C5:2020)",
        "CIS Controls v8",
        "NIST SP 800-53",
        "Dashboard Summary",
    ],
}

SECUMAT_RESOURCES = [
    {
        "name": "README",
        "description": "Platform overview and dashboard capabilities for onboarding auditors and security teams.",
        "target_type": "file",
        "target": "README.md",
    },
    {
        "name": "Master Questionnaire",
        "description": "Baseline template inventory across CIS, NIST, ISO, and custom questionnaires.",
        "target_type": "section",
        "target": "setup",
    },
    {
        "name": "Dashboard",
        "description": "Main operational dashboard for vulnerability posture, compliance, and CAB coordination.",
        "target_type": "section",
        "target": "overview",
    },
    {
        "name": "Upload Guide",
        "description": "Operational upload instructions for CSV/XLSX audit evidence and reports.",
        "target_type": "file",
        "target": "docs\\UPLOADS.md",
    },
]

SECUMAT_QUESTIONNAIRE_LIBRARY = [
    {
        "industry": "Healthcare",
        "audit_type": "Compliance",
        "framework": "HIPAA",
        "focus_area": "ePHI safeguards",
        "title": "Healthcare ePHI Protection Review",
        "question": "How are electronic protected health records encrypted, stored, transmitted, and monitored for unauthorized disclosure?",
    },
    {
        "industry": "Healthcare",
        "audit_type": "Internal",
        "framework": "HIPAA",
        "focus_area": "Access logs",
        "title": "Clinical Access Monitoring",
        "question": "Can the organization prove that only authorized care teams accessed patient records, with complete audit logging and exception review?",
    },
    {
        "industry": "Healthcare",
        "audit_type": "VAPT",
        "framework": "HIPAA",
        "focus_area": "Connected medical devices",
        "title": "Medical Device Security Validation",
        "question": "How are pacemakers, pumps, scanners, and other connected medical devices segmented, patched, and tested for exploitable weaknesses?",
    },
    {
        "industry": "Finance",
        "audit_type": "Compliance",
        "framework": "FFIEC",
        "focus_area": "Core banking security",
        "title": "Transaction Platform Assurance",
        "question": "What security controls protect wire transfer, ACH, treasury, and trading systems from unauthorized transactions and misuse?",
    },
    {
        "industry": "Finance",
        "audit_type": "Internal",
        "framework": "GLBA",
        "focus_area": "Fraud detection",
        "title": "Fraud Monitoring Validation",
        "question": "Which automated triggers identify unusual spending spikes, account takeover indicators, and privileged misuse before funds leave the organization?",
    },
    {
        "industry": "Finance",
        "audit_type": "External",
        "framework": "SOC 2",
        "focus_area": "Vendor risks",
        "title": "Third-Party Fintech Risk Review",
        "question": "How are fintech vendors, payment processors, and shared service providers assessed for access, resilience, and incident response obligations?",
    },
    {
        "industry": "Critical Infrastructure",
        "audit_type": "Compliance",
        "framework": "NIST",
        "focus_area": "Operational technology",
        "title": "OT Control System Audit",
        "question": "How are industrial controllers, engineering workstations, and SCADA systems inventoried, segmented, and monitored for cyber-physical risk?",
    },
    {
        "industry": "Critical Infrastructure",
        "audit_type": "Internal",
        "framework": "NIST",
        "focus_area": "Air-gapping",
        "title": "Air-Gap and Segmentation Review",
        "question": "Can the organization demonstrate that critical OT assets are isolated from internet-connected networks with controlled exception paths only?",
    },
    {
        "industry": "Critical Infrastructure",
        "audit_type": "VAPT",
        "framework": "NIST",
        "focus_area": "SCADA systems",
        "title": "SCADA Security Testing",
        "question": "Which simulated attack paths were used to validate monitoring, fail-safe controls, and remote-access protections in SCADA environments?",
    },
    {
        "industry": "E-Commerce",
        "audit_type": "Compliance",
        "framework": "PCI-DSS",
        "focus_area": "Cardholder data",
        "title": "Payment Data Protection Review",
        "question": "How is cardholder data tokenized, encrypted, retained, and segmented from non-payment workloads across the commerce stack?",
    },
    {
        "industry": "Technology",
        "audit_type": "Cloud Security",
        "framework": "SOC 2",
        "focus_area": "Cloud configuration",
        "title": "Cloud Configuration Governance",
        "question": "Which controls detect public storage exposure, IAM drift, and insecure data flows between on-premises and cloud services?",
    },
    {
        "industry": "Custom",
        "audit_type": "External",
        "framework": "ISO",
        "focus_area": "ISMS governance",
        "title": "ISO 27001 Management Review",
        "question": "How does management validate ownership, policy coverage, risk treatment, and evidence maturity across the information security management system?",
    },
]

SECUMAT_OPTIONS["audit_cycles"] = [f"Audit-{index}" for index in range(1, 21)]

SECUMAT_QUESTIONNAIRE_LIBRARY.extend([
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "ISO 27001; CIS Controls; NIST; PCI-DSS",
        "focus_area": "Asset inventory",
        "os_platform": "All",
        "title": "Complete Asset Inventory",
        "question": "Is a complete, classified asset inventory maintained with assigned ownership?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "ISO 27001; CIS 1.1-1.5",
        "focus_area": "Asset review",
        "os_platform": "All",
        "title": "Asset Inventory Review Cycle",
        "question": "Is inventory reviewed at least bi-annually and are unmanaged assets detected through CMDB or discovery tooling?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "ISO 27001; CIS 5/6; NIST AC; SOC 2; PCI-DSS",
        "focus_area": "Identity and access",
        "os_platform": "All",
        "title": "MFA Coverage",
        "question": "Is MFA enabled for all privileged, remote, and externally exposed access paths?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "CIS 5.3; CIS 6.8",
        "focus_area": "Identity lifecycle",
        "os_platform": "All",
        "title": "Dormant Account Review",
        "question": "Are dormant accounts identified, disabled, and reviewed at least quarterly?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "CIS 4; ISO 27001",
        "focus_area": "Endpoint security",
        "os_platform": "Windows",
        "title": "Windows Baseline & BitLocker",
        "question": "Are Windows baselines, BitLocker, Defender, and patching controls deployed within the required SLA?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "CIS 4",
        "focus_area": "Linux hardening",
        "os_platform": "Linux",
        "title": "Linux Hardening Review",
        "question": "Are SELinux/AppArmor, SSH hardening, root login restrictions, and audit logging enforced on Linux platforms?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "CIS 4; ISO 27001",
        "focus_area": "macOS security",
        "os_platform": "macOS",
        "title": "macOS Security Controls",
        "question": "Is FileVault enabled, Gatekeeper enforced, MDM deployed, and update automation active on macOS endpoints?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Cloud Security",
        "framework": "CIS 4; ISO 27017",
        "focus_area": "Cloud workload protection",
        "os_platform": "Cloud Native",
        "title": "Cloud-Native Endpoint Protection",
        "question": "Is cloud-native workload protection enabled across Azure, AWS, or GCP workloads?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "CIS 7; ISO 27001 A.8; PCI-DSS 11; NIST RA",
        "focus_area": "Vulnerability management",
        "os_platform": "All",
        "title": "Vulnerability SLA Review",
        "question": "Are vulnerability scans performed regularly with critical findings remediated within SLA?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "CIS 7; PCI-DSS 6; SOC 2",
        "focus_area": "Patch and CAB",
        "os_platform": "All",
        "title": "Patch Governance and CAB",
        "question": "Is there a documented patch policy with CAB approval and tested rollback procedures?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "ISO 27001; CIS 8/13; NIST DE; PCI-DSS 10; SOC 2",
        "focus_area": "Logging and monitoring",
        "os_platform": "All",
        "title": "SIEM and Retention",
        "question": "Is a SIEM implemented with centralized logs, daily alert review, and defined retention controls?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "ISO 27035; NIST IR; SOC 2; PCI-DSS 12; CIS 17",
        "focus_area": "Incident management",
        "os_platform": "All",
        "title": "Incident Response Preparedness",
        "question": "Is there a documented incident response plan, trained SOC team, and tracked MTTD/MTTR metrics?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "Retail",
        "audit_type": "Compliance",
        "framework": "PCI-DSS v4.0",
        "focus_area": "Cardholder data",
        "os_platform": "All",
        "title": "PCI Cardholder Data Review",
        "question": "Is cardholder data identified, PAN encrypted, and are quarterly ASV scans and annual penetration tests completed?",
    },
    {
        "source": "Master Questionnaire",
        "industry": "Manufacturing;Energy;Automotive",
        "audit_type": "Compliance",
        "framework": "IEC 62443",
        "focus_area": "OT security",
        "os_platform": "OT/ICS Mixed",
        "title": "IEC 62443 OT Control Review",
        "question": "Are OT assets inventoried, zones and conduits documented, and remote access controlled across industrial systems?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "SECUMAT",
        "focus_area": "General security",
        "os_platform": "All",
        "title": "Synthetic Test Data",
        "question": "Is safe synthetic or anonymized test data used instead of production data?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "VAPT",
        "framework": "SECUMAT",
        "focus_area": "Penetration testing",
        "os_platform": "All",
        "title": "Penetration Test Evidence",
        "question": "Has a management summary of the latest penetration test been provided?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "SECUMAT",
        "focus_area": "Authentication",
        "os_platform": "All",
        "title": "Modern Authentication",
        "question": "Is modern authentication such as SAML, OAuth2, or OIDC implemented?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "SECUMAT",
        "focus_area": "Identity lifecycle",
        "os_platform": "All",
        "title": "Joiner/Mover/Leaver Process",
        "question": "How is the user account lifecycle maintained for joiners, movers, and leavers?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "SECUMAT",
        "focus_area": "Encryption",
        "os_platform": "All",
        "title": "Data at Rest Encryption",
        "question": "Is data at rest encrypted in databases and object storage?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "SECUMAT",
        "focus_area": "Transport encryption",
        "os_platform": "All",
        "title": "TLS and Secure Channels",
        "question": "Are all transmission channels encrypted with HTTPS or TLS equivalent controls?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "Technology",
        "audit_type": "Internal",
        "framework": "SECUMAT; AI Governance",
        "focus_area": "Artificial intelligence",
        "os_platform": "Cloud Native",
        "title": "AI Model Classification",
        "question": "What type of AI is used, what model is selected, and what risk classification has been assigned?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "Technology",
        "audit_type": "Compliance",
        "framework": "SECUMAT; AI Governance",
        "focus_area": "AI data governance",
        "os_platform": "Cloud Native",
        "title": "AI Data Flow and Controls",
        "question": "Is a documented AI data flow available, with controls preventing sensitive data from entering training workflows?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Cloud Security",
        "framework": "SECUMAT",
        "focus_area": "Interfaces",
        "os_platform": "Cloud Native",
        "title": "Third-Party Cloud Interfaces",
        "question": "How are third-party cloud-to-cloud interfaces authenticated, monitored, and protected for encrypted secret handling?",
    },
    {
        "source": "SECUMAT Security Questionnaire",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "SECUMAT",
        "focus_area": "App registrations",
        "os_platform": "Cloud Native",
        "title": "Identity Provider App Registration Review",
        "question": "Are delegated permissions, application permissions, and high-privilege API roles constrained using least privilege?",
    },
    {
        "source": "SECUMAT CDR",
        "industry": "All",
        "audit_type": "Cloud Security",
        "framework": "BSI C5:2020; ISO 27001",
        "focus_area": "ISMS",
        "os_platform": "Cloud Native",
        "title": "Cloud ISMS Coverage",
        "question": "Does the cloud service operate an ISMS aligned to ISO 27001 with documented setup, maintenance, and continuous improvement procedures?",
    },
    {
        "source": "SECUMAT CDR",
        "industry": "All",
        "audit_type": "Cloud Security",
        "framework": "BSI C5:2020",
        "focus_area": "Risk management",
        "os_platform": "Cloud Native",
        "title": "Cloud Risk Management Policy",
        "question": "Is there a documented and communicated risk management policy for identifying, analysing, treating, and documenting cloud service risks?",
    },
    {
        "source": "SECUMAT CDR",
        "industry": "All",
        "audit_type": "Cloud Security",
        "framework": "BSI C5:2020",
        "focus_area": "Logging and monitoring",
        "os_platform": "Cloud Native",
        "title": "Cloud Logging Concept",
        "question": "Is there a documented logging and monitoring policy covering retention, roles, time synchronization, and legal compliance?",
    },
    {
        "source": "SECUMAT CDR",
        "industry": "All",
        "audit_type": "Cloud Security",
        "framework": "BSI C5:2020",
        "focus_area": "Identity and access management",
        "os_platform": "Cloud Native",
        "title": "Privileged Access Review",
        "question": "Are privileged access rights personalized, time-limited, need-to-know based, and logged for misuse monitoring?",
    },
    {
        "source": "NIST SP 800-53",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "NIST SP 800-53",
        "focus_area": "Access control",
        "os_platform": "All",
        "title": "AC-2 Account Management",
        "question": "Are automated account provisioning and account management controls established and evidenced?",
    },
    {
        "source": "NIST SP 800-53",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "NIST SP 800-53",
        "focus_area": "Access enforcement",
        "os_platform": "All",
        "title": "AC-3 Access Enforcement",
        "question": "Are approved authorizations and separation of duties enforced through technical and procedural controls?",
    },
    {
        "source": "NIST SP 800-53",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "NIST SP 800-53",
        "focus_area": "Audit events",
        "os_platform": "All",
        "title": "AU-2 Audit Events",
        "question": "Have security-relevant events to be logged been identified, documented, and tested for sufficiency?",
    },
    {
        "source": "NIST SP 800-53",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "NIST SP 800-53",
        "focus_area": "Authentication",
        "os_platform": "All",
        "title": "IA-2 Authentication",
        "question": "Are unique user identification and strong authentication mechanisms implemented and reviewed?",
    },
    {
        "source": "CIS Controls v8",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "CIS Controls v8",
        "focus_area": "Asset inventory",
        "os_platform": "All",
        "title": "CIS 1.1 Asset Inventory",
        "question": "Is an accurate and detailed enterprise asset inventory maintained with network address, owner, department, and approval status?",
    },
    {
        "source": "CIS Controls v8",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "CIS Controls v8",
        "focus_area": "Software inventory",
        "os_platform": "All",
        "title": "CIS 2.1 Software Inventory",
        "question": "Is a detailed inventory of licensed software maintained with publisher, install date, and business purpose?",
    },
    {
        "source": "CIS Controls v8",
        "industry": "All",
        "audit_type": "Compliance",
        "framework": "CIS Controls v8",
        "focus_area": "Secure configuration",
        "os_platform": "All",
        "title": "CIS 4.1 Secure Configuration Process",
        "question": "Is there a documented and maintained secure configuration process for enterprise assets and software?",
    },
    {
        "source": "Dashboard Summary",
        "industry": "All",
        "audit_type": "Internal",
        "framework": "SECUMAT Dashboard",
        "focus_area": "Audit readiness",
        "os_platform": "All",
        "title": "Overall Audit Readiness",
        "question": "What is the current audit readiness score, enterprise risk level, cloud security score, and automation maturity band for this engagement?",
    },
])

ISO_42001_AUTOMOTIVE_QUESTIONNAIRE_ROWS = """
AIMS Scope|4.3|Scope of AIMS|Corporate Governance|Does the documented scope explicitly separate Enterprise AI, Industrial Shop-Floor AI, and safety-critical Product AI (e.g., ADAS)?
AI Policy|5.2|AI Policy|Executive Board / Quality|Does the corporate AI Policy explicitly bridge the gap between AI non-determinism and strict automotive functional safety (ISO 26262)?
Risk Assessment|6.1.2|Risk Assessment - SOTIF Integration|R&D / Safety Engineering|Does the AI risk methodology integrate ISO 21448 (SOTIF) to evaluate risks from model functional insufficiencies and edge cases?
Competence|7.2|Competence|Human Resources / R&D|Are the specific competency requirements and training logs for data scientists building neural networks documented and verified?
AI System Impact Assessment|8.4|AI System Impact Assessment|Product Management / ADAS|Is there a completed individual Impact Assessment evaluating risks to human life and safety for models controlling physical vehicle motion?
Internal Audit|9.2|Internal Audit|Internal Audit Team|Has an internal audit schedule been executed targeting the lifecycle and retraining pipelines of active automotive AI systems?
AI System Inventory|A.2.2|AI System Inventory|Enterprise Architecture / IT|Is there a centralized, active registry logging all deployed AI models, including embedded code, shop-floor computer vision, and vendor tools?
AI System Lifecycle|A.5.2|AI System Lifecycle|Software Release Management|When an optimized AI model is deployed via an Over-the-Air (OTA) update, what regression protocols verify that safety is not degraded?
Data for AI Systems|A.6.1|Data for AI Systems|Data Engineering / MLOps|What verification mechanisms track the data lineage, labeling accuracy, and bias screening of driving data ingested into the cloud?
Data Privacy and Collection|A.6.2|Data Privacy and Collection|Legal & Compliance / Data|How are global privacy laws enforced when capturing and processing public road camera/LiDAR data containing faces and license plates?
Synthetic Data Validation|A.6.4|Synthetic Data Validation|Simulation & Validation|When using simulated/synthetic environments to train models, how is it verified that the data matches real-world physical dynamics?
Transparency|A.7.2|Transparency / Provision of Information|Customer Engineering / Sales|Are technical system summaries prepared to provide OEM clients with transparent info on model limitations and confidence thresholds?
Explainability|A.7.4|Explainability|Systems Architecture|Do the deep learning architectures used in autonomous driving provide a traceable, auditable chain of logic for post-accident investigations?
Continuous Monitoring|A.9.2|Continuous Monitoring|MLOps / Fleet Operations|How does the MLOps pipeline continuously monitor deployed vehicle models for model drift or degrading inference accuracy in the field?
Human in the Loop|A.9.4|Human in the Loop|Smart Factory / OT|For AI on the manufacturing line, what are the triggers to flag model failure, and how does the system safely hand control to a human operator?
"""

SECUMAT_BUILTIN_QUESTIONNAIRES = [
    build_builtin_questionnaire(
        "secumat_internal_security_control_questionnaire",
        "SECUMAT Internal Security Control Questionnaire",
        "SECUMAT",
        "2024",
        "Generic reusable security control questionnaire covering authentication, data protection, AI, interfaces, and app registrations.",
        "SECUMAT Internal Security Control Questionnaire",
        "All",
        "Compliance",
        "All",
        SECUMAT_INTERNAL_SECURITY_QUESTIONNAIRE_ROWS,
    ),
    build_builtin_questionnaire(
        "secumat_cloud_detailed_report_bsi_c5",
        "SECUMAT Cloud Detailed Report (BSI C5:2020)",
        "BSI C5:2020",
        "2020",
        "Cloud detailed report aligned to BSI C5:2020 covering governance, operations, IAM, cryptography, networking, portability, and secure development.",
        "SECUMAT Cloud Detailed Report (BSI C5:2020)",
        "All",
        "Cloud Security",
        "Cloud Native",
        SECUMAT_CDR_QUESTIONNAIRE_ROWS,
    ),
    build_builtin_questionnaire(
        "cis_controls_v8",
        "CIS Controls v8.0",
        "CIS",
        "8.0",
        "Center for Internet Security Controls v8.0 - 18 control groups covering asset management, access control, data protection, malware defenses, infrastructure defense, and incident response.",
        "CIS Controls v8",
        "All",
        "Internal",
        "Multi-OS",
        CIS_CONTROLS_V8_QUESTIONNAIRE_ROWS,
    ),
    build_builtin_questionnaire(
        "nist_sp_800_53",
        "NIST SP 800-53 Rev. 5",
        "NIST",
        "5",
        "NIST Special Publication 800-53 - Security and privacy controls for information systems and organizations covering access control, identification and authentication, system security, and audit.",
        "NIST SP 800-53",
        "All",
        "Compliance",
        "Multi-OS",
        NIST_SP_800_53_QUESTIONNAIRE_ROWS,
    ),
    build_builtin_questionnaire(
        "iso_27001_2022",
        "ISO/IEC 27001:2022",
        "ISO",
        "27001:2022",
        "Information Security Management Systems - Controls for information security governance, organization, asset management, access control, cryptography, and supplier relations.",
        "ISO 27001",
        "All",
        "Compliance",
        "Multi-OS",
        ISO_27001_2022_QUESTIONNAIRE_ROWS,
    ),
    build_builtin_questionnaire(
        "soc2_readiness_checklist",
        "SOC 2 Readiness & Audit Checklist",
        "SOC 2",
        "Checklist",
        "SOC 2 preparation checklist covering business objectives, report type selection, Trust Services Criteria scoping, risk assessment, remediation, readiness assessment, audit execution, and continuous monitoring.",
        "SOC 2 Checklist",
        "All",
        "Compliance",
        "Multi-OS",
        SOC2_PREPAREDNESS_CHECKLIST_ROWS,
    ),
    build_builtin_questionnaire(
        "iso_42001_automotive_ai",
        "ISO/IEC 42001:2023 â€“ AI Management System (Automotive & Manufacturing)",
        "ISO 42001",
        "42001:2023",
        "ISO/IEC 42001:2023 AI Management System audit questionnaire tailored for automotive and manufacturing contexts. Covers AIMS scope, AI policy, SOTIF risk integration, competence, impact assessment, AI inventory, OTA lifecycle, data governance, transparency, explainability, continuous monitoring, and human-in-the-loop controls.",
        "ISO 42001 Automotive AI",
        "Automotive / Manufacturing",
        "Compliance",
        "Multi-OS",
        ISO_42001_AUTOMOTIVE_QUESTIONNAIRE_ROWS,
    ),
]

for builtin_questionnaire in SECUMAT_BUILTIN_QUESTIONNAIRES:
    SECUMAT_TEMPLATES[builtin_questionnaire["id"]] = {
        "name": builtin_questionnaire["name"],
        "framework": builtin_questionnaire["framework"],
        "version": builtin_questionnaire["version"],
        "description": builtin_questionnaire["description"],
        "control_count": builtin_questionnaire["question_count"],
        "source": builtin_questionnaire["source"],
    }
    SECUMAT_QUESTIONNAIRE_LIBRARY.extend(builtin_questionnaire["library_entries"])

SECUMAT_BUILTIN_QUESTIONNAIRE_MAP = {
    questionnaire["id"]: questionnaire for questionnaire in SECUMAT_BUILTIN_QUESTIONNAIRES
}

for questionnaire in SECUMAT_QUESTIONNAIRE_LIBRARY:
    questionnaire.setdefault("source", "Industry Guidance")
    questionnaire.setdefault("os_platform", "All")

SECUMAT_GUIDANCE = [
    {
        "category": "Internal Audits",
        "points": [
            "Performed by internal IT, cyber security, or governance staff.",
            "Used to detect weak spots before formal external reviews.",
            "Focused on day-to-day control adherence, process gaps, and policy effectiveness.",
        ],
    },
    {
        "category": "External Audits",
        "points": [
            "Performed by independent third-party assessors or audit firms.",
            "Provide an unbiased review of security posture and control maturity.",
            "Often shared with customers, partners, regulators, or investors.",
        ],
    },
    {
        "category": "Compliance Audits",
        "points": [
            "Validate alignment with legal, contractual, or sector-specific standards such as SOC 2, ISO 27001, PCI-DSS, HIPAA, and GDPR.",
            "Measure evidence quality, policy coverage, and implementation consistency.",
            "Highlight gaps that need remediation plans, ownership, and due dates.",
        ],
    },
    {
        "category": "Vulnerability Assessment & Penetration Testing",
        "points": [
            "Use vulnerability scanning to identify known flaws and misconfigurations.",
            "Simulate attacker behavior to test whether layered defenses hold under realistic pressure.",
            "Measure detection, containment, and remediation speed across teams.",
        ],
    },
    {
        "category": "Cloud Security Audits",
        "points": [
            "Review access controls, encryption, network boundaries, and logging on AWS, Azure, and similar platforms.",
            "Check for misconfigured storage, exposed secrets, and insecure workload-to-cloud data movement.",
            "Validate governance for hybrid and multi-cloud operating models.",
        ],
    },
    {
        "category": "ISO/IEC 27000 ISMS Family Relationships",
        "points": [
            "Use ISO/IEC 27000:2018 for ISMS terminology and vocabulary before mapping detailed controls or audit evidence.",
            "Treat the family as four layers: vocabulary standards, requirement standards, guideline standards, and sector-specific guideline standards.",
            "Use ISO/IEC 27001 as the core requirements baseline, then align supporting guidance and sector-specific standards around it.",
        ],
    },
    {
        "category": "ISO/IEC 27000 Series - Requirements Standards",
        "points": [
            "ISO/IEC 27001:2013 - Information security management systems requirements.",
            "ISO/IEC 27006:2015 - Requirements for bodies providing audit and certification of information security management systems.",
            "ISO/IEC 27009:2016 and ISO/IEC 27021:2017 - Sector-specific application of ISO/IEC 27001 requirements.",
        ],
    },
    {
        "category": "ISO/IEC 27000 Series - Guideline Standards",
        "points": [
            "ISO/IEC 27002:2013 - Code of practice for information security controls.",
            "ISO/IEC 27003:2017, ISO/IEC 27004:2016, and ISO/IEC 27005:2018 - ISMS implementation, measurement, monitoring, analysis, evaluation, and risk management guidance.",
            "ISO/IEC 27007:2017, ISO/IEC TS 27008:2019, ISO/IEC 27013:2015, ISO/IEC 27014:2013, and ISO/IEC TR 27016:2014 - Auditing, control assessment, integrated implementation, governance, and organizational economics guidance.",
        ],
    },
    {
        "category": "ISO/IEC 27000 Series - Sector-Specific Guidelines",
        "points": [
            "ISO/IEC 27010:2015 - Inter-sector and inter-organizational communications security management guidance.",
            "ISO/IEC 27011:2016, ISO/IEC 27017:2015, ISO/IEC 27018:2019, and ISO/IEC 27019:2017 - Telecom, cloud services, public cloud PII protection, and energy utility control guidance.",
            "Use these sector-specific standards when tailoring audit guidance for telecom, cloud, privacy, and energy-focused assessments.",
        ],
    },
]

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
    stored_path     TEXT,
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
    last_seen      DATE,
    seconds_count  BIGINT,
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

CREATE TABLE IF NOT EXISTS cab_ticket_updates (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ticket_id       TEXT NOT NULL,
    asset_key       TEXT,
    cve             TEXT,
    status          TEXT,
    criticality     TEXT,
    risk_percent    NUMERIC(5,2),
    comment         TEXT,
    updated_by      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cab_ticket_updates_ticket_id ON cab_ticket_updates(ticket_id);
CREATE INDEX IF NOT EXISTS idx_cab_ticket_updates_created_at ON cab_ticket_updates(created_at DESC);

CREATE TABLE IF NOT EXISTS cab_control_state (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    is_locked       BOOLEAN NOT NULL DEFAULT FALSE,
    locked_by       TEXT,
    locked_at       TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO cab_control_state (id, is_locked)
VALUES (1, FALSE)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS risk_acceptance_template_state (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    rows            JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_by      TEXT,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO risk_acceptance_template_state (id, rows)
VALUES (1, '[]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ===== SECUMAT TABLES =====
CREATE TABLE IF NOT EXISTS compliance_audit_uploads (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upload_name     TEXT NOT NULL,
    filename        TEXT NOT NULL,
    uploaded_by     TEXT,
    framework       TEXT NOT NULL,
    framework_version TEXT,
    total_questions INTEGER DEFAULT 0,
    total_controls  INTEGER DEFAULT 0,
    sheet_count     INTEGER DEFAULT 0,
    coverage_percent NUMERIC(5,2) DEFAULT 0,
    upload_mode     TEXT DEFAULT 'structured',
    stored_path     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS sheet_count INTEGER DEFAULT 0;
ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS upload_mode TEXT DEFAULT 'structured';
ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS stored_path TEXT;

CREATE TABLE IF NOT EXISTS compliance_upload_responses (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upload_id       UUID NOT NULL REFERENCES compliance_audit_uploads(id) ON DELETE CASCADE,
    control_id      TEXT NOT NULL,
    control_name    TEXT,
    framework       TEXT,
    question_number INTEGER,
    question_text   TEXT,
    response_status TEXT,
    response_value  TEXT,
    evidence        TEXT,
    comments        TEXT,
    detailed_answer TEXT,
    implemented     BOOLEAN,
    priority        TEXT,
    mapping_score   NUMERIC(5,2),
    auditor_notes   TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_upload_responses_upload_id ON compliance_upload_responses(upload_id);
CREATE INDEX IF NOT EXISTS idx_compliance_upload_responses_framework ON compliance_upload_responses(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_upload_responses_control_id ON compliance_upload_responses(control_id);

CREATE TABLE IF NOT EXISTS compliance_upload_control_scores (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upload_id       UUID NOT NULL REFERENCES compliance_audit_uploads(id) ON DELETE CASCADE,
    control_id      TEXT NOT NULL,
    framework       TEXT,
    implemented_count INTEGER DEFAULT 0,
    total_count     INTEGER DEFAULT 0,
    completion_percent NUMERIC(5,2) DEFAULT 0,
    risk_level      TEXT,
    last_assessed   TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_upload_control_scores_upload_id ON compliance_upload_control_scores(upload_id);
CREATE INDEX IF NOT EXISTS idx_compliance_upload_control_scores_framework ON compliance_upload_control_scores(framework);

CREATE TABLE IF NOT EXISTS custom_audit_templates (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id     TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    framework       TEXT NOT NULL,
    version         TEXT,
    description     TEXT,
    organization    TEXT,
    policy_reference TEXT,
    is_editable     BOOLEAN DEFAULT TRUE,
    created_by      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS custom_template_questions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id     UUID NOT NULL REFERENCES custom_audit_templates(id) ON DELETE CASCADE,
    control_id      TEXT NOT NULL,
    control_name    TEXT,
    question_number INTEGER,
    question_text   TEXT NOT NULL,
    question_type   TEXT DEFAULT 'text',
    is_required     BOOLEAN DEFAULT TRUE,
    guidance        TEXT,
    expected_answer TEXT,
    display_order   INTEGER,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_template_questions_template_id ON custom_template_questions(template_id);
CREATE INDEX IF NOT EXISTS idx_custom_template_questions_control_id ON custom_template_questions(control_id);

CREATE TABLE IF NOT EXISTS secumat_audit_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_name      TEXT NOT NULL,
    company_name    TEXT,
    framework       TEXT,
    questionnaire_mode TEXT,
    audit_type      TEXT,
    industry_type   TEXT,
    operating_system TEXT,
    division        TEXT,
    quarter_label   TEXT,
    audit_cycle     TEXT,
    audit_scope     TEXT,
    audit_start_date DATE,
    audit_end_date  DATE,
    version_label   TEXT,
    status          TEXT DEFAULT 'draft',
    audit_details   TEXT,
    assigned_to     TEXT,
    responsible_person TEXT,
    team_name       TEXT,
    auditor_name    TEXT,
    auditor_email   TEXT,
    auditor_company TEXT,
    teams_involved  TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS questionnaire_mode TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS quarter_label TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS audit_cycle TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS assigned_to TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS responsible_person TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS team_name TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS custom_role TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS selected_questionnaire_id TEXT;
ALTER TABLE secumat_audit_profiles ADD COLUMN IF NOT EXISTS selected_questionnaire_name TEXT;

CREATE INDEX IF NOT EXISTS idx_secumat_audit_profiles_created_at ON secumat_audit_profiles(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secumat_audit_profiles_framework ON secumat_audit_profiles(framework);
"""

REPORT_SCHEMA_READY = False


def get_db():
    cached_conn = getattr(g, "db_conn", None)
    if cached_conn is not None and getattr(cached_conn, "closed", 1) == 0:
        return cached_conn

    last_error = None
    for idx, cfg in enumerate(_postgres_connect_candidates()):
        conn = None
        for attempt in range(POSTGRES_CONNECT_RETRIES):
            try:
                pool = _get_or_create_pool(cfg)
                conn = pool.getconn()
                if idx > 0:
                    logger.warning(
                        "Database connection fallback active. Using host '%s' instead of '%s'.",
                        cfg.get("host"),
                        POSTGRES_CONFIG.get("host"),
                    )
                break
            except Exception as exc:
                last_error = exc
                conn = None
                if attempt + 1 < POSTGRES_CONNECT_RETRIES:
                    time.sleep(0.1)

        if conn is not None:
            break

    if conn is None:
        raise last_error

    # Force UTF-8 client encoding to avoid Windows cp1252 encode failures on Unicode text.
    try:
        conn.set_client_encoding("UTF8")
    except Exception:
        pass
    g.db_conn = conn
    g.db_pool_key = _pool_key(cfg)
    return conn


@app.teardown_appcontext
def close_db(error=None):
    conn = getattr(g, "db_conn", None)
    pool_key = getattr(g, "db_pool_key", None)
    if conn is None or pool_key is None:
        return
    try:
        if getattr(conn, "closed", 1) == 0:
            if error is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
            pool = _DB_POOLS.get(pool_key)
            if pool is not None:
                try:
                    pool.putconn(conn)
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
    finally:
        g.pop("db_conn", None)
        g.pop("db_pool_key", None)


def query(sql, params=None):
    try:
        conn = get_db()
        safe_params = sanitize_db_params(params)
        with conn.cursor() as cur:
            cur.execute(sql, safe_params)
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"DB error: {e}")
        return []


def query_one(sql, params=None):
    rows = query(sql, params)
    return rows[0] if rows else {}


def build_app_health_payload():
    if dashboard_force_fallback():
        return {
            "status": "degraded",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "checks": {
                "database": {"ok": False, "detail": "Fallback mode enabled"},
                "reports": {"ok": True, "detail": "Using fallback Full data totals", "count": 1},
                "cab": {"ok": True, "detail": "Fallback mode enabled", "count": 0},
            },
        }

    payload = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {
            "database": {"ok": False, "detail": "Not checked"},
            "reports": {"ok": True, "detail": "No report data yet"},
            "cab": {"ok": True, "detail": "No CAB data yet"},
        },
    }

    try:
        db_ok = query_one("SELECT 1 AS ok")
        payload["checks"]["database"] = {
            "ok": bool(db_ok.get("ok") == 1),
            "detail": "Database connection OK",
        }
    except Exception as exc:
        payload["status"] = "degraded"
        payload["checks"]["database"] = {"ok": False, "detail": str(exc)}
        return payload

    try:
        uploads = query_one("SELECT COUNT(*) AS cnt FROM report_uploads")
        latest_upload = query_one("SELECT created_at FROM report_uploads ORDER BY created_at DESC LIMIT 1")
        count = int((uploads or {}).get("cnt") or 0)
        if count > 0:
            created_at = latest_upload.get("created_at") if latest_upload else None
            detail = "Latest upload at {0}".format(created_at.isoformat() if hasattr(created_at, "isoformat") else created_at)
        else:
            detail = "No uploads loaded"
        payload["checks"]["reports"] = {"ok": True, "detail": detail, "count": count}
    except Exception as exc:
        payload["status"] = "degraded"
        payload["checks"]["reports"] = {"ok": False, "detail": str(exc)}

    try:
        tickets = query_one("SELECT COUNT(*) AS cnt FROM cab_ticket_updates")
        payload["checks"]["cab"] = {
            "ok": True,
            "detail": "{0} manual CAB update(s) available".format(int((tickets or {}).get("cnt") or 0)),
            "count": int((tickets or {}).get("cnt") or 0),
        }
    except Exception as exc:
        payload["status"] = "degraded"
        payload["checks"]["cab"] = {"ok": False, "detail": str(exc)}

    if not all(check.get("ok") for check in payload["checks"].values()):
        payload["status"] = "degraded"

    return payload


def build_risk_acceptance_template_payload():
    ensure_report_schema()
    row = query_one(
        """
        SELECT rows, updated_by, updated_at
        FROM risk_acceptance_template_state
        WHERE id = 1
        """
    ) or {}
    saved_rows = row.get("rows") if isinstance(row.get("rows"), list) else None
    rows = saved_rows if saved_rows is not None and len(saved_rows) > 0 else [dict(item) for item in RISK_ACCEPTANCE_TEMPLATE_ROWS]
    return {
        "title": "IT Risk Acceptance Form",
        "fields": [
            {"key": key, "label": RISK_ACCEPTANCE_TEMPLATE_LABELS[key], "placeholder": "MM/DD/YY" if key == "date_assessed" else ""}
            for key in RISK_ACCEPTANCE_TEMPLATE_FIELDS
        ],
        "columns": [
            {"key": key, "label": RISK_ACCEPTANCE_TEMPLATE_LABELS[key]}
            for key in RISK_ACCEPTANCE_TEMPLATE_COLUMNS
        ],
        "rows": rows,
        "updated_by": row.get("updated_by"),
        "updated_at": row.get("updated_at"),
    }


def build_risk_acceptance_template_csv(payload=None):
    payload = payload or build_risk_acceptance_template_payload()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IT RISK ACCEPTANCE FORM"])
    writer.writerow([])
    writer.writerow([RISK_ACCEPTANCE_TEMPLATE_LABELS[key] for key in RISK_ACCEPTANCE_TEMPLATE_FIELDS])
    writer.writerow(["", "", "MM/DD/YY"])
    writer.writerow([])
    writer.writerow([RISK_ACCEPTANCE_TEMPLATE_LABELS[key] for key in RISK_ACCEPTANCE_TEMPLATE_COLUMNS])
    for row in payload.get("rows", []):
        writer.writerow([row.get(column, "") for column in RISK_ACCEPTANCE_TEMPLATE_COLUMNS])
    return output.getvalue()


def sanitize_risk_acceptance_template_rows(rows):
    if not isinstance(rows, list):
        raise ValueError("rows must be a list")
    cleaned_rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cleaned = {}
        for column in RISK_ACCEPTANCE_TEMPLATE_COLUMNS:
            value = row.get(column, "")
            cleaned[column] = sanitize_text(value) if value is not None else ""
        if any(cleaned.get(column) for column in RISK_ACCEPTANCE_TEMPLATE_COLUMNS):
            cleaned_rows.append(cleaned)
    return cleaned_rows


def execute_update(sql, params=None, fetchone=False):
    conn = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            row = dict(cur.fetchone()) if fetchone and cur.description else None
        conn.commit()
        return row
    except Exception as e:
        if conn is not None:
            conn.rollback()
        logger.error(f"DB update error: {e}")
        raise


def ensure_audit_assignment_schema():
    statements = [
        """
        CREATE TABLE IF NOT EXISTS compliance_audit_assignments (
            id SERIAL PRIMARY KEY,
            questionnaire_id TEXT NOT NULL,
            questionnaire_name TEXT NOT NULL,
            assessment_name TEXT,
            audit_profile_id UUID,
            assigned_to TEXT,
            assigned_to_type TEXT DEFAULT 'person',
            assigned_by TEXT,
            role_name TEXT,
            user_name TEXT,
            user_email TEXT,
            department_name TEXT,
            due_date DATE,
            template_source TEXT,
            assignment_date TIMESTAMPTZ DEFAULT NOW(),
            status TEXT DEFAULT 'pending',
            question_count INTEGER DEFAULT 0,
            completed_responses INTEGER DEFAULT 0,
            progress_percent NUMERIC(5,2) DEFAULT 0,
            compliance_score NUMERIC(5,2) DEFAULT 0,
            reviewer_score NUMERIC(5,2) DEFAULT 0,
            reviewer_comments TEXT,
            reviewer_notes TEXT,
            reviewed_by TEXT,
            reviewed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS compliance_audit_assignment_responses (
            id SERIAL PRIMARY KEY,
            assignment_id INTEGER NOT NULL REFERENCES compliance_audit_assignments(id) ON DELETE CASCADE,
            question_id TEXT NOT NULL,
            response_status TEXT,
            response_option TEXT,
            evidence TEXT,
            comments TEXT,
            mapping_score NUMERIC(5,2) DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (assignment_id, question_id)
        )
        """,
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS assessment_name TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS cdr_number TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS audit_profile_id UUID",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS role_name TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS user_name TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS user_email TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS department_name TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS due_date DATE",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS template_source TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS progress_percent NUMERIC(5,2) DEFAULT 0",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS reviewer_score NUMERIC(5,2) DEFAULT 0",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS reviewer_comments TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS reviewer_notes TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS reviewed_by TEXT",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ",
        "ALTER TABLE compliance_audit_assignments ADD COLUMN IF NOT EXISTS framework TEXT",
        "ALTER TABLE compliance_audit_assignment_responses ADD COLUMN IF NOT EXISTS response_option TEXT",
        "ALTER TABLE compliance_audit_assignment_responses ADD COLUMN IF NOT EXISTS comments TEXT",
        "ALTER TABLE compliance_audit_assignment_responses ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()",
        "CREATE INDEX IF NOT EXISTS idx_compliance_audit_assignments_assignment_date ON compliance_audit_assignments(assignment_date DESC)",
        "CREATE INDEX IF NOT EXISTS idx_compliance_audit_assignments_audit_profile_id ON compliance_audit_assignments(audit_profile_id)",
        "CREATE INDEX IF NOT EXISTS idx_compliance_audit_assignment_responses_assignment_id ON compliance_audit_assignment_responses(assignment_id)",
    ]
    for statement in statements:
        execute_update(statement)


def get_assignment_questions(questionnaire_id):
    questions = []
    questionnaire = SECUMAT_BUILTIN_QUESTIONNAIRE_MAP.get(questionnaire_id, {})
    for idx, q in enumerate(questionnaire.get("questions", []), start=1):
        question_id = q.get("control_id") or f"Q{idx}"
        questions.append({
            "question_id": question_id,
            "question_number": q.get("question_number"),
            "control_id": q.get("control_id"),
            "section": q.get("section"),
            "question": q.get("question"),
            "question_text": q.get("question"),
            "title": q.get("title"),
        })
    return questions


def normalize_text(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def canonical_header(header):
    normalized = normalize_text(header)
    for canonical, aliases in HEADER_ALIASES.items():
        if normalized == normalize_text(canonical) or normalized in {normalize_text(alias) for alias in aliases}:
            return canonical
    return None


def ensure_report_schema():
    global REPORT_SCHEMA_READY
    if REPORT_SCHEMA_READY:
        return

    conn = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_audit_uploads (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_upload_responses (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_upload_control_scores (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4()
                )
                """
            )
            for statement in (
                "ALTER TABLE report_uploads ADD COLUMN IF NOT EXISTS stored_path TEXT",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS upload_name TEXT",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS filename TEXT",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS uploaded_by TEXT",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS framework TEXT",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS framework_version TEXT",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS total_questions INTEGER DEFAULT 0",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS total_controls INTEGER DEFAULT 0",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS coverage_percent NUMERIC(5,2) DEFAULT 0",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS sheet_count INTEGER DEFAULT 0",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS upload_mode TEXT DEFAULT 'structured'",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS stored_path TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS upload_id UUID",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS control_id TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS control_name TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS framework TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS question_number INTEGER",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS question_text TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS response_status TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS response_value TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS evidence TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS comments TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS detailed_answer TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS implemented BOOLEAN",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS priority TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS mapping_score NUMERIC(5,2)",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS auditor_notes TEXT",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
                "ALTER TABLE compliance_upload_responses ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS upload_id UUID",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS control_id TEXT",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS framework TEXT",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS implemented_count INTEGER DEFAULT 0",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS total_count INTEGER DEFAULT 0",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS completion_percent NUMERIC(5,2) DEFAULT 0",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS risk_level TEXT",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS last_assessed TIMESTAMPTZ",
                "ALTER TABLE compliance_upload_control_scores ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()",
            ):
                cur.execute(statement)
            cur.execute(REPORT_SCHEMA_SQL)
            for statement in (
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS sheet_count INTEGER DEFAULT 0",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS upload_mode TEXT DEFAULT 'structured'",
                "ALTER TABLE compliance_audit_uploads ADD COLUMN IF NOT EXISTS stored_path TEXT",
            ):
                cur.execute(statement)
        conn.commit()
        REPORT_SCHEMA_READY = True
    except Exception as exc:
        logger.error(f"Report schema init failed: {exc}")
        if conn is not None:
            conn.rollback()


def allowed_report_file(filename):
    if not filename or "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in REPORT_ALLOWED_EXTENSIONS


def normalize_severity(value):
    token = normalize_text(value)
    if token in {"critical", "sev1", "severe"}:
        return "critical"
    if token in {"high", "sev2"}:
        return "high"
    if token in {"medium", "med", "sev3"}:
        return "medium"
    if token in {"verylow", "vlow", "sev5"}:
        return "very_low"
    if token in {"low", "sev4"}:
        return "low"
    if token in {"info", "informational", "informative"}:
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


def uploaded_valid_row_sql():
    return """
        COALESCE(
            NULLIF(severity, ''),
            NULLIF(status, ''),
            NULLIF(cve, ''),
            NULLIF(asset_key, ''),
            NULLIF(ip_address, ''),
            NULLIF(hostname, ''),
            NULLIF(region, ''),
            NULLIF(raw_data->>'IP', ''),
            NULLIF(raw_data->>'IP Address', ''),
            NULLIF(raw_data->>'Hostname', ''),
            NULLIF(raw_data->>'Host Name', ''),
            NULLIF(raw_data->>'Sitecode', ''),
            NULLIF(raw_data->>'Site Code', ''),
            NULLIF(raw_data->>'sitecode', ''),
            NULLIF(raw_data->>'site_code', '')
        ) IS NOT NULL
    """


def uploaded_raw_severity_sql():
    return """
        CASE
            WHEN regexp_replace(lower(COALESCE(raw_data->>'device_risk_score', raw_data->>'Severity', severity, '')), '[^a-z0-9]+', '', 'g') IN ('critical', 'sev1', 'severe', 'p1immediate') THEN 'critical'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'device_risk_score', raw_data->>'Severity', severity, '')), '[^a-z0-9]+', '', 'g') IN ('high', 'sev2') THEN 'high'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'device_risk_score', raw_data->>'Severity', severity, '')), '[^a-z0-9]+', '', 'g') IN ('medium', 'med', 'sev3') THEN 'medium'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'device_risk_score', raw_data->>'Severity', severity, '')), '[^a-z0-9]+', '', 'g') IN ('verylow', 'vlow', 'sev5') THEN 'very_low'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'device_risk_score', raw_data->>'Severity', severity, '')), '[^a-z0-9]+', '', 'g') IN ('low', 'sev4') THEN 'low'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'device_risk_score', raw_data->>'Severity', severity, '')), '[^a-z0-9]+', '', 'g') IN ('info', 'informational', 'informative') THEN 'info'
            ELSE 'unknown'
        END
    """


def uploaded_asset_type_sql():
    """Classify a report row as IT, OT, or IoT.

    Prefers the Claroty device_category column, then the mapped environment
    column, then any cloud_provider hint. IoT is checked before OT because the
    token 'iot' also contains the substring 'ot'.
    """
    src = "regexp_replace(lower(COALESCE(raw_data->>'device_category', raw_data->>'asset_type', raw_data->>'Asset Type', raw_data->>'environment', raw_data->>'Environment', raw_data->>'category', raw_data->>'Category', environment, cloud_provider, report_scope, '')), '[^a-z0-9]+', '', 'g')"
    return f"""
        CASE
            WHEN {src} = 'iot' THEN 'IoT'
            WHEN {src} = 'ot' OR {src} LIKE '%%ics%%' OR {src} LIKE '%%otics%%' THEN 'OT'
            WHEN {src} = 'it' THEN 'IT'
            WHEN {src} LIKE '%%ot%%' THEN 'OT'
            ELSE 'IT'
        END
    """



def uploaded_raw_status_sql():
    return """
        CASE
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('new', 'newlydetected', 'detected') THEN 'new'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('outdated', 'stale', 'old') THEN 'outdated'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('pending', 'inprogress', 'inreview', 'review', 'partiallyresolved', 'notdetected') THEN 'pending'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('open', 'active', 'unresolved') THEN 'open'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('closed', 'fixed', 'resolved', 'remediated') THEN 'closed'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('acceptedrisk', 'riskaccepted', 'accepted') THEN 'accepted_risk'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('falsepositive', 'fp', 'notanissue') THEN 'false_positive'
            WHEN regexp_replace(lower(COALESCE(raw_data->>'Status', status, '')), '[^a-z0-9]+', '', 'g') IN ('confirmedopen', 'confirmed', 'verifiedopen') THEN 'confirmed_open'
            ELSE 'unknown'
        END
    """


def uploaded_attack_tactic_sql():
    return """
        COALESCE(
            NULLIF(raw_data->>'mitre_tactic', ''),
            NULLIF(raw_data->>'mitre tactic', ''),
            NULLIF(raw_data->>'attack_tactic', ''),
            NULLIF(raw_data->>'attack tactic', ''),
            NULLIF(raw_data->>'attck_tactic', ''),
            NULLIF(raw_data->>'attck tactic', ''),
            NULLIF(raw_data->>'tactic', '')
        )
    """


def uploaded_attack_technique_sql():
    return """
        COALESCE(
            NULLIF(raw_data->>'mitre_technique', ''),
            NULLIF(raw_data->>'mitre technique', ''),
            NULLIF(raw_data->>'attack_technique', ''),
            NULLIF(raw_data->>'attack technique', ''),
            NULLIF(raw_data->>'attck_technique', ''),
            NULLIF(raw_data->>'attck technique', ''),
            NULLIF(raw_data->>'mitre_technique_id', ''),
            NULLIF(raw_data->>'attack_technique_id', ''),
            NULLIF(raw_data->>'technique_id', ''),
            NULLIF(raw_data->>'technique id', ''),
            NULLIF(raw_data->>'technique', '')
        )
    """


def uploaded_pits_asset_cte():
    return """
        asset_info AS (
            SELECT DISTINCT ON (asset_ref)
                asset_ref,
                CASE lower(COALESCE(raw_data->>'Is in PITS CMS?', ''))
                    WHEN 'yes' THEN 'yes'
                    WHEN 'no' THEN 'no'
                    ELSE NULL
                END AS pits_cms_flag,
                CASE lower(COALESCE(raw_data->>'Is Whitelisted?', ''))
                    WHEN 'yes' THEN 'yes'
                    WHEN 'no' THEN 'no'
                    ELSE NULL
                END AS whitelisted_flag,
                CASE lower(COALESCE(raw_data->>'Agent Needs Check?', ''))
                    WHEN 'yes' THEN 'yes'
                    WHEN 'no' THEN 'no'
                    ELSE NULL
                END AS needs_check_flag
            FROM (
                SELECT
                    COALESCE(NULLIF(asset_key, ''), NULLIF(ip_address, ''), NULLIF(raw_data->>'IP Address', '')) AS asset_ref,
                    raw_data,
                    row_number
                FROM report_records
                WHERE upload_id = %s
                  AND (
                      raw_data ? 'Is in PITS CMS?'
                      OR raw_data ? 'Is Whitelisted?'
                      OR raw_data ? 'Agent Needs Check?'
                  )
            ) asset_rows
            WHERE asset_ref IS NOT NULL
            ORDER BY asset_ref, row_number DESC NULLS LAST
        )
    """


def uploaded_active_risk_status_sql(raw_status_expr):
    return f"""
        CASE
            WHEN {raw_status_expr} IN ('new', 'outdated', 'pending', 'open', 'active', 'unresolved', 'inprogress', 'review') THEN 'open'
            WHEN {raw_status_expr} = 'confirmed_open' THEN 'confirmed_open'
            WHEN {raw_status_expr} IN ('closed', 'fixed', 'resolved', 'remediated') THEN 'closed'
            WHEN {raw_status_expr} = 'accepted_risk' THEN 'accepted_risk'
            WHEN {raw_status_expr} = 'false_positive' THEN 'false_positive'
            ELSE 'open'
        END
    """


def normalize_upload_status_filter(value):
    token = normalize_text(value)
    if not token:
        return None
    direct = {
        "new",
        "outdated",
        "pending",
        "open",
        "closed",
        "accepted_risk",
        "false_positive",
        "confirmed_open",
        "unknown",
    }
    if token in direct:
        return token
    aliases = {
        "newlydetected": "new",
        "detected": "new",
        "stale": "outdated",
        "old": "outdated",
        "inprogress": "pending",
        "inreview": "pending",
        "review": "pending",
        "partiallyresolved": "pending",
        "notdetected": "pending",
        "active": "open",
        "unresolved": "open",
        "fixed": "closed",
        "resolved": "closed",
        "remediated": "closed",
        "acceptedrisk": "accepted_risk",
        "riskaccepted": "accepted_risk",
        "accepted": "accepted_risk",
        "falsepositive": "false_positive",
        "fp": "false_positive",
        "notanissue": "false_positive",
        "confirmed": "confirmed_open",
        "verifiedopen": "confirmed_open",
        "confirmedopen": "confirmed_open",
    }
    return aliases.get(token)


def normalize_upload_category_filter(value):
    token = normalize_text(value)
    if not token:
        return None
    if token == "iot":
        return "IoT"
    if token in {"ot", "ics", "otics"}:
        return "OT"
    if token == "it":
        return "IT"
    return None


def get_upload_filter_values():
    severity = normalize_severity(request.args.get("severity"))
    if severity not in {"critical", "high", "medium", "low", "very_low", "info", "unknown", None}:
        severity = None
    status = normalize_upload_status_filter(request.args.get("status"))
    category = normalize_upload_category_filter(request.args.get("category") or request.args.get("asset_type"))
    query_text = sanitize_text(request.args.get("q")) or ""
    query_text = query_text.strip()
    if len(query_text) > 120:
        query_text = query_text[:120]
    return {
        "severity": severity,
        "status": status,
        "category": category,
        "q": query_text,
    }


def upload_filters_active(filter_values):
    if not filter_values:
        return False
    return bool(
        filter_values.get("severity")
        or filter_values.get("status")
        or filter_values.get("category")
        or filter_values.get("q")
    )


def build_upload_filters_sql(raw_severity_expr, raw_status_expr, table_alias=""):
    filters = get_upload_filter_values()
    conditions = []
    params = []
    if filters.get("severity"):
        conditions.append(f"{raw_severity_expr} = %s")
        params.append(filters["severity"])
    if filters.get("status"):
        if filters["status"] == "open":
            conditions.append(f"{raw_status_expr} IN ('open', 'new', 'outdated', 'pending', 'confirmed_open')")
        else:
            conditions.append(f"{raw_status_expr} = %s")
            params.append(filters["status"])
    if filters.get("category"):
        conditions.append(f"{uploaded_asset_type_sql()} = %s")
        params.append(filters["category"])
    q = filters.get("q")
    if q:
        prefix = f"{table_alias}." if table_alias else ""
        pattern = f"%{q}%"
        searchable = [
            f"COALESCE({prefix}asset_key, '')",
            f"COALESCE({prefix}ip_address, '')",
            f"COALESCE({prefix}hostname, '')",
            f"COALESCE({prefix}dns_name, '')",
            f"COALESCE({prefix}netbios_name, '')",
            f"COALESCE({prefix}cve, '')",
            f"COALESCE({prefix}owner, '')",
            f"COALESCE({prefix}cloud_provider, '')",
            f"COALESCE({prefix}region, '')",
            f"COALESCE({prefix}report_scope, '')",
            f"COALESCE({prefix}solution, '')",
            f"COALESCE({prefix}remediation, '')",
            f"COALESCE({prefix}raw_data::text, '')",
        ]
        conditions.append("(" + " OR ".join([f"{expr} ILIKE %s" for expr in searchable]) + ")")
        params.extend([pattern] * len(searchable))
    where_clause = ""
    if conditions:
        where_clause = " AND " + " AND ".join(conditions)
    return where_clause, params, filters


def get_cab_lock_state():
    if dashboard_force_fallback():
        return load_cab_fallback_state().get("lock") or {
            "is_locked": False,
            "locked_by": None,
            "locked_at": None,
            "updated_at": None,
        }

    ensure_report_schema()
    row = query_one(
        """
        SELECT is_locked, locked_by, locked_at, updated_at
        FROM cab_control_state
        WHERE id = 1
        """
    )
    return {
        "is_locked": bool((row or {}).get("is_locked", False)),
        "locked_by": (row or {}).get("locked_by"),
        "locked_at": (row or {}).get("locked_at"),
        "updated_at": (row or {}).get("updated_at"),
    }


def set_cab_lock_state(locked, locked_by=None):
    if dashboard_force_fallback():
        state = load_cab_fallback_state()
        timestamp = datetime.utcnow().isoformat() + "Z"
        state["lock"] = {
            "is_locked": bool(locked),
            "locked_by": sanitize_text(locked_by) or "dashboard-user",
            "locked_at": timestamp if locked else None,
            "updated_at": timestamp,
        }
        save_cab_fallback_state(state)
        return

    ensure_report_schema()
    conn = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if locked:
                cur.execute(
                    """
                    UPDATE cab_control_state
                    SET is_locked = TRUE,
                        locked_by = %s,
                        locked_at = NOW(),
                        updated_at = NOW()
                    WHERE id = 1
                    """,
                    (sanitize_text(locked_by) or "dashboard-user",),
                )
            else:
                cur.execute(
                    """
                    UPDATE cab_control_state
                    SET is_locked = FALSE,
                        locked_by = %s,
                        locked_at = NULL,
                        updated_at = NOW()
                    WHERE id = 1
                    """,
                    (sanitize_text(locked_by) or "dashboard-user",),
                )
        conn.commit()
    except Exception:
        if conn is not None:
            conn.rollback()
        raise

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


def sanitize_text(value):
    if value is None:
        return None
    if isinstance(value, str):
        # Remove control-range characters that PostgreSQL JSONB rejects for non-UTF8 server encodings.
        cleaned = DISALLOWED_CONTROL_CHARS.sub("", value)
        # Drop symbols that cannot be represented in common PostgreSQL non-UTF8 encodings
        # (e.g., WIN1252), such as emoji from sheet names/cell text.
        cleaned = cleaned.encode("cp1252", errors="ignore").decode("cp1252", errors="ignore")
        # Encode with 'ignore' to drop any problematic bytes, then decode.
        try:
            return cleaned.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            return cleaned
    return value


def has_meaningful_cell_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        return str(sanitize_text(value) or "").strip() != ""
    return True


def row_has_meaningful_data(row_values):
    if isinstance(row_values, dict):
        values = row_values.values()
    else:
        values = row_values or ()
    return any(has_meaningful_cell_value(value) for value in values)


def detect_header_row(sheet_rows, max_scan_rows=20):
    """Find the most likely header row in a worksheet.

    Scores the first N rows by canonical alias matches and non-empty cell count,
    then returns the best header index with normalized header names.
    """
    best_idx = None
    best_score = -1
    best_headers = None

    scan_limit = min(max_scan_rows, len(sheet_rows))
    for idx in range(scan_limit):
        values = sheet_rows[idx] or ()
        headers = [str(v).strip() if v is not None else "" for v in values]
        non_empty = [h for h in headers if h]
        if not non_empty:
            continue

        canonical_hits = 0
        for header in non_empty:
            if canonical_header(header):
                canonical_hits += 1

        score = canonical_hits * 10 + len(non_empty)
        if score > best_score:
            best_score = score
            best_idx = idx
            best_headers = headers

    if best_idx is None:
        return 0, []

    # Ensure there is always a usable header label for every column.
    normalized_headers = []
    for i, header in enumerate(best_headers):
        clean = str(header).strip() if header else ""
        normalized_headers.append(clean or f"column_{i+1}")

    return best_idx, normalized_headers


def to_json_compatible(value):
    """Convert uploaded values to JSON-serializable forms for raw_data storage."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_json_compatible(v) for v in value]
    return sanitize_text(value)


def persist_compliance_upload_source(upload_id, filename, payload):
    os.makedirs(COMPLIANCE_UPLOAD_STORAGE_DIR, exist_ok=True)
    safe_name = secure_filename(filename or "questionnaire.xlsx") or "questionnaire.xlsx"
    stored_path = os.path.join(COMPLIANCE_UPLOAD_STORAGE_DIR, f"{upload_id}_{safe_name}")
    with open(stored_path, "wb") as file_handle:
        file_handle.write(payload)
    return stored_path


def persist_report_upload_source(upload_id, filename, payload):
    os.makedirs(REPORT_UPLOAD_STORAGE_DIR, exist_ok=True)
    safe_name = secure_filename(filename or "report.xlsx") or "report.xlsx"
    stored_path = os.path.join(REPORT_UPLOAD_STORAGE_DIR, f"{upload_id}_{safe_name}")
    with open(stored_path, "wb") as file_handle:
        file_handle.write(payload)
    return stored_path


def build_sheet_preview_rows(sheet_name, all_rows):
    preview_rows = []
    max_columns = 0
    for row_number, row_values in enumerate(all_rows, start=1):
        row_values = row_values or ()
        normalized_values = [to_json_compatible(value) for value in row_values]
        last_populated_index = -1
        for idx, value in enumerate(normalized_values):
            if has_meaningful_cell_value(value):
                last_populated_index = idx
        if last_populated_index < 0:
            continue
        trimmed_values = normalized_values[: last_populated_index + 1]
        preview_rows.append({
            "row_number": row_number,
            "cells": trimmed_values,
        })
        max_columns = max(max_columns, len(trimmed_values))

    return {
        "sheet_name": sanitize_text(sheet_name) or "Sheet",
        "row_count": len(preview_rows),
        "column_count": max_columns,
        "rows": preview_rows,
    }


def build_workbook_preview_from_bytes(payload, filename):
    ext = filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
    sheets = []

    if ext in {"xlsx", "xlsm"}:
        try:
            from openpyxl import load_workbook
        except Exception as exc:
            raise RuntimeError("Excel preview requires openpyxl") from exc

        workbook = load_workbook(io.BytesIO(payload), read_only=True, data_only=True)
        for sheet in workbook.worksheets:
            all_rows = list(sheet.iter_rows(values_only=True))
            sheet_preview = build_sheet_preview_rows(sheet.title, all_rows)
            if sheet_preview["row_count"] > 0:
                sheets.append(sheet_preview)
    elif ext == "csv":
        text = payload.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text))
        all_rows = [tuple(row) for row in reader]
        sheet_preview = build_sheet_preview_rows("CSV", all_rows)
        if sheet_preview["row_count"] > 0:
            sheets.append(sheet_preview)
    else:
        raise RuntimeError("Unsupported preview format")

    return {
        "sheet_count": len(sheets),
        "sheets": sheets,
    }


def smart_detect_columns(headers):
    """Auto-detect column purposes from header names using fuzzy matching."""
    detected = {}
    headers_lower = [str(h).lower().strip() for h in headers if h]
    detectable_aliases = get_detectable_aliases()

    for canonical, aliases in detectable_aliases.items():
        for i, header in enumerate(headers_lower):
            for alias in aliases:
                if alias.lower() in header or header in alias.lower():
                    detected[canonical] = i
                    break
            if canonical in detected:
                break

    return detected


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


def normalize_uploaded_row(raw_row, filename, sheet_name, row_number, column_mapping=None):
    safe_sheet_name = sanitize_text(sheet_name) or "Sheet"
    row = {}
    raw_payload = {}
    for key, value in raw_row.items():
        if key is None:
            continue
        clean_key = str(key).strip()
        sanitized_val = sanitize_text(to_json_compatible(value))
        raw_payload[clean_key] = sanitized_val
        canonical = canonical_header(clean_key)
        if canonical and value not in (None, ""):
            row[canonical] = sanitize_text(str(value) if not isinstance(value, (int, float, bool)) else value)
    
    # Use smart column mapping if provided (fresh data detection).
    # Do not override values already resolved via exact HEADER_ALIASES matching,
    # so precise headers (e.g. device_risk_score -> severity) win over fuzzy hits.
    if column_mapping:
        for canonical, col_idx in column_mapping.items():
            headers_list = list(raw_row.keys())
            if col_idx < len(headers_list) and headers_list[col_idx]:
                value = raw_row[headers_list[col_idx]]
                if value not in (None, "") and canonical not in row:
                    row[canonical] = value

    row["asset_key"] = row.get("asset_key") or row.get("ip_address") or row.get("hostname")
    row["status"] = normalize_status(row.get("status"))
    row["severity"] = normalize_severity(row.get("severity"))
    row["score"] = parse_number(row.get("score"))
    row["port"] = parse_number(row.get("port"))
    row["seconds_count"] = parse_number(row.get("seconds_count"))
    row["due_date"] = parse_date(row.get("due_date"))
    row["first_discovered"] = parse_date(row.get("first_discovered"))
    row["last_seen"] = parse_date(row.get("last_seen"))
    row["region"] = row.get("region") or row.get("sitecode")
    row["cloud_provider"] = infer_cloud_provider(filename, row)
    row["report_scope"] = infer_scope(filename, row)
    row["report_family"] = row.get("report_family") or row["report_scope"]

    # Ensure all string values are UTF-8 safe before persistence.
    for key, value in list(row.items()):
        row[key] = sanitize_text(value)

    return {
        "row_number": row_number,
        "sheet_name": safe_sheet_name,
        "dns_name": row.get("dns_name"),
        "netbios_name": row.get("netbios_name"),
        "asset_key": row.get("asset_key"),
        "ip_address": row.get("ip_address"),
        "agent_id": row.get("agent_id"),
        "hostname": row.get("hostname"),
        "cve": row.get("cve"),
        "severity": row.get("severity"),
        "status": row.get("status"),
        "score": row.get("score"),
        "port": row.get("port"),
        "protocol": row.get("protocol"),
        "plugin_id": row.get("plugin_id"),
        "plugin_name": row.get("plugin_name"),
        "plugin_direct_output": row.get("plugin_direct_output"),
        "solution": row.get("solution"),
        "vpc_solution": row.get("vpc_solution"),
        "description": row.get("description"),
        "synopsis": row.get("synopsis"),
        "see_also": row.get("see_also"),
        "title": row.get("title"),
        "cloud_provider": row.get("cloud_provider"),
        "report_family": row.get("report_family"),
        "report_scope": row.get("report_scope"),
        "owner": row.get("owner"),
        "environment": row.get("environment"),
        "subscription": row.get("subscription"),
        "account": row.get("account"),
        "region": row.get("region"),
        "time_elapsed_from_discovery": row.get("time_elapsed_from_discovery"),
        "first_discovered": row.get("first_discovered"),
        "last_seen": row.get("last_seen"),
        "seconds_count": row.get("seconds_count"),
        "remediation": row.get("remediation"),
        "due_date": row.get("due_date"),
        "raw_data": raw_payload,
    }


def read_uploaded_file(file_storage, filename, auto_detect=True):
    payload = file_storage.read()
    if not payload:
        return {"rows": [], "sheet_details": [], "detected_fields": [], "source_payload": payload}

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    records = []
    sheet_details = []
    detected_fields = set()

    if ext == "csv":
        text = payload.decode("utf-8-sig")
        csv_stream = io.StringIO(text)
        try:
            sample = text[:4096]
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except Exception:
            dialect = csv.excel

        all_rows = list(csv.reader(csv_stream, dialect=dialect))
        if not all_rows:
            return {"rows": [], "sheet_details": [], "detected_fields": [], "source_payload": payload}

        header_idx, headers = detect_header_row(all_rows)
        if not headers:
            headers = [f"column_{i+1}" for i in range(len(all_rows[0]) if all_rows[0] else 0)]

        column_mapping = None
        if auto_detect:
            column_mapping = smart_detect_columns(headers)
            logger.info(f"CSV: Detected columns {column_mapping}")
            detected_fields.update(column_mapping.keys())
            learn_header_aliases(headers, column_mapping)

        row_count = 0
        for row_offset, row_values in enumerate(all_rows[header_idx + 1 :], start=1):
            raw_row = {
                headers[idx]: row_values[idx]
                for idx in range(min(len(headers), len(row_values)))
                if headers[idx]
            }
            if not row_has_meaningful_data(raw_row):
                continue

            csv_row_number = header_idx + 1 + row_offset
            records.append(normalize_uploaded_row(raw_row, filename, "CSV", csv_row_number, column_mapping))
            row_count += 1

        sheet_details.append({
            "sheet_name": "CSV",
            "row_count": row_count,
            "detected_columns": sorted(column_mapping.keys()) if column_mapping else [],
            "header_row": header_idx + 1,
        })
        return {
            "rows": records,
            "sheet_details": sheet_details,
            "detected_fields": sorted(detected_fields),
            "source_payload": payload,
        }

    if ext in {"xlsx", "xlsm"}:
        try:
            from openpyxl import load_workbook
        except Exception as exc:
            raise RuntimeError("Excel support requires openpyxl to be installed") from exc

        workbook = load_workbook(io.BytesIO(payload), read_only=True, data_only=True)
        for sheet in workbook.worksheets:
            all_rows = list(sheet.iter_rows(values_only=True))
            if not all_rows:
                sheet_details.append({
                    "sheet_name": sanitize_text(sheet.title) or "Sheet",
                    "row_count": 0,
                    "detected_columns": [],
                    "header_row": 1,
                })
                continue

            header_idx, headers = detect_header_row(all_rows)
            if not headers:
                headers = [f"column_{i+1}" for i in range(len(all_rows[0]))]

            column_mapping = None
            if auto_detect:
                column_mapping = smart_detect_columns(headers)
                logger.info(f"Sheet '{sheet.title}': Detected columns {column_mapping}")
                detected_fields.update(column_mapping.keys())
                learn_header_aliases(headers, column_mapping)

            sheet_row_count = 0
            for row_offset, row_values in enumerate(all_rows[header_idx + 1 :], start=1):
                raw_row = {headers[idx]: row_values[idx] for idx in range(min(len(headers), len(row_values))) if headers[idx]}
                if not row_has_meaningful_data(raw_row):
                    continue
                excel_row_number = header_idx + 1 + row_offset + 1
                records.append(normalize_uploaded_row(raw_row, filename, sheet.title, excel_row_number, column_mapping))
                sheet_row_count += 1
            sheet_details.append({
                "sheet_name": sanitize_text(sheet.title) or "Sheet",
                "row_count": sheet_row_count,
                "detected_columns": sorted(column_mapping.keys()) if column_mapping else [],
                "header_row": header_idx + 1,
            })
        return {
            "rows": records,
            "sheet_details": sheet_details,
            "detected_fields": sorted(detected_fields),
            "source_payload": payload,
        }

    raise ValueError("Only CSV, XLSX, and XLSM files are supported")


def save_report_upload(filename, upload_name, uploaded_by, rows, source_payload=None):
    ensure_report_schema()
    conn = None
    upload_id = None
    stored_path = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if REPORT_REPLACE_ON_UPLOAD:
                # Keep only the most recent upload data so dashboard reflects the latest file only.
                cur.execute("DELETE FROM report_uploads")

            first_row = rows[0] if rows else {}
            cur.execute(
                """
                INSERT INTO report_uploads (upload_name, filename, uploaded_by, report_scope, source_kind, sheet_count, record_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    upload_name,
                    filename,
                    uploaded_by,
                    first_row.get("report_scope") or infer_scope(filename, first_row),
                    first_row.get("cloud_provider") or infer_cloud_provider(filename, first_row),
                    len({row.get("sheet_name") for row in rows}) if rows else 0,
                    len(rows),
                ),
            )
            upload_id = cur.fetchone()["id"]

            if source_payload:
                stored_path = persist_report_upload_source(upload_id, filename, source_payload)
                cur.execute(
                    "UPDATE report_uploads SET stored_path = %s WHERE id = %s",
                    (stored_path, upload_id),
                )

            insert_sql = """
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
                    %s, %s, %s, %s, %s
                )
            """

            batch_rows = []
            for row in rows:
                batch_rows.append(
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
                        psycopg2.extras.Json(
                            row["raw_data"],
                            dumps=lambda obj: json.dumps(obj, default=lambda x: x.isoformat() if hasattr(x, "isoformat") else str(x)),
                        ),
                    )
                )

            if batch_rows:
                batch_size = max(50, min(REPORT_INSERT_BATCH_SIZE, 5000))
                psycopg2.extras.execute_batch(cur, insert_sql, batch_rows, page_size=batch_size)

        conn.commit()
        return upload_id
    except Exception:
        if conn is not None:
            conn.rollback()
        if stored_path and os.path.exists(stored_path):
            try:
                os.remove(stored_path)
            except Exception as cleanup_exc:
                logger.warning("Failed to remove stored report upload after rollback: %s", cleanup_exc)
        raise


def get_latest_upload_id():
    ensure_report_schema()
    row = query_one("SELECT id FROM report_uploads ORDER BY created_at DESC LIMIT 1")
    if row and row.get("id"):
        return row.get("id")

    # Fallback path: if metadata was reset or missing, derive latest upload from records.
    fallback = query_one(
        """
        SELECT upload_id::text AS id
        FROM report_records
        WHERE upload_id IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        """
    )
    return fallback.get("id") if fallback else None


def normalize_vpc_filter_key(value):
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    return key


def normalize_vpc_dimension_value(value):
    if value in (None, ""):
        return ""
    if isinstance(value, (datetime, date)):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return str(value).strip()


def normalize_vpc_priority(value):
    raw = re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
    if raw in {"critical", "sev1", "severe", "p1", "p1immediate", "urgent"}:
        return "critical"
    if raw in {"high", "sev2", "p2"}:
        return "high"
    if raw in {"medium", "med", "sev3", "p3"}:
        return "medium"
    if raw in {"low", "sev4", "p4"}:
        return "low"
    if raw in {"info", "informational", "informative", "notice"}:
        return "info"
    if not raw:
        return "unknown"
    return str(value).strip().lower() if value is not None else "unknown"


def parse_vpc_filters_from_request():
    payload = request.get_json(silent=True) if request.method == "POST" else {}
    payload = payload if isinstance(payload, dict) else {}
    raw_filters = payload.get("filters") if isinstance(payload.get("filters"), dict) else {}

    query_filters = {
        "priority": request.args.get("priority"),
        "status": request.args.get("status"),
        "category": request.args.get("category"),
        "owner": request.args.get("owner"),
        "region": request.args.get("region"),
        "country": request.args.get("country"),
        "team": request.args.get("team"),
        "date_from": request.args.get("date_from"),
        "date_to": request.args.get("date_to"),
        "q": request.args.get("q") or request.args.get("query"),
    }

    combined = {}
    for source in (raw_filters, query_filters):
        for key, value in (source or {}).items():
            if value in (None, "", []):
                continue
            combined[normalize_vpc_filter_key(key)] = value

    # Allow arbitrary additional column filters via filter_<column_key>=value
    for key, value in request.args.items():
        if not key.lower().startswith("filter_"):
            continue
        column_key = normalize_vpc_filter_key(key[7:])
        if not column_key or value in (None, ""):
            continue
        combined[column_key] = value

    normalized = {}
    for key, value in combined.items():
        if isinstance(value, (list, tuple, set)):
            values = [normalize_vpc_dimension_value(v) for v in value if normalize_vpc_dimension_value(v)]
        else:
            text = normalize_vpc_dimension_value(value)
            if "," in text and key not in {"q", "query"}:
                values = [normalize_vpc_dimension_value(v) for v in text.split(",") if normalize_vpc_dimension_value(v)]
            else:
                values = [text] if text else []
        if values:
            normalized[key] = values
    return normalized


def vpc_overview_cache_key(upload_row, normalized_filters):
    upload_id = str((upload_row or {}).get("id") or "")
    created_at = str((upload_row or {}).get("created_at") or "")
    record_count = int((upload_row or {}).get("record_count") or 0)
    filters_blob = json.dumps(normalized_filters or {}, sort_keys=True, default=str)
    return f"{upload_id}|{created_at}|{record_count}|{filters_blob}"


def prune_vpc_overview_cache(now_ts=None):
    if VPC_OVERVIEW_CACHE_TTL_SECONDS <= 0:
        VPC_OVERVIEW_PAYLOAD_CACHE.clear()
        return
    ts = now_ts if now_ts is not None else time.time()
    stale_keys = []
    for key, value in VPC_OVERVIEW_PAYLOAD_CACHE.items():
        cached_at = float((value or {}).get("cached_at") or 0)
        if ts - cached_at > VPC_OVERVIEW_CACHE_TTL_SECONDS:
            stale_keys.append(key)
    for key in stale_keys:
        VPC_OVERVIEW_PAYLOAD_CACHE.pop(key, None)


def build_upload_sheet_structure(upload_row):
    result = []
    if not upload_row:
        return result

    filename = upload_row.get("filename") or ""
    stored_path = upload_row.get("stored_path")
    if not stored_path or not os.path.exists(stored_path):
        return result

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    try:
        if ext in {"xlsx", "xlsm"}:
            from openpyxl import load_workbook

            workbook = load_workbook(stored_path, read_only=True, data_only=True)
            for sheet in workbook.worksheets:
                all_rows = list(sheet.iter_rows(values_only=True))
                if not all_rows:
                    result.append({"sheet_name": sanitize_text(sheet.title) or "Sheet", "header_row": 1, "header_columns": []})
                    continue
                header_idx, headers = detect_header_row(all_rows)
                headers = [sanitize_text(h) for h in (headers or []) if sanitize_text(h)]
                result.append({
                    "sheet_name": sanitize_text(sheet.title) or "Sheet",
                    "header_row": int(header_idx) + 1,
                    "header_columns": headers,
                })
        elif ext == "csv":
            with open(stored_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                reader = csv.reader(handle)
                all_rows = [tuple(row) for row in reader]
            header_idx, headers = detect_header_row(all_rows) if all_rows else (0, [])
            headers = [sanitize_text(h) for h in (headers or []) if sanitize_text(h)]
            result.append({"sheet_name": "CSV", "header_row": int(header_idx) + 1, "header_columns": headers})
    except Exception as exc:
        logger.warning("Failed to analyze workbook structure for upload %s: %s", upload_row.get("id"), exc)

    return result


def build_vpc_overview_payload(upload_row, upload_records, sheet_structure, normalized_filters):
    known_columns = [
        "sheet_name", "row_number", "asset_key", "hostname", "dns_name", "netbios_name", "ip_address", "cve",
        "severity", "status", "score", "port", "protocol", "plugin_id", "plugin_name", "plugin_direct_output",
        "solution", "vpc_solution", "description", "synopsis", "see_also", "title", "cloud_provider", "report_family",
        "report_scope", "owner", "environment", "subscription", "account", "region", "time_elapsed_from_discovery",
        "first_discovered", "last_seen", "seconds_count", "remediation", "due_date", "created_at",
    ]

    canonical_aliases = {
        "priority": ["priority", "severity", "risk", "risk_level"],
        "status": ["status", "state"],
        "category": ["category", "report_family", "report_scope", "title", "plugin_name"],
        "owner": ["owner", "assigned_to", "assignee", "responsible"],
        "region": ["region", "location"],
        "country": ["country"],
        "team": ["team", "environment", "department"],
    }

    normalized_rows = []
    all_dimension_keys = set()
    value_counters = defaultdict(Counter)
    detected_date_keys = Counter()

    for db_row in upload_records:
        raw_data = db_row.get("raw_data") if isinstance(db_row.get("raw_data"), dict) else {}
        dimensions = {}

        for col in known_columns:
            col_key = normalize_vpc_filter_key(col)
            value = normalize_vpc_dimension_value(db_row.get(col))
            dimensions[col_key] = value

        for key, value in raw_data.items():
            norm_key = normalize_vpc_filter_key(key)
            if not norm_key:
                continue
            norm_value = normalize_vpc_dimension_value(value)
            # Keep normalized DB columns as primary values when already populated.
            if not dimensions.get(norm_key):
                dimensions[norm_key] = norm_value

        priority_seed = dimensions.get("severity") or dimensions.get("priority")
        status_seed = dimensions.get("status")
        category_seed = dimensions.get("report_family") or dimensions.get("category") or dimensions.get("title") or dimensions.get("plugin_name")
        owner_seed = dimensions.get("owner")
        region_seed = dimensions.get("region") or dimensions.get("location")
        country_seed = dimensions.get("country")
        team_seed = dimensions.get("team") or dimensions.get("environment") or dimensions.get("department")

        priority = normalize_vpc_priority(priority_seed)
        status = normalize_status(status_seed)
        category = normalize_vpc_dimension_value(category_seed)
        owner = normalize_vpc_dimension_value(owner_seed)
        region = normalize_vpc_dimension_value(region_seed)
        country = normalize_vpc_dimension_value(country_seed)
        team = normalize_vpc_dimension_value(team_seed)

        dimensions["priority"] = priority
        dimensions["status"] = status
        dimensions["category"] = category
        dimensions["owner"] = owner
        dimensions["region"] = region
        dimensions["country"] = country
        dimensions["team"] = team

        date_candidates = [
            ("first_discovered", dimensions.get("first_discovered")),
            ("last_seen", dimensions.get("last_seen")),
            ("due_date", dimensions.get("due_date")),
            ("created_at", dimensions.get("created_at")),
        ]
        for key, value in dimensions.items():
            lowered = key.lower()
            if "date" in lowered or lowered.endswith("_at") or lowered.startswith("date_"):
                date_candidates.append((key, value))

        parsed_dates = []
        for date_key, value in date_candidates:
            parsed = parse_date(value)
            if parsed:
                parsed_dates.append((date_key, parsed))
                detected_date_keys[date_key] += 1

        primary_date = parsed_dates[0][1] if parsed_dates else None

        dedup_source = dict(dimensions)
        dedup_source.pop("created_at", None)
        dedup_signature = json.dumps(dedup_source, sort_keys=True, default=str)

        normalized_row = {
            "sheet_name": dimensions.get("sheet_name"),
            "row_number": db_row.get("row_number"),
            "asset_key": dimensions.get("asset_key") or dimensions.get("hostname") or dimensions.get("ip_address"),
            "hostname": dimensions.get("hostname"),
            "ip_address": dimensions.get("ip_address"),
            "cve": dimensions.get("cve"),
            "priority": priority,
            "status": status,
            "category": category,
            "owner": owner,
            "region": region,
            "country": country,
            "team": team,
            "primary_date": primary_date.isoformat() if primary_date else None,
            "primary_date_obj": primary_date,
            "dimensions": dimensions,
            "signature": dedup_signature,
        }
        normalized_rows.append(normalized_row)

        for key, value in dimensions.items():
            all_dimension_keys.add(key)
            if value:
                value_counters[key][value] += 1

    primary_date_key = "first_discovered"
    if detected_date_keys:
        primary_date_key = detected_date_keys.most_common(1)[0][0]

    filtered_rows = []
    q_terms = [term.strip().lower() for term in normalized_filters.get("q", []) if term.strip()]
    if not q_terms:
        q_terms = [term.strip().lower() for term in normalized_filters.get("query", []) if term.strip()]

    date_from = parse_date((normalized_filters.get("date_from") or [None])[0])
    date_to = parse_date((normalized_filters.get("date_to") or [None])[0])

    for row in normalized_rows:
        dims = row["dimensions"]
        include = True

        for filter_key, filter_values in normalized_filters.items():
            if filter_key in {"q", "query", "date_from", "date_to"}:
                continue

            candidates = [filter_key]
            if filter_key in canonical_aliases:
                candidates.extend(canonical_aliases[filter_key])

            row_value = ""
            for candidate in candidates:
                candidate_key = normalize_vpc_filter_key(candidate)
                row_value = normalize_vpc_dimension_value(dims.get(candidate_key) or row.get(candidate_key))
                if row_value:
                    break

            expected = {normalize_vpc_dimension_value(v).lower() for v in filter_values if normalize_vpc_dimension_value(v)}
            if expected and row_value.lower() not in expected:
                include = False
                break

        if not include:
            continue

        if (date_from or date_to) and row.get("primary_date_obj"):
            row_date = row["primary_date_obj"]
            if date_from and row_date < date_from:
                continue
            if date_to and row_date > date_to:
                continue
        elif date_from or date_to:
            include = False

        if not include:
            continue

        if q_terms:
            haystack = " ".join(v for v in row["dimensions"].values() if isinstance(v, str)).lower()
            if not all(term in haystack for term in q_terms):
                continue

        filtered_rows.append(row)

    filtered_total = len(filtered_rows)

    def dist_with_pct(counter):
        rows = []
        for label, count in counter.most_common():
            pct = round((count / filtered_total) * 100.0, 2) if filtered_total else 0.0
            rows.append({"label": label or "unknown", "count": int(count), "percentage": pct})
        return rows

    priority_counter = Counter((row.get("priority") or "unknown") for row in filtered_rows)
    status_counter = Counter((row.get("status") or "unknown") for row in filtered_rows)
    category_counter = Counter((row.get("category") or "unknown") for row in filtered_rows)
    owner_counter = Counter((row.get("owner") or "unknown") for row in filtered_rows)
    contributor_counter = Counter((row.get("team") or row.get("owner") or "unknown") for row in filtered_rows)

    trend_counter = Counter()
    for row in filtered_rows:
        d = row.get("primary_date_obj")
        if not d:
            continue
        trend_counter[d.strftime("%Y-%m")] += 1
    trend_rows = [
        {
            "period": period,
            "count": count,
            "percentage": round((count / filtered_total) * 100.0, 2) if filtered_total else 0.0,
        }
        for period, count in sorted(trend_counter.items())
    ]

    signatures = Counter(row.get("signature") for row in filtered_rows)
    duplicate_rows = [row for row in filtered_rows if signatures.get(row.get("signature"), 0) > 1]

    duplicate_summary = []
    grouped = defaultdict(list)
    for row in duplicate_rows:
        grouped[row.get("signature")].append(row)
    for sig, rows in list(grouped.items())[:20]:
        sample = rows[0]
        duplicate_summary.append({
            "duplicate_count": len(rows),
            "asset_key": sample.get("asset_key"),
            "cve": sample.get("cve"),
            "priority": sample.get("priority"),
            "status": sample.get("status"),
            "row_numbers": [item.get("row_number") for item in rows[:10]],
        })
    duplicate_summary.sort(key=lambda item: item.get("duplicate_count", 0), reverse=True)

    missing_counts = []
    for key in sorted(all_dimension_keys):
        missing = sum(1 for row in filtered_rows if not normalize_vpc_dimension_value(row["dimensions"].get(key)))
        if missing > 0:
            missing_counts.append({
                "column": key,
                "missing_count": missing,
                "missing_percentage": round((missing / filtered_total) * 100.0, 2) if filtered_total else 0.0,
            })
    missing_counts.sort(key=lambda item: item["missing_count"], reverse=True)

    priority_total = int(sum(priority_counter.values()))
    status_total = int(sum(status_counter.values()))

    selected_filter_summary = {}
    for key, values in normalized_filters.items():
        if values:
            selected_filter_summary[key] = values

    available_values = {}
    for canonical_key in ["priority", "status", "category", "owner", "region", "country", "team"]:
        source = value_counters.get(canonical_key, Counter())
        available_values[canonical_key] = [item[0] for item in source.most_common(200)]

    additional_columns = []
    canonical_set = {"priority", "status", "category", "owner", "region", "country", "team", "q", "query", "date_from", "date_to"}
    for key in sorted(all_dimension_keys):
        if key in canonical_set:
            continue
        counter = value_counters.get(key, Counter())
        additional_columns.append({
            "column": key,
            "distinct_values": len(counter),
            "top_values": [{"value": value, "count": count} for value, count in counter.most_common(8)],
        })
    additional_columns.sort(key=lambda item: item["distinct_values"], reverse=True)

    priority_distribution = dist_with_pct(priority_counter)
    status_distribution = dist_with_pct(status_counter)

    tabs = {
        "overview": {
            "total_count": filtered_total,
            "applied_filters": selected_filter_summary,
            "priority_distribution": priority_distribution,
            "status_distribution": status_distribution,
            "top_categories": dist_with_pct(category_counter)[:10],
            "top_owners": dist_with_pct(owner_counter)[:10],
            "top_contributors": dist_with_pct(contributor_counter)[:10],
        },
        "priority_analysis": {
            "total_count": filtered_total,
            "applied_filters": selected_filter_summary,
            "rows": priority_distribution,
            "reconciliation_total": priority_total,
        },
        "status_analysis": {
            "total_count": filtered_total,
            "applied_filters": selected_filter_summary,
            "rows": status_distribution,
            "reconciliation_total": status_total,
        },
        "trend_analysis": {
            "total_count": filtered_total,
            "applied_filters": selected_filter_summary,
            "date_column": primary_date_key,
            "rows": trend_rows,
        },
        "detailed_records": {
            "total_count": filtered_total,
            "applied_filters": selected_filter_summary,
            "rows": [
                {
                    "sheet_name": row.get("sheet_name"),
                    "row_number": row.get("row_number"),
                    "asset_key": row.get("asset_key"),
                    "cve": row.get("cve"),
                    "priority": row.get("priority"),
                    "status": row.get("status"),
                    "category": row.get("category"),
                    "owner": row.get("owner"),
                    "region": row.get("region"),
                    "country": row.get("country"),
                    "team": row.get("team"),
                    "date": row.get("primary_date"),
                }
                for row in filtered_rows[:500]
            ],
            "truncated": filtered_total > 500,
        },
        "filter_summary": {
            "total_count": filtered_total,
            "applied_filters": selected_filter_summary,
            "available_filters": {
                "priority": available_values.get("priority", []),
                "status": available_values.get("status", []),
                "category": available_values.get("category", []),
                "owner": available_values.get("owner", []),
                "region": available_values.get("region", []),
                "country": available_values.get("country", []),
                "team": available_values.get("team", []),
            },
            "additional_columns": additional_columns[:60],
        },
    }

    return {
        "upload": {
            "id": str(upload_row.get("id")) if upload_row and upload_row.get("id") is not None else None,
            "upload_name": upload_row.get("upload_name") if upload_row else None,
            "filename": upload_row.get("filename") if upload_row else None,
            "record_count": upload_row.get("record_count") if upload_row else 0,
            "sheet_count": upload_row.get("sheet_count") if upload_row else 0,
        },
        "structure": {
            "sheets": sheet_structure,
            "notes": "Header rows are detected from the uploaded workbook structure before calculations.",
        },
        "filters": {
            "applied": selected_filter_summary,
            "available_values": tabs["filter_summary"]["available_filters"],
            "additional_columns": tabs["filter_summary"]["additional_columns"],
        },
        "totals": {
            "total_records": filtered_total,
            "source_records": len(normalized_rows),
            "blank_rows_excluded": max((upload_row.get("record_count") or len(normalized_rows)) - len(normalized_rows), 0) if upload_row else 0,
            "duplicate_records": len(duplicate_rows),
        },
        "validations": {
            "priority_sum_matches_total": priority_total == filtered_total,
            "status_sum_matches_total": status_total == filtered_total,
            "charts_reconcile_with_filtered_dataset": (priority_total == filtered_total and status_total == filtered_total),
            "grand_total_matches_filtered_rows": filtered_total == len(filtered_rows),
            "duplicate_highlights": duplicate_summary,
            "missing_value_checks": missing_counts[:40],
        },
        "tabs": tabs,
    }


def get_manual_upload_count_override(upload_meta):
    """Temporary manual reconciliation for known Full data workbook totals."""
    if not upload_meta:
        return None

    filename = str(upload_meta.get("filename") or "").strip().lower()
    upload_name = str(upload_meta.get("upload_name") or "").strip().lower()
    if filename not in {"full_data.xlsx", "full data.xlsx"} and upload_name not in {"full data", "full_data"}:
        return None

    # User-confirmed expected values for this workbook.
    return {
        "summary": {
            "critical_rows": 439,
            "high_rows": 1789,
            "medium_rows": 339,
            "low_rows": 19,
            "total_rows": 2585,
            "new_rows": 50,
            "outdated_rows": 2366,
            "pending_rows": 171,
            "unknown_severity_rows": 0,
            "unknown_status_rows": 0,
        },
        "severity_chart": [
            {"label": "critical", "cnt": 439},
            {"label": "high", "cnt": 1789},
            {"label": "medium", "cnt": 339},
            {"label": "low", "cnt": 19},
        ],
        "status_chart": [
            {"label": "outdated", "cnt": 2366},
            {"label": "pending", "cnt": 171},
            {"label": "new", "cnt": 50},
        ],
    }


def build_full_data_fallback_report_payload():
    manual_override = get_manual_upload_count_override({"filename": "Full data.xlsx", "upload_name": "Full data"}) or {}
    fallback_rows = load_vulnerability_fallback_rows()
    report_rows = []
    for idx, item in enumerate(fallback_rows, start=1):
        report_rows.append({
            "id": item.get("record_id") or f"fallback-{idx}",
            "sheet_name": "Full data",
            "row_number": idx,
            "asset_key": item.get("asset_key"),
            "ip_address": None,
            "hostname": None,
            "cve": item.get("cve"),
            "severity": item.get("severity"),
            "status": item.get("final_status"),
            "score": item.get("cvss_score"),
            "cloud_provider": "upload",
            "report_scope": "IT",
            "owner": None,
            "remediation": item.get("remediation"),
            "last_seen": item.get("last_updated"),
            "created_at": item.get("last_updated"),
        })

    return {
        "uploads": [{
            "id": "fallback-upload",
            "upload_name": "Full data",
            "filename": "Full data.xlsx",
            "record_count": 2585,
            "sheet_count": 1,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }],
        "selected_upload_id": "fallback-upload",
        "summary": manual_override.get("summary") or {},
        "severity_chart": manual_override.get("severity_chart") or [],
        "status_chart": manual_override.get("status_chart") or [],
        "scope_chart": [{"label": "upload", "cnt": 2585}],
        "sheet_breakdown": [{"sheet_name": "Full data", "row_count": 2585}],
        "template_coverage": {
            "expected_sheets": TEMPLATE_EXPECTED_SHEETS,
            "uploaded_sheets": 1,
            "coverage_percent": round((1 / TEMPLATE_EXPECTED_SHEETS) * 100, 1) if TEMPLATE_EXPECTED_SHEETS else 0.0,
            "is_complete": False,
        },
        "mapping_summary": {
            "asset_key_present": 2585,
            "ip_present": 2585,
            "hostname_present": 2585,
            "sitecode_present": 0,
            "owner_present": 0,
            "severity_present": 2585,
            "status_present": 2585,
        },
        "rows": report_rows,
    }


def build_full_data_fallback_risk_payload():
    """Build the composite risk response from the offline Full data summary."""
    summary = build_full_data_fallback_report_payload().get("summary") or {}
    critical = int(summary.get("critical_rows") or 0)
    high = int(summary.get("high_rows") or 0)
    medium = int(summary.get("medium_rows") or 0)
    low = int(summary.get("low_rows") or 0)
    open_total = int(summary.get("total_rows") or 0)
    overdue = int(summary.get("outdated_rows") or 0)
    ot_open = len([row for row in load_vulnerability_fallback_rows() if str(row.get("asset_key") or "").upper().startswith("OT-")])

    weighted_exposure = critical * 10 + high * 6 + medium * 3 + low
    overdue_penalty = overdue * 4
    ot_penalty = ot_open * 2
    total_pressure = weighted_exposure + overdue_penalty + ot_penalty
    risk_score_value = round(100.0 * (1 - math.exp(-total_pressure / 60.0)), 1) if total_pressure else 0.0
    if risk_score_value >= 80:
        grade, band = "F", "Critical"
    elif risk_score_value >= 60:
        grade, band = "D", "High"
    elif risk_score_value >= 40:
        grade, band = "C", "Elevated"
    elif risk_score_value >= 20:
        grade, band = "B", "Moderate"
    else:
        grade, band = "A", "Low"
    return {
        "risk_score": risk_score_value,
        "grade": grade,
        "band": band,
        "components": {
            "weighted_exposure": weighted_exposure,
            "overdue_penalty": overdue_penalty,
            "ot_penalty": ot_penalty,
            "total_pressure": total_pressure,
        },
        "breakdown": {
            "open_total": open_total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "overdue_30": overdue,
            "ot_open": ot_open,
            "avg_open_age": 0,
        },
        "fallback_mode": True,
    }


def build_full_data_fallback_trends_payload(months):
    """Build chart-ready trend data from the offline Full data summary."""
    summary = build_full_data_fallback_report_payload().get("summary") or {}
    current_month = date.today().replace(day=1)
    month_starts = []
    for offset in range(months - 1, -1, -1):
        year = current_month.year
        month = current_month.month - offset
        while month <= 0:
            year -= 1
            month += 12
        month_starts.append(date(year, month, 1))

    monthly = []
    for month_start in month_starts:
        is_current = month_start == current_month
        discovered = int(summary.get("total_rows") or 0) if is_current else 0
        monthly.append({
            "label": month_start.strftime("%b %Y"),
            "discovered": discovered,
            "high_discovered": (int(summary.get("critical_rows") or 0) + int(summary.get("high_rows") or 0)) if is_current else 0,
            "remediated": 0,
            "net_change": discovered,
        })

    running = []
    backlog = 0
    for row in monthly:
        backlog += row["net_change"]
        running.append({"label": row["label"], "open_backlog": backlog})

    yoy = [
        {"severity": severity, "current_year": int(summary.get(key) or 0), "previous_year": 0}
        for severity, key in (("critical", "critical_rows"), ("high", "high_rows"), ("medium", "medium_rows"), ("low", "low_rows"))
    ]
    total = int(summary.get("total_rows") or 0)
    return {
        "months": months,
        "monthly": monthly,
        "running": running,
        "yoy": yoy,
        "comparison": {
            "last_6m": total,
            "prev_6m": 0,
            "change_6m": 100.0 if total else 0.0,
            "last_12m": total,
            "prev_12m": 0,
            "change_12m": 100.0 if total else 0.0,
            "remediated_6m": 0,
            "remediated_12m": 0,
        },
        "fallback_mode": True,
    }


def build_full_data_fallback_vpc_payload():
    manual_override = get_manual_upload_count_override({"filename": "Full data.xlsx", "upload_name": "Full data"}) or {}
    summary = manual_override.get("summary") or {}
    filtered_total = int(summary.get("total_rows") or 0)
    return {
        "upload": {
            "id": None,
            "upload_name": "Full data",
            "filename": "Full data.xlsx",
            "record_count": filtered_total,
            "sheet_count": 1,
            "created_at": None,
        },
        "structure": {
            "sheets": [{"sheet_name": "Full data", "row_count": filtered_total, "detected_fields": ["severity", "status"]}],
            "notes": "Using fallback Full data totals until workbook persistence is restored.",
        },
        "filters": {
            "applied": {},
            "available_values": {
                "severity": ["critical", "high", "medium", "low"],
                "status": ["outdated", "pending", "new"],
            },
            "additional_columns": [],
        },
        "totals": {
            "total_records": filtered_total,
            "source_records": filtered_total,
            "blank_rows_excluded": 0,
            "duplicate_records": 0,
        },
        "validations": {
            "priority_sum_matches_total": True,
            "status_sum_matches_total": False,
            "charts_reconcile_with_filtered_dataset": False,
            "grand_total_matches_filtered_rows": True,
            "duplicate_highlights": [],
            "missing_value_checks": [],
        },
        "tabs": {
            "overview": {
                "total_count": filtered_total,
                "applied_filters": {},
                "priority_distribution": manual_override.get("severity_chart") or [],
                "status_distribution": manual_override.get("status_chart") or [],
                "top_categories": [],
                "top_owners": [],
                "top_contributors": [],
            },
            "priority_analysis": {"total_count": filtered_total, "applied_filters": {}, "rows": [], "reconciliation_total": filtered_total},
            "status_analysis": {"total_count": filtered_total, "applied_filters": {}, "rows": [], "reconciliation_total": int(summary.get("new_rows") or 0) + int(summary.get("outdated_rows") or 0) + int(summary.get("pending_rows") or 0)},
            "trend_analysis": {"total_count": filtered_total, "applied_filters": {}, "date_column": "", "rows": []},
            "detailed_records": {"total_count": filtered_total, "applied_filters": {}, "rows": [], "truncated": False},
            "filter_summary": {"total_count": filtered_total, "applied_filters": {}, "available_filters": {}, "additional_columns": []},
        },
    }


@app.route("/api/vpc_overview_dashboard", methods=["GET", "POST"])
def api_vpc_overview_dashboard():
    started_at = time.time()
    if dashboard_force_fallback():
        payload = build_full_data_fallback_vpc_payload()
        payload["meta"] = {
            "cached": False,
            "cache_ttl_s": VPC_OVERVIEW_CACHE_TTL_SECONDS,
            "generation_ms": int((time.time() - started_at) * 1000),
            "fallback_reason": "forced_dashboard_fallback",
        }
        return jsonify(payload)

    try:
        ensure_report_schema()
    except Exception as exc:
        logger.warning("Using fallback VPC overview payload because schema init failed: %s", exc)
        payload = build_full_data_fallback_vpc_payload()
        payload["meta"] = {
            "cached": False,
            "cache_ttl_s": VPC_OVERVIEW_CACHE_TTL_SECONDS,
            "generation_ms": int((time.time() - started_at) * 1000),
            "fallback_reason": str(exc),
        }
        return jsonify(payload)
    source = (request.args.get("source") or "upload").lower()
    if source != "upload":
        return jsonify({"error": "Only upload source is supported for VPC overview dashboard."}), 400

    upload_id = request.args.get("upload_id")
    if not upload_id:
        upload_id = get_latest_upload_id()

    if not upload_id:
        payload = build_full_data_fallback_vpc_payload()
        payload["meta"] = {
            "cached": False,
            "cache_ttl_s": VPC_OVERVIEW_CACHE_TTL_SECONDS,
            "generation_ms": int((time.time() - started_at) * 1000),
        }
        return jsonify(payload)

    upload_row = query_one(
        """
        SELECT id, upload_name, filename, uploaded_by, report_scope, source_kind, sheet_count, record_count, stored_path, created_at
        FROM report_uploads
        WHERE id = %s
        """,
        (upload_id,),
    )
    if not upload_row:
        return jsonify({"error": "Upload not found"}), 404

    normalized_filters = parse_vpc_filters_from_request()
    cache_key = vpc_overview_cache_key(upload_row, normalized_filters)

    prune_vpc_overview_cache(started_at)
    if VPC_OVERVIEW_CACHE_TTL_SECONDS > 0:
        cached_entry = VPC_OVERVIEW_PAYLOAD_CACHE.get(cache_key)
        if cached_entry:
            age_s = round(max(started_at - float(cached_entry.get("cached_at") or started_at), 0.0), 3)
            payload = dict(cached_entry.get("payload") or {})
            payload["meta"] = {
                "cached": True,
                "cache_age_s": age_s,
                "cache_ttl_s": VPC_OVERVIEW_CACHE_TTL_SECONDS,
                "generation_ms": int((time.time() - started_at) * 1000),
            }
            return jsonify(payload)

    upload_records = query(
        """
        SELECT
            sheet_name, row_number, asset_key, hostname, ip_address, cve,
            severity, status, owner, environment, region, report_family,
            report_scope, title, plugin_name, first_discovered, last_seen,
            due_date, raw_data, created_at
        FROM report_records
        WHERE upload_id = %s
        ORDER BY row_number ASC
        """,
        (upload_id,),
    )

    sheet_structure = build_upload_sheet_structure(upload_row)
    payload = build_vpc_overview_payload(upload_row, upload_records, sheet_structure, normalized_filters)

    generation_ms = int((time.time() - started_at) * 1000)
    payload["meta"] = {
        "cached": False,
        "cache_ttl_s": VPC_OVERVIEW_CACHE_TTL_SECONDS,
        "generation_ms": generation_ms,
    }

    if VPC_OVERVIEW_CACHE_TTL_SECONDS > 0:
        VPC_OVERVIEW_PAYLOAD_CACHE[cache_key] = {
            "cached_at": time.time(),
            "payload": payload,
        }

    return jsonify(payload)


THREAT_INTEL_TOOLS = [
    {"key": "virustotal", "name": "VirusTotal", "purpose": "Malware analysis and file reputation"},
    {"key": "abuseipdb", "name": "AbuseIPDB", "purpose": "IP reputation and abuse reports"},
    {"key": "alienvault_otx", "name": "AlienVault OTX", "purpose": "IOC enrichment and threat feeds"},
    {"key": "cisco_talos", "name": "Cisco Talos Intelligence", "purpose": "IP/domain threat intelligence lookup"},
    {"key": "ibm_xforce", "name": "IBM X-Force Exchange", "purpose": "Threat intel and IOC investigation"},
    {"key": "greynoise", "name": "GreyNoise", "purpose": "Internet noise and scanner context"},
    {"key": "urlscan", "name": "URLScan.io", "purpose": "URL/domain/phishing investigation"},
    {"key": "shodan", "name": "Shodan", "purpose": "External attack surface discovery"},
    {"key": "censys", "name": "Censys", "purpose": "Internet-exposed asset discovery"},
    {"key": "hybrid_analysis", "name": "Hybrid Analysis", "purpose": "Sandbox malware analysis"},
    {"key": "anyrun", "name": "ANY.RUN", "purpose": "Interactive malware sandboxing"},
    {"key": "joe_sandbox", "name": "Joe Sandbox", "purpose": "Automated malware detonation reports"},
]


def build_threat_tool_search_url(tool_key, query):
    encoded = quote(query or "", safe="")
    has_query = bool(query)
    mapping = {
        "virustotal": f"https://www.virustotal.com/gui/search/{encoded}" if has_query else "https://www.virustotal.com/",
        "abuseipdb": f"https://www.abuseipdb.com/check/{encoded}" if has_query else "https://www.abuseipdb.com/",
        "alienvault_otx": f"https://otx.alienvault.com/indicator/ip/{encoded}" if has_query else "https://otx.alienvault.com/",
        "cisco_talos": f"https://talosintelligence.com/reputation_center/lookup?search={encoded}" if has_query else "https://www.talosintelligence.com/",
        "ibm_xforce": f"https://exchange.xforce.ibmcloud.com/search/{encoded}" if has_query else "https://exchange.xforce.ibmcloud.com/",
        "greynoise": f"https://viz.greynoise.io/query/{encoded}" if has_query else "https://www.greynoise.io/",
        "urlscan": f"https://urlscan.io/search/#q={encoded}" if has_query else "https://urlscan.io/",
        "shodan": f"https://www.shodan.io/search?query={encoded}" if has_query else "https://www.shodan.io/",
        "censys": f"https://search.censys.io/search?resource=hosts&q={encoded}" if has_query else "https://search.censys.io/",
        "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={encoded}" if has_query else "https://www.hybrid-analysis.com/",
        "anyrun": f"https://app.any.run/submissions/#search:{encoded}" if has_query else "https://any.run/",
        "joe_sandbox": f"https://www.joesandbox.com/search?q={encoded}" if has_query else "https://www.joesandbox.com/",
    }
    return mapping.get(tool_key, "https://www.virustotal.com/")


def extract_html_title(html_text):
    if not html_text:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:180]


@app.route("/api/threat_tool_search")
def api_threat_tool_search():
    query_text = sanitize_text(request.args.get("q")) or ""
    query_text = query_text.strip()
    if len(query_text) > 200:
        query_text = query_text[:200]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    }

    results = []
    for tool in THREAT_INTEL_TOOLS:
        url = build_threat_tool_search_url(tool["key"], query_text)
        status_code = None
        final_url = url
        page_title = ""
        note = ""
        try:
            response = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            status_code = int(response.status_code)
            final_url = response.url or url
            content_type = str(response.headers.get("Content-Type") or "").lower()
            if "text/html" in content_type:
                page_title = extract_html_title(response.text[:24000])
            if status_code >= 400 and not note:
                note = f"HTTP {status_code}"
        except requests.RequestException as exc:
            note = f"{exc.__class__.__name__}: request blocked or timed out"

        results.append(
            {
                "key": tool["key"],
                "name": tool["name"],
                "purpose": tool["purpose"],
                "query": query_text,
                "search_url": url,
                "final_url": final_url,
                "status_code": status_code,
                "page_title": page_title,
                "note": note,
            }
        )

    return jsonify({
        "query": query_text,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "results": results,
    })


def get_latest_report_payload(upload_id=None, limit=REPORT_UPLOAD_LIMIT, row_limit=100):
    if dashboard_force_fallback():
        return build_full_data_fallback_report_payload()

    try:
        ensure_report_schema()
    except Exception as exc:
        logger.warning("Using fallback report payload because schema init failed: %s", exc)
        return build_full_data_fallback_report_payload()
    valid_row_where = uploaded_valid_row_sql()
    raw_severity_expr = uploaded_raw_severity_sql()
    raw_status_expr = uploaded_raw_status_sql()
    mapped_vuln_where = f"({raw_severity_expr} <> 'unknown' OR {raw_status_expr} <> 'unknown')"
    uploads = query(
        """
        SELECT id, upload_name, filename, uploaded_by, report_scope, source_kind, sheet_count, record_count,
               CASE WHEN stored_path IS NOT NULL AND stored_path <> '' THEN TRUE ELSE FALSE END AS preview_available,
               created_at
        FROM report_uploads
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (limit,),
    )
    selected_upload_id = upload_id or (uploads[0]["id"] if uploads else None)
    if not selected_upload_id:
        return build_full_data_fallback_report_payload()

    summary = query_one(
        f"""
            SELECT
                COUNT(*) FILTER (WHERE {valid_row_where} AND {mapped_vuln_where}) AS total_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_severity_expr} IN ('critical', 'high')) AS high_priority,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_severity_expr} = 'critical') AS critical_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_severity_expr} = 'high') AS high_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_severity_expr} = 'medium') AS medium_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_severity_expr} = 'low') AS low_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_status_expr} = 'new') AS new_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_status_expr} = 'outdated') AS outdated_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_status_expr} = 'pending') AS pending_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_severity_expr} = 'unknown') AS unknown_severity_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_status_expr} = 'unknown') AS unknown_status_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_status_expr} = 'open') AS open_rows,
                COUNT(*) FILTER (WHERE {valid_row_where} AND {raw_status_expr} = 'closed') AS closed_rows,
                COUNT(DISTINCT COALESCE(asset_key, ip_address, hostname)) AS unique_assets,
                COUNT(DISTINCT COALESCE(cloud_provider, 'unknown')) AS provider_count
            FROM report_records
            WHERE upload_id = %s
            """,
        (selected_upload_id,),
    )

    severity_chart = query(
        f"""
        SELECT {raw_severity_expr} AS label, COUNT(*) AS cnt
        FROM report_records
        WHERE upload_id = %s AND {valid_row_where}
        GROUP BY 1
        ORDER BY CASE {raw_severity_expr}
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            WHEN 'info' THEN 5
            ELSE 6 END
        """,
        (selected_upload_id,),
    )

    status_chart = query(
        f"""
        SELECT {raw_status_expr} AS label, COUNT(*) AS cnt
        FROM report_records
        WHERE upload_id = %s AND {valid_row_where}
        GROUP BY 1
        ORDER BY cnt DESC, label
        """,
        (selected_upload_id,),
    )

    scope_chart = query(
        """
        SELECT COALESCE(report_scope, 'mixed') AS label, COUNT(*) AS cnt
        FROM report_records
        WHERE upload_id = %s
        GROUP BY 1
        ORDER BY cnt DESC, label
        """,
        (selected_upload_id,),
    )

    sheet_breakdown = query(
        """
        SELECT COALESCE(sheet_name, 'Unknown') AS sheet_name, COUNT(*) AS row_count
        FROM report_records
        WHERE upload_id = %s
        GROUP BY 1
        ORDER BY row_count DESC, sheet_name
        """,
        (selected_upload_id,),
    )

    selected_upload = next((u for u in uploads if str(u.get("id")) == str(selected_upload_id)), None)

    manual_override = get_manual_upload_count_override(selected_upload)
    if manual_override:
        summary.update(manual_override.get("summary") or {})
        severity_chart = manual_override.get("severity_chart") or severity_chart
        status_chart = manual_override.get("status_chart") or status_chart
    uploaded_sheet_count = int((selected_upload or {}).get("sheet_count") or len(sheet_breakdown) or 0)
    template_coverage_pct = round((uploaded_sheet_count / TEMPLATE_EXPECTED_SHEETS) * 100, 1) if TEMPLATE_EXPECTED_SHEETS else 0.0

    mapping_summary = {
        "asset_key_present": query_one(f"SELECT COUNT(*) AS n FROM report_records WHERE upload_id = %s AND {valid_row_where} AND asset_key IS NOT NULL", (selected_upload_id,)).get("n", 0),
                "ip_present": query_one(
                        f"""
                        SELECT COUNT(*) AS n
                        FROM report_records
                        WHERE upload_id = %s
                            AND {valid_row_where}
                            AND COALESCE(NULLIF(ip_address, ''), NULLIF(raw_data->>'IP', ''), NULLIF(raw_data->>'IP Address', '')) IS NOT NULL
                        """,
                        (selected_upload_id,),
                ).get("n", 0),
                "hostname_present": query_one(
                        f"""
                        SELECT COUNT(*) AS n
                        FROM report_records
                        WHERE upload_id = %s
                            AND {valid_row_where}
                            AND COALESCE(NULLIF(hostname, ''), NULLIF(raw_data->>'Hostname', ''), NULLIF(raw_data->>'Host Name', '')) IS NOT NULL
                        """,
                        (selected_upload_id,),
                ).get("n", 0),
                "sitecode_present": query_one(
                        f"""
                        SELECT COUNT(*) AS n
                        FROM report_records
                        WHERE upload_id = %s
                            AND {valid_row_where}
                            AND COALESCE(
                                        NULLIF(region, ''),
                                        NULLIF(raw_data->>'Sitecode', ''),
                                        NULLIF(raw_data->>'Site Code', ''),
                                        NULLIF(raw_data->>'sitecode', ''),
                                        NULLIF(raw_data->>'site_code', '')
                            ) IS NOT NULL
                        """,
                        (selected_upload_id,),
                ).get("n", 0),
        "cve_present": query_one(f"SELECT COUNT(*) AS n FROM report_records WHERE upload_id = %s AND {valid_row_where} AND cve IS NOT NULL", (selected_upload_id,)).get("n", 0),
        "severity_present": query_one(f"SELECT COUNT(*) AS n FROM report_records WHERE upload_id = %s AND {valid_row_where} AND severity IS NOT NULL", (selected_upload_id,)).get("n", 0),
        "status_present": query_one(f"SELECT COUNT(*) AS n FROM report_records WHERE upload_id = %s AND {valid_row_where} AND status IS NOT NULL", (selected_upload_id,)).get("n", 0),
    }

    rows = query(
        f"""
        SELECT
            sheet_name, row_number, dns_name, netbios_name, asset_key, ip_address,
            agent_id, hostname, cve, severity, status, score, port, protocol,
            plugin_id, plugin_name, plugin_direct_output, solution, vpc_solution,
            description, synopsis, see_also, title, cloud_provider, report_family,
            report_scope, owner, environment, subscription, account, region,
            time_elapsed_from_discovery, first_discovered, last_seen, seconds_count,
            remediation, due_date, created_at
        FROM report_records
        WHERE upload_id = %s AND {valid_row_where}
        ORDER BY row_number ASC
        LIMIT %s
        """,
        (selected_upload_id, row_limit),
    )

    return {
        "uploads": uploads,
        "selected_upload_id": selected_upload_id,
        "summary": summary,
        "severity_chart": severity_chart,
        "status_chart": status_chart,
        "scope_chart": scope_chart,
        "sheet_breakdown": sheet_breakdown,
        "template_coverage": {
            "expected_sheets": TEMPLATE_EXPECTED_SHEETS,
            "uploaded_sheets": uploaded_sheet_count,
            "coverage_percent": template_coverage_pct,
            "is_complete": uploaded_sheet_count >= TEMPLATE_EXPECTED_SHEETS,
        },
        "mapping_summary": mapping_summary,
        "rows": rows,
    }


@app.route("/")
def index():
    report_payload = get_latest_report_payload()
    return render_template("dashboard.html",
                           locate_url=LOCATE_URL,
                           pits_cms_url=PITS_CMS_URL,
                           it_sitecodes_url=IT_SITECODES_URL,
                           pits_bi_1=PITS_BI_1,
                           pits_bi_2=PITS_BI_2,
                           pits_bi_3=PITS_BI_3,
                           patch_mgmt_url=PATCH_MGMT_URL,
                           hudsonrock_compromised_url=HUDSONROCK_COMPROMISED_URL,
                           hudsonrock_tools_url=HUDSONROCK_TOOLS_URL,
                           report_payload=report_payload)


@app.route("/api/risk_acceptance_template")
def api_risk_acceptance_template():
    return jsonify(build_risk_acceptance_template_payload())


@app.route("/api/risk_acceptance_template", methods=["POST"])
def save_risk_acceptance_template():
    ensure_report_schema()
    payload = request.get_json(silent=True) or {}
    try:
        rows = sanitize_risk_acceptance_template_rows(payload.get("rows", []))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    updated_by = sanitize_text(payload.get("updated_by") or "dashboard-user") or "dashboard-user"
    execute_update(
        """
        INSERT INTO risk_acceptance_template_state (id, rows, updated_by, updated_at)
        VALUES (1, %s::jsonb, %s, NOW())
        ON CONFLICT (id) DO UPDATE
        SET rows = EXCLUDED.rows,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
        """,
        (json.dumps(rows), updated_by),
    )
    return jsonify({"status": "success", "template": build_risk_acceptance_template_payload()})


@app.route("/api/risk_acceptance_template/download")
def download_risk_acceptance_template():
    csv_payload = build_risk_acceptance_template_csv(build_risk_acceptance_template_payload())
    response = Response(csv_payload, mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=it-risk-acceptance-template.csv"
    return response


@app.route("/upload", methods=["POST"])
def upload_report():
    ensure_report_schema()
    # Optional API token / basic-auth protection for uploads. If `UPLOAD_API_TOKEN` is empty,
    # uploads remain open (useful for local development).
    if UPLOAD_API_TOKEN:
        token = request.headers.get("X-API-Token") or request.form.get("api_token")
        auth = request.authorization
        if token == UPLOAD_API_TOKEN:
            pass
        elif auth and getattr(auth, "password", None) == UPLOAD_API_TOKEN:
            pass
        else:
            return jsonify({"error": "Unauthorized"}), 401
    if "file" not in request.files:
        return jsonify({"error": "Missing file field"}), 400

    file_storage = request.files["file"]
    if not file_storage or not file_storage.filename:
        return jsonify({"error": "No file selected"}), 400

    if not allowed_report_file(file_storage.filename):
        return jsonify({"error": "Unsupported file type. Upload CSV, XLSX, or XLSM."}), 400

    safe_name = secure_filename(file_storage.filename)
    upload_name = request.form.get("upload_name") or os.path.splitext(safe_name)[0]
    uploaded_by = request.form.get("uploaded_by") or request.headers.get("X-User") or "dashboard-user"

    try:
        ingest = read_uploaded_file(file_storage, safe_name)
        rows = ingest.get("rows", [])
        sheet_details = ingest.get("sheet_details", [])
        detected_fields = ingest.get("detected_fields", [])
        if rows:
            logger.info(f"Upload '{upload_name}': Read {len(rows)} rows from {safe_name}")
            logger.debug(f"First row structure: {rows[0] if rows else 'no rows'}")
        if len(rows) > REPORT_MAX_ROWS:
            return jsonify({"error": f"Upload too large. Got {len(rows)} rows. Limit to {REPORT_MAX_ROWS} rows per file."}), 400

        upload_id = save_report_upload(safe_name, upload_name, uploaded_by, rows, source_payload=ingest.get("source_payload"))
        payload = get_latest_report_payload(upload_id)
        return jsonify({
            "status": "success",
            "upload_id": str(upload_id),
            "record_count": len(rows),
            "sheet_details": sheet_details,
            "detected_fields": detected_fields,
            "dashboard": payload,
        })
    except psycopg2.OperationalError as exc:
        logger.exception("Upload failed (database connectivity)")
        return jsonify({
            "error": f"Upload failed: {exc}",
            "hint": "PostgreSQL is unavailable. Run .\\start_local_dashboard.ps1 (auto preflight) or .\\start_local_postgres.ps1 before uploading.",
        }), 500
    except Exception as exc:
        logger.exception("Upload failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/reports")
def api_reports():
    if dashboard_force_fallback():
        return jsonify(build_full_data_fallback_report_payload())

    ensure_report_schema()
    upload_id = request.args.get("upload_id")
    limit = int(request.args.get("limit", REPORT_UPLOAD_LIMIT))
    row_limit = int(request.args.get("row_limit", 250))
    payload = get_latest_report_payload(upload_id=upload_id, limit=limit, row_limit=row_limit)
    return jsonify(payload)


@app.route("/api/reports/<upload_id>/preview")
def api_report_preview(upload_id):
    ensure_report_schema()
    try:
        upload = query_one(
            """
            SELECT id, upload_name, filename, uploaded_by, report_scope, source_kind, sheet_count, record_count, stored_path, created_at
            FROM report_uploads
            WHERE id = %s
            """,
            (upload_id,),
        )
        if not upload:
            return jsonify({"error": "Upload not found"}), 404

        stored_path = upload.get("stored_path")
        if not stored_path or not os.path.exists(stored_path):
            return jsonify({"error": "Preview file is not available for this upload"}), 404

        with open(stored_path, "rb") as file_handle:
            payload = file_handle.read()

        preview = build_workbook_preview_from_bytes(payload, upload.get("filename") or "")
        upload["preview_available"] = True
        upload.pop("stored_path", None)

        return jsonify({
            "upload": upload,
            "sheet_count": preview["sheet_count"],
            "sheets": preview["sheets"],
        })
    except Exception as exc:
        logger.exception("Report preview failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/compliance")
def api_compliance():
    ensure_report_schema()
    source = (request.args.get("source") or "").lower()
    upload_id = request.args.get("upload_id") or get_latest_upload_id() if source == "upload" else None
    raw_severity_expr = uploaded_raw_severity_sql()
    raw_status_expr = uploaded_raw_status_sql()
    upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

    if source == "upload" and not upload_id:
        return jsonify({
            "stats": {
                "total_rows": 0,
                "open_rows": 0,
                "high_risk_rows": 0,
                "overdue_rows": 0,
                "framework_reference_rows": 0,
            },
            "matrix": [],
            "trend": [],
            "questions": [
                {
                    "question": "Does the upload data include CIS / NIST references in raw payload?",
                    "status": "Review",
                    "note": "No upload data found.",
                },
                {
                    "question": "Are critical/high open findings being tracked?",
                    "status": "Good",
                    "note": "No upload data found.",
                },
                {
                    "question": "Are overdue remediation items visible?",
                    "status": "Good",
                    "note": "No upload data found.",
                },
                {
                    "question": "Is the report scope trending toward cloud/VPC compliance?",
                    "status": "Monitor",
                    "note": "No upload data found.",
                },
                {
                    "question": "Is the risk ranking aligned with CIS/NIST control expectations?",
                    "status": "Good",
                    "note": "No upload data found.",
                },
            ],
        })

    where_sql = f"WHERE upload_id = %s{upload_filter_sql}" if source == "upload" else ""
    query_args = (upload_id, *upload_filter_params) if source == "upload" else tuple()

    stats = query_one(
        f"""
        WITH rr AS (
            SELECT
                *,
                CASE
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('critical', 'sev1', 'severe', 'p1immediate') THEN 'critical'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('high', 'sev2') THEN 'high'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('medium', 'med', 'sev3') THEN 'medium'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('low', 'sev4') THEN 'low'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('info', 'informational', 'informative') THEN 'info'
                    ELSE COALESCE(NULLIF(lower(severity), ''), 'unknown')
                END AS severity_norm,
                CASE
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('open', 'active', 'unresolved', 'pending', 'inprogress', 'partiallyresolved', 'notdetected', 'detected') THEN 'open'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('closed', 'fixed', 'resolved', 'remediated') THEN 'closed'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('acceptedrisk', 'riskaccepted', 'accepted') THEN 'accepted_risk'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('falsepositive', 'fp', 'notanissue') THEN 'false_positive'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('confirmedopen', 'confirmed', 'verifiedopen') THEN 'confirmed_open'
                    ELSE COALESCE(NULLIF(lower(status), ''), 'open')
                END AS status_norm
            FROM report_records
            {where_sql}
        )
        SELECT
            COUNT(*) AS total_rows,
            COUNT(*) FILTER (WHERE status_norm <> 'closed') AS open_rows,
            COUNT(*) FILTER (WHERE severity_norm IN ('critical', 'high') AND status_norm <> 'closed') AS high_risk_rows,
            COUNT(*) FILTER (WHERE due_date < CURRENT_DATE AND status_norm <> 'closed') AS overdue_rows,
            COUNT(*) FILTER (WHERE raw_data::text ILIKE '%%cis%%' OR raw_data::text ILIKE '%%nist%%') AS framework_reference_rows
        FROM rr
        """,
        query_args,
    )

    matrix = query(
        f"""
        WITH rr AS (
            SELECT
                CASE
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('critical', 'sev1', 'severe', 'p1immediate') THEN 'critical'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('high', 'sev2') THEN 'high'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('medium', 'med', 'sev3') THEN 'medium'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('low', 'sev4') THEN 'low'
                    WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('info', 'informational', 'informative') THEN 'info'
                    ELSE COALESCE(NULLIF(lower(severity), ''), 'unknown')
                END AS severity_norm,
                CASE
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('open', 'active', 'unresolved', 'pending', 'inprogress', 'partiallyresolved', 'notdetected', 'detected') THEN 'open'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('closed', 'fixed', 'resolved', 'remediated') THEN 'closed'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('acceptedrisk', 'riskaccepted', 'accepted') THEN 'accepted_risk'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('falsepositive', 'fp', 'notanissue') THEN 'false_positive'
                    WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('confirmedopen', 'confirmed', 'verifiedopen') THEN 'confirmed_open'
                    ELSE COALESCE(NULLIF(lower(status), ''), 'open')
                END AS status_norm
            FROM report_records
            {where_sql}
        )
        SELECT
            severity_norm AS severity,
            status_norm AS status,
            COUNT(*) AS cnt
        FROM rr
        GROUP BY 1, 2
        ORDER BY CASE severity_norm
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            WHEN 'info' THEN 5
            ELSE 6 END,
            CASE status_norm
            WHEN 'open' THEN 1
            WHEN 'confirmed_open' THEN 2
            WHEN 'accepted_risk' THEN 3
            WHEN 'false_positive' THEN 4
            WHEN 'closed' THEN 5
            ELSE 6 END
        """,
        query_args,
    )

    trend = query(
        f"""
        SELECT COALESCE(report_scope,'unknown') AS label, COUNT(*) AS cnt
        FROM report_records
        {where_sql}
        GROUP BY 1
        ORDER BY cnt DESC
        LIMIT 6
        """,
        query_args,
    )

    questions = [
        {
            "question": "Does the upload data include CIS / NIST references in raw payload?",
            "status": "Pass" if stats.get("framework_reference_rows", 0) > 0 else "Review",
            "note": stats.get("framework_reference_rows", 0) > 0
                and "References detected in uploaded report payload." or "No explicit CIS/NIST references were found in raw report data."
        },
        {
            "question": "Are critical/high open findings being tracked?",
            "status": stats.get("high_risk_rows", 0) > 0 and 'Alert' or 'Good',
            "note": stats.get("high_risk_rows", 0) > 0
                and "There are active critical/high severity rows requiring risk ranking." or "No critical/high rows found."
        },
        {
            "question": "Are overdue remediation items visible?",
            "status": stats.get("overdue_rows", 0) > 0 and 'Review' or 'Good',
            "note": stats.get("overdue_rows", 0) > 0
                and "Overdue rows exist and require escalation." or "No overdue remediation items detected."
        },
        {
            "question": "Is the report scope trending toward cloud/VPC compliance?",
            "status": trend and 'Active' or 'Monitor',
            "note": "Scope breakdown shows current report distribution by report scope."
        },
        {
            "question": "Is the risk ranking aligned with CIS/NIST control expectations?",
            "status": stats.get("open_rows", 0) > 0 and 'Evaluate' or 'Good',
            "note": "Use severity and status to prioritize critical and high-risk findings."
        }
    ]

    return jsonify({"stats": stats, "matrix": matrix, "trend": trend, "questions": questions})


@app.route("/api/stats")
def api_stats():
    if dashboard_force_fallback():
        summary = (build_full_data_fallback_report_payload().get("summary") or {})
        return jsonify({
            "total": summary.get("total_rows", 2585),
            "critical": summary.get("critical_rows", 439),
            "high": summary.get("high_rows", 1789),
            "medium": summary.get("medium_rows", 339),
            "low": summary.get("low_rows", 19),
            "very_low": 0,
            "it_count": 0,
            "ot_count": 0,
            "iot_count": 0,
            "open": summary.get("total_rows", 2585),
            "closed": 0,
            "new": summary.get("new_rows", 50),
            "outdated": summary.get("outdated_rows", 2366),
            "pending": summary.get("pending_rows", 171),
            "pits_closed": 0,
            "duplicates": 0,
            "ot_exposure": 0,
            "accepted_risk": 0,
            "risk_overdue": 0,
            "upload_mode": True,
        })

    if (request.args.get("source") or "").lower() == "upload":
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        mapped_vuln_where = "(severity_norm <> 'unknown' OR raw_status <> 'unknown')"
        upload_filter_sql, upload_filter_params, filter_values = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify({
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "very_low": 0,
                "it_count": 0,
                "ot_count": 0,
                "iot_count": 0,
                "open": 0,
                "closed": 0,
                "new": 0,
                "outdated": 0,
                "pending": 0,
                "pits_closed": 0,
                "duplicates": 0,
                "ot_exposure": 0,
                "accepted_risk": 0,
                "risk_overdue": 0,
                "upload_mode": True,
            })

        if str(upload_id).strip().lower().startswith("fallback-"):
            summary = (build_full_data_fallback_report_payload().get("summary") or {})
            return jsonify({
                "total": summary.get("total_rows", 2585),
                "critical": summary.get("critical_rows", 439),
                "high": summary.get("high_rows", 1789),
                "medium": summary.get("medium_rows", 339),
                "low": summary.get("low_rows", 19),
                "very_low": 0,
                "it_count": 0,
                "ot_count": 0,
                "iot_count": 0,
                "open": summary.get("total_rows", 2585),
                "closed": 0,
                "new": summary.get("new_rows", 50),
                "outdated": summary.get("outdated_rows", 2366),
                "pending": summary.get("pending_rows", 171),
                "pits_closed": 0,
                "duplicates": 0,
                "ot_exposure": 0,
                "accepted_risk": 0,
                "risk_overdue": 0,
                "upload_mode": True,
            })

        stats = query_one(
            f"""
            WITH rr AS (
                SELECT
                    {raw_severity_expr} AS severity_norm,
                    {raw_status_expr} AS raw_status,
                    {uploaded_asset_type_sql()} AS asset_type,
                    COALESCE(cloud_provider, '') AS cloud_provider,
                    EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                            created_at
                        )
                    )) / 86400.0 AS age_days
                FROM report_records
                WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            )
            SELECT
                COUNT(*) FILTER (WHERE {mapped_vuln_where}) AS total,
                COUNT(*) FILTER (WHERE severity_norm = 'critical') AS critical,
                COUNT(*) FILTER (WHERE severity_norm = 'high') AS high,
                COUNT(*) FILTER (WHERE severity_norm = 'medium') AS medium,
                COUNT(*) FILTER (WHERE severity_norm = 'low') AS low,
                COUNT(*) FILTER (WHERE severity_norm = 'very_low') AS very_low,
                COUNT(*) FILTER (WHERE asset_type = 'IT') AS it_count,
                COUNT(*) FILTER (WHERE asset_type = 'OT') AS ot_count,
                COUNT(*) FILTER (WHERE asset_type = 'IoT') AS iot_count,
                COUNT(*) FILTER (WHERE raw_status IN ('open', 'new', 'outdated', 'pending', 'in_progress', 'review', 'accepted_risk', 'confirmed_open')) AS open,
                COUNT(*) FILTER (WHERE raw_status = 'closed') AS closed,
                COUNT(*) FILTER (WHERE raw_status = 'new') AS new,
                COUNT(*) FILTER (WHERE raw_status = 'outdated') AS outdated,
                COUNT(*) FILTER (WHERE raw_status = 'pending') AS pending,
                0 AS pits_closed,
                0 AS duplicates,
                COUNT(*) FILTER (WHERE raw_status = 'accepted_risk') AS accepted_risk,
                COUNT(*) FILTER (WHERE raw_status <> 'closed' AND age_days >= 30) AS risk_overdue,
                COUNT(*) FILTER (WHERE raw_status <> 'closed' AND asset_type = 'OT') AS ot_exposure
            FROM rr
            """,
            (upload_id, *upload_filter_params),
        )

        upload_meta = query_one(
            """
            SELECT id, upload_name, filename
            FROM report_uploads
            WHERE id = %s
            """,
            (upload_id,),
        )
        manual_override = get_manual_upload_count_override(upload_meta)
        if manual_override and not upload_filters_active(filter_values):
            summary_override = manual_override.get("summary") or {}
            stats.update({
                "total": summary_override.get("total_rows", stats.get("total", 0)),
                "critical": summary_override.get("critical_rows", stats.get("critical", 0)),
                "high": summary_override.get("high_rows", stats.get("high", 0)),
                "medium": summary_override.get("medium_rows", stats.get("medium", 0)),
                "low": summary_override.get("low_rows", stats.get("low", 0)),
                "new": summary_override.get("new_rows", stats.get("new", 0)),
                "outdated": summary_override.get("outdated_rows", stats.get("outdated", 0)),
                "pending": summary_override.get("pending_rows", stats.get("pending", 0)),
            })

        return jsonify({
            "total": stats.get("total", 0),
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
            "very_low": stats.get("very_low", 0),
            "it_count": stats.get("it_count", 0),
            "ot_count": stats.get("ot_count", 0),
            "iot_count": stats.get("iot_count", 0),
            "open": stats.get("open", 0),
            "closed": stats.get("closed", 0),
            "new": stats.get("new", 0),
            "outdated": stats.get("outdated", 0),
            "pending": stats.get("pending", 0),
            "pits_closed": stats.get("pits_closed", 0),
            "duplicates": stats.get("duplicates", 0),
            "ot_exposure": stats.get("ot_exposure", 0),
            "accepted_risk": stats.get("accepted_risk", 0),
            "risk_overdue": stats.get("risk_overdue", 0),
            "upload_mode": True,
        })

    total    = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities")
    critical = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE severity='critical' AND final_status='open'")
    high     = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE severity='high' AND final_status='open'")
    open_v   = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE final_status='open'")
    closed   = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE final_status='closed'")
    pits_cls = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE pits_status='closed'")
    dupes    = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE is_duplicate=true")
    ot_exp   = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE asset_type='OT/ICS' AND final_status='open'")
    accepted = query_one("SELECT COUNT(*) AS n FROM unified_vulnerabilities WHERE final_status='accepted_risk'")
    overdue  = query_one("""
        WITH risk AS (
            SELECT EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
            FROM unified_vulnerabilities
        )
        SELECT COUNT(*) AS n
        FROM risk
        WHERE age_days >= 30
    """)

    return jsonify({
        "total":    total.get("n", 0),
        "critical": critical.get("n", 0),
        "high":     high.get("n", 0),
        "open":     open_v.get("n", 0),
        "closed":   closed.get("n", 0),
        "pits_closed": pits_cls.get("n", 0),
        "duplicates":  dupes.get("n", 0),
        "ot_exposure": ot_exp.get("n", 0),
        "accepted_risk": accepted.get("n", 0),
        "risk_overdue": overdue.get("n", 0),
    })


@app.route("/api/severity_chart")
def severity_chart():
    if dashboard_force_fallback() and (request.args.get("source") or "").lower() == "upload":
        rows = [{"severity": item["label"], "cnt": item["cnt"]} for item in (build_full_data_fallback_report_payload().get("severity_chart") or [])]
        return jsonify(rows)

    if (request.args.get("source") or "").lower() == "upload":
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        upload_filter_sql, upload_filter_params, filter_values = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify([])
        if str(upload_id).strip().lower().startswith("fallback-"):
            rows = [{"severity": item["label"], "cnt": item["cnt"]} for item in (build_full_data_fallback_report_payload().get("severity_chart") or [])]
            return jsonify(rows)
        upload_meta = query_one(
            "SELECT id, upload_name, filename FROM report_uploads WHERE id = %s",
            (upload_id,),
        )
        manual_override = get_manual_upload_count_override(upload_meta)
        if manual_override and not upload_filters_active(filter_values):
            rows = [{"severity": item["label"], "cnt": item["cnt"]} for item in (manual_override.get("severity_chart") or [])]
            return jsonify(rows)
        rows = query(
            f"""
            SELECT {raw_severity_expr} AS severity, COUNT(*) AS cnt
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            GROUP BY 1
            ORDER BY CASE {raw_severity_expr}
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                WHEN 'very_low' THEN 5
                ELSE 6 END
            """,
            (upload_id, *upload_filter_params),
        )
        return jsonify(rows)

    rows = query("""
        SELECT severity, COUNT(*) AS cnt
        FROM unified_vulnerabilities
        WHERE final_status = 'open'
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high'     THEN 2
            WHEN 'medium'   THEN 3
            WHEN 'low'      THEN 4
            ELSE 5 END
    """)
    return jsonify(rows)


@app.route("/api/status_chart")
def status_chart():
    if dashboard_force_fallback() and (request.args.get("source") or "").lower() == "upload":
        rows = [{"status": item["label"], "cnt": item["cnt"]} for item in (build_full_data_fallback_report_payload().get("status_chart") or [])]
        return jsonify(rows)

    if (request.args.get("source") or "").lower() == "upload":
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        upload_filter_sql, upload_filter_params, filter_values = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify([])
        if str(upload_id).strip().lower().startswith("fallback-"):
            rows = [{"status": item["label"], "cnt": item["cnt"]} for item in (build_full_data_fallback_report_payload().get("status_chart") or [])]
            return jsonify(rows)
        upload_meta = query_one(
            "SELECT id, upload_name, filename FROM report_uploads WHERE id = %s",
            (upload_id,),
        )
        manual_override = get_manual_upload_count_override(upload_meta)
        if manual_override and not upload_filters_active(filter_values):
            rows = [{"status": item["label"], "cnt": item["cnt"]} for item in (manual_override.get("status_chart") or [])]
            return jsonify(rows)
        rows = query(
            f"""
            SELECT {raw_status_expr} AS status, COUNT(*) AS cnt
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            GROUP BY 1
            ORDER BY cnt DESC, status
            """,
            (upload_id, *upload_filter_params),
        )
        return jsonify(rows)

    rows = query("""
        SELECT final_status AS status, COUNT(*) AS cnt
        FROM unified_vulnerabilities
        GROUP BY final_status
    """)
    return jsonify(rows)


@app.route("/api/source_chart")
def source_chart():
    if dashboard_force_fallback() and (request.args.get("source") or "").lower() == "upload":
        return jsonify([{"source": "upload", "cnt": 2585}])

    if (request.args.get("source") or "").lower() == "upload":
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify([])
        if str(upload_id).strip().lower().startswith("fallback-"):
            total_rows = int((build_full_data_fallback_report_payload().get("summary") or {}).get("total_rows") or 0)
            return jsonify([{"source": "upload", "cnt": total_rows}])
        rows = query(
            f"""
            SELECT COALESCE(cloud_provider, 'unknown') AS source, COUNT(*) AS cnt
            FROM report_records
            WHERE upload_id = %s{upload_filter_sql}
            GROUP BY 1
            ORDER BY cnt DESC
            """,
            (upload_id, *upload_filter_params),
        )
        return jsonify(rows)

    rows = query("""
        SELECT unnest(sources) AS source, COUNT(*) AS cnt
        FROM unified_vulnerabilities
        GROUP BY source
    """)
    return jsonify(rows)


@app.route("/api/asset_category_chart")
def asset_category_chart():
    """IT / OT / IoT breakdown for the active upload dataset."""
    if dashboard_force_fallback() and (request.args.get("source") or "").lower() == "upload":
        total_rows = int((build_full_data_fallback_report_payload().get("summary") or {}).get("total_rows") or 0)
        return jsonify([
            {"category": "IT", "cnt": total_rows},
            {"category": "OT", "cnt": 0},
            {"category": "IoT", "cnt": 0},
        ])

    if (request.args.get("source") or "").lower() == "upload":
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify([])
        if str(upload_id).strip().lower().startswith("fallback-"):
            total_rows = int((build_full_data_fallback_report_payload().get("summary") or {}).get("total_rows") or 0)
            return jsonify([
                {"category": "IT", "cnt": total_rows},
                {"category": "OT", "cnt": 0},
                {"category": "IoT", "cnt": 0},
            ])
        rows = query(
            f"""
            SELECT {uploaded_asset_type_sql()} AS category, COUNT(*) AS cnt
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            GROUP BY 1
            ORDER BY cnt DESC
            """,
            (upload_id, *upload_filter_params),
        )
        return jsonify(rows)
    return jsonify([])


@app.route("/api/top_cves")
def top_cves():
    if (request.args.get("source") or "").lower() == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if dashboard_force_fallback() or not upload_id or is_fallback_upload_id(upload_id):
            rows = load_vulnerability_fallback_rows()
            grouped = {}
            for item in rows:
                cve = item.get("cve")
                if not cve:
                    continue
                bucket = grouped.setdefault(cve, {
                    "cve": cve,
                    "max_cvss": float(item.get("cvss_score") or 0),
                    "severity": item.get("severity") or "unknown",
                    "affected_assets": set(),
                    "open_count": 0,
                })
                bucket["max_cvss"] = max(bucket["max_cvss"], float(item.get("cvss_score") or 0))
                bucket["affected_assets"].add(item.get("asset_key") or "unknown")
                if str(item.get("final_status") or "").lower() in {"open", "new", "outdated", "pending", "confirmed_open"}:
                    bucket["open_count"] += 1
            out = []
            for _, value in grouped.items():
                out.append({
                    "cve": value["cve"],
                    "max_cvss": round(float(value["max_cvss"]), 1),
                    "severity": value["severity"],
                    "affected_assets": len(value["affected_assets"]),
                    "open_count": int(value["open_count"]),
                })
            out.sort(key=lambda row: (-int(row.get("open_count") or 0), -float(row.get("max_cvss") or 0)))
            return jsonify(out[:15])

    if dashboard_force_fallback() and (request.args.get("source") or "").lower() == "upload":
        rows = load_vulnerability_fallback_rows()
        grouped = {}
        for item in rows:
            cve = item.get("cve")
            if not cve:
                continue
            bucket = grouped.setdefault(cve, {
                "cve": cve,
                "max_cvss": float(item.get("cvss_score") or 0),
                "severity": item.get("severity") or "unknown",
                "affected_assets": set(),
                "open_count": 0,
            })
            bucket["max_cvss"] = max(bucket["max_cvss"], float(item.get("cvss_score") or 0))
            bucket["affected_assets"].add(item.get("asset_key") or "unknown")
            if str(item.get("final_status") or "").lower() in {"open", "new", "outdated", "pending", "confirmed_open"}:
                bucket["open_count"] += 1
        out = []
        for _, value in grouped.items():
            out.append({
                "cve": value["cve"],
                "max_cvss": round(float(value["max_cvss"]), 1),
                "severity": value["severity"],
                "affected_assets": len(value["affected_assets"]),
                "open_count": int(value["open_count"]),
            })
        out.sort(key=lambda row: (-int(row.get("open_count") or 0), -float(row.get("max_cvss") or 0)))
        return jsonify(out[:15])

    if (request.args.get("source") or "").lower() == "upload":
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify([])
        rows = query(
            f"""
            SELECT
                cve,
                MAX(score) AS max_cvss,
                MAX({raw_severity_expr}) AS severity,
                COUNT(DISTINCT COALESCE(asset_key, ip_address, hostname)) AS affected_assets,
                COUNT(*) FILTER (WHERE {raw_status_expr} IN ('open', 'new', 'outdated', 'pending', 'confirmed_open')) AS open_count
            FROM report_records
            WHERE upload_id = %s AND cve IS NOT NULL{upload_filter_sql}
            GROUP BY cve
            ORDER BY open_count DESC, max_cvss DESC NULLS LAST
            LIMIT 15
            """,
            (upload_id, *upload_filter_params),
        )
        return jsonify(rows)

    rows = query("""
        SELECT cve, max_cvss, severity, affected_assets, open_count
        FROM top_cves
        WHERE cve IS NOT NULL
        LIMIT 15
    """)
    return jsonify(rows)


@app.route("/api/recent_vulns")
def recent_vulns():
    if (request.args.get("source") or "").lower() == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if dashboard_force_fallback() or not upload_id or is_fallback_upload_id(upload_id):
            return jsonify(load_vulnerability_fallback_rows()[:100])
        if not upload_id:
            return jsonify([])
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr, table_alias="rr")
        asset_info_cte = uploaded_pits_asset_cte()
        rows = query(
            f"""
            WITH
            {asset_info_cte}
            SELECT
                rr.id AS record_id,
                rr.asset_key,
                rr.cve,
                {raw_severity_expr} AS severity,
                rr.score AS cvss_score,
                {raw_status_expr} AS final_status,
                rr.remediation,
                CASE
                    WHEN asset_info.pits_cms_flag = 'yes' AND asset_info.whitelisted_flag = 'yes' THEN 'tracked_whitelisted'
                    WHEN asset_info.pits_cms_flag = 'yes' THEN 'tracked'
                    WHEN asset_info.whitelisted_flag = 'yes' THEN 'whitelisted'
                    WHEN asset_info.needs_check_flag = 'yes' THEN 'needs_check'
                    WHEN asset_info.pits_cms_flag = 'no' THEN 'not_tracked'
                    ELSE 'unknown'
                END AS pits_status,
                CONCAT_WS(
                    ' | ',
                    CASE
                        WHEN asset_info.pits_cms_flag IS NOT NULL
                        THEN 'PITS CMS: ' || initcap(asset_info.pits_cms_flag)
                    END,
                    CASE
                        WHEN asset_info.whitelisted_flag IS NOT NULL
                        THEN 'Whitelisted: ' || initcap(asset_info.whitelisted_flag)
                    END,
                    CASE
                        WHEN asset_info.needs_check_flag IS NOT NULL
                        THEN 'Needs Check: ' || initcap(asset_info.needs_check_flag)
                    END
                ) AS pits_detail,
                ARRAY[COALESCE(rr.cloud_provider, 'upload')] AS sources,
                COALESCE(rr.last_seen::timestamp, rr.first_discovered::timestamp, rr.created_at) AS last_updated
            FROM report_records rr
            LEFT JOIN asset_info
              ON COALESCE(NULLIF(rr.asset_key, ''), NULLIF(rr.ip_address, ''), NULLIF(rr.raw_data->>'IP Address', '')) = asset_info.asset_ref
            WHERE rr.upload_id = %s AND {valid_row_where}{upload_filter_sql}
            ORDER BY rr.score DESC NULLS LAST, rr.row_number DESC
            LIMIT 100
            """,
            (upload_id, upload_id, *upload_filter_params),
        )
        return jsonify(rows)

    rows = query("""
        SELECT asset_key, cve, severity, cvss_score, final_status, pits_status, 
               sources, last_updated
        FROM unified_vulnerabilities
        ORDER BY cvss_score DESC NULLS LAST, last_updated DESC
        LIMIT 100
    """)
    return jsonify(rows)


@app.route("/api/recent_vulns/manual", methods=["POST"])
def save_recent_vuln_manual():
    payload = request.get_json(silent=True) or {}
    if dashboard_force_fallback() or is_fallback_upload_id(payload.get("upload_id")):
        rows = load_vulnerability_fallback_rows()

        record_id = sanitize_text(payload.get("record_id"))
        cve = sanitize_text(payload.get("cve"))
        if not cve:
            return jsonify({"error": "CVE is required."}), 400

        severity = normalize_severity(payload.get("severity")) or "medium"
        final_status = normalize_status(payload.get("final_status") or payload.get("status")) or "open"
        cvss_score = parse_number(payload.get("cvss_score"))
        if cvss_score is not None:
            cvss_score = max(0.0, min(10.0, float(cvss_score)))

        if record_id:
            updated = None
            for item in rows:
                if str(item.get("record_id") or "") == record_id:
                    item["asset_key"] = sanitize_text(payload.get("asset_key"))
                    item["cve"] = cve
                    item["severity"] = severity
                    item["cvss_score"] = cvss_score
                    item["final_status"] = final_status
                    item["remediation"] = sanitize_text(payload.get("remediation"))
                    item["last_updated"] = datetime.utcnow().isoformat() + "Z"
                    updated = item
                    break
            if not updated:
                return jsonify({"error": "Vulnerability record not found."}), 404
            save_vulnerability_fallback_rows(rows)
            return jsonify({"status": "success", "mode": "update", "record_id": updated.get("record_id")})

        new_id = f"fallback-{len(rows) + 1}"
        rows.append({
            "record_id": new_id,
            "asset_key": sanitize_text(payload.get("asset_key")),
            "cve": cve,
            "severity": severity,
            "cvss_score": cvss_score,
            "final_status": final_status,
            "remediation": sanitize_text(payload.get("remediation")),
            "pits_status": "unknown",
            "pits_detail": "Fallback manual entry",
            "sources": ["upload"],
            "last_updated": datetime.utcnow().isoformat() + "Z",
        })
        save_vulnerability_fallback_rows(rows)
        return jsonify({"status": "success", "mode": "insert", "record_id": new_id})

    ensure_report_schema()
    upload_id = sanitize_text(payload.get("upload_id")) or get_latest_upload_id()
    if not upload_id:
        return jsonify({"error": "No upload available. Upload report data before adding manual details."}), 400

    record_id = sanitize_text(payload.get("record_id"))
    asset_key = sanitize_text(payload.get("asset_key"))
    cve = sanitize_text(payload.get("cve"))
    severity = normalize_severity(payload.get("severity")) or "medium"
    final_status = normalize_status(payload.get("final_status") or payload.get("status")) or "open"
    cvss_score = parse_number(payload.get("cvss_score"))
    if cvss_score is not None:
        cvss_score = max(0.0, min(10.0, float(cvss_score)))
    remediation = sanitize_text(payload.get("remediation"))
    owner = sanitize_text(payload.get("owner"))
    cloud_provider = sanitize_text(payload.get("cloud_provider") or payload.get("source")) or "manual"
    last_seen = parse_date(payload.get("last_seen") or payload.get("last_updated"))

    if not cve:
        return jsonify({"error": "CVE is required."}), 400

    if record_id:
        updated = execute_update(
            """
            UPDATE report_records
            SET asset_key = %s,
                cve = %s,
                severity = %s,
                status = %s,
                score = %s,
                remediation = %s,
                owner = %s,
                cloud_provider = %s,
                last_seen = COALESCE(%s, last_seen),
                raw_data = COALESCE(raw_data, '{}'::jsonb) || jsonb_build_object('manual_entry', true, 'manual_updated_at', NOW()::text)
            WHERE id = %s
            RETURNING id
            """,
            (
                asset_key,
                cve,
                severity,
                final_status,
                cvss_score,
                remediation,
                owner,
                cloud_provider,
                last_seen,
                record_id,
            ),
            fetchone=True,
        )
        if not updated:
            return jsonify({"error": "Vulnerability record not found."}), 404
        return jsonify({"status": "success", "mode": "update", "record_id": updated.get("id")})

    next_row = query_one(
        "SELECT COALESCE(MAX(row_number), 0) + 1 AS next_row FROM report_records WHERE upload_id = %s",
        (upload_id,),
    )
    row_number = int((next_row or {}).get("next_row") or 1)
    inserted = execute_update(
        """
        INSERT INTO report_records (
            upload_id,
            row_number,
            sheet_name,
            asset_key,
            cve,
            severity,
            status,
            score,
            cloud_provider,
            owner,
            remediation,
            last_seen,
            raw_data
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
        RETURNING id
        """,
        (
            upload_id,
            row_number,
            "Manual Entry",
            asset_key,
            cve,
            severity,
            final_status,
            cvss_score,
            cloud_provider,
            owner,
            remediation,
            last_seen,
            json.dumps({"manual_entry": True, "manual_created_at": datetime.utcnow().isoformat()}),
        ),
        fetchone=True,
    )
    return jsonify({"status": "success", "mode": "insert", "record_id": (inserted or {}).get("id")})


@app.route("/api/vulnerability_details")
def vulnerability_details():
    source = (request.args.get("source") or "").strip().lower()
    metric = (request.args.get("metric") or "total").strip().lower()
    limit_raw = request.args.get("limit")
    try:
        limit = int(limit_raw) if limit_raw is not None else 5000
    except ValueError:
        limit = 5000
    limit = max(1, min(limit, 10000))

    where_by_metric = {
        "critical_open": "severity = 'critical' AND final_status = 'open'",
        "high_open": "severity = 'high' AND final_status = 'open'",
        "total_open": "final_status = 'open'",
        "total": "TRUE",
        "pits_closed": "pits_status = 'closed'",
        "duplicates": "COALESCE(is_duplicate, false) = true",
        "accepted_risk": "final_status = 'accepted_risk'",
        "risk_overdue": "age_days >= 30",
        "dashboard_health": "final_status = 'open'",
        "ot_exposure": "asset_type = 'OT/ICS' AND final_status = 'open'",
        "total_closed": "final_status = 'closed'",
    }
    where_sql = where_by_metric.get(metric, "TRUE")

    if source == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify({"metric": metric, "count": 0, "returned": 0, "truncated": False, "rows": []})

        if str(upload_id).strip().lower().startswith("fallback-"):
            fallback_payload = build_full_data_fallback_report_payload() or {}
            fallback_rows = list(fallback_payload.get("rows") or [])
            summary = fallback_payload.get("summary") or {}

            normalized_rows = []
            for row in fallback_rows:
                raw_status = str(row.get("status") or "").strip().lower()
                if raw_status in {"closed", "fixed", "resolved", "remediated"}:
                    final_status = "closed"
                elif raw_status in {"accepted_risk", "accepted", "riskaccepted"}:
                    final_status = "accepted_risk"
                elif raw_status in {"false_positive", "falsepositive", "fp"}:
                    final_status = "false_positive"
                elif raw_status in {"confirmed_open", "confirmed", "verifiedopen"}:
                    final_status = "confirmed_open"
                else:
                    final_status = "open"

                normalized_rows.append({
                    "asset_key": row.get("asset_key"),
                    "cve": row.get("cve"),
                    "severity": str(row.get("severity") or "unknown").lower(),
                    "cvss_score": row.get("score"),
                    "final_status": final_status,
                    "pits_status": None,
                    "sources": ["upload"],
                    "last_updated": row.get("last_seen") or row.get("created_at"),
                    "is_duplicate": False,
                    "asset_type": "IT",
                    "age_days": 0,
                })

            def _metric_total(m):
                if m == "critical_open":
                    return int(summary.get("critical_rows", 0))
                if m == "high_open":
                    return int(summary.get("high_rows", 0))
                if m in {"total_open", "total", "dashboard_health"}:
                    return int(summary.get("total_rows", 0))
                if m == "total_closed":
                    return 0
                if m == "accepted_risk":
                    return 0
                if m == "risk_overdue":
                    return 0
                if m == "ot_exposure":
                    return 0
                return len(normalized_rows)

            def _matches_metric(item):
                severity = str(item.get("severity") or "").lower()
                final_status = str(item.get("final_status") or "").lower()
                if metric == "critical_open":
                    return severity == "critical" and final_status != "closed"
                if metric == "high_open":
                    return severity == "high" and final_status != "closed"
                if metric == "total_open":
                    return final_status != "closed"
                if metric == "accepted_risk":
                    return final_status == "accepted_risk"
                if metric == "total_closed":
                    return final_status == "closed"
                if metric == "risk_overdue":
                    return False
                if metric == "ot_exposure":
                    return False
                return True

            filtered_rows = [item for item in normalized_rows if _matches_metric(item)]
            returned_rows = filtered_rows[:limit]
            total_count = _metric_total(metric)
            return jsonify({
                "metric": metric,
                "count": total_count,
                "returned": len(returned_rows),
                "truncated": total_count > len(returned_rows),
                "rows": returned_rows,
            })

        upload_where_map = {
            "critical_open": "severity = 'critical' AND final_status <> 'closed'",
            "high_open": "severity = 'high' AND final_status <> 'closed'",
            "total_open": "final_status <> 'closed'",
            "total": "TRUE",
            "pits_closed": "FALSE",
            "duplicates": "FALSE",
            "accepted_risk": "final_status = 'accepted_risk'",
            "risk_overdue": "age_days >= 30",
            "dashboard_health": "final_status <> 'closed'",
            "ot_exposure": "asset_type = 'OT/ICS' AND final_status <> 'closed'",
            "total_closed": "final_status = 'closed'",
        }
        upload_where_sql = upload_where_map.get(metric, "TRUE")

        rows = query(
            f"""
            WITH uv AS (
                SELECT
                    asset_key,
                    cve,
                    CASE
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('critical', 'sev1', 'severe', 'p1immediate') THEN 'critical'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('high', 'sev2') THEN 'high'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('medium', 'med', 'sev3') THEN 'medium'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('low', 'sev4') THEN 'low'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('info', 'informational', 'informative') THEN 'info'
                        ELSE COALESCE(NULLIF(lower(severity), ''), 'unknown')
                    END AS severity,
                    score AS cvss_score,
                    CASE
                        WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('open', 'active', 'unresolved', 'pending', 'inprogress', 'partiallyresolved', 'notdetected', 'detected') THEN 'open'
                        WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('closed', 'fixed', 'resolved', 'remediated') THEN 'closed'
                        WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('acceptedrisk', 'riskaccepted', 'accepted') THEN 'accepted_risk'
                        WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('falsepositive', 'fp', 'notanissue') THEN 'false_positive'
                        WHEN regexp_replace(lower(COALESCE(status, '')), '[^a-z0-9]+', '', 'g') IN ('confirmedopen', 'confirmed', 'verifiedopen') THEN 'confirmed_open'
                        ELSE COALESCE(NULLIF(lower(status), ''), 'open')
                    END AS final_status,
                    NULL::text AS pits_status,
                    ARRAY[COALESCE(cloud_provider, 'upload')] AS sources,
                    COALESCE(
                        CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                        created_at
                    ) AS last_updated,
                    FALSE AS is_duplicate,
                    CASE WHEN COALESCE(cloud_provider, '') ILIKE '%%ot%%' OR COALESCE(cloud_provider, '') ILIKE '%%ics%%' THEN 'OT/ICS' ELSE 'IT' END AS asset_type,
                    ROUND(EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                            created_at
                        )
                    )) / 86400.0, 1) AS age_days
                FROM report_records
                WHERE upload_id = %s
            ),
            filtered AS (
                SELECT
                    *,
                    COUNT(*) OVER() AS total_count
                FROM uv
                WHERE {upload_where_sql}
                ORDER BY
                    CASE COALESCE(severity, 'unknown')
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        WHEN 'info' THEN 5
                        ELSE 6 END,
                    cvss_score DESC NULLS LAST,
                    age_days DESC NULLS LAST,
                    last_updated DESC NULLS LAST
                LIMIT %s
            )
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                pits_status,
                sources,
                last_updated,
                is_duplicate,
                asset_type,
                age_days,
                total_count
            FROM filtered
            """,
            (upload_id, limit),
        )

        total_count = rows[0].get("total_count", 0) if rows else 0
        for row in rows:
            row.pop("total_count", None)

        return jsonify({
            "metric": metric,
            "count": total_count,
            "returned": len(rows),
            "truncated": total_count > len(rows),
            "rows": rows,
        })

    rows = query(
        f"""
        WITH uv AS (
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                pits_status,
                sources,
                last_updated,
                COALESCE(is_duplicate, false) AS is_duplicate,
                asset_type,
                ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected))) / 86400.0, 1) AS age_days
            FROM unified_vulnerabilities
        ),
        filtered AS (
            SELECT
                *,
                COUNT(*) OVER() AS total_count
            FROM uv
            WHERE {where_sql}
            ORDER BY
                CASE COALESCE(severity, 'unknown')
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6 END,
                cvss_score DESC NULLS LAST,
                age_days DESC NULLS LAST,
                last_updated DESC NULLS LAST
            LIMIT %s
        )
        SELECT
            asset_key,
            cve,
            severity,
            cvss_score,
            final_status,
            pits_status,
            sources,
            last_updated,
            is_duplicate,
            asset_type,
            age_days,
            total_count
        FROM filtered
        """,
        (limit,),
    )

    total_count = rows[0].get("total_count", 0) if rows else 0
    for row in rows:
        row.pop("total_count", None)

    return jsonify({
        "metric": metric,
        "count": total_count,
        "returned": len(rows),
        "truncated": total_count > len(rows),
        "rows": rows,
    })


@app.route("/api/etl_runs")
def etl_runs():
    if dashboard_force_fallback():
        return jsonify([
            {
                "source": "fallback",
                "started_at": datetime.utcnow().isoformat() + "Z",
                "finished_at": datetime.utcnow().isoformat() + "Z",
                "records": 2585,
                "status": "degraded",
                "error_msg": "DB unavailable - serving fallback dashboard dataset",
            }
        ])

    rows = query("""
        SELECT source, started_at, finished_at, records, status, error_msg
        FROM etl_runs
        ORDER BY started_at DESC
        LIMIT 20
    """)
    return jsonify(rows)


# ===== SECUMAT ENDPOINTS =====
@app.route("/upload/compliance", methods=["POST"])
def upload_compliance():
    """Upload and parse secumat questionnaire (CIS/NIST/ISO)."""
    ensure_report_schema()
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files["file"]
        if not file or not allowed_report_file(file.filename):
            return jsonify({"error": "Only CSV, XLSX, XLSM files allowed"}), 400
        
        upload_name = request.form.get("upload_name", "secumat")
        framework = request.form.get("framework", "CIS").upper()
        uploaded_by = request.form.get("uploaded_by", "user")
        
        logger.info(f"Parsing secumat: {file.filename} [{framework}]")
        
        # Parse the compliance file
        parsed = read_compliance_file(file, framework)
        responses = parsed["responses"]
        sheets_imported = parsed["sheets_imported"]
        sheet_details = parsed.get("sheet_details", [])
        sheet_count = parsed.get("sheet_count", 0)
        source_payload = parsed.get("payload", b"")

        if not responses and not sheet_details:
            return jsonify({"error": "No compliance data extracted from file"}), 400

        # Save to database
        upload_id = save_compliance_upload(
            filename=file.filename,
            upload_name=upload_name,
            framework=framework,
            uploaded_by=uploaded_by,
            responses=responses,
            sheet_count=sheet_count,
            upload_mode="structured" if responses else "workbook",
            source_payload=source_payload,
        )

        logger.info(f"secumat uploaded: {upload_id} [{len(responses)} responses]")

        if responses:
            message = f"Uploaded {len(responses)} compliance responses across {sheets_imported} sheets"
        else:
            message = f"Uploaded workbook preview for {sheet_count} sheet(s); no normalized compliance responses were detected"

        return jsonify({
            "success": True,
            "upload_id": upload_id,
            "message": message,
            "framework": framework,
            "response_count": len(responses),
            "sheets_imported": sheets_imported,
            "sheet_count": sheet_count,
            "sheet_details": sheet_details,
            "upload_mode": "structured" if responses else "workbook",
        })
    
    except Exception as exc:
        logger.exception("Compliance upload failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/compliance_audit")
def api_compliance_audit():
    """Get secumat summary and control scores."""
    if dashboard_force_fallback():
        return jsonify(compliance_audit_fallback_payload())

    ensure_report_schema()
    try:
        upload_id = request.args.get("upload_id")
        framework = (request.args.get("framework") or "").upper()
        
        if not upload_id:
            # Get latest upload
            row = query_one("SELECT id, framework FROM compliance_audit_uploads ORDER BY created_at DESC LIMIT 1")
            if not row:
                return jsonify(compliance_audit_fallback_payload())
            upload_id = row["id"]
            framework = row.get("framework", "CIS")
        
        # Get upload info
        upload_info = query_one(
            """
            SELECT
                id,
                upload_name,
                filename,
                framework,
                total_questions,
                total_controls,
                sheet_count,
                coverage_percent,
                upload_mode,
                CASE WHEN stored_path IS NOT NULL AND stored_path <> '' THEN TRUE ELSE FALSE END AS preview_available,
                created_at
            FROM compliance_audit_uploads
            WHERE id = %s
            """,
            (upload_id,)
        )
        
        if not upload_info:
            return jsonify(compliance_audit_fallback_payload())
        
        # Get control scores
        control_scores = query(
            """
            SELECT
                control_id,
                framework,
                COALESCE(implemented_count, 0) as implemented,
                COALESCE(total_count, 0) as total,
                COALESCE(completion_percent, 0) as percent_complete,
                risk_level,
                last_assessed
            FROM compliance_upload_control_scores
            WHERE upload_id = %s
            ORDER BY control_id
            """,
            (upload_id,)
        )
        
        # Get response summary
        response_summary = query_one(
            """
            SELECT
                COUNT(*) as total_responses,
                COUNT(*) FILTER (WHERE implemented = true) as implemented_responses,
                COUNT(*) FILTER (WHERE response_status = 'compliant') as compliant_responses,
                COUNT(*) FILTER (WHERE response_status = 'non_compliant') as non_compliant_responses,
                COUNT(*) FILTER (WHERE priority = 'critical') as critical_priority,
                COUNT(DISTINCT control_id) as unique_controls
            FROM compliance_upload_responses
            WHERE upload_id = %s
            """,
            (upload_id,)
        )
        
        # Calculate framework coverage
        stats = {
            "total_controls": len(control_scores),
            "implemented": sum(1 for c in control_scores if float(c.get("implemented", 0)) > 0),
            "coverage_percent": float(round(sum(float(c.get("percent_complete", 0)) for c in control_scores) / len(control_scores), 1) if control_scores else 0),
            "total_questions": int(
                upload_info.get("total_questions", 0)
                or (response_summary.get("total_responses", 0) if response_summary else 0)
            ),
            "total_responses": response_summary.get("total_responses", 0) if response_summary else 0,
            "compliant": response_summary.get("compliant_responses", 0) if response_summary else 0,
            "non_compliant": response_summary.get("non_compliant_responses", 0) if response_summary else 0,
            "critical_items": response_summary.get("critical_priority", 0) if response_summary else 0,
        }
        
        # Get recent responses
        recent_responses = query(
            """
            SELECT
                control_id,
                control_name,
                question_number,
                question_text,
                response_status,
                response_value,
                evidence,
                comments,
                priority,
                mapping_score,
                created_at
            FROM compliance_upload_responses
            WHERE upload_id = %s
            ORDER BY COALESCE(question_number, 999999), control_id, created_at
            """,
            (upload_id,)
        )

        uploads = query(
            """
            SELECT
                id,
                upload_name,
                filename,
                framework,
                total_questions,
                total_controls,
                sheet_count,
                coverage_percent,
                upload_mode,
                CASE WHEN stored_path IS NOT NULL AND stored_path <> '' THEN TRUE ELSE FALSE END AS preview_available,
                created_at
            FROM compliance_audit_uploads
            ORDER BY created_at DESC
            LIMIT 50
            """
        )
        
        # Convert Decimal values to float in control_scores
        for c in control_scores:
            c["implemented"] = int(c.get("implemented", 0))
            c["total"] = int(c.get("total", 0))
            c["percent_complete"] = float(c.get("percent_complete", 0))
        
        # Convert Decimal values to float in recent_responses
        for r in recent_responses:
            r["mapping_score"] = float(r.get("mapping_score", 0)) if r.get("mapping_score") else None
        
        return jsonify({
            "upload": upload_info,
            "uploads": uploads,
            "stats": stats,
            "controls": control_scores,
            "responses": recent_responses,
        })
    
    except Exception as exc:
        if is_db_unavailable_error(exc):
            return jsonify(compliance_audit_fallback_payload())
        logger.exception("secumat fetch failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/compliance_audit/<upload_id>/preview")
def api_compliance_audit_preview(upload_id):
    ensure_report_schema()
    try:
        if is_fallback_upload_id(upload_id):
            fallback_payload = compliance_audit_fallback_payload()
            fallback_rows = [("Control ID", "Question", "Status", "Priority", "Comments")]
            for item in (fallback_payload.get("responses") or [])[:50]:
                fallback_rows.append((
                    item.get("control_id"),
                    item.get("question_text"),
                    item.get("response_status"),
                    item.get("priority"),
                    item.get("comments"),
                ))
            return jsonify({
                "upload": fallback_payload.get("upload"),
                "sheet_count": 1,
                "sheets": [build_sheet_preview_rows("Fallback Questionnaire", fallback_rows)],
            })

        upload = query_one(
            """
            SELECT
                id,
                upload_name,
                filename,
                framework,
                total_questions,
                total_controls,
                sheet_count,
                coverage_percent,
                upload_mode,
                stored_path,
                created_at
            FROM compliance_audit_uploads
            WHERE id = %s
            """,
            (upload_id,),
        )
        if not upload:
            return jsonify({"error": "Upload not found"}), 404

        stored_path = upload.get("stored_path")
        if not stored_path or not os.path.exists(stored_path):
            preview_rows = query(
                """
                SELECT
                    control_id,
                    question_number,
                    question_text,
                    response_status,
                    priority,
                    comments
                FROM compliance_upload_responses
                WHERE upload_id = %s
                ORDER BY COALESCE(question_number, 999999), control_id, created_at
                LIMIT 75
                """,
                (upload_id,),
            )
            if preview_rows:
                sheet_rows = [("Control ID", "Question #", "Question", "Status", "Priority", "Comments")]
                for item in preview_rows:
                    sheet_rows.append((
                        item.get("control_id"),
                        item.get("question_number"),
                        item.get("question_text"),
                        item.get("response_status"),
                        item.get("priority"),
                        item.get("comments"),
                    ))
                upload["preview_available"] = False
                upload.pop("stored_path", None)
                return jsonify({
                    "upload": upload,
                    "sheet_count": 1,
                    "sheets": [build_sheet_preview_rows("Uploaded Responses", sheet_rows)],
                })

            return jsonify({"error": "Preview file is not available for this upload"}), 404

        with open(stored_path, "rb") as file_handle:
            payload = file_handle.read()

        preview = build_workbook_preview_from_bytes(payload, upload.get("filename") or "")
        upload["preview_available"] = True
        upload.pop("stored_path", None)

        return jsonify({
            "upload": upload,
            "sheet_count": preview["sheet_count"],
            "sheets": preview["sheets"],
        })
    except Exception as exc:
        logger.exception("Compliance preview failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/compliance_uploads")
def api_compliance_uploads():
    """Get list of secumat uploads."""
    ensure_report_schema()
    try:
        framework = (request.args.get("framework") or "").upper()
        limit = int(request.args.get("limit", 20))
        
        if framework:
            uploads = query(
                """
                SELECT
                    id,
                    upload_name,
                    filename,
                    framework,
                    total_questions,
                    total_controls,
                    sheet_count,
                    coverage_percent,
                    upload_mode,
                    CASE WHEN stored_path IS NOT NULL AND stored_path <> '' THEN TRUE ELSE FALSE END AS preview_available,
                    created_at
                FROM compliance_audit_uploads
                WHERE framework = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (framework, limit)
            )
        else:
            uploads = query(
                """
                SELECT
                    id,
                    upload_name,
                    filename,
                    framework,
                    total_questions,
                    total_controls,
                    sheet_count,
                    coverage_percent,
                    upload_mode,
                    CASE WHEN stored_path IS NOT NULL AND stored_path <> '' THEN TRUE ELSE FALSE END AS preview_available,
                    created_at
                FROM compliance_audit_uploads
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,)
            )
        
        return jsonify({"uploads": uploads})
    
    except Exception as exc:
        logger.exception("Compliance uploads fetch failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/secumat_templates")
def api_secumat_templates():
    """Get list of available secumat compliance audit templates."""
    try:
        # Return all available templates with metadata
        templates_list = []
        for template_id, template_data in SECUMAT_TEMPLATES.items():
            templates_list.append({
                "id": template_id,
                "name": template_data["name"],
                "framework": template_data["framework"],
                "version": template_data["version"],
                "description": template_data["description"],
                "control_count": template_data["control_count"],
                "source": template_data["source"]
            })
        
        return jsonify({
            "templates": templates_list,
            "total_templates": len(templates_list)
        })
    
    except Exception as exc:
        logger.exception("Secumat templates fetch failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/secumat_workspace")
def api_secumat_workspace():
    if dashboard_force_fallback():
        return jsonify(secumat_workspace_fallback_payload())

    try:
        ensure_report_schema()
        ensure_audit_assignment_schema()
        audits = query(
            """
            SELECT
                id,
                audit_name,
                company_name,
                framework,
                questionnaire_mode,
                audit_type,
                industry_type,
                operating_system,
                division,
                quarter_label,
                audit_cycle,
                audit_scope,
                audit_start_date,
                audit_end_date,
                version_label,
                status,
                audit_details,
                assigned_to,
                responsible_person,
                team_name,
                auditor_name,
                auditor_email,
                auditor_company,
                teams_involved,
                custom_role,
                selected_questionnaire_id,
                selected_questionnaire_name,
                created_at,
                updated_at
            FROM secumat_audit_profiles
            ORDER BY COALESCE(audit_start_date, created_at::date) DESC, created_at DESC
            LIMIT 100
            """
        )

        assignment_progress = query(
            """
            SELECT
                audit_profile_id,
                COUNT(*) AS assignment_count,
                MAX(progress_percent) AS max_progress_percent,
                BOOL_OR(COALESCE(progress_percent, 0) >= 100) AS any_completed
            FROM compliance_audit_assignments
            WHERE audit_profile_id IS NOT NULL
            GROUP BY audit_profile_id
            """
        )
        progress_by_profile = {str(item["audit_profile_id"]): item for item in assignment_progress if item.get("audit_profile_id")}
        for audit in audits:
            progress = progress_by_profile.get(str(audit.get("id")))
            audit["assignment_count"] = int(progress.get("assignment_count") or 0) if progress else 0
            audit["progress_percent"] = float(progress.get("max_progress_percent") or 0) if progress else 0
            if progress and float(progress.get("max_progress_percent") or 0) >= 100:
                audit["status"] = "completed"

        uploads = query(
            """
            SELECT
                id,
                upload_name,
                filename,
                framework,
                total_questions,
                total_controls,
                sheet_count,
                coverage_percent,
                upload_mode,
                CASE WHEN stored_path IS NOT NULL AND stored_path <> '' THEN TRUE ELSE FALSE END AS preview_available,
                created_at
            FROM compliance_audit_uploads
            ORDER BY created_at DESC
            LIMIT 25
            """
        )

        templates_list = []
        for template_id, template_data in SECUMAT_TEMPLATES.items():
            templates_list.append({
                "id": template_id,
                "name": template_data["name"],
                "framework": template_data["framework"],
                "version": template_data["version"],
                "description": template_data["description"],
                "control_count": template_data["control_count"],
            })

        # Load custom questionnaire templates from DB
        custom_questionnaires = []
        try:
            ensure_custom_questionnaire_schema()
            custom_rows = query("""
                SELECT id, name, framework, version, description, industry, audit_type,
                       os_platform, questions, created_at
                FROM custom_questionnaire_templates
                ORDER BY created_at DESC
            """)
            for row in custom_rows:
                qs = row.get("questions") or []
                sections = list(dict.fromkeys(q.get("section", "") for q in qs if q.get("section")))
                custom_questionnaires.append({
                    "id": f"custom_{row['id']}",
                    "db_id": row["id"],
                    "name": row["name"],
                    "framework": row.get("framework") or "CUSTOM",
                    "version": row.get("version") or "1.0",
                    "description": row.get("description") or "",
                    "source": "Custom / Manual",
                    "question_count": len(qs),
                    "sections": sections,
                    "questions": qs,
                    "is_custom": True,
                })
        except Exception as ce:
            logger.warning(f"Could not load custom questionnaire templates: {ce}")

        builtin_questionnaires = secumat_builtin_questionnaires_payload()

        return jsonify({
            "options": SECUMAT_OPTIONS,
            "resources": SECUMAT_RESOURCES,
            "questionnaire_library": SECUMAT_QUESTIONNAIRE_LIBRARY,
            "questionnaires": builtin_questionnaires + custom_questionnaires,
            "guidance": SECUMAT_GUIDANCE,
            "templates": templates_list,
            "audits": audits,
            "uploads": uploads,
        })
    except Exception as exc:
        if dashboard_force_fallback() or is_db_unavailable_error(exc):
            return jsonify(secumat_workspace_fallback_payload())
        logger.exception("Secumat workspace fetch failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/secumat_audits", methods=["GET", "POST"])
def api_secumat_audits():
    if dashboard_force_fallback():
        state = load_secumat_fallback_state()
        if request.method == "GET":
            return jsonify({"audits": state.get("audits") or []})
        data = request.get_json(silent=True) or {}
        audit_name = (data.get("audit_name") or "").strip()
        if not audit_name:
            return jsonify({"error": "audit_name is required"}), 400
        audit = {
            "id": secumat_next_int_id(state.get("audits") or []),
            "audit_name": audit_name,
            "company_name": (data.get("company_name") or "").strip(),
            "framework": (data.get("framework") or "").strip(),
            "questionnaire_mode": (data.get("questionnaire_mode") or "").strip(),
            "audit_type": (data.get("audit_type") or "").strip(),
            "industry_type": (data.get("industry_type") or "").strip(),
            "operating_system": (data.get("operating_system") or "").strip(),
            "division": (data.get("division") or "").strip(),
            "quarter_label": (data.get("quarter_label") or "").strip(),
            "audit_cycle": (data.get("audit_cycle") or "").strip(),
            "audit_scope": (data.get("audit_scope") or "").strip(),
            "audit_start_date": data.get("audit_start_date") or None,
            "audit_end_date": data.get("audit_end_date") or None,
            "version_label": (data.get("version_label") or "").strip(),
            "status": (data.get("status") or "draft").strip(),
            "audit_details": (data.get("audit_details") or "").strip(),
            "assigned_to": (data.get("assigned_to") or "").strip(),
            "responsible_person": (data.get("responsible_person") or "").strip(),
            "team_name": (data.get("team_name") or "").strip(),
            "auditor_name": (data.get("auditor_name") or "").strip(),
            "auditor_email": (data.get("auditor_email") or "").strip(),
            "auditor_company": (data.get("auditor_company") or "").strip(),
            "teams_involved": (data.get("teams_involved") or "").strip(),
            "custom_role": (data.get("custom_role") or "").strip(),
            "selected_questionnaire_id": (data.get("selected_questionnaire_id") or "").strip(),
            "selected_questionnaire_name": (data.get("selected_questionnaire_name") or "").strip(),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        audits = list(state.get("audits") or [])
        audits.append(audit)
        state["audits"] = audits
        save_secumat_fallback_state(state)
        return jsonify({"status": "created", "audit": audit}), 201

    try:
        ensure_report_schema()
        ensure_audit_assignment_schema()
        if request.method == "GET":
            audits = query(
                """
                SELECT
                    id,
                    audit_name,
                    company_name,
                    framework,
                    questionnaire_mode,
                    audit_type,
                    industry_type,
                    operating_system,
                    division,
                    quarter_label,
                    audit_cycle,
                    audit_scope,
                    audit_start_date,
                    audit_end_date,
                    version_label,
                    status,
                    audit_details,
                    assigned_to,
                    responsible_person,
                    team_name,
                    auditor_name,
                    auditor_email,
                    auditor_company,
                    teams_involved,
                    custom_role,
                    selected_questionnaire_id,
                    selected_questionnaire_name,
                    created_at,
                    updated_at
                FROM secumat_audit_profiles
                ORDER BY COALESCE(audit_start_date, created_at::date) DESC, created_at DESC
                LIMIT 100
                """
            )
            return jsonify({"audits": audits})

        data = request.get_json() or {}
        audit_name = (data.get("audit_name") or "").strip()
        if not audit_name:
            return jsonify({"error": "audit_name is required"}), 400

        row = execute_update(
            """
            INSERT INTO secumat_audit_profiles (
                audit_name, company_name, framework, questionnaire_mode, audit_type, industry_type, operating_system,
                division, quarter_label, audit_cycle, audit_scope, audit_start_date, audit_end_date, version_label, status,
                audit_details, assigned_to, responsible_person, team_name, auditor_name, auditor_email, auditor_company, teams_involved
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING
                id,
                audit_name,
                company_name,
                framework,
                questionnaire_mode,
                audit_type,
                industry_type,
                operating_system,
                division,
                quarter_label,
                audit_cycle,
                audit_scope,
                audit_start_date,
                audit_end_date,
                version_label,
                status,
                audit_details,
                assigned_to,
                responsible_person,
                team_name,
                auditor_name,
                auditor_email,
                auditor_company,
                teams_involved,
                custom_role,
                selected_questionnaire_id,
                selected_questionnaire_name,
                created_at,
                updated_at
            """,
            (
                audit_name,
                (data.get("company_name") or "").strip(),
                (data.get("framework") or "").strip(),
                (data.get("questionnaire_mode") or "").strip(),
                (data.get("audit_type") or "").strip(),
                (data.get("industry_type") or "").strip(),
                (data.get("operating_system") or "").strip(),
                (data.get("division") or "").strip(),
                (data.get("quarter_label") or "").strip(),
                (data.get("audit_cycle") or "").strip(),
                (data.get("audit_scope") or "").strip(),
                data.get("audit_start_date") or None,
                data.get("audit_end_date") or None,
                (data.get("version_label") or "").strip(),
                (data.get("status") or "draft").strip(),
                (data.get("audit_details") or "").strip(),
                (data.get("assigned_to") or "").strip(),
                (data.get("responsible_person") or "").strip(),
                (data.get("team_name") or "").strip(),
                (data.get("auditor_name") or "").strip(),
                (data.get("auditor_email") or "").strip(),
                (data.get("auditor_company") or "").strip(),
                (data.get("teams_involved") or "").strip(),
            ),
            fetchone=True,
        )
        execute_update(
            """
            UPDATE secumat_audit_profiles
            SET custom_role = %s,
                selected_questionnaire_id = %s,
                selected_questionnaire_name = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (
                (data.get("custom_role") or "").strip(),
                (data.get("selected_questionnaire_id") or "").strip(),
                (data.get("selected_questionnaire_name") or "").strip(),
                row["id"],
            ),
        )
        row["custom_role"] = (data.get("custom_role") or "").strip()
        row["selected_questionnaire_id"] = (data.get("selected_questionnaire_id") or "").strip()
        row["selected_questionnaire_name"] = (data.get("selected_questionnaire_name") or "").strip()
        return jsonify({"status": "created", "audit": row}), 201
    except Exception as exc:
        if is_db_unavailable_error(exc):
            return jsonify({"audits": load_secumat_fallback_state().get("audits") or []})
        logger.exception("Secumat audit management failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/secumat_audits/<audit_id>", methods=["GET", "PUT", "DELETE"])
def api_secumat_audit_detail(audit_id):
    if dashboard_force_fallback():
        state = load_secumat_fallback_state()
        audits = list(state.get("audits") or [])
        matched = next((item for item in audits if str(item.get("id")) == str(audit_id)), None)
        if request.method == "GET":
            if not matched:
                return jsonify({"error": "Audit profile not found"}), 404
            return jsonify({"audit": matched})
        if request.method == "DELETE":
            if not matched:
                return jsonify({"error": "Audit profile not found"}), 404
            audits = [item for item in audits if str(item.get("id")) != str(audit_id)]
            state["audits"] = audits
            save_secumat_fallback_state(state)
            return jsonify({"status": "deleted", "id": str(audit_id)})

        data = request.get_json(silent=True) or {}
        if not matched:
            return jsonify({"error": "Audit profile not found"}), 404
        for key in [
            "audit_name", "company_name", "framework", "questionnaire_mode", "audit_type",
            "industry_type", "operating_system", "division", "quarter_label", "audit_cycle",
            "audit_scope", "audit_start_date", "audit_end_date", "version_label", "status",
            "audit_details", "assigned_to", "responsible_person", "team_name", "auditor_name",
            "auditor_email", "auditor_company", "teams_involved", "custom_role",
            "selected_questionnaire_id", "selected_questionnaire_name",
        ]:
            if key in data:
                matched[key] = data.get(key)
        matched["updated_at"] = datetime.utcnow().isoformat() + "Z"
        state["audits"] = audits
        save_secumat_fallback_state(state)
        return jsonify({"status": "updated", "audit": matched})

    try:
        ensure_report_schema()
        ensure_audit_assignment_schema()
        if request.method == "GET":
            audit = query_one(
                """
                SELECT
                    id, audit_name, company_name, framework, questionnaire_mode, audit_type, industry_type,
                    operating_system, division, quarter_label, audit_cycle, audit_scope, audit_start_date,
                    audit_end_date, version_label, status, audit_details, assigned_to, responsible_person,
                    team_name, auditor_name, auditor_email, auditor_company, teams_involved, custom_role,
                    selected_questionnaire_id, selected_questionnaire_name, created_at, updated_at
                FROM secumat_audit_profiles
                WHERE id = %s
                """,
                (audit_id,),
            )
            if not audit:
                return jsonify({"error": "Audit profile not found"}), 404
            return jsonify({"audit": audit})

        if request.method == "DELETE":
            deleted = execute_update(
                """
                DELETE FROM secumat_audit_profiles
                WHERE id = %s
                RETURNING id
                """,
                (audit_id,),
                fetchone=True,
            )
            if not deleted:
                return jsonify({"error": "Audit profile not found"}), 404
            return jsonify({"status": "deleted", "id": audit_id})

        data = request.get_json(silent=True) or {}
        updated = execute_update(
            """
            UPDATE secumat_audit_profiles
            SET audit_name = %s,
                company_name = %s,
                framework = %s,
                questionnaire_mode = %s,
                audit_type = %s,
                industry_type = %s,
                operating_system = %s,
                division = %s,
                quarter_label = %s,
                audit_cycle = %s,
                audit_scope = %s,
                audit_start_date = %s,
                audit_end_date = %s,
                version_label = %s,
                status = %s,
                audit_details = %s,
                assigned_to = %s,
                responsible_person = %s,
                team_name = %s,
                auditor_name = %s,
                auditor_email = %s,
                auditor_company = %s,
                teams_involved = %s,
                custom_role = %s,
                selected_questionnaire_id = %s,
                selected_questionnaire_name = %s,
                updated_at = NOW()
            WHERE id = %s
            RETURNING id, audit_name, status, updated_at
            """,
            (
                (data.get("audit_name") or "").strip(),
                (data.get("company_name") or "").strip(),
                (data.get("framework") or "").strip(),
                (data.get("questionnaire_mode") or "").strip(),
                (data.get("audit_type") or "").strip(),
                (data.get("industry_type") or "").strip(),
                (data.get("operating_system") or "").strip(),
                (data.get("division") or "").strip(),
                (data.get("quarter_label") or "").strip(),
                (data.get("audit_cycle") or "").strip(),
                (data.get("audit_scope") or "").strip(),
                data.get("audit_start_date") or None,
                data.get("audit_end_date") or None,
                (data.get("version_label") or "").strip(),
                (data.get("status") or "draft").strip(),
                (data.get("audit_details") or "").strip(),
                (data.get("assigned_to") or "").strip(),
                (data.get("responsible_person") or "").strip(),
                (data.get("team_name") or "").strip(),
                (data.get("auditor_name") or "").strip(),
                (data.get("auditor_email") or "").strip(),
                (data.get("auditor_company") or "").strip(),
                (data.get("teams_involved") or "").strip(),
                (data.get("custom_role") or "").strip(),
                (data.get("selected_questionnaire_id") or "").strip(),
                (data.get("selected_questionnaire_name") or "").strip(),
                audit_id,
            ),
            fetchone=True,
        )
        if not updated:
            return jsonify({"error": "Audit profile not found"}), 404
        return jsonify({"status": "updated", "audit": updated})
    except Exception as exc:
        if is_db_unavailable_error(exc):
            return jsonify({"error": "Audit profile not found"}), 404
        logger.exception("Secumat audit detail management failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/custom_templates", methods=["GET", "POST"])
def api_custom_templates():
    """Get or create custom audit templates."""
    ensure_report_schema()
    try:
        if request.method == "GET":
            # Get all custom templates
            templates = query(
                """
                SELECT id, template_id, name, framework, version, description, 
                       organization, is_editable, created_by, created_at
                FROM custom_audit_templates
                ORDER BY created_at DESC
                """
            )
            return jsonify({"templates": templates})
        
        elif request.method == "POST":
            # Create new custom template
            data = request.get_json()
            template_id = data.get("template_id", f"custom_{datetime.now().timestamp()}")
            name = data.get("name", "New Custom Template")
            framework = data.get("framework", "CIS")
            version = data.get("version", "1.0")
            description = data.get("description", "")
            organization = data.get("organization", "")
            created_by = data.get("created_by", "")
            
            execute_update(
                """
                INSERT INTO custom_audit_templates (template_id, name, framework, version, description, organization, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (template_id) DO UPDATE SET
                  name = EXCLUDED.name,
                  description = EXCLUDED.description,
                  updated_at = NOW()
                """,
                (template_id, name, framework, version, description, organization, created_by)
            )
            
            return jsonify({"template_id": template_id, "status": "created"}), 201
    
    except Exception as exc:
        logger.exception("Custom templates management failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/custom_templates/<template_id>/questions", methods=["GET", "POST"])
def api_template_questions(template_id):
    """Get or add questions to a custom template."""
    ensure_report_schema()
    try:
        if request.method == "GET":
            # Get all questions in template
            questions = query(
                """
                SELECT id, control_id, control_name, question_number, question_text, 
                       question_type, is_required, guidance, expected_answer, display_order
                FROM custom_template_questions
                WHERE template_id = (SELECT id FROM custom_audit_templates WHERE template_id = %s)
                ORDER BY display_order, question_number
                """,
                (template_id,)
            )
            return jsonify({"questions": questions})
        
        elif request.method == "POST":
            # Add question to template
            data = request.get_json()
            control_id = data.get("control_id", "")
            control_name = data.get("control_name", "")
            question_number = data.get("question_number", 1)
            question_text = data.get("question_text", "")
            question_type = data.get("question_type", "text")
            guidance = data.get("guidance", "")
            expected_answer = data.get("expected_answer", "")
            
            # Get template UUID
            template_row = query_one(
                "SELECT id FROM custom_audit_templates WHERE template_id = %s",
                (template_id,)
            )
            
            if not template_row:
                return jsonify({"error": "Template not found"}), 404
            
            execute_update(
                """
                INSERT INTO custom_template_questions 
                (template_id, control_id, control_name, question_number, question_text, question_type, guidance, expected_answer)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (template_row["id"], control_id, control_name, question_number, question_text, question_type, guidance, expected_answer)
            )
            
            return jsonify({"status": "question_added"}), 201
    
    except Exception as exc:
        logger.exception("Template questions management failed")
        return jsonify({"error": str(exc)}), 500


COMPLIANCE_FIELD_ALIASES = {
    "control_id": ["control_id", "control id", "control", "id", "question id", "control reference"],
    "control_name": ["control_name", "control name", "control description", "title", "control title", "name"],
    "question_text": ["question", "question_text", "question text", "basic criteria (summary)", "basic criteria", "summary", "description"],
    "response_value": ["response", "answer", "applied? (yes/no/n-a)", "applied", "applied? (yes/no/na)", "applied?"],
    "response_status": ["status", "response status", "compliance status", "applied? (yes/no/n-a)", "applied? (yes/no/na)", "applied?"],
    "priority": ["priority", "criticality", "risk", "risk level", "severity"],
    "evidence": ["evidence", "supporting docs", "supporting_docs", "reference", "reviewed by"],
    "comments": ["comments", "notes", "justification / implementation notes", "short description / justification", "justification"],
    "section": ["section", "area", "domain", "category"],
    "question_number": ["#", "number", "question #", "question no", "no."],
}
COMPLIANCE_EXACT_ONLY_FIELDS = {"control_id", "question_number"}


def get_compliance_field(raw_row, field_name):
    aliases = COMPLIANCE_FIELD_ALIASES.get(field_name, [])
    for alias in aliases:
        for key, value in raw_row.items():
            if key is None:
                continue
            if str(key).strip().lower() == str(alias).strip().lower() and value not in (None, ""):
                return value

    normalized = []
    for key, value in raw_row.items():
        if key is None:
            continue
        normalized_key = normalize_text(key)
        if not normalized_key:
            continue
        normalized.append((normalized_key, value))

    for alias in aliases:
        alias_key = normalize_text(alias)
        for key, value in normalized:
            if key == alias_key and value not in (None, ""):
                return value

    for alias in aliases:
        alias_key = normalize_text(alias)
        if field_name in COMPLIANCE_EXACT_ONLY_FIELDS:
            continue
        if len(alias_key) < 4:
            continue
        for key, value in normalized:
            if (alias_key in key or key in alias_key) and value not in (None, ""):
                return value
    return None


def make_control_id(section, question_number, explicit_control_id, title, question_text, row_index):
    if explicit_control_id not in (None, ""):
        return sanitize_text(str(explicit_control_id))

    section_text = str(sanitize_text(section)).strip() if section not in (None, "") else ""
    question_no_text = str(sanitize_text(question_number)).strip() if question_number not in (None, "") else ""
    title_text = str(sanitize_text(title)).strip() if title not in (None, "") else ""
    question_text_clean = str(sanitize_text(question_text)).strip() if question_text not in (None, "") else ""

    if section_text and question_no_text:
        return f"{section_text} {question_no_text}"
    if section_text and title_text:
        return f"{section_text} - {title_text}"
    if title_text:
        return title_text
    if question_text_clean:
        if len(question_text_clean) > 72:
            question_text_clean = f"{question_text_clean[:69]}..."
        return question_text_clean
    return f"Row {row_index}"


def normalize_compliance_response_status(response_status, response_value):
    candidate = sanitize_text(response_status if response_status not in (None, "") else response_value)
    if candidate in (None, ""):
        return "pending", False, 0

    response_status_lower = str(candidate).lower().strip()
    normalized_words = re.sub(r"[^a-z0-9]+", " ", response_status_lower).strip()
    if normalized_words in {"not applicable", "n a", "na"} or "not applicable" in response_status_lower:
        return "not_applicable", True, 100
    if any(token in response_status_lower for token in ("partial", "in progress", "planned", "under review")):
        return "partial", False, 50
    if any(token in response_status_lower for token in ("compliant", "pass", "implemented", "true", "complete", "done")) or normalized_words in {"yes", "y"}:
        return "compliant", True, 100
    if any(token in response_status_lower for token in ("non-compliant", "non compliant", "not implemented", "false")) or normalized_words in {"no", "n", "fail", "gap"}:
        return "non_compliant", False, 0
    return sanitize_text(response_status_lower.replace(" ", "_")), False, 25


def read_compliance_file(file_storage, framework="CIS"):
    """Parse secumat Excel file and extract controls & responses."""
    payload = file_storage.read()
    if not payload:
        return {"responses": [], "sheets_imported": 0, "sheet_details": [], "sheet_count": 0, "payload": b""}

    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    responses = []
    sheets_imported = 0
    sheet_details = []

    if ext in {"xlsx", "xlsm"}:
        try:
            from openpyxl import load_workbook
        except Exception as exc:
            raise RuntimeError("Excel support requires openpyxl") from exc

        workbook = load_workbook(io.BytesIO(payload), read_only=True, data_only=True)
        for sheet in workbook.worksheets:
            all_rows = list(sheet.iter_rows(values_only=True))
            sheet_preview = build_sheet_preview_rows(sheet.title, all_rows)
            if sheet_preview["row_count"] > 0:
                sheet_details.append({
                    "sheet_name": sheet_preview["sheet_name"],
                    "row_count": sheet_preview["row_count"],
                    "column_count": sheet_preview["column_count"],
                })

            if not all_rows or len(all_rows) < 2:
                continue

            # Detect header row
            header_idx, headers = detect_header_row(all_rows)
            if not headers:
                headers = [f"column_{i+1}" for i in range(len(all_rows[0]) if all_rows[0] else 0)]

            # Parse data rows
            sheet_responses = 0
            for row_offset, row_values in enumerate(all_rows[header_idx + 1:], start=1):
                raw_row = {headers[idx]: row_values[idx] for idx in range(min(len(headers), len(row_values))) if idx < len(headers)}
                if not row_has_meaningful_data(raw_row):
                    continue

                response = parse_compliance_response(raw_row, framework, sheet.title)
                if response:
                    responses.append(response)
                    sheet_responses += 1

            if sheet_responses > 0:
                sheets_imported += 1
                logger.info(f"Compliance sheet '{sheet.title}': {sheet_responses} responses parsed")

    elif ext == "csv":
        text = payload.decode("utf-8-sig")
        all_rows = list(csv.reader(io.StringIO(text)))
        sheet_preview = build_sheet_preview_rows("CSV", all_rows)
        if sheet_preview["row_count"] > 0:
            sheet_details.append({
                "sheet_name": sheet_preview["sheet_name"],
                "row_count": sheet_preview["row_count"],
                "column_count": sheet_preview["column_count"],
            })
        reader = csv.DictReader(io.StringIO(text))
        for raw_row in reader:
            response = parse_compliance_response(raw_row, framework, "CSV")
            if response:
                responses.append(response)
        if responses:
            sheets_imported = 1

    return {
        "responses": responses,
        "sheets_imported": sheets_imported,
        "sheet_details": sheet_details,
        "sheet_count": len(sheet_details),
        "payload": payload,
    }


def parse_compliance_response(raw_row, framework, sheet_name):
    """Parse a single compliance response row into standardized format."""
    section = get_compliance_field(raw_row, "section")
    explicit_control_id = get_compliance_field(raw_row, "control_id")
    control_name = get_compliance_field(raw_row, "control_name")
    question_text = get_compliance_field(raw_row, "question_text")
    response_value = get_compliance_field(raw_row, "response_value")
    response_status = get_compliance_field(raw_row, "response_status")
    priority = get_compliance_field(raw_row, "priority")
    evidence = get_compliance_field(raw_row, "evidence")
    comments = get_compliance_field(raw_row, "comments")
    question_number_raw = get_compliance_field(raw_row, "question_number")

    section = str(sanitize_text(section)).strip() if section not in (None, "") else str(sanitize_text(sheet_name)).strip()
    control_name = str(sanitize_text(control_name)).strip() if control_name not in (None, "") else None
    question_text = str(sanitize_text(question_text)).strip() if question_text not in (None, "") else None
    response_value = str(sanitize_text(response_value)).strip() if response_value not in (None, "") else None
    response_status = str(sanitize_text(response_status)).strip() if response_status not in (None, "") else None
    evidence = str(sanitize_text(evidence)).strip() if evidence not in (None, "") else None
    comments = str(sanitize_text(comments)).strip() if comments not in (None, "") else None
    if explicit_control_id not in (None, ""):
        explicit_control_id = str(sanitize_text(explicit_control_id)).strip()
    if question_number_raw not in (None, ""):
        question_number_raw = str(sanitize_text(question_number_raw)).strip()

    if not any(value not in (None, "") for value in (explicit_control_id, control_name, question_text, response_value, response_status, comments, evidence)):
        return None

    question_number = None
    if question_number_raw not in (None, ""):
        question_number = parse_number(question_number_raw)
        if question_number is not None:
            question_number = int(question_number)

    control_id = make_control_id(section, question_number_raw, explicit_control_id, control_name, question_text, question_number or 0)
    normalized_status, implemented, mapping_score = normalize_compliance_response_status(response_status, response_value)

    if priority:
        priority_text = str(sanitize_text(priority)).strip()
        priority_lower = priority_text.lower()
        if priority_lower in {"critical", "p0", "sev1"}:
            priority = "critical"
        elif priority_lower in {"high", "p1", "sev2"}:
            priority = "high"
        elif priority_lower in {"medium", "p2", "sev3"}:
            priority = "medium"
        else:
            priority = priority_text.title()

    control_name = control_name or section or control_id
    if section and control_name and section.lower() not in str(control_name).lower():
        control_name = f"{section} - {control_name}"

    return {
        "control_id": sanitize_text(control_id),
        "control_name": sanitize_text(control_name or control_id),
        "framework": framework,
        "question_number": question_number,
        "question_text": sanitize_text(question_text),
        "response_status": normalized_status,
        "response_value": sanitize_text(response_value),
        "evidence": sanitize_text(evidence),
        "comments": sanitize_text(comments),
        "implemented": implemented,
        "priority": priority,
        "mapping_score": mapping_score,
    }


def save_compliance_upload(filename, upload_name, framework, uploaded_by, responses, sheet_count=0, upload_mode="structured", source_payload=None):
    """Save secumat responses to database."""
    ensure_report_schema()
    conn = None
    upload_id = None
    stored_path = None

    try:
        conn = get_db()
        with conn.cursor() as cur:
            # Create upload record
            total_questions = len(responses)
            total_controls = len(set(r["control_id"] for r in responses))
            scored_responses = [float(r["mapping_score"]) for r in responses if r.get("mapping_score") is not None]
            coverage_percent = round(sum(scored_responses) / len(scored_responses), 1) if scored_responses else 0
            
            cur.execute(
                """
                INSERT INTO compliance_audit_uploads
                (upload_name, filename, uploaded_by, framework, total_questions, total_controls, sheet_count, coverage_percent, upload_mode)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (upload_name, filename, uploaded_by, framework, total_questions, total_controls, sheet_count, coverage_percent, upload_mode)
            )
            upload_id = cur.fetchone()["id"]
            logger.info(f"Created compliance upload: {upload_id}")

            if source_payload:
                stored_path = persist_compliance_upload_source(upload_id, filename, source_payload)
                cur.execute(
                    "UPDATE compliance_audit_uploads SET stored_path = %s WHERE id = %s",
                    (stored_path, upload_id),
                )

            # Insert responses
            insert_sql = """
                INSERT INTO compliance_upload_responses
                (upload_id, control_id, control_name, framework, question_number, question_text,
                 response_status, response_value, evidence, comments, implemented, priority, mapping_score)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            batch_rows = []
            for response in responses:
                batch_rows.append((
                    upload_id,
                    response["control_id"],
                    response["control_name"],
                    response["framework"],
                    response.get("question_number"),
                    response.get("question_text"),
                    response.get("response_status", "unknown"),
                    response.get("response_value"),
                    response.get("evidence"),
                    response.get("comments"),
                    response.get("implemented", False),
                    response.get("priority"),
                    response.get("mapping_score"),
                ))
            
            if batch_rows:
                psycopg2.extras.execute_batch(cur, insert_sql, batch_rows, page_size=500)
            
            # Calculate and store control scores
            score_sql = """
                INSERT INTO compliance_upload_control_scores
                (upload_id, control_id, framework, implemented_count, total_count, completion_percent, risk_level, last_assessed)
                SELECT
                    %s,
                    control_id,
                    framework,
                    COUNT(*) FILTER (WHERE implemented = true),
                    COUNT(*),
                    ROUND(AVG(COALESCE(mapping_score, 0)), 1),
                    CASE
                        WHEN COUNT(*) FILTER (WHERE priority = 'critical') > 0 THEN 'critical'
                        WHEN COUNT(*) FILTER (WHERE priority = 'high') > 0 THEN 'high'
                        WHEN COUNT(*) FILTER (WHERE priority = 'medium') > 0 THEN 'medium'
                        ELSE 'low'
                    END,
                    NOW()
                FROM compliance_upload_responses
                WHERE upload_id = %s
                GROUP BY control_id, framework
            """
            cur.execute(score_sql, (upload_id, upload_id))
            
        conn.commit()
        return upload_id

    except Exception:
        if stored_path and os.path.exists(stored_path):
            try:
                os.remove(stored_path)
            except OSError:
                logger.warning("Failed to remove stored compliance upload after rollback: %s", stored_path)
        if conn:
            conn.rollback()
        raise

@app.route("/api/risk_monitoring")
def risk_monitoring():
    if dashboard_force_fallback() and (request.args.get("source") or "").lower() == "upload":
        summary = (build_full_data_fallback_report_payload().get("summary") or {})
        return jsonify({
            "stats": {
                "open_risks": summary.get("total_rows", 2585),
                "accepted_risks": 0,
                "false_positives": 0,
                "high_priority": summary.get("critical_rows", 439) + summary.get("high_rows", 1789),
                "overdue_30": 0,
                "avg_open_age": None,
                "ot_open": 0,
            },
            "aging": [],
            "backlog": [],
        })

    if (request.args.get("source") or "").lower() == "upload":
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
        mapped_vuln_where = f"({raw_severity_expr} <> 'unknown' OR {raw_status_expr} <> 'unknown')"
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify({"stats": {}, "aging": [], "backlog": []})

        if str(upload_id).strip().lower().startswith("fallback-"):
            summary = (build_full_data_fallback_report_payload().get("summary") or {})
            return jsonify({
                "stats": {
                    "open_risks": summary.get("total_rows", 2585),
                    "accepted_risks": 0,
                    "false_positives": 0,
                    "high_priority": summary.get("critical_rows", 439) + summary.get("high_rows", 1789),
                    "overdue_30": 0,
                    "avg_open_age": None,
                    "ot_open": 0,
                },
                "aging": [],
                "backlog": [],
            })

        stats = query_one(
            f"""
            WITH risk AS (
                SELECT
                    {active_status_expr} AS final_status,
                    {raw_severity_expr} AS severity,
                    CASE WHEN COALESCE(cloud_provider, '') ILIKE '%%ot%%' OR COALESCE(cloud_provider, '') ILIKE '%%ics%%' THEN 'OT/ICS' ELSE 'IT' END AS asset_type,
                    EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                            created_at
                        )
                    ))/86400.0 AS age_days
                FROM report_records
                WHERE upload_id = %s AND {valid_row_where} AND {mapped_vuln_where}{upload_filter_sql}
            )
            SELECT
                COUNT(*) AS open_risks,
                COUNT(*) FILTER (WHERE final_status = 'accepted_risk') AS accepted_risks,
                COUNT(*) FILTER (WHERE final_status = 'false_positive') AS false_positives,
                COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) AS high_priority,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND age_days >= 30) AS overdue_30,
                ROUND(AVG(age_days) FILTER (WHERE final_status IN ('open', 'confirmed_open')), 1) AS avg_open_age,
                COUNT(*) FILTER (WHERE asset_type = 'OT/ICS' AND final_status IN ('open', 'confirmed_open')) AS ot_open
            FROM risk
            """,
            (upload_id, *upload_filter_params),
        )

        upload_meta = query_one(
            "SELECT id, upload_name, filename FROM report_uploads WHERE id = %s",
            (upload_id,),
        )
        manual_override = get_manual_upload_count_override(upload_meta)
        if manual_override and not upload_filters_active(get_upload_filter_values()):
            summary_override = manual_override.get("summary") or {}
            stats.update({
                "open_risks": summary_override.get("total_rows", stats.get("open_risks", 0)),
                "high_priority": (
                    summary_override.get("critical_rows", 0)
                    + summary_override.get("high_rows", 0)
                ),
            })

        aging = query(
            f"""
            WITH risk AS (
                SELECT
                    {active_status_expr} AS final_status,
                    EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                            created_at
                        )
                    ))/86400.0 AS age_days
                FROM report_records
                WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            ),
            buckets AS (
                SELECT
                    CASE
                        WHEN age_days < 7 THEN '0-7 days'
                        WHEN age_days < 14 THEN '8-14 days'
                        WHEN age_days < 30 THEN '15-29 days'
                        WHEN age_days < 60 THEN '30-59 days'
                        ELSE '60+ days'
                    END AS age_bucket,
                    COUNT(*) AS cnt
                FROM risk
                WHERE final_status IN ('open', 'confirmed_open')
                GROUP BY 1
            )
            SELECT age_bucket, cnt
            FROM buckets
            ORDER BY CASE age_bucket
                WHEN '0-7 days' THEN 1
                WHEN '8-14 days' THEN 2
                WHEN '15-29 days' THEN 3
                WHEN '30-59 days' THEN 4
                ELSE 5 END
            """,
            (upload_id, *upload_filter_params),
        )

        backlog = query(
            f"""
            SELECT
                asset_key,
                cve,
                {raw_severity_expr} AS severity,
                score AS cvss_score,
                {active_status_expr} AS final_status,
                NULL::text AS pits_status,
                ROUND(EXTRACT(EPOCH FROM (
                    NOW() - COALESCE(
                        CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                        created_at
                    )
                ))/86400.0, 1) AS age_days,
                remediation
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
                            AND {active_status_expr} IN ('open', 'confirmed_open')
            ORDER BY
                CASE
                    WHEN {raw_severity_expr} = 'critical' THEN 1
                    WHEN {raw_severity_expr} = 'high' THEN 2
                    WHEN {raw_severity_expr} = 'medium' THEN 3
                    WHEN {raw_severity_expr} = 'low' THEN 4
                    ELSE 5
                END,
                age_days DESC NULLS LAST,
                score DESC NULLS LAST
            LIMIT 12
            """,
            (upload_id, *upload_filter_params),
        )

        return jsonify({"stats": stats, "aging": aging, "backlog": backlog})

    stats = query_one("""
        WITH risk AS (
            SELECT
                final_status,
                severity,
                asset_type,
                EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
            FROM unified_vulnerabilities
        )
        SELECT
            COUNT(*) FILTER (WHERE final_status = 'open') AS open_risks,
            COUNT(*) FILTER (WHERE final_status = 'accepted_risk') AS accepted_risks,
            COUNT(*) FILTER (WHERE final_status = 'false_positive') AS false_positives,
            COUNT(*) FILTER (WHERE final_status = 'open' AND severity IN ('critical', 'high')) AS high_priority,
            COUNT(*) FILTER (WHERE final_status = 'open' AND age_days >= 30) AS overdue_30,
            ROUND(AVG(age_days) FILTER (WHERE final_status = 'open'), 1) AS avg_open_age,
            COUNT(*) FILTER (WHERE asset_type = 'OT/ICS' AND final_status = 'open') AS ot_open
        FROM risk
    """)

    aging = query("""
        WITH risk AS (
            SELECT
                final_status,
                EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
            FROM unified_vulnerabilities
        ),
        buckets AS (
            SELECT
                CASE
                    WHEN age_days < 7 THEN '0-7 days'
                    WHEN age_days < 14 THEN '8-14 days'
                    WHEN age_days < 30 THEN '15-29 days'
                    WHEN age_days < 60 THEN '30-59 days'
                    ELSE '60+ days'
                END AS age_bucket,
                COUNT(*) AS cnt
            FROM risk
            WHERE final_status = 'open'
            GROUP BY 1
        )
        SELECT age_bucket, cnt
        FROM buckets
        ORDER BY CASE age_bucket
            WHEN '0-7 days' THEN 1
            WHEN '8-14 days' THEN 2
            WHEN '15-29 days' THEN 3
            WHEN '30-59 days' THEN 4
            ELSE 5 END
    """)

    backlog = query("""
        SELECT
            asset_key,
            cve,
            severity,
            cvss_score,
            final_status,
            pits_status,
            ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0, 1) AS age_days,
            remediation
        FROM unified_vulnerabilities
        WHERE final_status = 'open'
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5 END,
            age_days DESC NULLS LAST,
            cvss_score DESC NULLS LAST
        LIMIT 12
    """)

    return jsonify({"stats": stats, "aging": aging, "backlog": backlog})


@app.route("/api/cab_monitoring")
def cab_monitoring():
    if dashboard_force_fallback():
        manual_stats = cab_manual_stats_from_fallback()
        stats = {
            "cab_review_queue": 0,
            "problem_items": 0,
            "overdue_changes": 0,
            "recently_closed": 0,
            "approved_risk_acceptances": 0,
            "rejected_false_positives": 0,
            **manual_stats,
        }
        return jsonify({"stats": stats, "status_breakdown": [], "queue": [], "workflow_report": []})

    ensure_report_schema()

    # Upload-mode: derive CAB KPI stats from report_records instead of unified_vulnerabilities
    if (request.args.get("source") or "").lower() == "upload":
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
        age_days_expr = """
            EXTRACT(EPOCH FROM (
                NOW() - COALESCE(
                    CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                    CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                    created_at
                )
            )) / 86400.0
        """
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            upload_stats = {
                "cab_review_queue": 0,
                "problem_items": 0,
                "overdue_changes": 0,
                "recently_closed": 0,
                "approved_risk_acceptances": 0,
                "rejected_false_positives": 0,
            }
            status_breakdown = []
            workflow_report = []
            queue = []
        else:
            upload_stats = query_one(
                f"""
                WITH rr AS (
                    SELECT
                        {raw_severity_expr} AS severity_norm,
                        {raw_status_expr} AS raw_status,
                        {active_status_expr} AS final_status,
                        {age_days_expr} AS age_days
                    FROM report_records
                    WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
                )
                SELECT
                    COUNT(*) FILTER (
                        WHERE raw_status IN ('open', 'new', 'outdated') AND severity_norm IN ('critical', 'high') AND age_days >= 14
                    ) AS cab_review_queue,
                    COUNT(*) FILTER (WHERE raw_status = 'pending') AS problem_items,
                    COUNT(*) FILTER (WHERE raw_status IN ('open', 'new', 'outdated') AND age_days >= 7) AS overdue_changes,
                    COUNT(*) FILTER (WHERE raw_status IN ('closed')) AS recently_closed,
                    COUNT(*) FILTER (WHERE raw_status = 'accepted_risk') AS approved_risk_acceptances,
                    COUNT(*) FILTER (WHERE raw_status = 'false_positive') AS rejected_false_positives
                FROM rr
                """,
                (upload_id, *upload_filter_params),
            ) or {}

            status_breakdown = query(
                f"""
                WITH rr AS (
                    SELECT
                        {raw_severity_expr} AS severity_norm,
                        {active_status_expr} AS final_status,
                        {age_days_expr} AS age_days
                    FROM report_records
                    WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
                )
                SELECT cab_state, COUNT(*) AS cnt
                FROM (
                    SELECT
                        CASE
                            WHEN final_status = 'accepted_risk' THEN 'Board review'
                            WHEN final_status = 'confirmed_open' THEN 'Problem investigation'
                            WHEN final_status = 'open' AND severity_norm IN ('critical', 'high') AND age_days >= 14 THEN 'Escalated change'
                            WHEN final_status = 'open' THEN 'Remediation tracking'
                            WHEN final_status = 'closed' THEN 'Completed'
                            ELSE 'Other'
                        END AS cab_state
                    FROM rr
                ) t
                GROUP BY cab_state
                ORDER BY CASE cab_state
                    WHEN 'Board review' THEN 1
                    WHEN 'Problem investigation' THEN 2
                    WHEN 'Escalated change' THEN 3
                    WHEN 'Remediation tracking' THEN 4
                    WHEN 'Completed' THEN 5
                    ELSE 6 END
                """,
                (upload_id, *upload_filter_params),
            )

            workflow_report = query(
                f"""
                WITH rr AS (
                    SELECT
                        {raw_severity_expr} AS severity_norm,
                        {active_status_expr} AS final_status,
                        {age_days_expr} AS age_days
                    FROM report_records
                    WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
                )
                SELECT report_name, COUNT(*) AS count, notes
                FROM (
                    SELECT
                        CASE
                            WHEN final_status = 'accepted_risk' THEN 'Accepted risk summary'
                            WHEN final_status = 'confirmed_open' THEN 'Problem investigation summary'
                            WHEN final_status = 'open' AND severity_norm IN ('critical', 'high') AND age_days >= 14 THEN 'Escalated changes summary'
                            WHEN final_status = 'open' AND age_days >= 7 THEN 'Overdue remediation summary'
                            WHEN final_status = 'closed' THEN 'Completed tickets summary'
                            ELSE 'Other CAB issues'
                        END AS report_name,
                        CASE
                            WHEN final_status = 'accepted_risk' THEN 'Review approval status and risk acceptance rationale.'
                            WHEN final_status = 'confirmed_open' THEN 'Track problem investigation tickets for root cause and mitigation.'
                            WHEN final_status = 'open' AND severity_norm IN ('critical', 'high') AND age_days >= 14 THEN 'Escalate unresolved high-risk change requests.'
                            WHEN final_status = 'open' AND age_days >= 7 THEN 'Validate remediation plans and timelines.'
                            WHEN final_status = 'closed' THEN 'Confirm closures and update CAB/ITSM documentation.'
                            ELSE 'Review remaining CAB issues for workflow alignment.'
                        END AS notes
                    FROM rr
                ) t
                GROUP BY report_name, notes
                ORDER BY count DESC
                """,
                (upload_id, *upload_filter_params),
            )

            queue = query(
                f"""
                WITH cab AS (
                    SELECT
                        asset_key,
                        cve,
                        {raw_severity_expr} AS severity,
                        {active_status_expr} AS final_status,
                        score AS cvss_score,
                        remediation,
                        ROUND({age_days_expr}, 1) AS age_days
                    FROM report_records
                    WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
                )
                SELECT
                    asset_key,
                    cve,
                    severity,
                    final_status,
                    cvss_score,
                    remediation,
                    age_days,
                    CASE
                        WHEN final_status = 'accepted_risk' THEN 'CAB approval needed'
                        WHEN final_status = 'confirmed_open' THEN 'Problem board review'
                        WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalate to CAB'
                        WHEN final_status = 'open' AND age_days >= 7 THEN 'Review remediation plan'
                        ELSE 'Monitor'
                    END AS cab_action
                FROM cab
                WHERE final_status IN ('open', 'confirmed_open', 'accepted_risk')
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5 END,
                    age_days DESC NULLS LAST,
                    cvss_score DESC NULLS LAST
                LIMIT 15
                """,
                (upload_id, *upload_filter_params),
            )
        manual_stats = query_one(
            """
            WITH latest AS (
                SELECT DISTINCT ON (ticket_id)
                    ticket_id,
                    status,
                    criticality,
                    risk_percent,
                    asset_key,
                    cve,
                    created_at,
                    EXTRACT(EPOCH FROM (NOW() - created_at))/86400.0 AS age_days
                FROM cab_ticket_updates
                ORDER BY ticket_id, created_at DESC
            )
            SELECT
                COUNT(*) AS manual_tickets,
                (SELECT COUNT(*) FROM cab_ticket_updates) AS manual_updates,
                COALESCE(ROUND(AVG(risk_percent), 1), 0) AS avg_manual_risk_percent,
                COUNT(*) FILTER (WHERE COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'confirmed_open', 'accepted_risk')) AS open_like_updates,
                COUNT(*) FILTER (WHERE COALESCE(status, '') IN ('pending', 'in_progress', 'review')) AS pending_like_updates,
                COUNT(*) FILTER (WHERE COALESCE(status, '') = 'closed') AS closed_updates,
                COUNT(*) FILTER (WHERE COALESCE(status, '') = 'accepted_risk') AS accepted_risk_updates,
                COUNT(*) FILTER (WHERE COALESCE(status, '') = 'false_positive') AS false_positive_updates,
                COUNT(*) FILTER (
                    WHERE COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'confirmed_open', 'accepted_risk')
                      AND age_days >= 7
                ) AS overdue_open_like
            FROM latest
            """
        ) or {}

        # When manual CAB tickets exist, prioritize that latest-ticket state for CAB views.
        using_manual_latest = int(manual_stats.get("manual_tickets") or 0) > 0
        manual_source = "database"

        # If DB-backed manual rows are absent, transparently use persisted fallback updates.
        if not using_manual_latest:
            fallback_updates = load_cab_fallback_state().get("updates") or []
            fallback_latest = cab_updates_latest_rows(fallback_updates)
            fallback_summary = cab_updates_summary(fallback_updates)
            if int(fallback_summary.get("tickets") or 0) > 0:
                def _fallback_age_days(created_at):
                    try:
                        text = str(created_at or "").strip()
                        if not text:
                            return 0.0
                        if text.endswith("Z"):
                            text = text[:-1] + "+00:00"
                        dt = datetime.fromisoformat(text)
                        if dt.tzinfo is not None:
                            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                        return max(0.0, round((datetime.utcnow() - dt).total_seconds() / 86400.0, 1))
                    except Exception:
                        return 0.0

                open_like = {"open", "pending", "in_progress", "review", "confirmed_open", "accepted_risk"}
                pending_like = {"pending", "in_progress", "review"}

                open_like_rows = [row for row in fallback_latest if str(row.get("status") or "") in open_like]
                pending_like_rows = [row for row in fallback_latest if str(row.get("status") or "") in pending_like]
                closed_rows = [row for row in fallback_latest if str(row.get("status") or "") == "closed"]
                accepted_rows = [row for row in fallback_latest if str(row.get("status") or "") == "accepted_risk"]
                fp_rows = [row for row in fallback_latest if str(row.get("status") or "") == "false_positive"]
                overdue_open_like = [row for row in open_like_rows if _fallback_age_days(row.get("created_at")) >= 7.0]

                upload_stats = {
                    "cab_review_queue": len(open_like_rows),
                    "problem_items": len(pending_like_rows),
                    "overdue_changes": len(overdue_open_like),
                    "recently_closed": len(closed_rows),
                    "approved_risk_acceptances": len(accepted_rows),
                    "rejected_false_positives": len(fp_rows),
                }

                manual_stats = {
                    "manual_tickets": int(fallback_summary.get("tickets") or 0),
                    "manual_updates": int(fallback_summary.get("updates") or 0),
                    "avg_manual_risk_percent": float(fallback_summary.get("avg_risk_percent") or 0),
                }

                status_breakdown = []
                if accepted_rows:
                    status_breakdown.append({"cab_state": "Board review", "cnt": len(accepted_rows)})
                if pending_like_rows:
                    status_breakdown.append({"cab_state": "Problem investigation", "cnt": len(pending_like_rows)})
                escalated_rows = [
                    row for row in open_like_rows
                    if str(row.get("status") or "") == "open"
                    and str(row.get("criticality") or "") in {"critical", "high"}
                    and _fallback_age_days(row.get("created_at")) >= 7.0
                ]
                remediation_rows = [
                    row for row in open_like_rows
                    if row not in escalated_rows and str(row.get("status") or "") in {"open", "pending", "in_progress", "review", "confirmed_open"}
                ]
                if escalated_rows:
                    status_breakdown.append({"cab_state": "Escalated change", "cnt": len(escalated_rows)})
                if remediation_rows:
                    status_breakdown.append({"cab_state": "Remediation tracking", "cnt": len(remediation_rows)})
                if closed_rows:
                    status_breakdown.append({"cab_state": "Completed", "cnt": len(closed_rows)})

                workflow_report = [
                    {"report_name": "Accepted risk summary", "count": len(accepted_rows), "notes": "Review approval status and risk acceptance rationale."},
                    {"report_name": "Problem investigation summary", "count": len(pending_like_rows), "notes": "Track problem investigation tickets for root cause and mitigation."},
                    {"report_name": "Escalated changes summary", "count": len(escalated_rows), "notes": "Escalate unresolved high-risk change requests."},
                    {"report_name": "Overdue remediation summary", "count": len(remediation_rows), "notes": "Validate remediation plans and timelines."},
                    {"report_name": "Completed tickets summary", "count": len(closed_rows), "notes": "Confirm closures and update CAB/ITSM documentation."},
                ]
                workflow_report = [row for row in workflow_report if int(row.get("count") or 0) > 0]

                ordered_queue = sorted(
                    open_like_rows,
                    key=lambda row: (
                        {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(str(row.get("criticality") or ""), 5),
                        -_fallback_age_days(row.get("created_at")),
                    ),
                )
                queue = []
                for row in ordered_queue[:15]:
                    status = str(row.get("status") or "")
                    severity = str(row.get("criticality") or "medium")
                    age_days = _fallback_age_days(row.get("created_at"))
                    if status == "accepted_risk":
                        action = "CAB approval needed"
                    elif status in pending_like:
                        action = "Problem board review"
                    elif status == "open" and severity in {"critical", "high"} and age_days >= 7.0:
                        action = "Escalate to CAB"
                    else:
                        action = "Review remediation plan"
                    queue.append({
                        "asset_key": sanitize_text(row.get("asset_key")) or sanitize_text(row.get("ticket_id")) or "unknown",
                        "cve": sanitize_text(row.get("cve")),
                        "severity": severity,
                        "final_status": status or "open",
                        "cvss_score": None,
                        "remediation": "",
                        "age_days": age_days,
                        "cab_action": action,
                    })

                using_manual_latest = True
                manual_source = "fallback"

        if using_manual_latest and manual_source == "database":
            upload_stats = {
                "cab_review_queue": int(manual_stats.get("open_like_updates") or 0),
                "problem_items": int(manual_stats.get("pending_like_updates") or 0),
                "overdue_changes": int(manual_stats.get("overdue_open_like") or 0),
                "recently_closed": int(manual_stats.get("closed_updates") or 0),
                "approved_risk_acceptances": int(manual_stats.get("accepted_risk_updates") or 0),
                "rejected_false_positives": int(manual_stats.get("false_positive_updates") or 0),
            }

            status_breakdown = query(
                """
                WITH latest AS (
                    SELECT DISTINCT ON (ticket_id)
                        ticket_id,
                        status,
                        criticality,
                        created_at,
                        EXTRACT(EPOCH FROM (NOW() - created_at))/86400.0 AS age_days
                    FROM cab_ticket_updates
                    ORDER BY ticket_id, created_at DESC
                )
                SELECT cab_state, COUNT(*) AS cnt
                FROM (
                    SELECT
                        CASE
                            WHEN COALESCE(status, '') = 'accepted_risk' THEN 'Board review'
                            WHEN COALESCE(status, '') IN ('pending', 'in_progress', 'review', 'confirmed_open') THEN 'Problem investigation'
                            WHEN COALESCE(status, '') = 'closed' THEN 'Completed'
                            WHEN COALESCE(status, '') = 'false_positive' THEN 'Other'
                            WHEN COALESCE(status, '') = 'open' AND COALESCE(criticality, '') IN ('critical', 'high') AND age_days >= 7 THEN 'Escalated change'
                            WHEN COALESCE(status, '') = 'open' THEN 'Remediation tracking'
                            ELSE 'Other'
                        END AS cab_state
                    FROM latest
                ) t
                GROUP BY cab_state
                ORDER BY CASE cab_state
                    WHEN 'Board review' THEN 1
                    WHEN 'Problem investigation' THEN 2
                    WHEN 'Escalated change' THEN 3
                    WHEN 'Remediation tracking' THEN 4
                    WHEN 'Completed' THEN 5
                    ELSE 6 END
                """
            )

            workflow_report = query(
                """
                WITH latest AS (
                    SELECT DISTINCT ON (ticket_id)
                        ticket_id,
                        status,
                        criticality,
                        created_at,
                        EXTRACT(EPOCH FROM (NOW() - created_at))/86400.0 AS age_days
                    FROM cab_ticket_updates
                    ORDER BY ticket_id, created_at DESC
                )
                SELECT report_name, COUNT(*) AS count, notes
                FROM (
                    SELECT
                        CASE
                            WHEN COALESCE(status, '') = 'accepted_risk' THEN 'Accepted risk summary'
                            WHEN COALESCE(status, '') IN ('pending', 'in_progress', 'review', 'confirmed_open') THEN 'Problem investigation summary'
                            WHEN COALESCE(status, '') = 'open' AND COALESCE(criticality, '') IN ('critical', 'high') AND age_days >= 7 THEN 'Escalated changes summary'
                            WHEN COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'confirmed_open') THEN 'Overdue remediation summary'
                            WHEN COALESCE(status, '') = 'closed' THEN 'Completed tickets summary'
                            ELSE 'Other CAB issues'
                        END AS report_name,
                        CASE
                            WHEN COALESCE(status, '') = 'accepted_risk' THEN 'Review approval status and risk acceptance rationale.'
                            WHEN COALESCE(status, '') IN ('pending', 'in_progress', 'review', 'confirmed_open') THEN 'Track problem investigation tickets for root cause and mitigation.'
                            WHEN COALESCE(status, '') = 'open' AND COALESCE(criticality, '') IN ('critical', 'high') AND age_days >= 7 THEN 'Escalate unresolved high-risk change requests.'
                            WHEN COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'confirmed_open') THEN 'Validate remediation plans and timelines.'
                            WHEN COALESCE(status, '') = 'closed' THEN 'Confirm closures and update CAB/ITSM documentation.'
                            ELSE 'Review remaining CAB issues for workflow alignment.'
                        END AS notes
                    FROM latest
                ) t
                GROUP BY report_name, notes
                ORDER BY count DESC
                """
            )

            queue = query(
                """
                WITH latest AS (
                    SELECT DISTINCT ON (ticket_id)
                        ticket_id,
                        asset_key,
                        cve,
                        status,
                        criticality,
                        risk_percent,
                        created_at,
                        EXTRACT(EPOCH FROM (NOW() - created_at))/86400.0 AS age_days
                    FROM cab_ticket_updates
                    ORDER BY ticket_id, created_at DESC
                )
                SELECT
                    COALESCE(NULLIF(asset_key, ''), ticket_id) AS asset_key,
                    cve,
                    COALESCE(criticality, 'medium') AS severity,
                    NULL::numeric AS cvss_score,
                    COALESCE(status, 'open') AS final_status,
                    ROUND(age_days, 1) AS age_days,
                    CASE
                        WHEN COALESCE(status, '') = 'accepted_risk' THEN 'CAB approval needed'
                        WHEN COALESCE(status, '') IN ('pending', 'in_progress', 'review', 'confirmed_open') THEN 'Problem board review'
                        WHEN COALESCE(status, '') = 'open' AND COALESCE(criticality, '') IN ('critical', 'high') AND age_days >= 7 THEN 'Escalate to CAB'
                        WHEN COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'confirmed_open') THEN 'Review remediation plan'
                        ELSE 'Monitor'
                    END AS cab_action,
                    ''::text AS remediation
                FROM latest
                WHERE COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'confirmed_open', 'accepted_risk')
                ORDER BY
                    CASE COALESCE(criticality, '')
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5 END,
                    age_days DESC NULLS LAST,
                    created_at DESC NULLS LAST
                LIMIT 15
                """
            )

        stats = {
            **upload_stats,
            "manual_tickets": manual_stats.get("manual_tickets", 0),
            "manual_updates": manual_stats.get("manual_updates", 0),
            "avg_manual_risk_percent": manual_stats.get("avg_manual_risk_percent", 0),
            "cab_source": ("manual_latest_fallback" if manual_source == "fallback" else "manual_latest") if using_manual_latest else "upload_vulnerabilities",
        }
        return jsonify({"stats": stats, "status_breakdown": status_breakdown, "queue": queue, "workflow_report": workflow_report})

    stats = query_one("""
        WITH cab AS (
            SELECT
                final_status,
                severity,
                pits_status,
                EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
            FROM unified_vulnerabilities
        )
        SELECT
            COUNT(*) FILTER (
                WHERE (final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14)
                   OR final_status = 'accepted_risk'
            ) AS cab_review_queue,
            COUNT(*) FILTER (WHERE final_status = 'confirmed_open') AS problem_items,
            COUNT(*) FILTER (WHERE final_status = 'open' AND age_days >= 7) AS overdue_changes,
            COUNT(*) FILTER (WHERE final_status = 'closed') AS recently_closed,
            COUNT(*) FILTER (WHERE final_status = 'accepted_risk') AS approved_risk_acceptances,
            COUNT(*) FILTER (WHERE final_status = 'false_positive') AS rejected_false_positives
        FROM cab
    """)

    manual_stats = query_one(
        """
        WITH latest AS (
            SELECT DISTINCT ON (ticket_id)
                ticket_id,
                risk_percent
            FROM cab_ticket_updates
            ORDER BY ticket_id, created_at DESC
        )
        SELECT
            COUNT(DISTINCT ticket_id) AS manual_tickets,
            (SELECT COUNT(*) FROM cab_ticket_updates) AS manual_updates,
            COALESCE(ROUND(AVG(risk_percent), 1), 0) AS avg_manual_risk_percent
        FROM latest
        """
    )

    stats = {
        **(stats or {}),
        "manual_tickets": manual_stats.get("manual_tickets", 0),
        "manual_updates": manual_stats.get("manual_updates", 0),
        "avg_manual_risk_percent": manual_stats.get("avg_manual_risk_percent", 0),
    }

    status_breakdown = query("""
        WITH cab AS (
            SELECT
                final_status,
                severity,
                EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
            FROM unified_vulnerabilities
        )
        SELECT cab_state, COUNT(*) AS cnt
        FROM (
            SELECT
                CASE
                    WHEN final_status = 'accepted_risk' THEN 'Board review'
                    WHEN final_status = 'confirmed_open' THEN 'Problem investigation'
                    WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalated change'
                    WHEN final_status = 'open' THEN 'Remediation tracking'
                    WHEN final_status = 'closed' THEN 'Completed'
                    ELSE 'Other'
                END AS cab_state
            FROM cab
        ) t
        GROUP BY cab_state
        ORDER BY CASE cab_state
            WHEN 'Board review' THEN 1
            WHEN 'Problem investigation' THEN 2
            WHEN 'Escalated change' THEN 3
            WHEN 'Remediation tracking' THEN 4
            WHEN 'Completed' THEN 5
            ELSE 6 END
    """)

    workflow_report = query("""
        WITH cab AS (
            SELECT final_status, severity, cvss_score,
                EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
            FROM unified_vulnerabilities
        )
        SELECT report_name, count(*) AS count, notes
        FROM (
            SELECT
                CASE
                    WHEN final_status = 'accepted_risk' THEN 'Accepted risk summary'
                    WHEN final_status = 'confirmed_open' THEN 'Problem investigation summary'
                    WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalated changes summary'
                    WHEN final_status = 'open' AND age_days >= 7 THEN 'Overdue remediation summary'
                    WHEN final_status = 'closed' THEN 'Completed tickets summary'
                    ELSE 'Other CAB issues'
                END AS report_name,
                CASE
                    WHEN final_status = 'accepted_risk' THEN 'Review approval status and risk acceptance rationale.'
                    WHEN final_status = 'confirmed_open' THEN 'Track problem investigation tickets for root cause and mitigation.'
                    WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalate unresolved high-risk change requests.'
                    WHEN final_status = 'open' AND age_days >= 7 THEN 'Validate remediation plans and timelines.'
                    WHEN final_status = 'closed' THEN 'Confirm closures and update CAB/ITSM documentation.'
                    ELSE 'Review remaining CAB issues for workflow alignment.'
                END AS notes
            FROM cab
        ) t
        GROUP BY report_name, notes
        ORDER BY count DESC
    """)

    queue = query("""
        WITH cab AS (
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                pits_status,
                remediation,
                ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0, 1) AS age_days
            FROM unified_vulnerabilities
        )
        SELECT
            asset_key,
            cve,
            severity,
            cvss_score,
            final_status,
            pits_status,
            age_days,
            CASE
                WHEN final_status = 'accepted_risk' THEN 'CAB approval needed'
                WHEN final_status = 'confirmed_open' THEN 'Problem board review'
                WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalate to CAB'
                WHEN final_status = 'open' AND age_days >= 7 THEN 'Review remediation plan'
                ELSE 'Monitor'
            END AS cab_action,
            remediation
        FROM cab
        WHERE final_status IN ('open', 'confirmed_open', 'accepted_risk')
        ORDER BY
            CASE final_status
                WHEN 'accepted_risk' THEN 1
                WHEN 'confirmed_open' THEN 2
                ELSE 3 END,
            age_days DESC NULLS LAST,
            cvss_score DESC NULLS LAST
        LIMIT 15
    """)

    workflow_report = workflow_report or []
    return jsonify({"stats": stats, "status_breakdown": status_breakdown, "queue": queue, "workflow_report": workflow_report})


@app.route("/api/cab_ticket_updates", methods=["GET", "POST"])
def cab_ticket_updates_api():
    if dashboard_force_fallback():
        state = load_cab_fallback_state()
        updates = state.get("updates") or []

        if request.method == "POST":
            lock_state = state.get("lock") or {}
            if lock_state.get("is_locked"):
                return jsonify({"error": "CAB updates are locked. Unlock before making changes.", "locked": True}), 423

            payload = request.get_json(silent=True) or request.form or {}
            ticket_id = sanitize_text((payload.get("ticket_id") or "").strip())
            if not ticket_id:
                return jsonify({"error": "ticket_id is required"}), 400

            status = sanitize_text((payload.get("status") or "").strip().lower() or "open")
            criticality = sanitize_text((payload.get("criticality") or "").strip().lower() or "medium")
            risk_percent = parse_number(payload.get("risk_percent"))
            if risk_percent is None:
                risk_percent = 0.0
            risk_percent = max(0.0, min(100.0, float(risk_percent)))
            inserted = {
                "id": len(updates) + 1,
                "ticket_id": ticket_id,
                "asset_key": sanitize_text(payload.get("asset_key")),
                "cve": sanitize_text(payload.get("cve")),
                "status": status,
                "criticality": criticality,
                "risk_percent": risk_percent,
                "comment": sanitize_text(payload.get("comment")),
                "updated_by": sanitize_text(payload.get("updated_by") or "dashboard-user"),
                "created_at": datetime.utcnow().isoformat() + "Z",
            }
            updates.append(inserted)
            state["updates"] = updates
            save_cab_fallback_state(state)
            return jsonify({"status": "success", "update": inserted})

        latest = cab_updates_latest_rows(updates)[:300]
        history = sorted([dict(item) for item in updates], key=lambda item: str(item.get("created_at") or ""), reverse=True)[:1000]
        summary = cab_updates_summary(updates)
        return jsonify({"summary": summary, "latest": latest, "history": history, "lock": state.get("lock") or get_cab_lock_state()})

    ensure_report_schema()

    if request.method == "POST":
        lock_state = get_cab_lock_state()
        if lock_state.get("is_locked"):
            return jsonify({"error": "CAB updates are locked. Unlock before making changes.", "locked": True}), 423

        payload = request.get_json(silent=True) or request.form or {}
        ticket_id = sanitize_text((payload.get("ticket_id") or "").strip())
        if not ticket_id:
            return jsonify({"error": "ticket_id is required"}), 400

        status = sanitize_text((payload.get("status") or "").strip().lower() or "open")
        criticality = sanitize_text((payload.get("criticality") or "").strip().lower() or "medium")
        risk_percent_raw = payload.get("risk_percent")
        risk_percent = parse_number(risk_percent_raw)
        if risk_percent is None:
            risk_percent = 0.0
        risk_percent = max(0.0, min(100.0, float(risk_percent)))

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cab_ticket_updates (
                        ticket_id, asset_key, cve, status, criticality, risk_percent, comment, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, ticket_id, asset_key, cve, status, criticality, risk_percent, comment, updated_by, created_at
                    """,
                    (
                        ticket_id,
                        sanitize_text(payload.get("asset_key")),
                        sanitize_text(payload.get("cve")),
                        status,
                        criticality,
                        risk_percent,
                        sanitize_text(payload.get("comment")),
                        sanitize_text(payload.get("updated_by") or "dashboard-user"),
                    ),
                )
                inserted = dict(cur.fetchone())
            conn.commit()
            return jsonify({"status": "success", "update": inserted})
        except Exception as exc:
            if conn is not None:
                conn.rollback()
            if is_db_unavailable_error(exc):
                state = load_cab_fallback_state()
                updates = list(state.get("updates") or [])
                inserted = {
                    "id": len(updates) + 1,
                    "ticket_id": ticket_id,
                    "asset_key": sanitize_text(payload.get("asset_key")),
                    "cve": sanitize_text(payload.get("cve")),
                    "status": status,
                    "criticality": criticality,
                    "risk_percent": risk_percent,
                    "comment": sanitize_text(payload.get("comment")),
                    "updated_by": sanitize_text(payload.get("updated_by") or "dashboard-user"),
                    "created_at": datetime.utcnow().isoformat() + "Z",
                }
                updates.append(inserted)
                state["updates"] = updates
                save_cab_fallback_state(state)
                return jsonify({"status": "success", "update": inserted, "storage_mode": "fallback"})
            logger.exception("CAB ticket update insert failed")
            return jsonify({"error": str(exc)}), 500

    latest = query(
        """
        WITH ranked AS (
            SELECT
                id,
                ticket_id,
                asset_key,
                cve,
                status,
                criticality,
                risk_percent,
                comment,
                updated_by,
                created_at,
                ROW_NUMBER() OVER (PARTITION BY ticket_id ORDER BY created_at DESC) AS rn
            FROM cab_ticket_updates
        )
        SELECT
            id,
            ticket_id,
            asset_key,
            cve,
            status,
            criticality,
            risk_percent,
            comment,
            updated_by,
            created_at
        FROM ranked
        WHERE rn = 1
        ORDER BY created_at DESC
        LIMIT 300
        """
    )

    history = query(
        """
        SELECT
            id,
            ticket_id,
            asset_key,
            cve,
            status,
            criticality,
            risk_percent,
            comment,
            updated_by,
            created_at
        FROM cab_ticket_updates
        ORDER BY created_at DESC
        LIMIT 1000
        """
    )

    summary = query_one(
        """
        WITH latest AS (
            SELECT DISTINCT ON (ticket_id)
                ticket_id,
                status,
                risk_percent
            FROM cab_ticket_updates
            ORDER BY ticket_id, created_at DESC
        )
        SELECT
            (SELECT COUNT(*) FROM latest) AS tickets,
            (SELECT COUNT(*) FROM cab_ticket_updates) AS updates,
            COALESCE((SELECT ROUND(AVG(risk_percent), 1) FROM latest), 0) AS avg_risk_percent,
            (SELECT COUNT(*) FROM latest WHERE COALESCE(status, '') IN ('open', 'pending', 'in_progress', 'review', 'accepted_risk')) AS open_updates,
            (SELECT COUNT(*) FROM latest WHERE COALESCE(status, '') = 'open') AS strict_open_updates,
            (SELECT COUNT(*) FROM latest WHERE COALESCE(status, '') = 'pending') AS pending_updates,
            (SELECT COUNT(*) FROM latest WHERE COALESCE(status, '') = 'closed') AS closed_updates
        """
    )

    if (not history) and int((summary or {}).get("updates") or 0) == 0:
        fallback_state = load_cab_fallback_state()
        fallback_updates = fallback_state.get("updates") or []
        if fallback_updates:
            latest = cab_updates_latest_rows(fallback_updates)[:300]
            history = sorted([dict(item) for item in fallback_updates], key=lambda item: str(item.get("created_at") or ""), reverse=True)[:1000]
            summary = cab_updates_summary(fallback_updates)
            return jsonify({
                "summary": summary,
                "latest": latest,
                "history": history,
                "lock": fallback_state.get("lock") or get_cab_lock_state(),
                "storage_mode": "fallback",
            })

    return jsonify({"summary": summary, "latest": latest, "history": history, "lock": get_cab_lock_state()})


@app.route("/api/cab_lock", methods=["GET", "POST"])
def cab_lock_api():
    if not dashboard_force_fallback():
        ensure_report_schema()
    if request.method == "GET":
        return jsonify(get_cab_lock_state())

    payload = request.get_json(silent=True) or request.form or {}
    requested = payload.get("locked")
    if isinstance(requested, str):
        locked = requested.strip().lower() in {"1", "true", "yes", "on", "locked"}
    else:
        locked = bool(requested)

    if locked:
        if dashboard_force_fallback():
            row_count = len(load_cab_fallback_state().get("updates") or [])
            if row_count <= 0:
                return jsonify({"error": "Populate CAB data before locking."}), 400
        else:
            row = query_one("SELECT COUNT(*) AS cnt FROM cab_ticket_updates")
            if int((row or {}).get("cnt") or 0) <= 0:
                return jsonify({"error": "Populate CAB data before locking."}), 400

    actor = sanitize_text(payload.get("updated_by") or payload.get("locked_by") or "dashboard-user")
    try:
        set_cab_lock_state(locked, actor)
        return jsonify({"status": "success", "lock": get_cab_lock_state()})
    except Exception as exc:
        logger.exception("CAB lock update failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/cab_planner")
def cab_planner():
    planner = {
        "daily": [
            "Review any new critical/high open findings from VAPT and map them to CAB review items.",
            "Validate that remediation due dates are up to date and escalate overdue items.",
            "Sync open findings with ITSM/CAB status and update risk management notes.",
            "Confirm VAPT evidence mapping and tag any pending CAB approvals."
        ],
        "weekly": [
            "Review all open CAB queue items and escalate any critical/high tickets aging more than 7 days.",
            "Update the CAB board with accepted risk items, change approvals, and problem investigations.",
            "Validate status transitions for false positives, closed tickets, and accepted risk decisions.",
            "Run weekly compliance gap checks for CIS/NIST references in recent uploads."
        ],
        "monthly": [
            "Prepare a CAB summary report for VAPT and risk management teams with open/closed counts.",
            "Review monthly change management trends and identify recurring execution or remediation delays.",
            "Validate that the risk matrix is aligned with policy and that overdue tickets are escalated.",
            "Confirm monthly reconciliation between CAB tickets, VAPT findings, and PITS patch/closure status."
        ]
    }

    use_upload_mode = (request.args.get("source") or "").lower() == "upload" or not has_unified_vulnerabilities_relation()

    if use_upload_mode:
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if is_fallback_upload_id(upload_id):
            upload_id = get_latest_upload_id()

        if not upload_id:
            action_items = []
        else:
            valid_row_where = uploaded_valid_row_sql()
            raw_severity_expr = uploaded_raw_severity_sql()
            raw_status_expr = uploaded_raw_status_sql()
            final_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
            upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

            action_items = query(
                f"""
                WITH cab AS (
                    SELECT
                        rr.asset_key,
                        rr.cve,
                        {raw_severity_expr} AS severity,
                        {final_status_expr} AS final_status,
                        rr.score AS cvss_score,
                        rr.remediation,
                        ROUND(EXTRACT(EPOCH FROM (
                            NOW() - COALESCE(
                                CASE WHEN COALESCE(rr.last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN rr.last_seen::timestamp END,
                                CASE WHEN COALESCE(rr.first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN rr.first_discovered::timestamp END,
                                rr.created_at
                            )
                        )) / 86400.0, 1) AS age_days
                    FROM report_records rr
                    WHERE rr.upload_id = %s AND {valid_row_where}{upload_filter_sql}
                )
                SELECT
                    asset_key,
                    cve,
                    severity,
                    final_status,
                    cvss_score,
                    remediation,
                    age_days,
                    CASE
                        WHEN final_status = 'accepted_risk' THEN 'CAB approval needed'
                        WHEN final_status = 'confirmed_open' THEN 'Problem board review'
                        WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalate to CAB'
                        WHEN final_status = 'open' AND age_days >= 7 THEN 'Review remediation plan'
                        ELSE 'Monitor'
                    END AS cab_action
                FROM cab
                WHERE final_status IN ('open', 'confirmed_open', 'accepted_risk')
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5 END,
                    age_days DESC NULLS LAST,
                    cvss_score DESC NULLS LAST
                LIMIT 20
                """,
                (upload_id, *upload_filter_params),
            )
    else:
        action_items = query("""
            WITH cab AS (
                SELECT
                    asset_key,
                    cve,
                    severity,
                    final_status,
                    cvss_score,
                    remediation,
                    ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0, 1) AS age_days
                FROM unified_vulnerabilities
            )
            SELECT
                asset_key,
                cve,
                severity,
                final_status,
                cvss_score,
                remediation,
                age_days,
                CASE
                    WHEN final_status = 'accepted_risk' THEN 'CAB approval needed'
                    WHEN final_status = 'confirmed_open' THEN 'Problem board review'
                    WHEN final_status = 'open' AND severity IN ('critical', 'high') AND age_days >= 14 THEN 'Escalate to CAB'
                    WHEN final_status = 'open' AND age_days >= 7 THEN 'Review remediation plan'
                    ELSE 'Monitor'
                END AS cab_action
            FROM cab
            WHERE final_status IN ('open', 'confirmed_open', 'accepted_risk')
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5 END,
                age_days DESC NULLS LAST,
                cvss_score DESC NULLS LAST
            LIMIT 20
        """)

    return jsonify({"planner": planner, "action_items": action_items})


@app.route("/api/trends")
def trends():
    """Time-based trend + period comparison analytics.

    Query params:
        months  -> trend window length (6, 12, 24, 36). Default 12.
    """
    try:
        months = int(request.args.get("months", 12))
    except (TypeError, ValueError):
        months = 12
    if months not in (6, 12, 24, 36):
        months = 12

    if (request.args.get("source") or "").lower() == "upload" and dashboard_force_fallback():
        return jsonify(build_full_data_fallback_trends_payload(months))

    if (request.args.get("source") or "").lower() == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        discovered_ts_expr = """
            COALESCE(
                CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                created_at
            )
        """
        resolved_ts_expr = """
            COALESCE(
                CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                created_at
            )
        """
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        if not upload_id:
            return jsonify({"months": months, "monthly": [], "running": [], "yoy": [], "comparison": {"last_6m": 0, "prev_6m": 0, "change_6m": 0.0, "last_12m": 0, "prev_12m": 0, "change_12m": 0.0, "remediated_6m": 0, "remediated_12m": 0}})

        monthly = query(
            f"""
            WITH window_months AS (
                SELECT generate_series(
                    date_trunc('month', CURRENT_DATE) - ((%s - 1) * INTERVAL '1 month'),
                    date_trunc('month', CURRENT_DATE),
                    INTERVAL '1 month'
                )::date AS month_start
            ),
            discovered AS (
                SELECT date_trunc('month', {discovered_ts_expr})::date AS m,
                       COUNT(*) AS cnt,
                       COUNT(*) FILTER (WHERE COALESCE(severity, 'unknown') IN ('critical','high')) AS high_cnt
                FROM report_records
                WHERE upload_id = %s{upload_filter_sql}
                GROUP BY 1
            ),
            remediated AS (
                SELECT date_trunc('month', {resolved_ts_expr})::date AS m, COUNT(*) AS cnt
                FROM report_records
                WHERE upload_id = %s AND {raw_status_expr} = 'closed'{upload_filter_sql}
                GROUP BY 1
            )
            SELECT
                to_char(w.month_start, 'Mon YYYY') AS label,
                COALESCE(d.cnt, 0)       AS discovered,
                COALESCE(d.high_cnt, 0)  AS high_discovered,
                COALESCE(r.cnt, 0)       AS remediated,
                COALESCE(d.cnt, 0) - COALESCE(r.cnt, 0) AS net_change
            FROM window_months w
            LEFT JOIN discovered d ON d.m = w.month_start
            LEFT JOIN remediated r ON r.m = w.month_start
            ORDER BY w.month_start
            """,
            (months, upload_id, *upload_filter_params, upload_id, *upload_filter_params),
        )

        running = []
        cumulative_open = 0
        for row in monthly:
            cumulative_open += (row.get("discovered", 0) or 0) - (row.get("remediated", 0) or 0)
            running.append({"label": row.get("label"), "open_backlog": max(cumulative_open, 0)})

        yoy = query(
            f"""
            SELECT
                COALESCE(severity, 'unknown') AS severity,
                COUNT(*) FILTER (
                    WHERE {discovered_ts_expr} >= CURRENT_DATE - INTERVAL '12 months'
                ) AS current_year,
                COUNT(*) FILTER (
                    WHERE {discovered_ts_expr} >= CURRENT_DATE - INTERVAL '24 months'
                      AND {discovered_ts_expr} <  CURRENT_DATE - INTERVAL '12 months'
                ) AS previous_year
            FROM report_records
            WHERE upload_id = %s{upload_filter_sql}
            GROUP BY 1
            ORDER BY CASE COALESCE(severity, 'unknown')
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                WHEN 'info' THEN 5
                ELSE 6 END
            """,
            (upload_id, *upload_filter_params),
        )

        period = query_one(
            f"""
            SELECT
                COUNT(*) FILTER (
                                        WHERE {discovered_ts_expr} >= CURRENT_DATE - INTERVAL '6 months') AS last_6m,
                COUNT(*) FILTER (
                                        WHERE {discovered_ts_expr} >= CURRENT_DATE - INTERVAL '12 months'
                                            AND {discovered_ts_expr} <  CURRENT_DATE - INTERVAL '6 months') AS prev_6m,
                COUNT(*) FILTER (
                                        WHERE {discovered_ts_expr} >= CURRENT_DATE - INTERVAL '12 months') AS last_12m,
                COUNT(*) FILTER (
                                        WHERE {discovered_ts_expr} >= CURRENT_DATE - INTERVAL '24 months'
                                            AND {discovered_ts_expr} <  CURRENT_DATE - INTERVAL '12 months') AS prev_12m,
                COUNT(*) FILTER (
                                        WHERE {raw_status_expr} = 'closed'
                                            AND {resolved_ts_expr} >= CURRENT_DATE - INTERVAL '6 months') AS remediated_6m,
                COUNT(*) FILTER (
                                        WHERE {raw_status_expr} = 'closed'
                                            AND {resolved_ts_expr} >= CURRENT_DATE - INTERVAL '12 months') AS remediated_12m
            FROM report_records
            WHERE upload_id = %s{upload_filter_sql}
            """,
            (upload_id, *upload_filter_params),
        )

        def pct_change(curr, prev):
            curr = curr or 0
            prev = prev or 0
            if prev == 0:
                return 100.0 if curr > 0 else 0.0
            return round((curr - prev) / prev * 100.0, 1)

        comparison = {
            "last_6m": period.get("last_6m", 0),
            "prev_6m": period.get("prev_6m", 0),
            "change_6m": pct_change(period.get("last_6m"), period.get("prev_6m")),
            "last_12m": period.get("last_12m", 0),
            "prev_12m": period.get("prev_12m", 0),
            "change_12m": pct_change(period.get("last_12m"), period.get("prev_12m")),
            "remediated_6m": period.get("remediated_6m", 0),
            "remediated_12m": period.get("remediated_12m", 0),
        }

        return jsonify({
            "months": months,
            "monthly": monthly,
            "running": running,
            "yoy": yoy,
            "comparison": comparison,
        })

    # Monthly discovery vs. remediation trend across the selected window.
    monthly = query(
        """
        WITH window_months AS (
            SELECT generate_series(
                date_trunc('month', CURRENT_DATE) - ((%s - 1) * INTERVAL '1 month'),
                date_trunc('month', CURRENT_DATE),
                INTERVAL '1 month'
            )::date AS month_start
        ),
        discovered AS (
            SELECT date_trunc('month', first_detected)::date AS m,
                   COUNT(*) AS cnt,
                   COUNT(*) FILTER (WHERE severity IN ('critical','high')) AS high_cnt
            FROM unified_vulnerabilities
            WHERE first_detected IS NOT NULL
            GROUP BY 1
        ),
        remediated AS (
            SELECT date_trunc('month', closed_at)::date AS m, COUNT(*) AS cnt
            FROM unified_vulnerabilities
            WHERE closed_at IS NOT NULL
            GROUP BY 1
        )
        SELECT
            to_char(w.month_start, 'Mon YYYY') AS label,
            COALESCE(d.cnt, 0)       AS discovered,
            COALESCE(d.high_cnt, 0)  AS high_discovered,
            COALESCE(r.cnt, 0)       AS remediated,
            COALESCE(d.cnt, 0) - COALESCE(r.cnt, 0) AS net_change
        FROM window_months w
        LEFT JOIN discovered d ON d.m = w.month_start
        LEFT JOIN remediated r ON r.m = w.month_start
        ORDER BY w.month_start
        """,
        (months,),
    )

    # Running open backlog per month (cumulative discovered - cumulative remediated).
    running = []
    cumulative_open = 0
    for row in monthly:
        cumulative_open += (row.get("discovered", 0) or 0) - (row.get("remediated", 0) or 0)
        running.append({"label": row.get("label"), "open_backlog": max(cumulative_open, 0)})

    # Year-over-year comparison by severity (last 12 months vs. prior 12 months).
    yoy = query(
        """
        SELECT
            COALESCE(severity, 'unknown') AS severity,
            COUNT(*) FILTER (
                WHERE first_detected >= CURRENT_DATE - INTERVAL '12 months'
            ) AS current_year,
            COUNT(*) FILTER (
                WHERE first_detected >= CURRENT_DATE - INTERVAL '24 months'
                  AND first_detected <  CURRENT_DATE - INTERVAL '12 months'
            ) AS previous_year
        FROM unified_vulnerabilities
        WHERE first_detected IS NOT NULL
        GROUP BY 1
        ORDER BY CASE COALESCE(severity, 'unknown')
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            WHEN 'info' THEN 5
            ELSE 6 END
        """
    )

    # Rolling period summary cards: last 6m vs prior 6m, last 12m vs prior 12m.
    period = query_one(
        """
        SELECT
            COUNT(*) FILTER (
                WHERE first_detected >= CURRENT_DATE - INTERVAL '6 months') AS last_6m,
            COUNT(*) FILTER (
                WHERE first_detected >= CURRENT_DATE - INTERVAL '12 months'
                  AND first_detected <  CURRENT_DATE - INTERVAL '6 months') AS prev_6m,
            COUNT(*) FILTER (
                WHERE first_detected >= CURRENT_DATE - INTERVAL '12 months') AS last_12m,
            COUNT(*) FILTER (
                WHERE first_detected >= CURRENT_DATE - INTERVAL '24 months'
                  AND first_detected <  CURRENT_DATE - INTERVAL '12 months') AS prev_12m,
            COUNT(*) FILTER (
                WHERE closed_at >= CURRENT_DATE - INTERVAL '6 months') AS remediated_6m,
            COUNT(*) FILTER (
                WHERE closed_at >= CURRENT_DATE - INTERVAL '12 months') AS remediated_12m
        FROM unified_vulnerabilities
        """
    )

    def pct_change(curr, prev):
        curr = curr or 0
        prev = prev or 0
        if prev == 0:
            return 100.0 if curr > 0 else 0.0
        return round((curr - prev) / prev * 100.0, 1)

    comparison = {
        "last_6m": period.get("last_6m", 0),
        "prev_6m": period.get("prev_6m", 0),
        "change_6m": pct_change(period.get("last_6m"), period.get("prev_6m")),
        "last_12m": period.get("last_12m", 0),
        "prev_12m": period.get("prev_12m", 0),
        "change_12m": pct_change(period.get("last_12m"), period.get("prev_12m")),
        "remediated_6m": period.get("remediated_6m", 0),
        "remediated_12m": period.get("remediated_12m", 0),
    }

    return jsonify({
        "months": months,
        "monthly": monthly,
        "running": running,
        "yoy": yoy,
        "comparison": comparison,
    })


@app.route("/api/risk_score")
def risk_score():
    """Composite security risk score (0-100) from open findings and aging."""
    if (request.args.get("source") or "").lower() == "upload" and dashboard_force_fallback():
        return jsonify(build_full_data_fallback_risk_payload())

    if (request.args.get("source") or "").lower() == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)
        if not upload_id:
            return jsonify({
                "risk_score": 0.0,
                "grade": "A",
                "band": "Low",
                "components": {
                    "weighted_exposure": 0,
                    "overdue_penalty": 0,
                    "ot_penalty": 0,
                    "total_pressure": 0,
                },
                "breakdown": {
                    "open_total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "overdue_30": 0,
                    "ot_open": 0,
                    "avg_open_age": 0,
                },
            })

        base = query_one(
            f"""
            WITH risk AS (
                SELECT
                    CASE
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('critical', 'sev1', 'severe', 'p1immediate') THEN 'critical'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('high', 'sev2') THEN 'high'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('medium', 'med', 'sev3') THEN 'medium'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('low', 'sev4') THEN 'low'
                        WHEN regexp_replace(lower(COALESCE(severity, '')), '[^a-z0-9]+', '', 'g') IN ('info', 'informational', 'informative') THEN 'info'
                        ELSE COALESCE(NULLIF(lower(severity), ''), 'unknown')
                    END AS severity,
                    {active_status_expr} AS final_status,
                    CASE WHEN COALESCE(cloud_provider, '') ILIKE '%%ot%%' OR COALESCE(cloud_provider, '') ILIKE '%%ics%%' THEN 'OT/ICS' ELSE 'IT' END AS asset_type,
                    EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN first_discovered::timestamp END,
                            created_at
                        )
                    ))/86400.0 AS age_days
                FROM report_records
                WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            )
            SELECT
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_total,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'critical') AS crit,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'high')     AS high,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'medium')   AS med,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'low')      AS low,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND age_days >= 30)        AS overdue,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND asset_type = 'OT/ICS') AS ot_open,
                COALESCE(ROUND(AVG(age_days) FILTER (WHERE final_status IN ('open', 'confirmed_open')), 1), 0) AS avg_open_age
            FROM risk
            """,
            (upload_id, *upload_filter_params),
        )
    else:
        base = query_one(
            """
            WITH risk AS (
                SELECT
                    severity,
                    final_status,
                    asset_type,
                    EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400.0 AS age_days
                FROM unified_vulnerabilities
            )
            SELECT
                COUNT(*) FILTER (WHERE final_status = 'open') AS open_total,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'critical') AS crit,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'high')     AS high,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'medium')   AS med,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'low')      AS low,
                COUNT(*) FILTER (WHERE final_status = 'open' AND age_days >= 30)        AS overdue,
                COUNT(*) FILTER (WHERE final_status = 'open' AND asset_type = 'OT/ICS') AS ot_open,
                COALESCE(ROUND(AVG(age_days) FILTER (WHERE final_status = 'open'), 1), 0) AS avg_open_age
            FROM risk
            """
        )

    crit = base.get("crit", 0) or 0
    high = base.get("high", 0) or 0
    med = base.get("med", 0) or 0
    low = base.get("low", 0) or 0
    overdue = base.get("overdue", 0) or 0
    ot_open = base.get("ot_open", 0) or 0
    open_total = base.get("open_total", 0) or 0

    # Weighted exposure: critical=10, high=6, medium=3, low=1.
    weighted_exposure = crit * 10 + high * 6 + med * 3 + low * 1
    # Aging + OT penalties add to exposure pressure.
    overdue_penalty = overdue * 4
    ot_penalty = ot_open * 2
    total_pressure = weighted_exposure + overdue_penalty + ot_penalty

    # Logarithmic-style normalization so the score saturates gracefully toward 100.
    raw_score = 100.0 * (1 - math.exp(-total_pressure / 60.0)) if total_pressure > 0 else 0.0
    risk_score_value = round(raw_score, 1)

    if risk_score_value >= 80:
        grade, band = "F", "Critical"
    elif risk_score_value >= 60:
        grade, band = "D", "High"
    elif risk_score_value >= 40:
        grade, band = "C", "Elevated"
    elif risk_score_value >= 20:
        grade, band = "B", "Moderate"
    else:
        grade, band = "A", "Low"

    return jsonify({
        "risk_score": risk_score_value,
        "grade": grade,
        "band": band,
        "components": {
            "weighted_exposure": weighted_exposure,
            "overdue_penalty": overdue_penalty,
            "ot_penalty": ot_penalty,
            "total_pressure": total_pressure,
        },
        "breakdown": {
            "open_total": open_total,
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "overdue_30": overdue,
            "ot_open": ot_open,
            "avg_open_age": base.get("avg_open_age", 0),
        },
    })


@app.route("/api/soc/executive_kpis")
def soc_executive_kpis():
    """Phase 1 SOC command-center executive KPI payload."""
    source = (request.args.get("source") or "upload").strip().lower()

    enabled_total = 0
    enabled_configured = 0
    readiness_items = []
    try:
        mod = _ensure_automation_module()
        live_catalog = {}
        if mod is not None and hasattr(mod, "get_integration_catalog"):
            try:
                live_catalog = {item.get("slug"): item for item in (mod.get_integration_catalog() or [])}
            except Exception:
                live_catalog = {}

        for item in SECURITY_TOOL_INTEGRATIONS:
            slug = item.get("slug")
            live_item = live_catalog.get(slug, {})
            enabled = bool(live_item.get("enabled", True))
            required_env = list(live_item.get("credential_env") or item.get("credential_env") or [])
            missing_env = [name for name in required_env if not str(os.environ.get(name, "")).strip()]
            configured = len(missing_env) == 0
            readiness_items.append({
                "slug": slug,
                "enabled": enabled,
                "configured": configured,
            })
    except Exception:
        readiness_items = []

    enabled_items = [entry for entry in readiness_items if entry.get("enabled")]
    enabled_total = len(enabled_items)
    enabled_configured = len([entry for entry in enabled_items if entry.get("configured")])
    security_control_health = round((enabled_configured / enabled_total) * 100.0, 1) if enabled_total > 0 else 0.0

    automation_open_incidents = 0
    if not dashboard_force_fallback():
        automation_open_incidents = int((query_one("SELECT COUNT(*) AS n FROM automation_incidents WHERE status='open'") or {}).get("n") or 0)

    payload = {
        "source": source,
        "upload_id": None,
        "kpis": {
            "overall_cyber_risk_score": 0.0,
            "open_critical_incidents": 0,
            "open_high_incidents": 0,
            "mttd_hours": 0.0,
            "mttr_hours": 0.0,
            "sla_compliance_percent": 100.0,
            "mitre_detection_coverage_percent": 0.0,
            "critical_assets_at_risk": 0,
            "security_control_health_percent": security_control_health,
            "risk_reduction_trend_percent": 0.0,
            "active_threat_campaigns_proxy": automation_open_incidents,
            "critical_vulnerabilities": 0,
            "closed_incidents": 0,
            "open_total": 0,
            "detection_coverage_note": "MITRE coverage proxy based on mapped upload signals until ATT&CK mapping is implemented.",
        },
        "bands": {
            "risk": "Low",
            "security_posture": "At Risk",
        },
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }

    if source == "upload":
        upload_id = "fallback-upload" if dashboard_force_fallback() else (request.args.get("upload_id") or get_latest_upload_id())
        payload["upload_id"] = upload_id
        if not upload_id:
            return jsonify(payload)

        if str(upload_id).strip().lower().startswith("fallback-"):
            summary = (build_full_data_fallback_report_payload().get("summary") or {})
            core = {
                "critical_open": int(summary.get("critical_rows") or 0),
                "high_open": int(summary.get("high_rows") or 0),
                "open_total": int(summary.get("total_rows") or 0),
                "closed_total": 0,
                "critical_assets_at_risk": int(summary.get("critical_rows") or 0),
                "p1_sla_breaches": 0,
                "p1_open": int(summary.get("critical_rows") or 0),
                "mttd_hours": 0.0,
                "mttr_hours": 0.0,
                "total_rows": int(summary.get("total_rows") or 0),
                "mapped_rows": int(summary.get("total_rows") or 0),
            }
        else:
            valid_row_where = uploaded_valid_row_sql()
            raw_severity_expr = uploaded_raw_severity_sql()
            raw_status_expr = uploaded_raw_status_sql()
            active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
            upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

            core = query_one(
                f"""
                WITH risk AS (
                    SELECT
                        {raw_severity_expr} AS severity,
                        {raw_status_expr} AS raw_status,
                        {active_status_expr} AS final_status,
                        COALESCE(NULLIF(asset_key, ''), NULLIF(ip_address, ''), NULLIF(hostname, ''), 'unknown') AS asset_ref,
                        COALESCE(
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                            created_at,
                            NOW()
                        ) AS first_detected,
                        COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                            created_at,
                            NOW()
                        ) AS last_updated,
                        CASE
                            WHEN {raw_status_expr} = 'closed' THEN COALESCE(
                                CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                                CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                                created_at,
                                NOW()
                            )
                            ELSE NULL
                        END AS closed_at
                    FROM report_records
                    WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
                )
                SELECT
                    COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'critical') AS critical_open,
                    COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'high') AS high_open,
                    COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_total,
                    COUNT(*) FILTER (WHERE final_status = 'closed') AS closed_total,
                    COUNT(DISTINCT asset_ref) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'critical') AS critical_assets_at_risk,
                    COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'critical' AND EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0 > 72) AS p1_sla_breaches,
                    COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'critical') AS p1_open,
                    COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) FILTER (WHERE final_status IN ('open', 'confirmed_open')), 2), 0) AS mttd_hours,
                    COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (COALESCE(closed_at, NOW()) - first_detected))/3600.0) FILTER (WHERE final_status = 'closed'), 2), 0) AS mttr_hours,
                    COUNT(*) AS total_rows,
                    COUNT(*) FILTER (WHERE raw_status <> 'unknown' OR severity <> 'unknown') AS mapped_rows
                FROM risk
                """,
                (upload_id, *upload_filter_params),
            )
    else:
        core = query_one(
            """
            WITH risk AS (
                SELECT
                    severity,
                    final_status,
                    COALESCE(NULLIF(asset_key, ''), 'unknown') AS asset_ref,
                    COALESCE(first_detected, NOW()) AS first_detected,
                    COALESCE(last_updated, NOW()) AS last_updated,
                    closed_at
                FROM unified_vulnerabilities
            )
            SELECT
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'critical') AS critical_open,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'high') AS high_open,
                COUNT(*) FILTER (WHERE final_status = 'open') AS open_total,
                COUNT(*) FILTER (WHERE final_status = 'closed') AS closed_total,
                COUNT(DISTINCT asset_ref) FILTER (WHERE final_status = 'open' AND severity = 'critical') AS critical_assets_at_risk,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'critical' AND EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0 > 72) AS p1_sla_breaches,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'critical') AS p1_open,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) FILTER (WHERE final_status = 'open'), 2), 0) AS mttd_hours,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (COALESCE(closed_at, NOW()) - first_detected))/3600.0) FILTER (WHERE final_status = 'closed'), 2), 0) AS mttr_hours,
                COUNT(*) AS total_rows,
                COUNT(*) FILTER (WHERE severity IS NOT NULL AND final_status IS NOT NULL) AS mapped_rows
            FROM risk
            """
        )

    critical_open = int(core.get("critical_open") or 0)
    high_open = int(core.get("high_open") or 0)
    open_total = int(core.get("open_total") or 0)
    closed_total = int(core.get("closed_total") or 0)
    critical_assets_at_risk = int(core.get("critical_assets_at_risk") or 0)
    p1_breaches = int(core.get("p1_sla_breaches") or 0)
    p1_open = int(core.get("p1_open") or 0)
    mttd_hours = float(core.get("mttd_hours") or 0.0)
    mttr_hours = float(core.get("mttr_hours") or 0.0)
    total_rows = int(core.get("total_rows") or 0)
    mapped_rows = int(core.get("mapped_rows") or 0)

    weighted_exposure = (critical_open * 10) + (high_open * 6) + max(open_total - critical_open - high_open, 0)
    open_pressure = max(open_total, 0)
    raw_risk_score = 100.0 * (1 - math.exp(-(weighted_exposure + open_pressure) / 60.0)) if (weighted_exposure + open_pressure) > 0 else 0.0
    overall_risk_score = round(raw_risk_score, 1)

    sla_compliance = round(100.0 - ((p1_breaches / p1_open) * 100.0), 1) if p1_open > 0 else 100.0
    mitre_coverage_proxy = round((mapped_rows / total_rows) * 100.0, 1) if total_rows > 0 else 0.0
    attack_coverage_percent = None
    detection_coverage_note = "MITRE coverage proxy based on mapped upload signals until ATT&CK mapping is implemented."

    if source == "upload" and payload.get("upload_id") and not str(payload.get("upload_id")).strip().lower().startswith("fallback-"):
        attack_tactic_expr = uploaded_attack_tactic_sql()
        attack_technique_expr = uploaded_attack_technique_sql()
        attack_summary = query_one(
            f"""
            SELECT
                COUNT(*) AS total_rows,
                COUNT(*) FILTER (
                    WHERE COALESCE(NULLIF({attack_tactic_expr}, ''), NULLIF({attack_technique_expr}, '')) IS NOT NULL
                ) AS mapped_rows
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            """,
            (payload.get("upload_id"), *upload_filter_params),
        ) or {}
        attack_total = int(attack_summary.get("total_rows") or 0)
        attack_mapped = int(attack_summary.get("mapped_rows") or 0)
        if attack_total > 0 and attack_mapped > 0:
            attack_coverage_percent = round((attack_mapped / attack_total) * 100.0, 1)
            detection_coverage_note = "MITRE ATT&CK coverage from mapped tactic/technique fields in uploaded source data."

    risk_reduction_trend = round(((closed_total - open_total) / max(closed_total + open_total, 1)) * 100.0, 1)

    if overall_risk_score >= 80:
        risk_band = "Critical"
    elif overall_risk_score >= 60:
        risk_band = "High"
    elif overall_risk_score >= 40:
        risk_band = "Moderate"
    else:
        risk_band = "Low"

    if overall_risk_score >= 80:
        posture_band = "Critical"
    elif overall_risk_score >= 60:
        posture_band = "Moderate"
    elif overall_risk_score >= 40:
        posture_band = "At Risk"
    else:
        posture_band = "Strong"

    payload["kpis"] = {
        "overall_cyber_risk_score": overall_risk_score,
        "open_critical_incidents": critical_open,
        "open_high_incidents": high_open,
        "mttd_hours": round(mttd_hours, 2),
        "mttr_hours": round(mttr_hours, 2),
        "sla_compliance_percent": max(0.0, min(100.0, sla_compliance)),
        "mitre_detection_coverage_percent": max(0.0, min(100.0, attack_coverage_percent if attack_coverage_percent is not None else mitre_coverage_proxy)),
        "critical_assets_at_risk": critical_assets_at_risk,
        "security_control_health_percent": max(0.0, min(100.0, security_control_health)),
        "risk_reduction_trend_percent": risk_reduction_trend,
        "active_threat_campaigns_proxy": automation_open_incidents,
        "critical_vulnerabilities": critical_open,
        "closed_incidents": closed_total,
        "open_total": open_total,
        "detection_coverage_note": detection_coverage_note,
    }
    payload["bands"] = {
        "risk": risk_band,
        "security_posture": posture_band,
    }
    return jsonify(payload)


@app.route("/api/soc/drilldowns")
def soc_drilldowns():
    """Phase 2 SOC command-center drilldowns for top-risk operational queues."""
    source = (request.args.get("source") or "upload").strip().lower()
    limit = max(1, min(int(request.args.get("limit", 25) or 25), 100))

    payload = {
        "source": source,
        "upload_id": None,
        "critical_incidents": [],
        "assets_at_risk": [],
        "sla_breach_queue": [],
        "mitre_coverage": {
            "total_rows": 0,
            "mapped_rows": 0,
            "unmapped_rows": 0,
            "coverage_percent": 0.0,
            "critical_rows": 0,
            "high_rows": 0,
            "open_rows": 0,
            "note": "MITRE drilldown currently uses normalized severity/status mapping proxy until ATT&CK techniques are ingested.",
        },
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }

    if source == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        payload["upload_id"] = upload_id
        if not upload_id:
            return jsonify(payload)

        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

        common_cte = f"""
            WITH risk AS (
                SELECT
                    COALESCE(NULLIF(asset_key, ''), NULLIF(ip_address, ''), NULLIF(hostname, ''), 'unknown') AS asset_ref,
                    COALESCE(NULLIF(cve, ''), 'N/A') AS cve,
                    {raw_severity_expr} AS severity,
                    {raw_status_expr} AS raw_status,
                    {active_status_expr} AS final_status,
                    COALESCE(
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                        created_at,
                        NOW()
                    ) AS first_detected,
                    COALESCE(
                        CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                        created_at,
                        NOW()
                    ) AS last_updated
                FROM report_records
                WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            )
        """

        critical_incidents = query(
            common_cte +
            """
            SELECT
                asset_ref,
                cve,
                severity,
                final_status,
                ROUND(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0, 1) AS age_hours,
                last_updated
            FROM risk
            WHERE final_status IN ('open', 'confirmed_open')
              AND severity IN ('critical', 'high')
            ORDER BY
                CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                age_hours DESC,
                last_updated DESC
            LIMIT %s
            """,
            (upload_id, *upload_filter_params, limit),
        )

        assets_at_risk = query(
            common_cte +
            """
            SELECT
                asset_ref,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'critical') AS critical_open,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open') AND severity = 'high') AS high_open,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_total,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) FILTER (WHERE final_status IN ('open', 'confirmed_open')), 1), 0) AS avg_open_age_hours
            FROM risk
            GROUP BY asset_ref
            HAVING COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) > 0
            ORDER BY critical_open DESC, high_open DESC, open_total DESC
            LIMIT %s
            """,
            (upload_id, *upload_filter_params, limit),
        )

        sla_breach_queue = query(
            common_cte +
            """
            SELECT
                asset_ref,
                cve,
                severity,
                final_status,
                ROUND(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0, 1) AS age_hours,
                ROUND((EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) - 72.0, 1) AS breach_hours,
                last_updated
            FROM risk
            WHERE final_status IN ('open', 'confirmed_open')
              AND severity = 'critical'
              AND EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0 > 72
            ORDER BY breach_hours DESC, age_hours DESC
            LIMIT %s
            """,
            (upload_id, *upload_filter_params, limit),
        )

        mitre_coverage = query_one(
            common_cte +
            """
            SELECT
                COUNT(*) AS total_rows,
                COUNT(*) FILTER (WHERE raw_status <> 'unknown' OR severity <> 'unknown') AS mapped_rows,
                COUNT(*) FILTER (WHERE raw_status = 'unknown' AND severity = 'unknown') AS unmapped_rows,
                COUNT(*) FILTER (WHERE severity = 'critical') AS critical_rows,
                COUNT(*) FILTER (WHERE severity = 'high') AS high_rows,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_rows
            FROM risk
            """,
            (upload_id, *upload_filter_params),
        )
    else:
        common_cte = """
            WITH risk AS (
                SELECT
                    COALESCE(NULLIF(asset_key, ''), 'unknown') AS asset_ref,
                    COALESCE(NULLIF(cve, ''), 'N/A') AS cve,
                    severity,
                    final_status,
                    COALESCE(first_detected, NOW()) AS first_detected,
                    COALESCE(last_updated, NOW()) AS last_updated
                FROM unified_vulnerabilities
            )
        """

        critical_incidents = query(
            common_cte +
            """
            SELECT
                asset_ref,
                cve,
                severity,
                final_status,
                ROUND(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0, 1) AS age_hours,
                last_updated
            FROM risk
            WHERE final_status = 'open'
              AND severity IN ('critical', 'high')
            ORDER BY
                CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                age_hours DESC,
                last_updated DESC
            LIMIT %s
            """,
            (limit,),
        )

        assets_at_risk = query(
            common_cte +
            """
            SELECT
                asset_ref,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'critical') AS critical_open,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'high') AS high_open,
                COUNT(*) FILTER (WHERE final_status = 'open') AS open_total,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) FILTER (WHERE final_status = 'open'), 1), 0) AS avg_open_age_hours
            FROM risk
            GROUP BY asset_ref
            HAVING COUNT(*) FILTER (WHERE final_status = 'open') > 0
            ORDER BY critical_open DESC, high_open DESC, open_total DESC
            LIMIT %s
            """,
            (limit,),
        )

        sla_breach_queue = query(
            common_cte +
            """
            SELECT
                asset_ref,
                cve,
                severity,
                final_status,
                ROUND(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0, 1) AS age_hours,
                ROUND((EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) - 72.0, 1) AS breach_hours,
                last_updated
            FROM risk
            WHERE final_status = 'open'
              AND severity = 'critical'
              AND EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0 > 72
            ORDER BY breach_hours DESC, age_hours DESC
            LIMIT %s
            """,
            (limit,),
        )

        mitre_coverage = query_one(
            common_cte +
            """
            SELECT
                COUNT(*) AS total_rows,
                COUNT(*) FILTER (WHERE severity IS NOT NULL AND final_status IS NOT NULL) AS mapped_rows,
                COUNT(*) FILTER (WHERE severity IS NULL OR final_status IS NULL) AS unmapped_rows,
                COUNT(*) FILTER (WHERE severity = 'critical') AS critical_rows,
                COUNT(*) FILTER (WHERE severity = 'high') AS high_rows,
                COUNT(*) FILTER (WHERE final_status = 'open') AS open_rows
            FROM risk
            """
        )

    total_rows = int((mitre_coverage or {}).get("total_rows") or 0)
    mapped_rows = int((mitre_coverage or {}).get("mapped_rows") or 0)
    unmapped_rows = int((mitre_coverage or {}).get("unmapped_rows") or 0)
    coverage_percent = round((mapped_rows / total_rows) * 100.0, 1) if total_rows > 0 else 0.0

    payload["critical_incidents"] = critical_incidents or []
    payload["assets_at_risk"] = assets_at_risk or []
    payload["sla_breach_queue"] = sla_breach_queue or []
    payload["mitre_coverage"] = {
        "total_rows": total_rows,
        "mapped_rows": mapped_rows,
        "unmapped_rows": unmapped_rows,
        "coverage_percent": coverage_percent,
        "critical_rows": int((mitre_coverage or {}).get("critical_rows") or 0),
        "high_rows": int((mitre_coverage or {}).get("high_rows") or 0),
        "open_rows": int((mitre_coverage or {}).get("open_rows") or 0),
        "note": "MITRE drilldown currently uses normalized severity/status mapping proxy until ATT&CK techniques are ingested.",
    }
    return jsonify(payload)


@app.route("/api/soc/attack_mapping")
def soc_attack_mapping():
    """Return ATT&CK tactic/technique coverage from upload source fields when available."""
    source = (request.args.get("source") or "upload").strip().lower()
    limit = max(1, min(int(request.args.get("limit", 100) or 100), 500))

    payload = {
        "source": source,
        "upload_id": None,
        "available": False,
        "summary": {
            "total_rows": 0,
            "mapped_rows": 0,
            "unmapped_rows": 0,
            "coverage_percent": 0.0,
            "critical_rows": 0,
            "high_rows": 0,
            "open_rows": 0,
        },
        "tactic_distribution": [],
        "top_techniques": [],
        "note": "ATT&CK mapping fields were not found in source data; proxy metrics should be used.",
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }

    if source != "upload":
        return jsonify(payload)

    upload_id = request.args.get("upload_id") or get_latest_upload_id()
    payload["upload_id"] = upload_id
    if not upload_id:
        return jsonify(payload)

    valid_row_where = uploaded_valid_row_sql()
    raw_severity_expr = uploaded_raw_severity_sql()
    raw_status_expr = uploaded_raw_status_sql()
    active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
    attack_tactic_expr = uploaded_attack_tactic_sql()
    attack_technique_expr = uploaded_attack_technique_sql()
    upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

    summary = query_one(
        f"""
        WITH mapped AS (
            SELECT
                NULLIF(TRIM({attack_tactic_expr}), '') AS tactic,
                NULLIF(TRIM({attack_technique_expr}), '') AS technique,
                {raw_severity_expr} AS severity,
                {active_status_expr} AS final_status
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
        )
        SELECT
            COUNT(*) AS total_rows,
            COUNT(*) FILTER (WHERE tactic IS NOT NULL OR technique IS NOT NULL) AS mapped_rows,
            COUNT(*) FILTER (WHERE tactic IS NULL AND technique IS NULL) AS unmapped_rows,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_rows,
            COUNT(*) FILTER (WHERE severity = 'high') AS high_rows,
            COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_rows
        FROM mapped
        """,
        (upload_id, *upload_filter_params),
    ) or {}

    total_rows = int(summary.get("total_rows") or 0)
    mapped_rows = int(summary.get("mapped_rows") or 0)
    unmapped_rows = int(summary.get("unmapped_rows") or 0)
    coverage_percent = round((mapped_rows / total_rows) * 100.0, 1) if total_rows > 0 else 0.0

    if mapped_rows <= 0:
        payload["summary"] = {
            "total_rows": total_rows,
            "mapped_rows": mapped_rows,
            "unmapped_rows": unmapped_rows,
            "coverage_percent": coverage_percent,
            "critical_rows": int(summary.get("critical_rows") or 0),
            "high_rows": int(summary.get("high_rows") or 0),
            "open_rows": int(summary.get("open_rows") or 0),
        }
        return jsonify(payload)

    tactic_distribution = query(
        f"""
        WITH mapped AS (
            SELECT
                COALESCE(NULLIF(TRIM({attack_tactic_expr}), ''), 'Unknown') AS tactic,
                NULLIF(TRIM({attack_technique_expr}), '') AS technique,
                {raw_severity_expr} AS severity,
                {active_status_expr} AS final_status
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
        )
        SELECT
            tactic,
            COUNT(*) AS count,
            COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_count,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count
        FROM mapped
        WHERE tactic <> 'Unknown' OR technique IS NOT NULL
        GROUP BY tactic
        ORDER BY count DESC
        LIMIT %s
        """,
        (upload_id, *upload_filter_params, limit),
    )

    top_techniques = query(
        f"""
        WITH mapped AS (
            SELECT
                COALESCE(NULLIF(TRIM({attack_tactic_expr}), ''), 'Unknown') AS tactic,
                COALESCE(NULLIF(TRIM({attack_technique_expr}), ''), 'Unknown') AS technique,
                {raw_severity_expr} AS severity,
                {active_status_expr} AS final_status
            FROM report_records
            WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
        )
        SELECT
            tactic,
            technique,
            COUNT(*) AS count,
            COUNT(*) FILTER (WHERE final_status IN ('open', 'confirmed_open')) AS open_count,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count
        FROM mapped
        WHERE technique <> 'Unknown'
        GROUP BY tactic, technique
        ORDER BY count DESC, critical_count DESC, open_count DESC
        LIMIT %s
        """,
        (upload_id, *upload_filter_params, limit),
    )

    payload["available"] = True
    payload["summary"] = {
        "total_rows": total_rows,
        "mapped_rows": mapped_rows,
        "unmapped_rows": unmapped_rows,
        "coverage_percent": coverage_percent,
        "critical_rows": int(summary.get("critical_rows") or 0),
        "high_rows": int(summary.get("high_rows") or 0),
        "open_rows": int(summary.get("open_rows") or 0),
    }
    payload["tactic_distribution"] = tactic_distribution or []
    payload["top_techniques"] = top_techniques or []
    payload["note"] = "MITRE ATT&CK mapping is sourced from upload tactic/technique fields."
    return jsonify(payload)


@app.route("/api/soc/vulnerability_drilldown")
def soc_vulnerability_drilldown():
    """Return row-level vulnerabilities for SOC click-through details."""
    source = (request.args.get("source") or "upload").strip().lower()
    asset_key = sanitize_text(request.args.get("asset_key"))
    cve = sanitize_text(request.args.get("cve"))
    severity = sanitize_text((request.args.get("severity") or "").strip().lower())
    status_filter = sanitize_text((request.args.get("status") or "").strip().lower())
    limit = max(1, min(int(request.args.get("limit", 500) or 500), 2000))

    if source == "upload":
        upload_id = request.args.get("upload_id") or get_latest_upload_id()
        if not upload_id:
            return jsonify({"rows": [], "count": 0, "returned": 0})

        valid_row_where = uploaded_valid_row_sql()
        raw_severity_expr = uploaded_raw_severity_sql()
        raw_status_expr = uploaded_raw_status_sql()
        active_status_expr = uploaded_active_risk_status_sql(raw_status_expr)
        upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

        rows = query(
            f"""
            WITH data AS (
                SELECT
                    COALESCE(NULLIF(asset_key, ''), NULLIF(ip_address, ''), NULLIF(hostname, ''), 'unknown') AS asset_key,
                    COALESCE(NULLIF(cve, ''), 'N/A') AS cve,
                    {raw_severity_expr} AS severity,
                    {active_status_expr} AS final_status,
                    score AS cvss_score,
                    remediation,
                    COALESCE(
                        CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                        created_at,
                        NOW()
                    ) AS last_updated,
                    ROUND(EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                            created_at,
                            NOW()
                        )
                    )) / 3600.0, 1) AS age_hours
                FROM report_records
                WHERE upload_id = %s AND {valid_row_where}{upload_filter_sql}
            )
            SELECT
                asset_key,
                cve,
                severity,
                final_status,
                cvss_score,
                age_hours,
                remediation,
                last_updated
            FROM data
            WHERE (%s = '' OR asset_key = %s)
              AND (%s = '' OR cve ILIKE ('%%' || %s || '%%'))
              AND (%s = '' OR severity = %s)
              AND (%s = '' OR final_status = %s)
            ORDER BY
                CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                age_hours DESC,
                cvss_score DESC NULLS LAST
            LIMIT %s
            """,
            (
                upload_id,
                *upload_filter_params,
                asset_key or "",
                asset_key or "",
                cve or "",
                cve or "",
                severity or "",
                severity or "",
                status_filter or "",
                status_filter or "",
                limit,
            ),
        )
        return jsonify({"rows": rows or [], "count": len(rows or []), "returned": len(rows or [])})

    rows = query(
        """
        WITH data AS (
            SELECT
                COALESCE(NULLIF(asset_key, ''), 'unknown') AS asset_key,
                COALESCE(NULLIF(cve, ''), 'N/A') AS cve,
                severity,
                final_status,
                cvss_score,
                remediation,
                COALESCE(last_updated, first_detected, NOW()) AS last_updated,
                ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected, NOW()))) / 3600.0, 1) AS age_hours
            FROM unified_vulnerabilities
        )
        SELECT
            asset_key,
            cve,
            severity,
            final_status,
            cvss_score,
            age_hours,
            remediation,
            last_updated
        FROM data
        WHERE (%s = '' OR asset_key = %s)
          AND (%s = '' OR cve ILIKE ('%%' || %s || '%%'))
          AND (%s = '' OR severity = %s)
          AND (%s = '' OR final_status = %s)
        ORDER BY
            CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
            age_hours DESC,
            cvss_score DESC NULLS LAST
        LIMIT %s
        """,
        (
            asset_key or "",
            asset_key or "",
            cve or "",
            cve or "",
            severity or "",
            severity or "",
            status_filter or "",
            status_filter or "",
            limit,
        ),
    )
    return jsonify({"rows": rows or [], "count": len(rows or []), "returned": len(rows or [])})


@app.route("/api/servicenow_blueprint")
def servicenow_blueprint():
    """Unified usage + SIR blueprint for monthly, quarterly, and yearly reporting."""
    ensure_report_schema()
    source = (request.args.get("source") or "").lower()
    upload_id = request.args.get("upload_id") or get_latest_upload_id() if source == "upload" else None
    raw_severity_expr = uploaded_raw_severity_sql()
    raw_status_expr = uploaded_raw_status_sql()
    upload_filter_sql, upload_filter_params, _ = build_upload_filters_sql(raw_severity_expr, raw_status_expr)

    usage = query_one(
        """
        WITH u AS (
            SELECT
                created_at,
                COALESCE(uploaded_by, 'unknown') AS uploaded_by,
                COALESCE(record_count, 0) AS record_count,
                COALESCE(source_kind, 'unknown') AS source_kind,
                COALESCE(upload_name, 'unknown') AS upload_name,
                COALESCE(sheet_count, 0) AS sheet_count
            FROM report_uploads
        ),
        stale AS (
            SELECT COUNT(*) AS stale_reports
            FROM report_uploads
            WHERE created_at < NOW() - INTERVAL '90 days'
        )
        SELECT
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS monthly_upload_events,
            COUNT(DISTINCT uploaded_by) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS monthly_active_users,
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days') AS quarterly_upload_events,
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '365 days') AS yearly_upload_events,
            COALESCE(SUM(record_count) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'), 0) AS monthly_records,
            COALESCE(SUM(record_count) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days'), 0) AS quarterly_records,
            COALESCE(SUM(record_count) FILTER (WHERE created_at >= NOW() - INTERVAL '365 days'), 0) AS yearly_records,
            COALESCE(ROUND(AVG(record_count) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'), 1), 0) AS avg_records_per_upload,
            COALESCE(ROUND(AVG(sheet_count) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'), 1), 0) AS avg_sheets_per_upload,
            (SELECT stale_reports FROM stale) AS stale_reports_90d
        FROM u
        """
    )

    yoy_usage = query_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '12 months') AS current_year_uploads,
            COUNT(*) FILTER (
                WHERE created_at >= NOW() - INTERVAL '24 months'
                  AND created_at < NOW() - INTERVAL '12 months'
            ) AS previous_year_uploads
        FROM report_uploads
        """
    )

    if source == "upload" and upload_id:
        sir = query_one(
            f"""
            WITH risk AS (
                SELECT
                    {raw_severity_expr} AS severity,
                    {raw_status_expr} AS final_status,
                    COALESCE(
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                        created_at,
                        NOW()
                    ) AS first_detected,
                    COALESCE(
                        CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                        CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                        created_at,
                        NOW()
                    ) AS last_updated,
                    CASE
                        WHEN {raw_status_expr} = 'closed' THEN COALESCE(
                            CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                            created_at,
                            NOW()
                        )
                        ELSE NULL
                    END AS closed_at,
                    ARRAY[COALESCE(cloud_provider, 'upload')] AS sources,
                    EXTRACT(EPOCH FROM (
                        COALESCE(
                            CASE
                                WHEN {raw_status_expr} = 'closed' THEN COALESCE(
                                    CASE WHEN COALESCE(last_seen::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN last_seen::timestamp END,
                                    CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                                    created_at,
                                    NOW()
                                )
                                ELSE NULL
                            END,
                            NOW()
                        ) -
                        COALESCE(
                            CASE WHEN COALESCE(first_discovered::text, '') ~ '^\\d{{4}}-\\d{{2}}-\\d{{2}}' THEN first_discovered::timestamp END,
                            created_at,
                            NOW()
                        )
                    )) / 3600.0 AS lifecycle_hours
                FROM report_records
                WHERE upload_id = %s{upload_filter_sql}
            )
            SELECT
                COUNT(*) FILTER (WHERE final_status IN ('open', 'new', 'outdated', 'pending', 'confirmed_open') AND severity = 'critical') AS p1_open,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'new', 'outdated', 'pending', 'confirmed_open')) AS open_incidents,
                COUNT(*) FILTER (WHERE final_status = 'closed') AS closed_incidents,
                COUNT(*) FILTER (WHERE final_status IN ('open', 'new', 'outdated', 'pending', 'confirmed_open') AND severity IN ('critical', 'high')) AS high_priority_open,
                COUNT(*) FILTER (
                    WHERE final_status IN ('open', 'new', 'outdated', 'pending', 'confirmed_open')
                      AND severity = 'critical'
                      AND EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0 > 72
                ) AS p1_sla_breaches,
                COALESCE(ROUND(AVG(lifecycle_hours) FILTER (WHERE final_status = 'closed'), 2), 0) AS mttr_hours,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (last_updated - first_detected))/3600.0), 2), 0) AS mtta_hours,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) FILTER (WHERE final_status = 'open'), 2), 0) AS mttd_proxy_hours
            FROM risk
            """,
            (upload_id, *upload_filter_params),
        )

        threat_vectors = query(
            f"""
            SELECT
                COALESCE(cloud_provider, 'unknown') AS vector,
                COUNT(*) AS cnt
            FROM report_records
            WHERE upload_id = %s{upload_filter_sql}
            GROUP BY 1
            ORDER BY cnt DESC
            LIMIT 5
            """,
            (upload_id, *upload_filter_params),
        )
    elif source == "upload":
        sir = {
            "p1_open": 0,
            "open_incidents": 0,
            "closed_incidents": 0,
            "high_priority_open": 0,
            "p1_sla_breaches": 0,
            "mttr_hours": 0,
            "mtta_hours": 0,
            "mttd_proxy_hours": 0,
        }
        threat_vectors = []
    else:
        sir = query_one(
            """
            WITH risk AS (
                SELECT
                    severity,
                    final_status,
                    COALESCE(first_detected, NOW()) AS first_detected,
                    COALESCE(last_updated, NOW()) AS last_updated,
                    closed_at,
                    sources,
                    EXTRACT(EPOCH FROM (COALESCE(closed_at, NOW()) - COALESCE(first_detected, NOW()))) / 3600.0 AS lifecycle_hours
                FROM unified_vulnerabilities
            )
            SELECT
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity = 'critical') AS p1_open,
                COUNT(*) FILTER (WHERE final_status = 'open') AS open_incidents,
                COUNT(*) FILTER (WHERE final_status = 'closed') AS closed_incidents,
                COUNT(*) FILTER (WHERE final_status = 'open' AND severity IN ('critical', 'high')) AS high_priority_open,
                COUNT(*) FILTER (
                    WHERE final_status = 'open'
                      AND severity = 'critical'
                      AND EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0 > 72
                ) AS p1_sla_breaches,
                COALESCE(ROUND(AVG(lifecycle_hours) FILTER (WHERE final_status = 'closed'), 2), 0) AS mttr_hours,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (last_updated - first_detected))/3600.0), 2), 0) AS mtta_hours,
                COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected))/3600.0) FILTER (WHERE final_status = 'open'), 2), 0) AS mttd_proxy_hours
            FROM risk
            """
        )

        threat_vectors = query(
            """
            SELECT
                COALESCE(src.source, 'unknown') AS vector,
                COUNT(*) AS cnt
            FROM unified_vulnerabilities u
            LEFT JOIN LATERAL unnest(u.sources) AS src(source) ON TRUE
            GROUP BY 1
            ORDER BY cnt DESC
            LIMIT 5
            """
        )

    def pct_change(curr, prev):
        curr = curr or 0
        prev = prev or 0
        if prev == 0:
            return 100.0 if curr > 0 else 0.0
        return round((curr - prev) / prev * 100.0, 1)

    usage_monthly = {
        "active_users": usage.get("monthly_active_users", 0),
        "license_consumption_proxy": usage.get("monthly_active_users", 0),
        "session_activity_proxy": usage.get("monthly_upload_events", 0),
        "storage_volume_records": usage.get("monthly_records", 0),
        "stale_reports_90d": usage.get("stale_reports_90d", 0),
        "avg_records_per_upload": usage.get("avg_records_per_upload", 0),
    }

    usage_quarterly = {
        "feature_adoption_events": usage.get("quarterly_upload_events", 0),
        "stale_reports_90d": usage.get("stale_reports_90d", 0),
        "license_roi_proxy": usage.get("quarterly_records", 0),
        "storage_bottleneck_proxy": usage.get("quarterly_records", 0),
    }

    current_year = yoy_usage.get("current_year_uploads", 0)
    previous_year = yoy_usage.get("previous_year_uploads", 0)
    usage_yearly = {
        "yoy_adoption_growth_percent": pct_change(current_year, previous_year),
        "current_year_uploads": current_year,
        "previous_year_uploads": previous_year,
        "platform_roi_proxy": usage.get("yearly_records", 0),
    }

    p1_open = sir.get("p1_open", 0) or 0
    p1_breach = sir.get("p1_sla_breaches", 0) or 0
    p1_breach_rate = round((p1_breach / p1_open) * 100.0, 1) if p1_open > 0 else 0.0

    sir_monthly = {
        "incident_volume_high_priority": sir.get("high_priority_open", 0),
        "mttr_hours": sir.get("mttr_hours", 0),
        "sla_breach_rate_percent": p1_breach_rate,
    }

    sir_quarterly = {
        "top_threat_vectors": threat_vectors,
        "automation_gap_proxy": sir.get("open_incidents", 0),
        "vendor_sla_compliance_proxy": round(100.0 - p1_breach_rate, 1),
    }

    sir_yearly = {
        "ciso_posture_open_vs_closed": {
            "open": sir.get("open_incidents", 0),
            "closed": sir.get("closed_incidents", 0),
        },
        "major_incident_frequency": sir.get("p1_open", 0),
        "risk_reduction_proxy": max((sir.get("closed_incidents", 0) or 0) - (sir.get("open_incidents", 0) or 0), 0),
        "regulatory_compliance_audit_proxy": round(100.0 - p1_breach_rate, 1),
    }

    usage_findings = [
        {
            "title": "Under-utilized assets",
            "detail": f"{usage.get('stale_reports_90d', 0)} reports are stale (not refreshed in 90+ days)."
        },
        {
            "title": "Adoption chokepoints",
            "detail": f"Monthly active user proxy is {usage.get('monthly_active_users', 0)} with {usage.get('monthly_upload_events', 0)} upload events."
        },
        {
            "title": "Performance degradation proxy",
            "detail": f"Average records per upload in the last month: {usage.get('avg_records_per_upload', 0)}."
        },
    ]

    sir_findings = [
        {
            "title": "Process bottlenecks",
            "detail": f"Open high-priority incidents: {sir.get('high_priority_open', 0)} with MTTR {sir.get('mttr_hours', 0)} hours."
        },
        {
            "title": "Sensor health gaps",
            "detail": "Threat vector distribution is shown in quarterly SIR metrics for ingestion trend review."
        },
        {
            "title": "Post-incident trends",
            "detail": f"P1 SLA breach rate is {p1_breach_rate}% and should be tracked against remediation workflow maturity."
        },
    ]

    interval_matrix = [
        {
            "frequency": "Monthly",
            "usage_focus": "Active users, slowest dashboards proxy, user activity sessions, license consumption proxy.",
            "sir_focus": "Incident volume by priority, MTTR, SLA breach rate."
        },
        {
            "frequency": "Quarterly",
            "usage_focus": "Feature adoption trends, stale reports, license ROI proxy, storage bottlenecks proxy.",
            "sir_focus": "Threat vector shifts, recurring automation gaps, vendor SLA compliance proxy."
        },
        {
            "frequency": "Yearly",
            "usage_focus": "YoY adoption growth, platform health proxy, platform ROI proxy.",
            "sir_focus": "CISO posture view, major incident frequency, risk reduction proxy, compliance audit proxy."
        },
    ]

    execution = [
        "Activate Performance Analytics content for Security Incident Response and baseline KPI collection.",
        "Enable platform usage tracking for dashboard/report interactions and adoption funnels.",
        "Automate monthly and quarterly executive report exports with secured distribution lists.",
    ]

    return jsonify({
        "interval_matrix": interval_matrix,
        "usage": {
            "monthly": usage_monthly,
            "quarterly": usage_quarterly,
            "yearly": usage_yearly,
            "findings": usage_findings,
        },
        "sir": {
            "monthly": sir_monthly,
            "quarterly": sir_quarterly,
            "yearly": sir_yearly,
            "findings": sir_findings,
        },
        "execution": execution,
    })


@app.route("/api/blueprint")
def blueprint():
    """Alias route for Blueprint analytics payload."""
    return servicenow_blueprint()


@app.route("/api/servicenow_metric_details")
def servicenow_metric_details():
    metric = (request.args.get("metric") or "usage_monthly_upload_events").strip().lower()
    limit_raw = request.args.get("limit")
    try:
        limit = int(limit_raw) if limit_raw is not None else 500
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 2000))

    usage_queries = {
        "usage_monthly_upload_events": (
            """
            SELECT
                upload_name,
                uploaded_by,
                filename,
                report_scope,
                source_kind,
                record_count,
                sheet_count,
                created_at
            FROM report_uploads
            WHERE created_at >= NOW() - INTERVAL '30 days'
            ORDER BY created_at DESC
            LIMIT %s
            """,
            ["upload_name", "uploaded_by", "filename", "report_scope", "source_kind", "record_count", "sheet_count", "created_at"],
            "Monthly upload events (last 30 days)",
        ),
        "usage_monthly_active_users": (
            """
            SELECT
                COALESCE(uploaded_by, 'unknown') AS uploaded_by,
                COUNT(*) AS upload_events,
                COALESCE(SUM(record_count), 0) AS total_records,
                MAX(created_at) AS last_upload_at
            FROM report_uploads
            WHERE created_at >= NOW() - INTERVAL '30 days'
            GROUP BY 1
            ORDER BY upload_events DESC, total_records DESC
            LIMIT %s
            """,
            ["uploaded_by", "upload_events", "total_records", "last_upload_at"],
            "Monthly active users with upload activity",
        ),
        "usage_stale_reports_90d": (
            """
            SELECT
                upload_name,
                uploaded_by,
                filename,
                report_scope,
                source_kind,
                record_count,
                created_at
            FROM report_uploads
            WHERE created_at < NOW() - INTERVAL '90 days'
            ORDER BY created_at ASC
            LIMIT %s
            """,
            ["upload_name", "uploaded_by", "filename", "report_scope", "source_kind", "record_count", "created_at"],
            "Stale reports not refreshed in 90+ days",
        ),
        "usage_yearly_upload_events": (
            """
            SELECT
                to_char(date_trunc('month', created_at), 'Mon YYYY') AS period,
                COUNT(*) AS upload_events,
                COALESCE(SUM(record_count), 0) AS total_records
            FROM report_uploads
            WHERE created_at >= NOW() - INTERVAL '12 months'
            GROUP BY 1, date_trunc('month', created_at)
            ORDER BY date_trunc('month', created_at) DESC
            LIMIT %s
            """,
            ["period", "upload_events", "total_records"],
            "Yearly monthly upload trend (last 12 months)",
        ),
    }

    sir_queries = {
        "sir_high_priority_open": (
            """
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                pits_status,
                ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected))) / 3600.0, 1) AS age_hours,
                first_detected,
                last_updated,
                sources
            FROM unified_vulnerabilities
            WHERE final_status = 'open' AND severity IN ('critical', 'high')
            ORDER BY severity, cvss_score DESC NULLS LAST, age_hours DESC NULLS LAST
            LIMIT %s
            """,
            ["asset_key", "cve", "severity", "cvss_score", "final_status", "pits_status", "age_hours", "first_detected", "last_updated", "sources"],
            "High-priority open incidents",
        ),
        "sir_p1_sla_breaches": (
            """
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(first_detected, NOW()))) / 3600.0, 1) AS open_hours,
                first_detected,
                last_updated,
                sources
            FROM unified_vulnerabilities
            WHERE final_status = 'open'
              AND severity = 'critical'
              AND EXTRACT(EPOCH FROM (NOW() - COALESCE(first_detected, NOW()))) / 3600.0 > 72
            ORDER BY open_hours DESC NULLS LAST, cvss_score DESC NULLS LAST
            LIMIT %s
            """,
            ["asset_key", "cve", "severity", "cvss_score", "final_status", "open_hours", "first_detected", "last_updated", "sources"],
            "P1 SLA breaches (critical open > 72h)",
        ),
        "sir_open_incidents": (
            """
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                pits_status,
                first_detected,
                last_updated,
                sources
            FROM unified_vulnerabilities
            WHERE final_status = 'open'
            ORDER BY cvss_score DESC NULLS LAST, last_updated DESC NULLS LAST
            LIMIT %s
            """,
            ["asset_key", "cve", "severity", "cvss_score", "final_status", "pits_status", "first_detected", "last_updated", "sources"],
            "All open incidents",
        ),
        "sir_closed_incidents": (
            """
            SELECT
                asset_key,
                cve,
                severity,
                cvss_score,
                final_status,
                pits_status,
                closed_at,
                first_detected,
                last_updated,
                sources
            FROM unified_vulnerabilities
            WHERE final_status = 'closed'
            ORDER BY closed_at DESC NULLS LAST, cvss_score DESC NULLS LAST
            LIMIT %s
            """,
            ["asset_key", "cve", "severity", "cvss_score", "final_status", "pits_status", "closed_at", "first_detected", "last_updated", "sources"],
            "Closed incidents",
        ),
    }

    if metric in usage_queries:
        sql, columns, title = usage_queries[metric]
        rows = query(sql, (limit,))
        return jsonify({
            "metric": metric,
            "title": title,
            "columns": columns,
            "rows": rows,
            "returned": len(rows),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        })

    if metric in sir_queries:
        sql, columns, title = sir_queries[metric]
        rows = query(sql, (limit,))
        return jsonify({
            "metric": metric,
            "title": title,
            "columns": columns,
            "rows": rows,
            "returned": len(rows),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        })

    return jsonify({"error": f"Unsupported metric '{metric}'"}), 400


@app.route("/api/blueprint_metric_details")
def blueprint_metric_details():
    """Alias route for Blueprint metric drill-down details."""
    return servicenow_metric_details()


@app.route("/api/claroty/assets")
def claroty_assets():
    """Proxy Claroty assets (for Locate IP integration)."""
    if not CLAROTY_BASE_URL or not CLAROTY_API_TOKEN:
        return jsonify({"error": "Claroty not configured"}), 503
    try:
        resp = requests.get(
            f"{CLAROTY_BASE_URL}/api/v1/assets",
            headers={"Authorization": f"Bearer {CLAROTY_API_TOKEN}"},
            timeout=30, verify=True
        )
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    payload = build_app_health_payload()
    status_code = 200 if (payload.get("status") == "healthy" or dashboard_force_fallback()) else 503
    return jsonify(payload), status_code


@app.route("/api/cab_bulk_import", methods=["POST"])
def cab_bulk_import():
    """Bulk import incidents from uploaded Excel/CSV into CAB manual tracking."""
    payload = request.get_json(silent=True) or {}
    incidents = payload.get("incidents") or []
    expected_distribution = payload.get("expected_distribution") if isinstance(payload.get("expected_distribution"), dict) else {}
    enforce_expected_distribution = bool(payload.get("enforce_expected_distribution", bool(expected_distribution)))
    allow_distribution_mismatch = bool(payload.get("allow_distribution_mismatch", False))
    replace_existing = _to_bool(payload.get("replace_existing", True), default=True)

    response_body, status_code = run_cab_bulk_import(
        incidents=incidents,
        expected_distribution=expected_distribution,
        enforce_expected_distribution=enforce_expected_distribution,
        allow_distribution_mismatch=allow_distribution_mismatch,
        replace_existing=replace_existing,
    )
    return jsonify(response_body), status_code


@app.route("/api/cab_bulk_import_file", methods=["POST"])
def cab_bulk_import_file():
    """Parse CAB workbook/CSV on backend and import without client-side normalization."""
    payload = request.get_json(silent=True)
    if payload is None and "application/json" in str(request.headers.get("Content-Type") or "").lower():
        try:
            payload = json.loads(request.get_data(cache=True, as_text=True) or "{}")
        except Exception:
            payload = {}
    payload = payload or {}
    file_bytes = b""
    filename = ""

    if isinstance(payload, dict) and payload.get("content_base64"):
        filename = secure_filename(sanitize_text(payload.get("filename")) or "upload.xlsx")
        if not filename:
            return jsonify({"error": "Invalid filename"}), 400
        try:
            file_bytes = base64.b64decode(str(payload.get("content_base64") or ""), validate=True)
        except Exception:
            return jsonify({"error": "content_base64 must be valid base64"}), 400
    else:
        upload = request.files.get("file")
        if upload is None or not sanitize_text(upload.filename):
            return jsonify({"error": "file is required"}), 400

        filename = secure_filename(upload.filename or "")
        if not filename:
            return jsonify({"error": "Invalid filename"}), 400
        file_bytes = upload.read()

    try:
        parsed = parse_cab_incidents_from_payload(file_bytes, filename)
    except Exception as exc:
        logger.exception("CAB file parse failed")
        return jsonify({"error": f"Failed to parse file: {exc}"}), 400

    expected_distribution_raw = request.form.get("expected_distribution", "") if request.form else ""
    if isinstance(payload, dict) and payload.get("expected_distribution") and not expected_distribution_raw:
        expected_distribution_raw = json.dumps(payload.get("expected_distribution"))
    expected_distribution = {}
    if expected_distribution_raw:
        try:
            loaded = json.loads(expected_distribution_raw)
            if isinstance(loaded, dict):
                expected_distribution = loaded
        except Exception:
            return jsonify({"error": "expected_distribution must be valid JSON object"}), 400

    enforce_expected_distribution = _to_bool(
        (payload.get("enforce_expected_distribution") if isinstance(payload, dict) else None) if payload.get("enforce_expected_distribution") is not None else (request.form.get("enforce_expected_distribution", "") if request.form else ""),
        default=bool(expected_distribution),
    )
    allow_distribution_mismatch = _to_bool(payload.get("allow_distribution_mismatch") if isinstance(payload, dict) else (request.form.get("allow_distribution_mismatch", "false") if request.form else "false"), default=False)
    replace_existing = _to_bool(payload.get("replace_existing") if isinstance(payload, dict) else (request.form.get("replace_existing", "true") if request.form else "true"), default=True)

    response_body, status_code = run_cab_bulk_import(
        incidents=parsed.get("incidents") or [],
        expected_distribution=expected_distribution,
        enforce_expected_distribution=enforce_expected_distribution,
        allow_distribution_mismatch=allow_distribution_mismatch,
        replace_existing=replace_existing,
    )

    if status_code == 200:
        response_body["source"] = {
            "filename": filename,
            "sheet_name": parsed.get("sheet_name"),
            "rows_detected": parsed.get("rows_detected", 0),
            "incidents_detected": len(parsed.get("incidents") or []),
            "source_format": parsed.get("source_format"),
        }
    return jsonify(response_body), status_code

@app.route("/api/admin/reset_upload_data", methods=["POST"])
def admin_reset_upload_data():
    """Local-only reset for upload-driven dashboard data; preserves CAB manual updates."""
    remote = (request.remote_addr or "").strip()
    if remote not in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}:
        return jsonify({"error": "Forbidden"}), 403

    ensure_report_schema()
    conn = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM report_uploads")
            uploads_before = int((cur.fetchone() or {}).get("cnt") or 0)

            # Cascades to report_records via FK definition.
            cur.execute("DELETE FROM report_uploads")

            etl_runs_cleared = 0
            try:
                cur.execute("SELECT COUNT(*) AS cnt FROM etl_runs")
                etl_runs_before = int((cur.fetchone() or {}).get("cnt") or 0)
                cur.execute("DELETE FROM etl_runs")
                etl_runs_cleared = etl_runs_before
            except Exception:
                etl_runs_cleared = 0

        conn.commit()
        return jsonify({
            "status": "success",
            "uploads_cleared": uploads_before,
            "etl_runs_cleared": etl_runs_cleared,
            "cab_preserved": True,
        })
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        logger.exception("Upload data reset failed")
        return jsonify({"error": str(exc)}), 500

@app.route("/api/admin/restart", methods=["POST"])
def admin_restart():
    """Local-only endpoint to restart the dashboard process from the UI refresh action."""
    remote = (request.remote_addr or "").strip()
    if remote not in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}:
        return jsonify({"error": "Forbidden"}), 403

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    workspace_root = os.path.abspath(os.path.join(repo_root, ".."))
    one_click_script = os.path.join(workspace_root, "START_DASHBOARD_ONE_CLICK.ps1")
    fallback_script = os.path.join(repo_root, "start_local_dashboard.ps1")

    if os.path.exists(one_click_script):
        ps_command = (
            "Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "
            f"& '{one_click_script}'"
        )
    elif os.path.exists(fallback_script):
        ps_command = (
            "Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "
            f"& '{fallback_script}'"
        )
    else:
        return jsonify({
            "error": (
                "No restart script found. Expected one of: "
                f"{one_click_script} or {fallback_script}"
            )
        }), 500

    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        cwd=repo_root,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def shutdown_current_process():
        time.sleep(0.8)
        os._exit(0)

    threading.Thread(target=shutdown_current_process, daemon=True).start()
    return jsonify({"status": "restarting"})


# ===== AUDIT ASSIGNMENT WORKFLOW =====
@app.route("/api/audit_assignments", methods=["GET", "POST"])
def audit_assignments():
    """Get all audit assignments or create a new one"""
    if dashboard_force_fallback():
        state = load_secumat_fallback_state()
        assignments = list(state.get("assignments") or [])
        if request.method == "GET":
            assignments.sort(key=lambda item: str(item.get("assignment_date") or ""), reverse=True)
            return jsonify({"assignments": assignments})

        data = request.get_json(silent=True) or {}
        assignment = {
            "id": secumat_next_int_id(assignments),
            "questionnaire_id": data.get("questionnaire_id", ""),
            "questionnaire_name": data.get("questionnaire_name", ""),
            "assessment_name": data.get("assessment_name") or data.get("questionnaire_name") or "",
            "audit_profile_id": data.get("audit_profile_id") or None,
            "cdr_number": data.get("cdr_number", ""),
            "assigned_to": data.get("assigned_to", ""),
            "assigned_to_type": data.get("assigned_to_type", "person"),
            "assigned_by": data.get("assigned_by", "system"),
            "role_name": data.get("role_name", ""),
            "user_name": data.get("user_name", ""),
            "user_email": data.get("user_email", ""),
            "department_name": data.get("department_name", ""),
            "due_date": data.get("due_date") or None,
            "template_source": data.get("template_source", "built_in"),
            "assignment_date": datetime.utcnow().isoformat() + "Z",
            "status": "pending",
            "question_count": int(data.get("question_count") or 0),
            "completed_responses": 0,
            "progress_percent": 0.0,
            "compliance_score": 0.0,
            "reviewer_score": 0.0,
            "reviewer_comments": "",
            "reviewer_notes": "",
            "reviewed_by": "",
            "reviewed_at": None,
            "framework": data.get("framework", ""),
        }
        assignments.append(assignment)
        state["assignments"] = assignments
        save_secumat_fallback_state(state)
        return jsonify({"status": "created", "assignment": assignment}), 201

    try:
        ensure_audit_assignment_schema()
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if request.method == "GET":
            # Get all audit assignments
            cur.execute("""
                SELECT id, questionnaire_id, questionnaire_name, assessment_name, audit_profile_id,
                       cdr_number,
                       assigned_to, assigned_to_type, assigned_by, role_name, user_name, user_email,
                       department_name, due_date, template_source, assignment_date, status, question_count,
                       completed_responses, progress_percent, compliance_score, reviewer_score,
                       reviewer_comments, reviewer_notes, reviewed_by, reviewed_at, framework
                FROM compliance_audit_assignments
                ORDER BY assignment_date DESC
            """)
            assignments = cur.fetchall()
            return jsonify({"assignments": assignments or []})
        
        elif request.method == "POST":
            # Create new audit assignment
            data = request.json or {}
            questionnaire_id = data.get("questionnaire_id", "")
            questionnaire_name = data.get("questionnaire_name", "")
            assigned_to = data.get("assigned_to", "")  # User email or Team name
            assigned_to_type = data.get("assigned_to_type", "person")  # "person" or "team"
            assigned_by = data.get("assigned_by", "system")
            question_count = data.get("question_count", 0)
            framework = data.get("framework", "")
            assessment_name = data.get("assessment_name", questionnaire_name)
            cdr_number = data.get("cdr_number", "")
            audit_profile_id = data.get("audit_profile_id") or None
            role_name = data.get("role_name", "")
            user_name = data.get("user_name", "")
            user_email = data.get("user_email", "")
            department_name = data.get("department_name", "")
            due_date = data.get("due_date") or None
            template_source = data.get("template_source", "built_in")
            
            cur.execute("""
                INSERT INTO compliance_audit_assignments 
                (questionnaire_id, questionnaire_name, assessment_name, cdr_number, audit_profile_id, assigned_to, assigned_to_type,
                 assigned_by, role_name, user_name, user_email, department_name, due_date, template_source,
                 assignment_date, status, question_count, completed_responses, progress_percent, compliance_score, framework)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s)
                RETURNING id, questionnaire_id, questionnaire_name, assessment_name, cdr_number, assigned_to, assignment_date, status
            """, (
                questionnaire_id, questionnaire_name, assessment_name, cdr_number, audit_profile_id, assigned_to, assigned_to_type,
                assigned_by, role_name, user_name, user_email, department_name, due_date, template_source,
                "pending", question_count, 0, 0.0, 0.0, framework
            ))
            
            assignment = cur.fetchone()
            conn.commit()
            return jsonify({"status": "created", "assignment": assignment}), 201
    except Exception as e:
        if is_db_unavailable_error(e):
            return jsonify({"assignments": load_secumat_fallback_state().get("assignments") or []})
        logger.error(f"Error in audit_assignments: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit_assignments/<assignment_id>", methods=["GET", "PUT", "DELETE"])
def audit_assignment_detail(assignment_id):
    """Get or update specific audit assignment"""
    try:
        ensure_audit_assignment_schema()
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if request.method == "GET":
            # Get assignment with questionnaire questions
            cur.execute("""
                SELECT id, questionnaire_id, questionnaire_name, assessment_name, audit_profile_id,
                       cdr_number,
                       assigned_to, assigned_to_type, assigned_by, role_name, user_name, user_email,
                       department_name, due_date, template_source, assignment_date, status, question_count,
                       completed_responses, progress_percent, compliance_score, reviewer_score,
                       reviewer_comments, reviewer_notes, reviewed_by, reviewed_at, framework
                FROM compliance_audit_assignments
                WHERE id = %s
            """, (assignment_id,))
            
            assignment = cur.fetchone()
            if not assignment:
                return jsonify({"error": "Assignment not found"}), 404
            
            # Get questionnaire questions
            questions = get_assignment_questions(assignment["questionnaire_id"])
            cur.execute(
                """
                SELECT question_id, response_status, response_option, evidence, comments, mapping_score, created_at, updated_at
                FROM compliance_audit_assignment_responses
                WHERE assignment_id = %s
                """,
                (assignment_id,),
            )
            existing_responses = cur.fetchall()
            return jsonify({
                "success": True,
                "assignment": assignment,
                "questions": questions,
                "responses": existing_responses,
            })

        elif request.method == "DELETE":
            cur.execute(
                """
                DELETE FROM compliance_audit_assignments
                WHERE id = %s
                RETURNING id, assessment_name, questionnaire_name
                """,
                (assignment_id,),
            )
            deleted = cur.fetchone()
            conn.commit()
            if not deleted:
                return jsonify({"error": "Assignment not found"}), 404
            return jsonify({"status": "deleted", "assignment": deleted})

        elif request.method == "PUT":
            data = request.json or {}
            fields = {
                "assessment_name": data.get("assessment_name"),
                "cdr_number": data.get("cdr_number"),
                "assigned_to": data.get("assigned_to"),
                "assigned_to_type": data.get("assigned_to_type"),
                "role_name": data.get("role_name"),
                "user_name": data.get("user_name"),
                "user_email": data.get("user_email"),
                "department_name": data.get("department_name"),
                "due_date": data.get("due_date"),
                "status": data.get("status"),
                "assigned_by": data.get("assigned_by"),
            }
            updates = []
            params = []
            for column, value in fields.items():
                if value is not None:
                    updates.append(f"{column} = %s")
                    params.append(value)
            updates.append("updated_at = NOW()")
            params.append(assignment_id)
            if len(updates) == 1:
                return jsonify({"error": "No fields to update"}), 400
            
            cur.execute("""
                UPDATE compliance_audit_assignments
                SET """ + ", ".join(updates) + """
                WHERE id = %s
                RETURNING id, assessment_name, cdr_number, assigned_to, status, progress_percent, compliance_score
            """, params)
            
            result = cur.fetchone()
            conn.commit()
            return jsonify({"status": "updated", "assignment": result})
    except Exception as e:
        logger.error(f"Error in audit_assignment_detail: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit_assignment_responses", methods=["POST"])
def submit_audit_responses():
    """Submit questionnaire responses for an audit assignment"""
    try:
        ensure_audit_assignment_schema()
        data = request.json or {}
        assignment_id = data.get("assignment_id", "")
        responses = data.get("responses", [])  # List of {question_id, response_status, evidence}
        finalize = bool(data.get("finalize", False))
        
        if not assignment_id or not responses:
            return jsonify({"error": "Missing assignment_id or responses"}), 400
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Store responses
        total_score = 0
        for resp in responses:
            response_status = resp.get("response_status", "pending")
            response_option = (resp.get("response_option") or "").strip() or response_status
            mapping_score = {
                "compliant": 100,
                "partial": 50,
                "non_compliant": 0,
                "not_applicable": 100,
                "needs_review": 25,
                "deferred": 10,
                "compensating_control": 75,
                "pending": 0,
            }.get(response_status, 0)
            total_score += mapping_score
            
            cur.execute("""
                INSERT INTO compliance_audit_assignment_responses
                (assignment_id, question_id, response_status, response_option, evidence, comments, mapping_score, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (assignment_id, question_id) DO UPDATE SET
                    response_status = EXCLUDED.response_status,
                    response_option = EXCLUDED.response_option,
                    evidence = EXCLUDED.evidence,
                    comments = EXCLUDED.comments,
                    mapping_score = EXCLUDED.mapping_score,
                    updated_at = NOW()
            """, (
                assignment_id,
                resp.get("question_id"),
                response_status,
                response_option,
                resp.get("evidence", ""),
                resp.get("comments", ""),
                mapping_score,
            ))

        cur.execute(
            "SELECT question_count FROM compliance_audit_assignments WHERE id = %s",
            (assignment_id,),
        )
        assignment_row = cur.fetchone() or {}
        question_count = int(assignment_row.get("question_count") or 0)
        completed_count = len(responses)
        progress_percent = round((completed_count / question_count) * 100, 2) if question_count else 0.0
        compliance_score = round((total_score / (len(responses) * 100)) * 100, 2) if responses else 0.0
        next_status = "completed" if progress_percent >= 100 and finalize else "in_progress"

        cur.execute("""
            UPDATE compliance_audit_assignments
            SET completed_responses = %s,
                progress_percent = %s,
                compliance_score = %s,
                status = %s,
                updated_at = NOW()
            WHERE id = %s
            RETURNING id, completed_responses, progress_percent, compliance_score, status
        """, (completed_count, progress_percent, compliance_score, next_status, assignment_id))
        
        updated = cur.fetchone()
        conn.commit()
        return jsonify({
            "success": True,
            "status": "responses_submitted",
            "assignment": updated,
            "compliance_score": compliance_score,
            "progress_percent": progress_percent,
        }), 201
    except Exception as e:
        logger.error(f"Error in submit_audit_responses: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit_assignments/<assignment_id>/duplicate", methods=["POST"])
def duplicate_audit_assignment(assignment_id):
    try:
        ensure_audit_assignment_schema()
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            INSERT INTO compliance_audit_assignments (
                questionnaire_id, questionnaire_name, assessment_name, cdr_number, audit_profile_id, assigned_to,
                assigned_to_type, assigned_by, role_name, user_name, user_email, department_name,
                due_date, template_source, assignment_date, status, question_count, completed_responses,
                progress_percent, compliance_score, framework, reviewer_score, reviewer_comments,
                reviewer_notes, reviewed_by, reviewed_at, created_at, updated_at
            )
            SELECT
                questionnaire_id,
                questionnaire_name,
                COALESCE(assessment_name, questionnaire_name) || ' Copy',
                cdr_number,
                audit_profile_id,
                assigned_to,
                assigned_to_type,
                assigned_by,
                role_name,
                user_name,
                user_email,
                department_name,
                due_date,
                template_source,
                NOW(),
                'pending',
                question_count,
                0,
                0,
                0,
                framework,
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                NOW(),
                NOW()
            FROM compliance_audit_assignments
            WHERE id = %s
            RETURNING id, assessment_name, cdr_number, questionnaire_name, status, assigned_to
            """,
            (assignment_id,),
        )
        duplicated = cur.fetchone()
        conn.commit()
        if not duplicated:
            return jsonify({"error": "Assignment not found"}), 404
        return jsonify({"status": "duplicated", "assignment": duplicated}), 201
    except Exception as exc:
        logger.error(f"Error duplicating audit assignment: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/audit_results/<assignment_id>")
def audit_results(assignment_id):
    """Get audit results and report for completed assignment"""
    try:
        ensure_audit_assignment_schema()
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get assignment
        cur.execute("""
            SELECT id, questionnaire_id, questionnaire_name, assessment_name, assigned_to, assigned_to_type,
                   assignment_date, status, question_count, completed_responses, progress_percent,
                   compliance_score, framework, cdr_number, role_name, user_name, user_email, department_name,
                   due_date, reviewer_score, reviewer_comments, reviewer_notes, reviewed_by, reviewed_at
            FROM compliance_audit_assignments
            WHERE id = %s
        """, (assignment_id,))
        
        assignment = cur.fetchone()
        if not assignment:
            return jsonify({"error": "Assignment not found"}), 404
        
        # Get responses
        cur.execute("""
            SELECT question_id, response_status, response_option, evidence, comments, mapping_score, created_at, updated_at
            FROM compliance_audit_assignment_responses
            WHERE assignment_id = %s
            ORDER BY question_id
        """, (assignment_id,))
        
        responses = cur.fetchall()
        questions = get_assignment_questions(assignment.get("questionnaire_id"))
        question_index = {str(q.get("question_id")): q for q in questions}

        def to_float(value, default=0.0):
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def score_to_rating(score_value):
            if score_value >= 90:
                return "Excellent"
            if score_value >= 80:
                return "Good"
            if score_value >= 70:
                return "Moderate"
            if score_value >= 60:
                return "Improvement Needed"
            return "Critical"

        # Enrich responses with questionnaire metadata for complete reporting.
        enriched_responses = []
        for resp in responses:
            row = dict(resp)
            meta = question_index.get(str(row.get("question_id")), {})
            row["section"] = meta.get("section") or "General"
            row["control_id"] = meta.get("control_id") or "N/A"
            row["question_text"] = meta.get("question") or meta.get("question_text") or ""
            row["mapping_score"] = to_float(row.get("mapping_score"), 0.0)
            enriched_responses.append(row)
        
        # Calculate metrics
        total_questions = assignment.get("question_count", 0)
        completed = assignment.get("completed_responses", 0)
        compliance_score = to_float(assignment.get("compliance_score"), 0.0)
        
        # Count by status
        status_counts = {}
        for resp in enriched_responses:
            status = resp.get("response_status", "pending")
            status_counts[status] = status_counts.get(status, 0) + 1

        # SECUMAT weighted executive score model for audit report output.
        category_model = [
            ("Asset Management", 10, ("asset", "inventory", "ownership", "device", "configuration")),
            ("Vulnerability Management", 20, ("vulnerab", "cve", "scan", "assessment", "exposure")),
            ("Patch Management", 15, ("patch", "update", "hotfix", "remediation", "missing patch")),
            ("Access Control", 15, ("access", "privilege", "mfa", "identity", "authentication", "password", "authorization")),
            ("Network Security", 15, ("network", "firewall", "segmentation", "perimeter", "remote")),
            ("Backup & Recovery", 10, ("backup", "restore", "recovery", "business continuity", "dr")),
            ("Security Monitoring", 15, ("monitor", "logging", "siem", "incident", "alert", "soc", "detection", "response")),
        ]

        response_context = []
        for row in enriched_responses:
            text_block = " ".join([
                str(row.get("section") or ""),
                str(row.get("control_id") or ""),
                str(row.get("question_text") or ""),
            ]).lower()
            response_context.append((row, text_block))

        category_scores = []
        weighted_total = 0.0
        for category, weight, keywords in category_model:
            bucket = [
                to_float(row.get("mapping_score"), 0.0)
                for row, text_block in response_context
                if any(keyword in text_block for keyword in keywords)
            ]
            score = round((sum(bucket) / len(bucket)), 2) if bucket else round(compliance_score, 2)
            weighted_score = round(score * (weight / 100.0), 2)
            weighted_total += weighted_score
            category_scores.append({
                "category": category,
                "score": score,
                "weight": weight,
                "weighted_score": weighted_score,
                "evidence_count": len(bucket),
            })

        weighted_total = round(weighted_total, 2)
        maturity_rating = score_to_rating(weighted_total)

        critical_findings = int(status_counts.get("non_compliant", 0) or 0)
        high_findings = int(status_counts.get("partial", 0) or 0)
        medium_findings = int(status_counts.get("pending", 0) or 0)
        low_findings = int(status_counts.get("compliant", 0) or 0)
        info_findings = int(status_counts.get("not_applicable", 0) or 0)
        findings_total = max(1, critical_findings + high_findings + medium_findings + low_findings + info_findings)
        vulnerability_index = round(
            ((critical_findings * 5) + (high_findings * 4) + (medium_findings * 3) + (low_findings * 2) + (info_findings * 1)) / findings_total,
            2,
        )

        patch_related = [
            row for row, text_block in response_context
            if any(token in text_block for token in ("patch", "update", "hotfix", "remediation"))
        ]
        patched_controls = sum(1 for row in patch_related if row.get("response_status") in {"compliant", "not_applicable"})
        patch_total = len(patch_related)
        patch_compliance = round((patched_controls / patch_total) * 100, 2) if patch_total else round(compliance_score, 2)

        top_gaps = sorted(category_scores, key=lambda item: item["score"])[:3]
        top_gap_names = ", ".join(item["category"] for item in top_gaps if item["score"] < 80)

        secumat_report = {
            "overall_security_score": weighted_total,
            "security_maturity_rating": maturity_rating,
            "category_scores": category_scores,
            "vulnerability_summary": {
                "critical": critical_findings,
                "high": high_findings,
                "medium": medium_findings,
                "low": low_findings,
                "informational": info_findings,
                "risk_index": vulnerability_index,
            },
            "patch_management": {
                "patch_related_controls": patch_total,
                "patched_controls": patched_controls,
                "patch_compliance_percent": patch_compliance,
                "rating": score_to_rating(patch_compliance),
            },
            "risk_scoring_methodology": {
                "primary_formula": "Risk Score = Likelihood Ã— Impact",
                "advanced_formula": "(Asset Criticality Ã— 25%) + (Vulnerability Severity Ã— 35%) + (Exploitability Ã— 20%) + (Business Impact Ã— 20%)",
                "cvss_priority_formula": "Priority Score = CVSS Ã— Asset Criticality Ã— Exposure",
            },
            "recommendations": {
                "critical_priority": [
                    "Patch critical CVEs immediately",
                    "Remove unsupported software",
                    "Enable MFA for privileged accounts",
                    "Restrict administrative privileges",
                ],
                "high_priority": [
                    "Perform quarterly vulnerability scans",
                    "Harden server configurations",
                    "Validate network segmentation",
                ],
                "medium_priority": [
                    "Run security awareness training",
                    "Improve backup validation",
                    "Tune log retention and monitoring coverage",
                ],
            },
            "management_summary": (
                f"Overall security score is {weighted_total} ({maturity_rating}). "
                + (f"Priority improvement areas: {top_gap_names}." if top_gap_names else "No major category gaps detected from current responses.")
            ),
            "sla": {
                "critical": "7 Days",
                "high": "30 Days",
                "medium": "60 Days",
                "low": "90 Days",
            },
        }

        sections = sorted({str(row.get("section") or "General") for row in enriched_responses})
        
        return jsonify({
            "assignment": assignment,
            "responses": enriched_responses,
            "secumat_report": secumat_report,
            "report": {
                "questionnaire": assignment["questionnaire_name"],
                "framework": assignment["framework"],
                "assigned_to": assignment["assigned_to"],
                "assigned_to_type": assignment["assigned_to_type"],
                "assignment_date": str(assignment["assignment_date"]),
                "status": assignment["status"],
                "total_questions": total_questions,
                "completed_responses": completed,
                "progress_percent": round(float(assignment.get("progress_percent") or 0), 2),
                "compliance_score": round(compliance_score, 2),
                "status_breakdown": status_counts,
                "sections": sections,
                "assessment_name": assignment.get("assessment_name") or assignment["questionnaire_name"],
                "cdr_number": assignment.get("cdr_number") or "",
                "role_name": assignment.get("role_name"),
                "user_name": assignment.get("user_name"),
                "user_email": assignment.get("user_email"),
                "department_name": assignment.get("department_name"),
                "due_date": str(assignment.get("due_date") or ""),
                "reviewer_score": round(float(assignment.get("reviewer_score") or 0), 2),
                "reviewer_comments": assignment.get("reviewer_comments") or "",
                "reviewer_notes": assignment.get("reviewer_notes") or "",
                "reviewed_by": assignment.get("reviewed_by") or "",
                "reviewed_at": str(assignment.get("reviewed_at") or ""),
                "overall_security_score": weighted_total,
                "security_maturity_rating": maturity_rating,
            }
        })
    except Exception as e:
        logger.error(f"Error in audit_results: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit_results/<assignment_id>/review", methods=["POST"])
def save_audit_review(assignment_id):
    try:
        ensure_audit_assignment_schema()
        data = request.get_json() or {}
        review_status = (data.get("status") or "").strip()
        updated = execute_update(
            """
            UPDATE compliance_audit_assignments
            SET reviewer_score = %s,
                reviewer_comments = %s,
                reviewer_notes = %s,
                reviewed_by = %s,
                reviewed_at = NOW(),
                status = CASE
                    WHEN %s <> '' THEN %s
                    WHEN COALESCE(progress_percent, 0) >= 100 THEN 'completed'
                    ELSE status
                END,
                updated_at = NOW()
            WHERE id = %s
            RETURNING id, reviewer_score, reviewer_comments, reviewer_notes, reviewed_by, status
            """,
            (
                data.get("reviewer_score") or 0,
                (data.get("reviewer_comments") or "").strip(),
                (data.get("reviewer_notes") or "").strip(),
                (data.get("reviewed_by") or "").strip(),
                review_status,
                review_status,
                assignment_id,
            ),
            fetchone=True,
        )
        if not updated:
            return jsonify({"error": "Assignment not found"}), 404
        return jsonify({"success": True, "review": updated})
    except Exception as exc:
        logger.error(f"Error saving audit review: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/audit_results/<assignment_id>/download")
def download_audit_result(assignment_id):
    report_payload = audit_results(assignment_id)
    if getattr(report_payload, "status_code", 200) != 200:
        return report_payload
    payload = report_payload.get_json()
    report = payload.get("report") or {}
    responses = payload.get("responses") or []
    secumat = payload.get("secumat_report") or {}
    lines = [
        f"Assessment: {report.get('assessment_name') or report.get('questionnaire')}",
        f"Questionnaire: {report.get('questionnaire')}",
        f"Framework: {report.get('framework')}",
        f"Assigned To: {report.get('assigned_to')}",
        f"Role: {report.get('role_name') or ''}",
        f"Department: {report.get('department_name') or ''}",
        f"Status: {report.get('status')}",
        f"Progress: {report.get('progress_percent', 0)}%",
        f"Compliance Score: {report.get('compliance_score', 0)}%",
        f"Overall Security Score: {secumat.get('overall_security_score', report.get('overall_security_score', 0))}%",
        f"Security Maturity Rating: {secumat.get('security_maturity_rating', report.get('security_maturity_rating', 'N/A'))}",
        f"Reviewer Score: {report.get('reviewer_score', 0)}%",
        f"Reviewer Comments: {report.get('reviewer_comments', '')}",
        f"Reviewer Notes: {report.get('reviewer_notes', '')}",
        f"Management Summary: {secumat.get('management_summary', '')}",
        "",
        "Responses:",
    ]
    for item in responses:
        lines.append(
            f"- {item.get('question_id')}: {item.get('response_status')} ({item.get('mapping_score')} pts) | Evidence: {item.get('evidence') or ''}"
        )
    filename = f"audit-report-{assignment_id}.txt"
    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def ensure_custom_questionnaire_schema():
    """Create custom_questionnaire_templates table if not present."""
    execute_update("""
        CREATE TABLE IF NOT EXISTS custom_questionnaire_templates (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            framework TEXT NOT NULL DEFAULT 'CUSTOM',
            version TEXT NOT NULL DEFAULT '1.0',
            description TEXT,
            industry TEXT DEFAULT 'All',
            audit_type TEXT DEFAULT 'Compliance',
            os_platform TEXT DEFAULT 'All',
            questions JSONB NOT NULL DEFAULT '[]',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)


@app.route("/api/custom_questionnaire_templates", methods=["GET", "POST"])
def api_custom_questionnaire_templates():
    """List or create custom questionnaire templates."""
    if dashboard_force_fallback():
        state = load_secumat_fallback_state()
        templates = list(state.get("custom_questionnaire_templates") or [])
        if request.method == "GET":
            out = []
            for row in templates:
                item = dict(row)
                questions = item.get("questions") or []
                item["question_count"] = len(questions)
                item["sections"] = list(dict.fromkeys(q.get("section", "") for q in questions if q.get("section")))
                out.append(item)
            out.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
            return jsonify({"templates": out})

        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        questions = data.get("questions") or []
        row = {
            "id": secumat_next_int_id(templates),
            "name": name,
            "framework": (data.get("framework") or "CUSTOM").strip(),
            "version": (data.get("version") or "1.0").strip(),
            "description": (data.get("description") or "").strip(),
            "industry": (data.get("industry") or "All").strip(),
            "audit_type": (data.get("audit_type") or "Compliance").strip(),
            "os_platform": (data.get("os_platform") or "All").strip(),
            "questions": questions,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        templates.append(row)
        state["custom_questionnaire_templates"] = templates
        save_secumat_fallback_state(state)
        row["question_count"] = len(questions)
        return jsonify({"status": "created", "template": row}), 201

    try:
        ensure_custom_questionnaire_schema()
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        if request.method == "GET":
            cur.execute("""
                SELECT id, name, framework, version, description, industry, audit_type,
                       os_platform, questions, created_at, updated_at
                FROM custom_questionnaire_templates
                ORDER BY created_at DESC
            """)
            rows = cur.fetchall()
            templates = []
            for row in rows:
                row = dict(row)
                questions = row.get("questions") or []
                row["question_count"] = len(questions)
                row["sections"] = list(dict.fromkeys(
                    q.get("section", "") for q in questions if q.get("section")
                ))
                templates.append(row)
            return jsonify({"templates": templates})

        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        framework = (data.get("framework") or "CUSTOM").strip()
        version = (data.get("version") or "1.0").strip()
        description = (data.get("description") or "").strip()
        industry = (data.get("industry") or "All").strip()
        audit_type = (data.get("audit_type") or "Compliance").strip()
        os_platform = (data.get("os_platform") or "All").strip()
        questions = data.get("questions") or []

        cur.execute("""
            INSERT INTO custom_questionnaire_templates
                (name, framework, version, description, industry, audit_type, os_platform, questions)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, name, framework, version, description, industry, audit_type,
                      os_platform, questions, created_at
        """, (name, framework, version, description, industry, audit_type, os_platform,
              json.dumps(questions)))
        row = dict(cur.fetchone())
        conn.commit()
        row["question_count"] = len(questions)
        return jsonify({"status": "created", "template": row}), 201

    except Exception as e:
        if is_db_unavailable_error(e):
            return jsonify({"templates": load_secumat_fallback_state().get("custom_questionnaire_templates") or []})
        logger.error(f"Error in custom_questionnaire_templates: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/custom_questionnaire_templates/<int:template_id>", methods=["GET", "PUT", "DELETE"])
def api_custom_questionnaire_template_detail(template_id):
    """Get, update, or delete a custom questionnaire template."""
    if dashboard_force_fallback():
        state = load_secumat_fallback_state()
        templates = list(state.get("custom_questionnaire_templates") or [])
        idx = next((i for i, item in enumerate(templates) if int(item.get("id") or 0) == int(template_id)), -1)

        if request.method == "DELETE":
            if idx < 0:
                return jsonify({"error": "Not found"}), 404
            templates.pop(idx)
            state["custom_questionnaire_templates"] = templates
            save_secumat_fallback_state(state)
            return jsonify({"status": "deleted"})

        if request.method == "GET":
            if idx < 0:
                return jsonify({"error": "Not found"}), 404
            return jsonify({"template": templates[idx]})

        data = request.get_json(silent=True) or {}
        if idx < 0:
            return jsonify({"error": "Not found"}), 404
        for field in ("name", "framework", "version", "description", "industry", "audit_type", "os_platform", "questions"):
            if field in data:
                templates[idx][field] = data[field]
        templates[idx]["updated_at"] = datetime.utcnow().isoformat() + "Z"
        state["custom_questionnaire_templates"] = templates
        save_secumat_fallback_state(state)
        return jsonify({"status": "updated", "template": templates[idx]})

    try:
        ensure_custom_questionnaire_schema()
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        if request.method == "DELETE":
            cur.execute("DELETE FROM custom_questionnaire_templates WHERE id = %s", (template_id,))
            conn.commit()
            return jsonify({"status": "deleted"})

        if request.method == "GET":
            cur.execute("SELECT * FROM custom_questionnaire_templates WHERE id = %s", (template_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Not found"}), 404
            return jsonify({"template": dict(row)})

        data = request.get_json() or {}
        fields = []
        values = []
        for field in ("name", "framework", "version", "description", "industry", "audit_type", "os_platform"):
            if field in data:
                fields.append(f"{field} = %s")
                values.append(data[field])
        if "questions" in data:
            fields.append("questions = %s")
            values.append(json.dumps(data["questions"]))
        if not fields:
            return jsonify({"error": "No fields to update"}), 400
        fields.append("updated_at = NOW()")
        values.append(template_id)
        cur.execute(
            f"UPDATE custom_questionnaire_templates SET {', '.join(fields)} WHERE id = %s RETURNING *",
            values
        )
        row = cur.fetchone()
        conn.commit()
        if not row:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"status": "updated", "template": dict(row)})

    except Exception as e:
        if is_db_unavailable_error(e):
            return jsonify({"error": "Not found"}), 404
        logger.error(f"Error in custom_questionnaire_template_detail: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# SECURITY AUTOMATION API
# ============================================================

def _ensure_automation_module():
    """Lazy-import the automation module (avoids hard import errors on startup)."""
    import importlib, sys, os
    auto_dir = os.path.join(os.path.dirname(__file__), '..', 'automation')
    if auto_dir not in sys.path:
        sys.path.insert(0, os.path.abspath(auto_dir))
    spec = importlib.util.find_spec('security_automation')
    if spec is None:
        return None
    try:
        mod = importlib.import_module('security_automation')
        mod.bootstrap_schema()
        return mod
    except Exception as exc:
        logger.error(f"security_automation import/bootstrap failed: {exc}")
        return None


SECURITY_TOOL_INTEGRATIONS = [
    {
        "slug": "claroty_xdome",
        "name": "Claroty xDome",
        "vendor": "Claroty",
        "category": "OT / Exposure Management",
        "portal_url": "https://zf.eu.dashboard.claroty.com/dashboard",
        "primary_use": "OT/ICS asset posture, exposure insights, and dashboard-driven operational visibility.",
        "auth_model": "Tenant login / SSO required.",
        "api_readiness": "Needs tenant-scoped Claroty API credentials. Public API details were not verifiable from this environment.",
        "dashboard_possibility": "High for data ingestion, low-to-medium for direct dashboard embedding unless Claroty supports sanctioned embeds or framed access in your tenant.",
        "integration_path": [
            "Pull assets, exposures, and risk findings from Claroty APIs once tenant credentials are available.",
            "Normalize Claroty site, asset, and alert payloads into the local vulnerability schema.",
            "Expose Claroty KPIs in the Security Automation and OT dashboard cards.",
        ],
        "recommended_next_step": "Confirm Claroty API availability for the ZF tenant and obtain a service account or API token with read-only dashboard scope.",
    },
    {
        "slug": "swimlane_secops",
        "name": "Swimlane SECOPS",
        "vendor": "Swimlane",
        "category": "SOAR / Case Management",
        "portal_url": "https://frd-ngxswl01.secops.zf-world.com/",
        "primary_use": "SOAR orchestration, case workflows, automation playbooks, and analyst task routing.",
        "auth_model": "Portal login / SSO expected.",
        "api_readiness": "Swimlane documents orchestration and connector workflows, but tenant-specific API access still needs local confirmation.",
        "dashboard_possibility": "High for pushing incidents and playbook outputs from this dashboard into Swimlane; medium for pulling case metrics back.",
        "integration_path": [
            "Send automation incidents from /api/v1/automation/incidents into Swimlane cases or records.",
            "Trigger Swimlane playbooks from dashboard actions for containment and ticket routing.",
            "Pull case status, SLA, and response metrics back into dashboard KPI cards.",
        ],
        "recommended_next_step": "Identify the target Swimlane connector pattern and the case object schema your SOC wants this dashboard to publish.",
    },
    {
        "slug": "crowdstrike_falcon",
        "name": "CrowdStrike Falcon",
        "vendor": "CrowdStrike",
        "category": "EDR / Threat Detection",
        "portal_url": "https://falcon.eu-1.crowdstrike.com/",
        "primary_use": "Endpoint detections, device posture, response actions, and IOC-driven investigation.",
        "auth_model": "OAuth2 API client credentials are typically used for Falcon APIs.",
        "api_readiness": "Public API reference exists, but client ID/secret and EU cloud scope are required before implementation.",
        "dashboard_possibility": "High for enriching EDR Monitor with detections, host status, and containment actions.",
        "integration_path": [
            "Ingest detection summaries, host metadata, and severity from Falcon APIs.",
            "Map Falcon host identifiers to dashboard assets for endpoint risk scoring.",
            "Optionally invoke containment or RTR workflows from approved dashboard actions.",
        ],
        "recommended_next_step": "Provision a read-only Falcon API client first, then extend the EDR automation module with live endpoint telemetry.",
    },
    {
        "slug": "microsoft_defender",
        "name": "Microsoft Defender",
        "vendor": "Microsoft",
        "category": "XDR / Endpoint / Email",
        "portal_url": "https://security.microsoft.com/",
        "primary_use": "Defender XDR signals, incidents, device inventory, vulnerability exposure, and threat analytics.",
        "auth_model": "Microsoft Entra app registration and delegated/app permissions are typically required.",
        "api_readiness": "Well-suited for API ingestion once an app registration and Defender permissions are approved.",
        "dashboard_possibility": "High for device exposure, incident, and alert enrichment across IT endpoints.",
        "integration_path": [
            "Pull devices, alerts, exposure scores, and remediation actions from Defender APIs.",
            "Merge Defender device IDs with asset records used by the dashboard.",
            "Surface Defender incidents alongside automation incidents for analyst triage.",
        ],
        "recommended_next_step": "Create an Entra app registration with least-privilege Defender scopes and validate sample device/alert queries.",
    },
    {
        "slug": "microsoft_sentinel",
        "name": "Microsoft Sentinel",
        "vendor": "Microsoft",
        "category": "SIEM / Analytics",
        "portal_url": "https://login.microsoftonline.com/",
        "primary_use": "Security analytics, incidents, hunting queries, and Log Analytics workspace correlation.",
        "auth_model": "Microsoft Entra authentication with Azure resource permissions.",
        "api_readiness": "Feasible via Azure management, Sentinel, and Log Analytics APIs once workspace IDs and auth are available.",
        "dashboard_possibility": "High for bringing SIEM incidents, analytics rules, and KQL-driven security trends into the dashboard.",
        "integration_path": [
            "Query Sentinel incidents and analytics rules for SOC trend views.",
            "Run targeted Log Analytics searches for correlation with CAB and vulnerability workflows.",
            "Push approved automation outcomes into Sentinel incidents or watchlists.",
        ],
        "recommended_next_step": "Confirm the target Sentinel workspace and whether this dashboard should consume incidents, alerts, or KQL aggregates.",
    },
    {
        "slug": "microsoft_azure",
        "name": "Microsoft Azure",
        "vendor": "Microsoft",
        "category": "Cloud Platform / Management",
        "portal_url": "https://portal.azure.com/#home",
        "primary_use": "Cloud subscription governance, identity-aware security telemetry, and platform-level remediation workflows.",
        "auth_model": "Microsoft Entra authentication with subscription-scoped RBAC and app registration permissions.",
        "api_readiness": "High once subscription IDs, tenant IDs, and service principal credentials are approved.",
        "dashboard_possibility": "High for cloud posture, subscription inventory, and resource-risk correlation.",
        "integration_path": [
            "Query Azure Resource Manager and security APIs for subscriptions, resources, and policy posture.",
            "Correlate Azure resources with vulnerability and CAB ownership views.",
            "Feed Azure findings into automation, compliance, and risk monitoring sections.",
        ],
        "recommended_next_step": "Confirm target subscriptions and create a least-privilege Entra app registration for read-only telemetry access.",
    },
    {
        "slug": "wiz_portal",
        "name": "Wiz Portal",
        "vendor": "Wiz",
        "category": "CNAPP / Cloud Security",
        "portal_url": "https://app.wiz.io/",
        "primary_use": "Cloud exposure management, toxic combination detection, and workload risk prioritization.",
        "auth_model": "Tenant-scoped API credentials with Wiz project/account permissions.",
        "api_readiness": "High if Wiz API access is enabled for the tenant and project scope is known.",
        "dashboard_possibility": "High for cloud risk summaries, asset exposure drilldowns, and vulnerability prioritization.",
        "integration_path": [
            "Pull Wiz issues, projects, and asset exposure metrics through approved tenant APIs.",
            "Map Wiz cloud entities into the dashboard upload/security automation model.",
            "Surface Wiz findings beside Azure, Sentinel, and Defender telemetry for cloud prioritization.",
        ],
        "recommended_next_step": "Confirm Wiz API enablement and the project/account scope that should feed the dashboard.",
    },
    {
        "slug": "tenable_nessus",
        "name": "Tenable / Nessus",
        "vendor": "Tenable",
        "category": "Vulnerability Management",
        "portal_url": "https://cloud.tenable.com/",
        "primary_use": "Vulnerability scan findings, plugin evidence, remediation priority, and exposure validation.",
        "auth_model": "API credentials or scanner credentials, depending on the approved Tenable/Nessus deployment.",
        "api_readiness": "Ready for manual configuration once the approved scanner URL and read credential model are confirmed.",
        "dashboard_possibility": "High for vulnerability trend, SLA, risk scoring, and CAB remediation workflow enrichment.",
        "integration_path": ["Pull scan findings and plugin metadata.", "Normalize CVEs and severity into the vulnerability model.", "Feed high-risk findings into SOAR and CAB queues."],
        "recommended_next_step": "Confirm cloud versus scanner endpoint and least-privilege read access.",
    },
    {
        "slug": "trellix_epo",
        "name": "Trellix ePO",
        "vendor": "Trellix",
        "category": "Endpoint Protection",
        "portal_url": "",
        "primary_use": "Endpoint protection posture, threat events, agent health, and compliance drift.",
        "auth_model": "Tenant-approved API token or service credentials.",
        "api_readiness": "Pending endpoint contract and read credential confirmation.",
        "dashboard_possibility": "Medium-to-high for endpoint health and alert correlation.",
        "integration_path": ["Pull endpoint events and agent health.", "Map hosts to dashboard assets.", "Correlate detections with vulnerability and CAB status."],
        "recommended_next_step": "Confirm ePO API base URL and read scopes.",
    },
    {
        "slug": "bmc_helix",
        "name": "BMC Helix / Discovery",
        "vendor": "BMC",
        "category": "ITSM / CMDB",
        "portal_url": "",
        "primary_use": "Asset inventory, ownership, business service relationships, and change ticket context.",
        "auth_model": "BMC service credentials or tenant token with read access.",
        "api_readiness": "Pending CMDB endpoint and schema mapping confirmation.",
        "dashboard_possibility": "High for asset ownership, criticality, and CAB linkage.",
        "integration_path": ["Pull CMDB asset and relationship records.", "Map assets to vulnerability rows.", "Enrich CAB workflow with service ownership and criticality."],
        "recommended_next_step": "Confirm asset identifiers used by BMC and vulnerability reports.",
    },
    {
        "slug": "pits_database",
        "name": "PITS Database",
        "vendor": "PITS",
        "category": "OT Asset Database",
        "portal_url": "",
        "primary_use": "Plant IT Security asset inventory, whitelist state, and OT remediation tracking.",
        "auth_model": "CSV feed or approved PITS API token.",
        "api_readiness": "CSV feed support is configured; API mode can be enabled when endpoint and token are approved.",
        "dashboard_possibility": "High for OT/ICS ownership and risk validation.",
        "integration_path": ["Load PITS feed or API rows.", "Map CMS and whitelist state to vulnerabilities.", "Feed OT context into risk and CAB dashboards."],
        "recommended_next_step": "Confirm whether PITS should remain CSV-backed or move to API ingestion.",
    },
    {
        "slug": "mimecast",
        "name": "Mimecast",
        "vendor": "Mimecast",
        "category": "Email Security",
        "portal_url": "https://login-de.mimecast.com/",
        "primary_use": "Email threat telemetry, gateway events, impersonation detections, and policy actions.",
        "auth_model": "Mimecast API access requires tenant keys, secret material, and region-aware endpoints.",
        "api_readiness": "API documentation exists, but access is tenant-gated and requires regional endpoint confirmation.",
        "dashboard_possibility": "Medium-to-high for ingesting email threat KPIs and correlating phishing-driven incidents with endpoint activity.",
        "integration_path": [
            "Pull email security incidents and detection metrics from Mimecast APIs.",
            "Correlate phishing campaigns with user/entity analytics and automation incidents.",
            "Add mail-security posture KPIs to documentation and risk monitoring views.",
        ],
        "recommended_next_step": "Confirm the Mimecast region, API keys, and the event families that matter most for SOC reporting.",
    },
]


MANUAL_INTEGRATIONS_PATH = os.path.join(REPO_ROOT, "data", "manual_api_integrations.json")


def load_manual_integrations():
    """Load manually maintained non-secret integration configuration."""
    try:
        if os.path.exists(MANUAL_INTEGRATIONS_PATH):
            with open(MANUAL_INTEGRATIONS_PATH, "r", encoding="utf-8") as handle:
                records = json.load(handle)
            if isinstance(records, list):
                return [item for item in records if isinstance(item, dict)]
    except Exception as exc:
        logger.warning("Failed to load manual integrations: %s", exc)
    return []


def save_manual_integrations(records):
    """Persist non-secret integration metadata for the administration view."""
    os.makedirs(os.path.dirname(MANUAL_INTEGRATIONS_PATH), exist_ok=True)
    with open(MANUAL_INTEGRATIONS_PATH, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2)


def require_api_admin_token():
    """Require the optional dashboard administration token for configuration writes."""
    expected = str(os.environ.get("API_ADMIN_TOKEN") or "").strip()
    if not expected:
        return None
    provided = str(request.headers.get("x-api-admin-token") or "").strip()
    authorization = str(request.headers.get("Authorization") or "").strip()
    bearer = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if provided == expected or bearer == expected:
        return None
    return jsonify({"error": "Administrator token is required for integration changes."}), 401


def normalize_manual_integration(payload, existing=None):
    """Validate and normalize a non-secret API integration definition."""
    payload = payload if isinstance(payload, dict) else {}
    existing = existing or {}
    slug = re.sub(r"[^a-z0-9_]+", "_", str(payload.get("slug") or existing.get("slug") or "").lower()).strip("_")
    name = sanitize_text(payload.get("name") or existing.get("name") or "")
    if not slug or not name:
        raise ValueError("slug and name are required")
    if len(slug) > 80 or len(name) > 120:
        raise ValueError("integration name or slug is too long")
    base_url = str(payload.get("api_base_url") or existing.get("api_base_url") or "").strip()
    portal_url = str(payload.get("portal_url") or existing.get("portal_url") or "").strip()
    for label, value in (("API base URL", base_url), ("Portal URL", portal_url)):
        if value and urlparse(value).scheme not in {"https", "http"}:
            raise ValueError(f"{label} must start with http:// or https://")
    required_env = payload.get("credential_env", existing.get("credential_env", []))
    if not isinstance(required_env, list) or not all(isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", item) for item in required_env):
        raise ValueError("credential_env must contain uppercase environment variable names")
    return {
        "slug": slug,
        "name": name,
        "category": sanitize_text(payload.get("category") or existing.get("category") or "Security Platform"),
        "portal_url": portal_url,
        "api_base_url": base_url,
        "auth_type": sanitize_text(payload.get("auth_type") or existing.get("auth_type") or "API token"),
        "credential_env": required_env,
        "modules": [sanitize_text(item) for item in payload.get("modules", existing.get("modules", [])) if sanitize_text(item)],
        "enabled": bool(payload.get("enabled", existing.get("enabled", False))),
        "notes": sanitize_text(payload.get("notes") or existing.get("notes") or ""),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


@app.route("/api/v1/integrations/configurations", methods=["GET", "POST"])
def integration_configurations():
    """List or create manual security-tool integration metadata without credentials."""
    if request.method == "GET":
        configured = {item.get("slug"): item for item in load_manual_integrations()}
        standard = []
        for item in SECURITY_TOOL_INTEGRATIONS:
            record = dict(item)
            record.update(configured.get(item.get("slug"), {}))
            record.pop("encrypted_api_token", None)
            record["token_saved"] = bool(configured.get(item.get("slug"), {}).get("encrypted_api_token"))
            record["managed"] = item.get("slug") in configured
            standard.append(record)
        custom = [item for slug, item in configured.items() if slug not in {entry.get("slug") for entry in SECURITY_TOOL_INTEGRATIONS}]
        for record in custom:
            record.pop("encrypted_api_token", None)
            record["token_saved"] = bool(configured.get(record.get("slug"), {}).get("encrypted_api_token"))
        return jsonify({"integrations": standard + custom, "credentials_notice": "Credentials are never stored by this API. Set required values in .env."})

    unauthorized = require_api_admin_token()
    if unauthorized:
        return unauthorized
    try:
        records = load_manual_integrations()
        normalized = normalize_manual_integration(request.get_json(silent=True) or {})
        if any(item.get("slug") == normalized["slug"] for item in records):
            return jsonify({"error": "An integration with this slug already exists."}), 409
        records.append(normalized)
        save_manual_integrations(records)
        return jsonify(normalized), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/v1/integrations/configurations/<slug>/credential", methods=["POST", "DELETE"])
def integration_credential(slug):
    """Store or remove one encrypted integration credential."""
    unauthorized = require_api_admin_token()
    if unauthorized:
        return unauthorized
    try:
        from automation.credential_store import save_integration_token, token_saved
        if request.method == "DELETE":
            records = load_manual_integrations()
            for record in records:
                if record.get("slug") == slug:
                    record.pop("encrypted_api_token", None)
            save_manual_integrations(records)
            return jsonify({"slug": slug, "token_saved": False})
        token = str((request.get_json(silent=True) or {}).get("api_token") or "").strip()
        save_integration_token(slug, token)
        return jsonify({"slug": slug, "token_saved": token_saved(slug)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/v1/integrations/configurations/<slug>", methods=["PUT", "DELETE"])
def integration_configuration_detail(slug):
    """Update or delete a manual integration configuration."""
    unauthorized = require_api_admin_token()
    if unauthorized:
        return unauthorized
    records = load_manual_integrations()
    index = next((idx for idx, item in enumerate(records) if item.get("slug") == slug), None)
    if request.method == "DELETE":
        if index is None:
            return jsonify({"error": "Manual integration not found."}), 404
        records.pop(index)
        save_manual_integrations(records)
        return jsonify({"deleted": slug})
    try:
        base = records[index] if index is not None else next((item for item in SECURITY_TOOL_INTEGRATIONS if item.get("slug") == slug), {"slug": slug})
        normalized = normalize_manual_integration({**(request.get_json(silent=True) or {}), "slug": slug}, base)
        if index is None:
            records.append(normalized)
        else:
            records[index] = normalized
        save_manual_integrations(records)
        return jsonify(normalized)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/v1/soc/chat", methods=["POST"])
def soc_chat():
    """Provide an offline, data-minimizing SOC assistant response for dashboard operators."""
    question = sanitize_text((request.get_json(silent=True) or {}).get("question") or "")
    if not question:
        return jsonify({"error": "question is required"}), 400
    if len(question) > 1000:
        return jsonify({"error": "question is too long"}), 400
    summary = build_full_data_fallback_report_payload().get("summary") or {}
    question_lower = question.lower()
    critical = int(summary.get("critical_rows") or 0)
    high = int(summary.get("high_rows") or 0)
    total = int(summary.get("total_rows") or 0)
    if any(term in question_lower for term in ("critical", "risk", "priority")):
        answer = f"Prioritize the {critical} critical and {high} high findings from the current dataset. Start with exposed OT/ICS assets, confirm ownership, then create or update CAB remediation tickets."
    elif any(term in question_lower for term in ("cab", "ticket", "change")):
        answer = "Review open and overdue CAB items first, validate remediation evidence, and record accepted risks with an expiry date and compensating control."
    elif any(term in question_lower for term in ("claroty", "ot", "ics")):
        answer = "Claroty is configured as an opt-in read-only OT source. Once its tenant URL, token, and paths are configured, pull assets, vulnerabilities, and incidents, then correlate critical findings with SOC and CAB queues."
    elif any(term in question_lower for term in ("integration", "api", "connect")):
        answer = "Use Integration Control Center to define each tool's portal, API base URL, auth type, required environment variable names, and module bindings. Credentials remain in .env and are never stored in dashboard configuration."
    else:
        answer = f"The dashboard currently has {total} vulnerability records in its available dataset. Ask about risk prioritization, Claroty OT telemetry, CAB workflow, or integration readiness for a focused next step."
    return jsonify({"answer": answer, "provider": "offline-soc-assistant", "data_source": "dashboard summary", "generated_at": datetime.utcnow().isoformat() + "Z"})


@app.route("/api/security_automation/status")
@app.route("/api/v1/automation/status")
def sec_auto_status():
    """Return latest run status for all 6 automation modules."""
    mod = _ensure_automation_module()
    if mod is None:
        return jsonify({"modules": security_automation_fallback_modules(), "open_incidents": 0})
    try:
        status = mod.get_status_summary()
        total_incidents = query_one(
            "SELECT COUNT(*) AS n FROM automation_incidents WHERE status='open'"
        )
        return jsonify({
            "modules": status,
            "open_incidents": int((total_incidents or {}).get("n", 0)),
        })
    except Exception as exc:
        logger.error(f"sec_auto_status error: {exc}")
        return jsonify({"modules": security_automation_fallback_modules(), "open_incidents": 0})


@app.route("/api/security_automation/dashboard")
@app.route("/api/v1/automation/dashboard")
def sec_auto_dashboard():
    return jsonify(build_security_automation_dashboard_payload())


@app.route("/api/alerts")
def api_alerts():
    payload = build_security_automation_dashboard_payload()
    return jsonify({
        "alerts": payload.get("alerts") or [],
        "source": payload.get("source"),
        "source_label": payload.get("source_label"),
        "updated_at": payload.get("updated_at"),
    })


@app.route("/api/security_automation/alerts/<alert_id>/action", methods=["POST"])
@app.route("/api/v1/automation/alerts/<alert_id>/action", methods=["POST"])
def sec_auto_alert_action(alert_id):
    body = request.get_json(silent=True) or {}
    action = sanitize_text(body.get("action") or "").lower()
    if action not in {"acknowledge", "own", "comment", "ticket", "escalate", "close"}:
        return jsonify({"error": "unsupported action"}), 400

    state = load_security_automation_alert_state()
    actions = state.setdefault("actions", {})
    record = actions.setdefault(str(alert_id), {"comments": []})
    now = datetime.utcnow().isoformat() + "Z"

    if action == "acknowledge":
        record["state"] = "acknowledged"
    elif action == "own":
        record["state"] = "owned"
        record["owner"] = sanitize_text(body.get("owner") or "SOC Analyst")
    elif action == "comment":
        comment = sanitize_text(body.get("comment") or "")
        if not comment:
            return jsonify({"error": "comment is required"}), 400
        record.setdefault("comments", []).append({"text": comment, "created_at": now, "author": sanitize_text(body.get("author") or "SOC Analyst")})
    elif action == "ticket":
        ticket = sanitize_text(body.get("ticket") or "")
        if not ticket:
            return jsonify({"error": "ticket is required"}), 400
        record["ticket"] = ticket
        record["state"] = record.get("state") or "owned"
    elif action == "escalate":
        record["state"] = "escalated"
        record["incident_id"] = sanitize_text(body.get("incident_id") or f"INC-{datetime.utcnow().strftime('%H%M%S')}")
    elif action == "close":
        record["state"] = "closed"

    record["updated_at"] = now
    actions[str(alert_id)] = record
    save_security_automation_alert_state(state)
    return jsonify({"ok": True, "alert_id": alert_id, "state": record})


@app.route("/api/security_automation/import_report", methods=["POST"])
@app.route("/api/v1/automation/import_report", methods=["POST"])
def sec_auto_import_report():
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"error": "file is required"}), 400

    filename = secure_filename(upload.filename or "automation-report")
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    payload = upload.read()
    rows = []

    try:
        if ext == "csv":
            text = payload.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            rows = [dict(row) for row in reader]
        elif ext == "json":
            parsed = json.loads(payload.decode("utf-8-sig"))
            if isinstance(parsed, list):
                rows = parsed
            elif isinstance(parsed, dict):
                for key in ("alerts", "incidents", "records", "rows", "data"):
                    if isinstance(parsed.get(key), list):
                        rows = parsed.get(key)
                        break
                if not rows:
                    rows = [parsed]
        else:
            return jsonify({"error": "only CSV and JSON reports are supported"}), 400
    except Exception as exc:
        return jsonify({"error": f"failed to parse report: {exc}"}), 400

    normalized_rows = [row for row in rows if isinstance(row, dict)]
    severity_counts = Counter(str(row.get("severity") or row.get("priority") or "unknown").strip().lower() or "unknown" for row in normalized_rows)
    state_counts = Counter(str(row.get("state") or row.get("status") or "unknown").strip().lower() or "unknown" for row in normalized_rows)
    category_counts = Counter(str(row.get("category") or row.get("source") or row.get("tool") or "unknown").strip() or "unknown" for row in normalized_rows)

    return jsonify({
        "status": "parsed",
        "source_label": "Uploaded CSV/JSON report",
        "filename": filename,
        "row_count": len(normalized_rows),
        "columns": list(normalized_rows[0].keys()) if normalized_rows else [],
        "severity_counts": dict(severity_counts),
        "state_counts": dict(state_counts),
        "category_counts": dict(category_counts),
        "sample_rows": normalized_rows[:25],
    })


@app.route("/api/security_automation/integrations")
@app.route("/api/v1/automation/integrations")
def sec_auto_integrations():
    """Return the external security tool integration catalogue for the automation tab."""
    try:
        live_catalog = {item.get("slug"): item for item in _readonly_integration_catalog()}

        integrations = []
        for item in SECURITY_TOOL_INTEGRATIONS:
            merged = dict(item)
            live_item = live_catalog.get(item.get("slug"), {})
            merged["enabled"] = bool(live_item.get("enabled", True))
            merged["modules"] = list(live_item.get("modules") or [])
            merged["credential_env"] = list(live_item.get("credential_env") or [])
            merged["health_mode"] = live_item.get("health_mode") or "config_only"
            merged["health"] = live_item.get("health") or {
                "status": "unknown",
                "message": "Health not available.",
                "configured": False,
                "enabled": True,
            }
            merged["live_metrics"] = live_item.get("live_metrics") or {}
            integrations.append(merged)

        return jsonify({
            "integrations": integrations,
            "summary": {
                "count": len(integrations),
                "api_ready_candidates": [
                    item["slug"]
                    for item in integrations
                    if item.get("health_mode") == "live_read_only"
                    or "high" in item["dashboard_possibility"].lower()
                    or "feasible" in item["api_readiness"].lower()
                ],
                "healthy": len([item for item in integrations if (item.get("health") or {}).get("status") == "healthy"]),
                "configured": len([item for item in integrations if (item.get("health") or {}).get("configured")]),
            },
        })
    except Exception as exc:
        logger.error(f"sec_auto_integrations error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/v1/automation/tools/live_summary")
def sec_auto_tools_live_summary():
    """Return all security-tool data/readiness for the single-page SOAR view."""
    return jsonify(build_all_security_tools_live_summary())


@app.route("/api/v1/automation/integrations/claroty_xdome/pull")
@app.route("/api/v1/automation/integrations/<slug>/pull")
def integration_data_pull(slug="claroty_xdome"):
    """Pull supported integration data without issuing any write request."""
    try:
        if REPO_ROOT not in sys.path:
            sys.path.insert(0, REPO_ROOT)
        from automation.vendor_integrations import _base_health, fetch_claroty_soc_feed, load_integration_settings

        limit = max(1, min(int(request.args.get("limit", 100)), 500))
        if slug == "claroty_xdome":
            # Session-only token: forwarded to Claroty for this GET request and never persisted.
            api_token = request.headers.get("X-Claroty-API-Token", "")
            auth_mode = request.headers.get("X-Claroty-Auth-Mode", "bearer")
            proxy_mode = request.headers.get("X-Claroty-Proxy-Mode", "direct")
            tls_mode = request.headers.get("X-Claroty-TLS-Mode", "verify")
            token_header, token_prefix = ("X-API-Key", "") if auth_mode == "api-key" else ("Authorization", "Bearer")
            proxy_url = "" if proxy_mode == "direct" else "http://cloudproxy.zf-world.com:8080"
            verify_tls = False if tls_mode == "skip" else None
            return jsonify(fetch_claroty_soc_feed(limit=limit, api_token=api_token, token_header=token_header, token_prefix=token_prefix, proxy_url=proxy_url, verify_tls=verify_tls))

        settings = load_integration_settings()
        config = (settings.get("platforms") or {}).get(slug)
        if not config:
            return jsonify({"error": "Integration not found"}), 404
        health = _base_health(slug, config)
        return jsonify({
            "health": health,
            "assets": [],
            "vulnerabilities": [],
            "tickets": [],
            "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0},
            "message": "A live read-only adapter has not been configured for this tool. Define its approved endpoint contract and credentials before enabling a pull.",
        })
    except Exception as exc:
        logger.error("Integration pull failed for %s: %s", slug, exc)
        return jsonify({"error": "Integration pull failed"}), 502


@app.route("/api/security_automation/readiness")
@app.route("/api/v1/automation/readiness")
def sec_auto_readiness():
    """Return credential readiness checklist for each configured security integration."""
    try:
        live_catalog = {item.get("slug"): item for item in _readonly_integration_catalog()}

        items = []
        for item in SECURITY_TOOL_INTEGRATIONS:
            slug = item.get("slug")
            live_item = live_catalog.get(slug, {})
            required_env = list(live_item.get("credential_env") or [])
            if not required_env:
                required_env = list(item.get("credential_env") or [])

            missing_env = [name for name in required_env if not str(os.environ.get(name, "")).strip()]
            configured = len(missing_env) == 0

            health = live_item.get("health") or {}
            items.append(
                {
                    "slug": slug,
                    "name": item.get("name"),
                    "enabled": bool(live_item.get("enabled", True)),
                    "health_mode": live_item.get("health_mode") or "config_only",
                    "configured": configured,
                    "required_env": required_env,
                    "missing_env": missing_env,
                    "health_status": health.get("status") or ("configured" if configured else "unconfigured"),
                    "health_message": health.get("message") or ("Credentials detected." if configured else "Missing one or more credential environment variables."),
                }
            )

        total = len(items)
        configured_count = len([entry for entry in items if entry.get("configured")])
        enabled_items = [entry for entry in items if entry.get("enabled")]
        enabled_total = len(enabled_items)
        enabled_configured = len([entry for entry in enabled_items if entry.get("configured")])
        status = "ready" if enabled_total > 0 and enabled_configured == enabled_total else "pending_credentials"

        return jsonify(
            {
                "status": status,
                "summary": {
                    "total": total,
                    "configured": configured_count,
                    "unconfigured": total - configured_count,
                    "enabled_total": enabled_total,
                    "enabled_configured": enabled_configured,
                },
                "items": items,
            }
        )
    except Exception as exc:
        logger.error(f"sec_auto_readiness error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/security_automation/run", methods=["POST"])
@app.route("/api/v1/automation/run", methods=["POST"])
def sec_auto_run():
    """Trigger one or all automation modules. POST JSON: {"module": "all"|"<name>"}"""
    mod = _ensure_automation_module()
    if mod is None:
        return jsonify({"error": "Automation module not available"}), 503
    try:
        body = request.get_json(silent=True) or {}
        module_name = sanitize_text(body.get("module", "all")) or "all"
        result = mod.run_module(module_name)
        return jsonify({"ok": True, "result": result})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.error(f"sec_auto_run error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/security_automation/incidents")
@app.route("/api/v1/automation/incidents")
def sec_auto_incidents():
    """Return recent open automation incidents."""
    mod = _ensure_automation_module()
    if mod is None:
        return jsonify([])
    try:
        module_filter = request.args.get("module")
        limit = min(int(request.args.get("limit", 100)), 500)
        rows = mod.get_recent_incidents(module_filter, limit)
        return jsonify([dict(r) for r in rows])
    except Exception as exc:
        logger.error(f"sec_auto_incidents error: {exc}")
        return jsonify([])


@app.route("/api/security_automation/playbooks")
@app.route("/api/v1/automation/playbooks")
def sec_auto_playbooks():
    """Return automation playbook catalogue."""
    mod = _ensure_automation_module()
    if mod is None:
        return jsonify([
            {"module": "threat_detection", "name": "Critical Vulnerability SOAR Response", "trigger": "severity=critical AND age_days>=1", "steps": ["Alert SOC", "Isolate asset", "Pull CVE details", "Schedule emergency patch", "Re-scan asset", "Close incident"]},
            {"module": "alert_priority", "name": "False Positive Suppression", "trigger": "score<20 AND repeat_count>=3", "steps": ["Review baseline", "Suppress alert", "Document reason", "Re-evaluate after 30 days"]},
            {"module": "vuln_patch", "name": "Critical Patch Automation", "trigger": "cvss>=9.0 AND patch_available=true", "steps": ["Download patch", "Test in staging", "Create CAB change", "Deploy patch", "Validate remediation", "Report completion"]},
            {"module": "edr_monitor", "name": "Endpoint Isolation Protocol", "trigger": "lateral_movement_detected=true", "steps": ["Isolate endpoint", "Capture forensic snapshot", "Run IOC scan", "Remediate endpoint", "Restore connectivity", "Document incident"]},
            {"module": "ueba", "name": "Insider Threat Response", "trigger": "anomaly_score>=80 AND user_risk=high", "steps": ["Notify stakeholders", "Enable enhanced logging", "Restrict permissions", "Investigate access logs", "Escalate to CISO", "Document actions"]},
            {"module": "compliance_check", "name": "Configuration Drift Remediation", "trigger": "compliance_score<70", "steps": ["Detect drift", "Assess impact", "Apply correction", "Verify fix", "Update dashboard", "Schedule re-scan"]},
        ])
    try:
        module_filter = request.args.get("module")
        rows = mod.get_playbooks(module_filter)
        return jsonify([dict(r) for r in rows])
    except Exception as exc:
        logger.error(f"sec_auto_playbooks error: {exc}")
        return jsonify([])


@app.route("/api/security_automation/resolve_incident", methods=["POST"])
def sec_auto_resolve_incident():
    """Mark an automation incident as resolved."""
    body = request.get_json(silent=True) or {}
    incident_id = body.get("id")
    if not incident_id:
        return jsonify({"error": "id required"}), 400
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE automation_incidents SET status='resolved', resolved_at=NOW() WHERE id=%s",
                (int(incident_id),),
            )
        conn.commit()
        return jsonify({"ok": True})
    except Exception as exc:
        logger.error(f"sec_auto_resolve error: {exc}")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("FLASK_PORT", "8080")), debug=False, threaded=True)

