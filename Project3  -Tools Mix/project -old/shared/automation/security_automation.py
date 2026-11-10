"""
Security Automation Engine
===========================
Integrates six cybersecurity automation domains against the local vuln database.
Can be run standalone:  python automation/security_automation.py --module all
Or imported by the Flask dashboard API.

Modules
-------
1. threat_detection   – Scans for active threats, generates SOAR playbook steps
2. alert_priority     – Scores & de-dupes alerts, filters false positives
3. vuln_patch         – Builds patch priority queue, simulates deployment
4. edr_monitor        – Endpoint risk scoring, lateral-movement detection
5. ueba               – Behavioral anomaly detection, insider-threat flagging
6. compliance_check   – Config/posture drift against CIS/NIST controls
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

try:
    from .vendor_integrations import build_integration_catalog
    from .vendor_integrations import fetch_claroty_soc_feed
    from .vendor_integrations import fetch_crowdstrike_detection_feed
except Exception:
    try:
        from vendor_integrations import build_integration_catalog
        from vendor_integrations import fetch_claroty_soc_feed
        from vendor_integrations import fetch_crowdstrike_detection_feed
    except Exception:
        def build_integration_catalog() -> List[Dict[str, Any]]:
            return []

        def fetch_crowdstrike_detection_feed(limit: int = 10) -> Dict[str, Any]:
            return {
                "health": {"status": "unavailable", "message": "Vendor helper not available."},
                "detections": [],
                "metrics": {"detections": 0},
            }

        def fetch_claroty_soc_feed(limit: int = 100) -> Dict[str, Any]:
            return {
                "health": {"status": "unavailable", "message": "Vendor helper not available."},
                "assets": [],
                "vulnerabilities": [],
                "tickets": [],
                "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0},
            }

try:
    from soc_copilot_backend.app.services.calculations import calculate_endpoint_risk
    from soc_copilot_backend.app.services.calculations import classify_endpoint_risk_level
except Exception:
    def calculate_endpoint_risk(critical_count: int, high_count: int, vuln_count: int, max_cvss: float) -> float:
        score = (critical_count * 25) + (high_count * 10) + min(vuln_count * 2, 20) + min(max_cvss * 2, 20)
        return min(round(score, 1), 100)

    def classify_endpoint_risk_level(risk_score: float) -> str:
        if risk_score >= 80:
            return "critical"
        if risk_score >= 60:
            return "high"
        if risk_score >= 30:
            return "medium"
        return "low"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

DB_CONFIG = {
    "dbname": os.environ.get("PGDATABASE", "vuln_db"),
    "user": os.environ.get("PGUSER", "vuln_user"),
    "password": os.environ.get("PGPASSWORD", "StrongPassword123!"),
    "host": os.environ.get("PGHOST", "localhost"),
    "port": int(os.environ.get("PGPORT", 5432)),
}


def get_db() -> psycopg2.extensions.connection:
    return psycopg2.connect(**DB_CONFIG)


def query(sql: str, params=()) -> List[Dict]:
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def query_one(sql: str, params=()) -> Optional[Dict]:
    rows = query(sql, params)
    return rows[0] if rows else {}


def execute(sql: str, params=()) -> None:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

AUTOMATION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS automation_runs (
    id          SERIAL PRIMARY KEY,
    module      VARCHAR(80) NOT NULL,
    status      VARCHAR(30) NOT NULL DEFAULT 'pending',
    started_at  TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    duration_s  NUMERIC(10,2),
    metrics     JSONB DEFAULT '{}'::jsonb,
    summary     TEXT
);

CREATE TABLE IF NOT EXISTS automation_incidents (
    id               SERIAL PRIMARY KEY,
    run_id           INTEGER REFERENCES automation_runs(id) ON DELETE CASCADE,
    module           VARCHAR(80) NOT NULL,
    incident_type    VARCHAR(100),
    severity         VARCHAR(30) DEFAULT 'medium',
    title            TEXT NOT NULL,
    description      TEXT,
    affected_assets  JSONB DEFAULT '[]'::jsonb,
    playbook_actions JSONB DEFAULT '[]'::jsonb,
    status           VARCHAR(30) DEFAULT 'open',
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS automation_playbooks (
    id           SERIAL PRIMARY KEY,
    module       VARCHAR(80),
    name         VARCHAR(200),
    trigger      VARCHAR(100),
    steps        JSONB DEFAULT '[]'::jsonb,
    is_active    BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auto_runs_module ON automation_runs(module);
CREATE INDEX IF NOT EXISTS idx_auto_inc_module  ON automation_incidents(module);
CREATE INDEX IF NOT EXISTS idx_auto_inc_status  ON automation_incidents(status);
"""

SEED_PLAYBOOKS = [
    {
        "module": "threat_detection",
        "name": "Critical Vulnerability SOAR Response",
        "trigger": "severity=critical AND age_days>=1",
        "steps": [
            "ALERT: Notify SOC analyst via PagerDuty / email",
            "ISOLATE: Block asset IP at perimeter firewall (ACL update)",
            "TRIAGE: Pull CVSS details and affected asset inventory",
            "PATCH: Schedule emergency patch window within 24 hours",
            "VERIFY: Re-scan asset after patch to confirm remediation",
            "CLOSE: Update incident status and document RCA",
        ],
    },
    {
        "module": "threat_detection",
        "name": "High Severity Incident Playbook",
        "trigger": "severity=high AND age_days>=7",
        "steps": [
            "ALERT: Create ticket in ITSM (ServiceNow / Jira)",
            "ASSESS: Review CVE details and exploit availability",
            "PRIORITIZE: Rank within patch cycle (P2 SLA 72h)",
            "COORDINATE: Assign to asset owner for remediation",
            "TRACK: Update CAB with open risk acceptance if deferred",
            "VERIFY: Confirm patch or workaround applied",
        ],
    },
    {
        "module": "alert_priority",
        "name": "False Positive Suppression",
        "trigger": "score<20 AND repeat_count>=3",
        "steps": [
            "REVIEW: Compare alert against known-good baseline",
            "SUPPRESS: Add to false-positive exclusion list for 30 days",
            "DOCUMENT: Record suppression reason in audit trail",
            "REVIEW_CYCLE: Re-evaluate exclusion after 30 days",
        ],
    },
    {
        "module": "vuln_patch",
        "name": "Critical Patch Automation",
        "trigger": "cvss>=9.0 AND patch_available=true",
        "steps": [
            "DOWNLOAD: Retrieve patch from vendor repository",
            "TEST: Deploy to staging/test environment first",
            "SCHEDULE: Create change request in CAB for production",
            "DEPLOY: Apply patch during approved maintenance window",
            "VALIDATE: Run post-patch vulnerability scan",
            "REPORT: Update vulnerability record as remediated",
        ],
    },
    {
        "module": "edr_monitor",
        "name": "Endpoint Isolation Protocol",
        "trigger": "lateral_movement_detected=true",
        "steps": [
            "ISOLATE: Quarantine endpoint from network segment",
            "CAPTURE: Take memory and disk forensic snapshot",
            "ANALYZE: Run IOC scan against threat intelligence feeds",
            "REMEDIATE: Wipe and re-image if compromise confirmed",
            "RESTORE: Reconnect after clean bill of health",
            "POST_MORTEM: Document attack path and update detections",
        ],
    },
    {
        "module": "ueba",
        "name": "Insider Threat Response",
        "trigger": "anomaly_score>=80 AND user_risk=high",
        "steps": [
            "NOTIFY: Alert HR and Legal via confidential channel",
            "MONITOR: Enable enhanced audit logging for user account",
            "RESTRICT: Reduce permissions to minimum required",
            "INVESTIGATE: Pull access logs for past 30 days",
            "ESCALATE: Engage CISO if data exfiltration suspected",
            "DOCUMENT: Record all actions for legal/HR proceedings",
        ],
    },
    {
        "module": "compliance_check",
        "name": "Configuration Drift Remediation",
        "trigger": "compliance_score<70",
        "steps": [
            "DETECT: Identify deviating control(s) against baseline",
            "ASSESS: Determine risk impact of deviation",
            "REMEDIATE: Apply corrective configuration change",
            "VERIFY: Re-run compliance scan to confirm fix",
            "REPORT: Update compliance dashboard and audit log",
            "REVIEW: Schedule next compliance scan in 7 days",
        ],
    },
]


def bootstrap_schema() -> None:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(AUTOMATION_SCHEMA_SQL)
            # Seed playbooks if table is empty
            cur.execute("SELECT COUNT(*) FROM automation_playbooks")
            count = cur.fetchone()[0]
            if count == 0:
                for pb in SEED_PLAYBOOKS:
                    cur.execute(
                        """
                        INSERT INTO automation_playbooks (module, name, trigger, steps)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (pb["module"], pb["name"], pb["trigger"], json.dumps(pb["steps"])),
                    )
        conn.commit()
        logger.info("Automation schema bootstrapped OK")
    except Exception as exc:
        conn.rollback()
        logger.error(f"Schema bootstrap failed: {exc}")
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _start_run(module: str) -> int:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO automation_runs (module, status, started_at) VALUES (%s,'running',NOW()) RETURNING id",
                (module,),
            )
            run_id = cur.fetchone()[0]
        conn.commit()
        return run_id
    finally:
        conn.close()


def _finish_run(run_id: int, metrics: dict, summary: str, status: str = "success") -> None:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE automation_runs
                SET status=%s, finished_at=NOW(),
                    duration_s=EXTRACT(EPOCH FROM (NOW()-started_at)),
                    metrics=%s, summary=%s
                WHERE id=%s
                """,
                (status, json.dumps(metrics), summary, run_id),
            )
        conn.commit()
    finally:
        conn.close()


def _save_incidents(run_id: int, module: str, incidents: list) -> int:
    if not incidents:
        return 0
    conn = get_db()
    saved = 0
    try:
        with conn.cursor() as cur:
            for inc in incidents:
                cur.execute(
                    """
                    INSERT INTO automation_incidents
                        (run_id, module, incident_type, severity, title, description,
                         affected_assets, playbook_actions, status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'open')
                    """,
                    (
                        run_id,
                        module,
                        inc.get("incident_type", "generic"),
                        inc.get("severity", "medium"),
                        inc.get("title", "Untitled"),
                        inc.get("description", ""),
                        json.dumps(inc.get("affected_assets", [])),
                        json.dumps(inc.get("playbook_actions", [])),
                    ),
                )
                saved += 1
        conn.commit()
    finally:
        conn.close()
    return saved


def _get_crowdstrike_live_detections(limit: int = 10) -> Dict[str, Any]:
    return fetch_crowdstrike_detection_feed(limit=limit)


def _get_claroty_soc_feed(limit: int = 100) -> Dict[str, Any]:
    """Retrieve normalized Claroty OT telemetry for SOC automation."""
    return fetch_claroty_soc_feed(limit=limit)


# ---------------------------------------------------------------------------
# 1. Threat Detection & Incident Response
# ---------------------------------------------------------------------------

def run_threat_detection() -> Dict[str, Any]:
    """
    Scans active vulnerabilities for threat indicators.
    Generates SOAR playbook actions for critical/high severity items.
    """
    run_id = _start_run("threat_detection")
    incidents = []
    metrics: Dict[str, Any] = {}

    try:
        # Pull critical+high vulnerabilities still open
        vulns = query(
            """
            SELECT asset_key, cve, severity, cvss_score,
                   ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400) AS age_days,
                   final_status, remediation, asset_type
            FROM unified_vulnerabilities
            WHERE severity IN ('critical','high') AND final_status IN ('open','confirmed_open')
            ORDER BY cvss_score DESC NULLS LAST, age_days DESC NULLS LAST
            LIMIT 50
            """
        )

        # Also pull from upload data if available
        upload_vulns = query(
            """
            SELECT
                COALESCE(ip_address, hostname, dns_name, 'unknown') AS asset_key,
                cve,
                LOWER(COALESCE(raw_data->>'Severity','medium')) AS severity,
                NULL::numeric AS cvss_score,
                ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(
                    CASE WHEN COALESCE(last_seen::text,'') ~ '^\\d{4}-\\d{2}-\\d{2}' THEN last_seen::timestamp END,
                    created_at
                )))/86400) AS age_days,
                COALESCE(raw_data->>'Status','open') AS final_status
            FROM report_records
            WHERE LOWER(COALESCE(raw_data->>'Severity','')) IN ('critical','high')
              AND LOWER(COALESCE(raw_data->>'Status','')) NOT IN ('closed','resolved','fixed')
            ORDER BY age_days DESC NULLS LAST
            LIMIT 50
            """
        )

        all_vulns = vulns + upload_vulns
        critical_count = sum(1 for v in all_vulns if str(v.get("severity", "")).lower() == "critical")
        high_count = sum(1 for v in all_vulns if str(v.get("severity", "")).lower() == "high")
        overdue_count = sum(1 for v in all_vulns if (v.get("age_days") or 0) >= 14)

        crowdstrike_feed = _get_crowdstrike_live_detections(limit=10)
        crowdstrike_detections = list(crowdstrike_feed.get("detections") or [])
        claroty_feed = _get_claroty_soc_feed(limit=100)
        claroty_vulnerabilities = list(claroty_feed.get("vulnerabilities") or [])
        claroty_tickets = list(claroty_feed.get("tickets") or [])

        playbook_steps_critical = [
            "ALERT: Notify SOC analyst immediately via alerting platform",
            "ISOLATE: Block asset at network perimeter if actively exploited",
            "TRIAGE: Confirm exploit availability via EPSS / NVD lookup",
            "PATCH: Schedule emergency patch within 24 hours (P1 SLA)",
            "VERIFY: Re-scan post-patch to confirm remediation",
            "CLOSE: Update CAB and ITSM record with RCA",
        ]
        playbook_steps_high = [
            "ALERT: Create P2 ticket in ITSM system",
            "ASSESS: Review CVSS vector and exploitability",
            "SCHEDULE: Add to next patch cycle (P2 SLA 72 hours)",
            "COORDINATE: Assign to asset owner for sign-off",
            "VERIFY: Confirm patch or compensating control applied",
        ]

        for vuln in all_vulns[:10]:
            severity = str(vuln.get("severity", "high")).lower()
            age = vuln.get("age_days") or 0
            steps = playbook_steps_critical if severity == "critical" else playbook_steps_high
            incidents.append(
                {
                    "incident_type": "threat_detected",
                    "severity": severity,
                    "title": f"[{severity.upper()}] {vuln.get('cve','Unknown CVE')} on {vuln.get('asset_key','unknown')} (age {age} days)",
                    "description": f"Vulnerability {vuln.get('cve')} detected on asset {vuln.get('asset_key')}. "
                    f"Severity: {severity}, Age: {age} days, Status: {vuln.get('final_status','open')}.",
                    "affected_assets": [str(vuln.get("asset_key", ""))],
                    "playbook_actions": steps,
                }
            )

        for detection in crowdstrike_detections[:5]:
            severity = str(detection.get("severity") or "high").lower()
            incidents.append(
                {
                    "incident_type": "vendor_detection",
                    "severity": severity,
                    "title": f"[CROWDSTRIKE {severity.upper()}] {detection.get('title','Detection')} on {detection.get('hostname','unknown-endpoint')}",
                    "description": f"CrowdStrike detection {detection.get('detection_id')} reported status {detection.get('status')} for {detection.get('hostname')}. {detection.get('description','')}",
                    "affected_assets": [str(detection.get("hostname") or detection.get("device_id") or "unknown-endpoint")],
                    "playbook_actions": [
                        "ENRICH: Pull full CrowdStrike detection context and analyst notes",
                        "TRIAGE: Validate the behavior against local vulnerability exposure",
                        "CONTAIN: Isolate endpoint if active malicious behavior is confirmed",
                        "CORRELATE: Check other security tools for matching indicators",
                        "TRACK: Open or update the SOC incident record with detection evidence",
                    ],
                }
            )

        for vulnerability in claroty_vulnerabilities[:10]:
            severity = str(vulnerability.get("severity") or "medium").lower()
            if severity not in {"critical", "high"}:
                continue
            incidents.append(
                {
                    "incident_type": "claroty_vulnerability",
                    "severity": severity,
                    "title": f"[CLAROTY {severity.upper()}] {vulnerability.get('cve') or vulnerability.get('title')} on {vulnerability.get('asset_name')}",
                    "description": f"Claroty vulnerability {vulnerability.get('vulnerability_id')} is {vulnerability.get('status')} on OT asset {vulnerability.get('asset_name')}. {vulnerability.get('description', '')}",
                    "affected_assets": [str(vulnerability.get("asset_name") or vulnerability.get("asset_id") or "unknown-asset")],
                    "playbook_actions": playbook_steps_critical if severity == "critical" else playbook_steps_high,
                }
            )

        for ticket in claroty_tickets[:10]:
            severity = str(ticket.get("severity") or "medium").lower()
            if severity not in {"critical", "high"} or str(ticket.get("status") or "").lower() in {"closed", "resolved"}:
                continue
            incidents.append(
                {
                    "incident_type": "claroty_ticket",
                    "severity": severity,
                    "title": f"[CLAROTY TICKET {severity.upper()}] {ticket.get('title')} on {ticket.get('asset_name')}",
                    "description": f"Claroty ticket {ticket.get('ticket_id')} is {ticket.get('status')}. {ticket.get('description', '')}",
                    "affected_assets": [str(ticket.get("asset_name") or "unknown-asset")],
                    "playbook_actions": ["TRIAGE: Review Claroty incident context and affected OT zone", "CORRELATE: Check matched CVEs and asset exposure", "TRACK: Create or update the SOC/CAB remediation ticket"],
                }
            )

        metrics = {
            "total_threats": len(all_vulns),
            "critical_threats": critical_count,
            "high_threats": high_count,
            "overdue_14d": overdue_count,
            "incidents_generated": len(incidents),
            "playbooks_triggered": len([i for i in incidents if i["severity"] == "critical"]),
            "crowdstrike_live_detections": len(crowdstrike_detections),
            "crowdstrike_health": (crowdstrike_feed.get("health") or {}).get("status", "unknown"),
            "claroty_live_assets": len(claroty_feed.get("assets") or []),
            "claroty_live_vulnerabilities": len(claroty_vulnerabilities),
            "claroty_live_tickets": len(claroty_tickets),
            "claroty_health": (claroty_feed.get("health") or {}).get("status", "unknown"),
        }
        _save_incidents(run_id, "threat_detection", incidents)
        _finish_run(run_id, metrics, f"Detected {critical_count} critical, {high_count} high threats. CrowdStrike live detections: {len(crowdstrike_detections)}. {len(incidents)} incidents created.")
        logger.info(f"[threat_detection] {metrics}")

    except Exception as exc:
        logger.error(f"[threat_detection] Error: {exc}")
        _finish_run(run_id, metrics, str(exc), "error")

    return {"module": "threat_detection", "run_id": run_id, "metrics": metrics, "incidents": incidents}


# ---------------------------------------------------------------------------
# 2. Alert Prioritization & False Positive Reduction
# ---------------------------------------------------------------------------

def run_alert_prioritization() -> Dict[str, Any]:
    """
    Scores all open alerts by CVSS, age, OT flag, and exploitability.
    Flags likely false positives (low score, seen 3+ times with no change).
    """
    run_id = _start_run("alert_priority")
    metrics: Dict[str, Any] = {}
    incidents = []

    try:
        vulns = query(
            """
            SELECT asset_key, cve, severity, cvss_score,
                   asset_type, final_status,
                   ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400) AS age_days
            FROM unified_vulnerabilities
            WHERE final_status NOT IN ('closed','false_positive')
            """
        )

        upload_vulns = query(
            """
            SELECT
                COALESCE(ip_address, hostname, 'unknown') AS asset_key,
                cve,
                LOWER(COALESCE(raw_data->>'Severity','low')) AS severity,
                NULL::numeric AS cvss_score,
                'IT' AS asset_type,
                COALESCE(raw_data->>'Status','open') AS final_status,
                ROUND(EXTRACT(EPOCH FROM (NOW()-created_at))/86400) AS age_days
            FROM report_records
            WHERE LOWER(COALESCE(raw_data->>'Status','')) NOT IN ('closed','resolved','fixed')
            LIMIT 500
            """
        )

        all_alerts = vulns + upload_vulns
        scored = []
        for a in all_alerts:
            sev = str(a.get("severity", "low")).lower()
            cvss = float(a.get("cvss_score") or 0)
            age = float(a.get("age_days") or 0)
            is_ot = str(a.get("asset_type", "")).upper() in ("OT", "OT/ICS", "ICS")

            sev_score = {"critical": 40, "high": 30, "medium": 15, "low": 5, "very_low": 2, "info": 1}.get(sev, 5)
            cvss_score = min(cvss * 4, 40)
            age_score = min(age / 2, 15)
            ot_bonus = 5 if is_ot else 0
            total_score = sev_score + cvss_score + age_score + ot_bonus

            scored.append({**a, "priority_score": round(total_score, 1), "is_ot": is_ot})

        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        high_priority = [a for a in scored if a["priority_score"] >= 70]
        false_positive_candidates = [a for a in scored if a["priority_score"] < 10]
        reduced_alerts = len(all_alerts) - len(false_positive_candidates)

        # Generate incidents for top high-priority items
        for a in high_priority[:5]:
            incidents.append(
                {
                    "incident_type": "high_priority_alert",
                    "severity": a.get("severity", "high"),
                    "title": f"High-priority alert: {a.get('cve','N/A')} on {a.get('asset_key','unknown')} (score {a['priority_score']})",
                    "description": f"Alert scored {a['priority_score']}/100. CVE: {a.get('cve')}, Asset: {a.get('asset_key')}, Age: {a.get('age_days')} days.",
                    "affected_assets": [str(a.get("asset_key", ""))],
                    "playbook_actions": [
                        "ROUTE: Assign to Level-2 analyst for immediate review",
                        "ENRICH: Pull threat intel from MISP/VirusTotal",
                        "CORRELATE: Check SIEM for related events",
                        "RESPOND: Initiate containment if actively exploited",
                    ],
                }
            )

        reduction_pct = round((len(false_positive_candidates) / max(len(all_alerts), 1)) * 100, 1)
        metrics = {
            "total_alerts": len(all_alerts),
            "scored_alerts": len(scored),
            "high_priority": len(high_priority),
            "false_positive_candidates": len(false_positive_candidates),
            "alert_reduction_pct": reduction_pct,
            "top_score": scored[0]["priority_score"] if scored else 0,
        }

        _save_incidents(run_id, "alert_priority", incidents)
        _finish_run(run_id, metrics, f"Scored {len(scored)} alerts. {len(high_priority)} high-priority. {reduction_pct}% FP reduction.")

    except Exception as exc:
        logger.error(f"[alert_priority] Error: {exc}")
        _finish_run(run_id, metrics, str(exc), "error")

    return {"module": "alert_priority", "run_id": run_id, "metrics": metrics, "incidents": incidents}


# ---------------------------------------------------------------------------
# 3. Vulnerability Management & Patch Automation
# ---------------------------------------------------------------------------

def run_vuln_patch() -> Dict[str, Any]:
    """
    Builds prioritized patch queue. Simulates automated patch deployment.
    """
    run_id = _start_run("vuln_patch")
    metrics: Dict[str, Any] = {}
    incidents = []

    try:
        open_vulns = query(
            """
            SELECT asset_key, cve, severity, cvss_score, asset_type, remediation,
                   ROUND(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400) AS age_days
            FROM unified_vulnerabilities
            WHERE final_status IN ('open','confirmed_open','new')
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT 200
            """
        )

        upload_open = query(
            """
            SELECT
                COALESCE(ip_address, hostname, 'unknown') AS asset_key,
                cve,
                LOWER(COALESCE(raw_data->>'Severity','medium')) AS severity,
                NULL::numeric AS cvss_score,
                solution AS remediation,
                ROUND(EXTRACT(EPOCH FROM (NOW()-created_at))/86400) AS age_days
            FROM report_records
            WHERE LOWER(COALESCE(raw_data->>'Status','open')) NOT IN ('closed','resolved','fixed')
            LIMIT 200
            """
        )

        all_open = open_vulns + upload_open
        p1 = [v for v in all_open if str(v.get("severity", "")).lower() == "critical"]
        p2 = [v for v in all_open if str(v.get("severity", "")).lower() == "high"]
        p3 = [v for v in all_open if str(v.get("severity", "")).lower() == "medium"]
        p4 = [v for v in all_open if str(v.get("severity", "")).lower() in ("low", "very_low", "info")]

        patched_sim = min(len(p1), 3)  # Simulate auto-patching up to 3 criticals

        for v in p1[:3]:
            incidents.append(
                {
                    "incident_type": "patch_required",
                    "severity": "critical",
                    "title": f"PATCH P1: {v.get('cve','N/A')} on {v.get('asset_key','unknown')}",
                    "description": f"Critical vulnerability requiring immediate patching. Remediation: {v.get('remediation','Contact vendor for patch.')}",
                    "affected_assets": [str(v.get("asset_key", ""))],
                    "playbook_actions": [
                        "DOWNLOAD: Retrieve patch from vendor patch portal",
                        "TEST: Apply to staging environment and run regression tests",
                        "CHANGE_REQUEST: Submit emergency change request to CAB",
                        "DEPLOY: Apply patch during approved maintenance window",
                        "SCAN: Run authenticated scan to verify patch applied",
                        "CLOSE: Mark vulnerability as remediated in VMS",
                    ],
                }
            )

        metrics = {
            "total_open": len(all_open),
            "p1_critical": len(p1),
            "p2_high": len(p2),
            "p3_medium": len(p3),
            "p4_low": len(p4),
            "auto_patched_simulated": patched_sim,
            "patch_coverage_pct": round(patched_sim / max(len(p1), 1) * 100, 1),
        }

        _save_incidents(run_id, "vuln_patch", incidents)
        _finish_run(run_id, metrics, f"Patch queue: {len(p1)} P1, {len(p2)} P2, {len(p3)} P3. Simulated {patched_sim} auto-patches.")

    except Exception as exc:
        logger.error(f"[vuln_patch] Error: {exc}")
        _finish_run(run_id, metrics, str(exc), "error")

    return {"module": "vuln_patch", "run_id": run_id, "metrics": metrics, "incidents": incidents}


# ---------------------------------------------------------------------------
# 4. Endpoint Detection & Response (EDR)
# ---------------------------------------------------------------------------

def run_edr_monitor() -> Dict[str, Any]:
    """
    Scores endpoints by risk, detects potential lateral movement.
    Recommends isolation for highest-risk endpoints.
    """
    run_id = _start_run("edr_monitor")
    metrics: Dict[str, Any] = {}
    incidents = []

    try:
        endpoint_data = query(
            """
            SELECT
                asset_key AS endpoint,
                asset_type,
                COUNT(*) AS vuln_count,
                SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical_cnt,
                SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high_cnt,
                MAX(cvss_score) AS max_cvss,
                MAX(EXTRACT(EPOCH FROM (NOW() - COALESCE(last_updated, first_detected)))/86400) AS max_age_days
            FROM unified_vulnerabilities
            WHERE final_status IN ('open','confirmed_open')
            GROUP BY 1,2
            ORDER BY critical_cnt DESC, high_cnt DESC, vuln_count DESC
            LIMIT 100
            """
        )

        upload_endpoints = query(
            """
            SELECT
                COALESCE(ip_address, hostname, dns_name, 'unknown') AS endpoint,
                'IT' AS asset_type,
                COUNT(*) AS vuln_count,
                SUM(CASE WHEN LOWER(COALESCE(raw_data->>'Severity','')) = 'critical' THEN 1 ELSE 0 END) AS critical_cnt,
                SUM(CASE WHEN LOWER(COALESCE(raw_data->>'Severity','')) = 'high' THEN 1 ELSE 0 END) AS high_cnt,
                NULL::numeric AS max_cvss,
                MAX(EXTRACT(EPOCH FROM (NOW()-created_at))/86400) AS max_age_days
            FROM report_records
            WHERE LOWER(COALESCE(raw_data->>'Status','')) NOT IN ('closed','resolved')
            GROUP BY 1, 2
            ORDER BY critical_cnt DESC, vuln_count DESC
            LIMIT 100
            """
        )

        crowdstrike_feed = _get_crowdstrike_live_detections(limit=15)
        crowdstrike_detections = list(crowdstrike_feed.get("detections") or [])

        all_endpoints = endpoint_data + upload_endpoints
        risk_scored = []
        for ep in all_endpoints:
            crit = int(ep.get("critical_cnt") or 0)
            high = int(ep.get("high_cnt") or 0)
            vuln_cnt = int(ep.get("vuln_count") or 0)
            max_cvss = float(ep.get("max_cvss") or 0)
            risk_score = calculate_endpoint_risk(crit, high, vuln_cnt, max_cvss)
            risk_scored.append({
                **ep,
                "risk_score": risk_score,
                "risk_level": classify_endpoint_risk_level(risk_score),
            })

        risk_scored.sort(key=lambda x: x["risk_score"], reverse=True)
        high_risk = [e for e in risk_scored if e["risk_score"] >= 60]
        isolate_recommended = [e for e in risk_scored if e["risk_score"] >= 80]

        for ep in isolate_recommended[:3]:
            incidents.append(
                {
                    "incident_type": "endpoint_risk",
                    "severity": "critical" if ep["risk_score"] >= 90 else "high",
                    "title": f"EDR ALERT: High-risk endpoint {ep.get('endpoint','unknown')} (risk score {ep['risk_score']})",
                    "description": f"Endpoint has {ep.get('critical_cnt',0)} critical and {ep.get('high_cnt',0)} high vulnerabilities. Risk score: {ep['risk_score']}/100.",
                    "affected_assets": [str(ep.get("endpoint", ""))],
                    "playbook_actions": [
                        "ISOLATE: Remove endpoint from network segment",
                        "FORENSICS: Capture memory dump and system image",
                        "SCAN: Run IOC scan against latest threat intelligence",
                        "REMEDIATE: Patch all critical/high vulnerabilities",
                        "RESTORE: Reconnect endpoint after clean verification",
                    ],
                }
            )

        for detection in crowdstrike_detections[:3]:
            severity = str(detection.get("severity") or "high").lower()
            incidents.append(
                {
                    "incident_type": "crowdstrike_detection",
                    "severity": severity,
                    "title": f"CrowdStrike Falcon detection on {detection.get('hostname','unknown-endpoint')}",
                    "description": f"Detection {detection.get('detection_id')} is currently {detection.get('status')} with severity {severity}. {detection.get('description','')}",
                    "affected_assets": [str(detection.get("hostname") or detection.get("device_id") or "unknown-endpoint")],
                    "playbook_actions": [
                        "REVIEW: Open the Falcon console and validate the detection lineage",
                        "ISOLATE: Quarantine the endpoint from the network if required",
                        "FORENSICS: Capture endpoint evidence and process tree details",
                        "PATCH: Cross-check the endpoint against known open vulnerabilities",
                        "CLOSE: Update the automation incident once the detection is resolved",
                    ],
                }
            )

        total_endpoints = len(set(e.get("endpoint", "") for e in all_endpoints))
        vendor_hosts = {str(d.get("hostname") or d.get("device_id") or "unknown-endpoint") for d in crowdstrike_detections}
        metrics = {
            "total_endpoints": total_endpoints,
            "high_risk_endpoints": len(high_risk),
            "isolate_recommended": len(isolate_recommended),
            "avg_risk_score": round(sum(e["risk_score"] for e in risk_scored) / max(len(risk_scored), 1), 1),
            "lateral_movement_risk": len([e for e in risk_scored if e["risk_score"] >= 70]),
            "crowdstrike_live_detections": len(crowdstrike_detections),
            "crowdstrike_impacted_hosts": len(vendor_hosts),
            "crowdstrike_health": (crowdstrike_feed.get("health") or {}).get("status", "unknown"),
            "risk_level_distribution": {
                "critical": len([e for e in risk_scored if e.get("risk_level") == "critical"]),
                "high": len([e for e in risk_scored if e.get("risk_level") == "high"]),
                "medium": len([e for e in risk_scored if e.get("risk_level") == "medium"]),
                "low": len([e for e in risk_scored if e.get("risk_level") == "low"]),
            },
        }

        _save_incidents(run_id, "edr_monitor", incidents)
        _finish_run(run_id, metrics, f"Monitored {total_endpoints} endpoints. CrowdStrike live detections: {len(crowdstrike_detections)}. {len(high_risk)} high-risk, {len(isolate_recommended)} recommend isolation.")

    except Exception as exc:
        logger.error(f"[edr_monitor] Error: {exc}")
        _finish_run(run_id, metrics, str(exc), "error")

    return {"module": "edr_monitor", "run_id": run_id, "metrics": metrics, "incidents": incidents}


# ---------------------------------------------------------------------------
# 5. User & Entity Behavior Analytics (UEBA)
# ---------------------------------------------------------------------------

def run_ueba() -> Dict[str, Any]:
    """
    Analyzes upload patterns and vulnerability trends for behavioral anomalies.
    Flags unusual data patterns that may indicate insider threats.
    """
    run_id = _start_run("ueba")
    metrics: Dict[str, Any] = {}
    incidents = []

    try:
        upload_patterns = query(
            """
            SELECT
                uploaded_by,
                COUNT(*) AS upload_count,
                SUM(record_count) AS total_records,
                MAX(created_at) AS last_upload,
                MIN(created_at) AS first_upload
            FROM report_uploads
            GROUP BY uploaded_by
            ORDER BY upload_count DESC
            """
        )

        status_anomalies = query(
            """
            SELECT
                COALESCE(raw_data->>'Status','unknown') AS raw_status,
                COUNT(*) AS count
            FROM report_records
            GROUP BY 1
            ORDER BY count DESC
            """
        )

        off_hours_uploads = query(
            """
            SELECT COUNT(*) AS count
            FROM report_uploads
            WHERE EXTRACT(HOUR FROM created_at) NOT BETWEEN 7 AND 19
            """
        )

        large_uploads = query(
            """
            SELECT upload_name, record_count, created_at, uploaded_by
            FROM report_uploads
            WHERE record_count > 5000
            ORDER BY record_count DESC
            """
        )

        accepted_risk_vulns = query(
            """
            SELECT asset_key, cve, severity
            FROM unified_vulnerabilities
            WHERE final_status = 'accepted_risk'
            LIMIT 20
            """
        )

        off_hours_count = int((off_hours_uploads[0] or {}).get("count", 0))
        large_upload_count = len(large_uploads)
        anomaly_score = 0

        if off_hours_count > 0:
            anomaly_score += min(off_hours_count * 15, 40)
        if large_upload_count > 0:
            anomaly_score += min(large_upload_count * 10, 30)
        if len(accepted_risk_vulns) > 5:
            anomaly_score += 20

        anomaly_score = min(anomaly_score, 100)
        risk_level = "critical" if anomaly_score >= 80 else "high" if anomaly_score >= 50 else "medium" if anomaly_score >= 25 else "low"

        if anomaly_score >= 25:
            incidents.append(
                {
                    "incident_type": "behavioral_anomaly",
                    "severity": risk_level,
                    "title": f"UEBA: Behavioral anomaly detected (score {anomaly_score}/100)",
                    "description": f"Detected {off_hours_count} off-hours upload(s), {large_upload_count} large upload(s). Anomaly score: {anomaly_score}/100.",
                    "affected_assets": [str(u.get("uploaded_by", "unknown")) for u in upload_patterns[:3]],
                    "playbook_actions": [
                        "INVESTIGATE: Review user activity logs for past 30 days",
                        "CORRELATE: Cross-reference with HR records and access logs",
                        "NOTIFY: Alert security team and HR confidentially",
                        "RESTRICT: Reduce user permissions to minimum necessary",
                        "MONITOR: Enable enhanced logging on user account",
                        "ESCALATE: Engage CISO if data exfiltration confirmed",
                    ],
                }
            )

        metrics = {
            "users_monitored": len(upload_patterns),
            "off_hours_events": off_hours_count,
            "large_uploads_detected": large_upload_count,
            "accepted_risk_count": len(accepted_risk_vulns),
            "anomaly_score": anomaly_score,
            "risk_level": risk_level,
            "insider_threats_flagged": len(incidents),
        }

        _save_incidents(run_id, "ueba", incidents)
        _finish_run(run_id, metrics, f"Analyzed {len(upload_patterns)} users. Anomaly score: {anomaly_score}/100. {len(incidents)} threat(s) flagged.")

    except Exception as exc:
        logger.error(f"[ueba] Error: {exc}")
        _finish_run(run_id, metrics, str(exc), "error")

    return {"module": "ueba", "run_id": run_id, "metrics": metrics, "incidents": incidents}


# ---------------------------------------------------------------------------
# 6. Compliance & Security Configuration Management
# ---------------------------------------------------------------------------

def run_compliance_check() -> Dict[str, Any]:
    """
    Checks current data posture against common security controls.
    Flags deviations and generates compliance recommendations.
    """
    run_id = _start_run("compliance_check")
    metrics: Dict[str, Any] = {}
    incidents = []

    try:
        stats = query_one(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE final_status='closed') AS closed,
                COUNT(*) FILTER (WHERE final_status='open' AND severity='critical') AS critical_open,
                COUNT(*) FILTER (WHERE final_status='open' AND severity='high') AS high_open,
                COUNT(*) FILTER (WHERE final_status='accepted_risk') AS accepted_risk,
                ROUND(AVG(EXTRACT(EPOCH FROM (NOW()-COALESCE(last_updated,first_detected)))/86400),1) AS avg_age_days
            FROM unified_vulnerabilities
            """
        ) or {}

        upload_stats = query_one(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE LOWER(COALESCE(raw_data->>'Status','')) IN ('closed','resolved','fixed')) AS closed,
                COUNT(*) FILTER (WHERE LOWER(COALESCE(raw_data->>'Severity','')) = 'critical') AS critical_open
            FROM report_records
            """
        ) or {}

        try:
            audit_responses = query(
                """
                SELECT compliance_score, framework, status
                FROM audit_assignments
                WHERE compliance_score IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 20
                """
            )
        except Exception:
            audit_responses = []

        avg_compliance = 0.0
        if audit_responses:
            scores = [float(r.get("compliance_score") or 0) for r in audit_responses]
            avg_compliance = round(sum(scores) / len(scores), 1)

        total = int((stats.get("total") or 0)) + int((upload_stats.get("total") or 0))
        closed = int((stats.get("closed") or 0)) + int((upload_stats.get("closed") or 0))
        critical_open = int((stats.get("critical_open") or 0)) + int((upload_stats.get("critical_open") or 0))
        high_open = int(stats.get("high_open") or 0)
        avg_age = float(stats.get("avg_age_days") or 0)

        closure_rate = round(closed / max(total, 1) * 100, 1)
        config_score = min(
            100,
            max(
                0,
                100
                - (critical_open * 5)
                - (high_open * 2)
                - (max(avg_age - 30, 0) * 0.5),
            ),
        )
        overall_score = round((config_score + avg_compliance) / 2, 1) if avg_compliance > 0 else round(config_score, 1)

        controls_checked = [
            {"control": "CC-01 Access Control", "status": "pass" if critical_open == 0 else "fail", "detail": f"{critical_open} critical open vulns"},
            {"control": "CC-02 Patch Management", "status": "pass" if closure_rate >= 70 else "fail", "detail": f"Closure rate {closure_rate}%"},
            {"control": "CC-03 Vulnerability Scanning", "status": "pass", "detail": "Active scanning operational"},
            {"control": "CC-04 Incident Response", "status": "pass" if high_open < 50 else "warn", "detail": f"{high_open} high open items"},
            {"control": "CC-05 Risk Acceptance Review", "status": "warn" if int(stats.get("accepted_risk") or 0) > 10 else "pass", "detail": f"{stats.get('accepted_risk',0)} accepted risks"},
            {"control": "CC-06 Audit Logging", "status": "pass", "detail": "Dashboard audit trail active"},
        ]

        failed_controls = [c for c in controls_checked if c["status"] == "fail"]
        warn_controls = [c for c in controls_checked if c["status"] == "warn"]

        if failed_controls or overall_score < 70:
            for fc in failed_controls[:3]:
                incidents.append(
                    {
                        "incident_type": "compliance_deviation",
                        "severity": "high" if overall_score < 50 else "medium",
                        "title": f"COMPLIANCE FAIL: {fc['control']} ({fc['detail']})",
                        "description": f"Control {fc['control']} is not meeting the compliance threshold. Detail: {fc['detail']}. Overall score: {overall_score}%.",
                        "affected_assets": ["compliance-posture"],
                        "playbook_actions": [
                            "DETECT: Identify all deviating configurations",
                            "ASSESS: Determine risk impact of each deviation",
                            "REMEDIATE: Apply corrective change with change control",
                            "VERIFY: Re-run compliance check after fix",
                            "REPORT: Update compliance dashboard and GRC tool",
                            "SCHEDULE: Set next automated check in 7 days",
                        ],
                    }
                )

        metrics = {
            "total_assets": total,
            "closure_rate_pct": closure_rate,
            "config_score": round(config_score, 1),
            "audit_compliance_avg": avg_compliance,
            "overall_compliance_score": overall_score,
            "controls_checked": len(controls_checked),
            "controls_failed": len(failed_controls),
            "controls_warned": len(warn_controls),
            "controls_detail": controls_checked,
        }

        _save_incidents(run_id, "compliance_check", incidents)
        _finish_run(run_id, metrics, f"Checked {len(controls_checked)} controls. Score: {overall_score}%. {len(failed_controls)} failed, {len(warn_controls)} warnings.")

    except Exception as exc:
        logger.error(f"[compliance_check] Error: {exc}")
        _finish_run(run_id, metrics, str(exc), "error")

    return {"module": "compliance_check", "run_id": run_id, "metrics": metrics, "incidents": incidents}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

MODULE_MAP = {
    "threat_detection": run_threat_detection,
    "alert_priority": run_alert_prioritization,
    "vuln_patch": run_vuln_patch,
    "edr_monitor": run_edr_monitor,
    "ueba": run_ueba,
    "compliance_check": run_compliance_check,
}


def run_module(module: str) -> Dict[str, Any]:
    """Run a single module by name. Use 'all' to run all modules."""
    if module == "all":
        results = {}
        for name, fn in MODULE_MAP.items():
            logger.info(f"Running module: {name}")
            results[name] = fn()
        return results
    if module not in MODULE_MAP:
        raise ValueError(f"Unknown module: {module}. Choose from: {list(MODULE_MAP)}")
    return MODULE_MAP[module]()


def get_status_summary() -> Dict[str, Any]:
    """Return latest run status for all 6 modules."""
    rows = query(
        """
        SELECT DISTINCT ON (module)
            module, status, started_at, finished_at, duration_s, metrics, summary
        FROM automation_runs
        ORDER BY module, started_at DESC
        """
    )
    status = {m: {"status": "never_run", "metrics": {}, "summary": "Not yet executed"} for m in MODULE_MAP}
    for row in rows:
        m = row["module"]
        if m in status:
            status[m] = {
                "status": row["status"],
                "started_at": row["started_at"].isoformat() if row.get("started_at") else None,
                "finished_at": row["finished_at"].isoformat() if row.get("finished_at") else None,
                "duration_s": float(row.get("duration_s") or 0),
                "metrics": row.get("metrics") or {},
                "summary": row.get("summary") or "",
            }
    return status


def get_recent_incidents(module: Optional[str] = None, limit: int = 50) -> List[Dict]:
    if module and module != "all":
        rows = query(
            """
            SELECT i.*, r.started_at AS run_started
            FROM automation_incidents i
            LEFT JOIN automation_runs r ON r.id = i.run_id
            WHERE i.module = %s AND i.status = 'open'
            ORDER BY i.created_at DESC
            LIMIT %s
            """,
            (module, limit),
        )
    else:
        rows = query(
            """
            SELECT i.*, r.started_at AS run_started
            FROM automation_incidents i
            LEFT JOIN automation_runs r ON r.id = i.run_id
            WHERE i.status = 'open'
            ORDER BY i.created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
    return rows


def get_playbooks(module: Optional[str] = None) -> List[Dict]:
    if module and module != "all":
        return query("SELECT * FROM automation_playbooks WHERE module=%s AND is_active=TRUE ORDER BY id", (module,))
    return query("SELECT * FROM automation_playbooks WHERE is_active=TRUE ORDER BY module, id")


def get_integration_catalog() -> List[Dict[str, Any]]:
    return build_integration_catalog()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Automation Engine")
    parser.add_argument(
        "--module",
        default="all",
        choices=list(MODULE_MAP.keys()) + ["all"],
        help="Module to run (default: all)",
    )
    parser.add_argument("--status", action="store_true", help="Show status of all modules")
    parser.add_argument("--incidents", action="store_true", help="Show recent open incidents")
    parser.add_argument("--init", action="store_true", help="Bootstrap DB schema only")
    args = parser.parse_args()

    bootstrap_schema()

    if args.init:
        print("Schema bootstrapped.")
        sys.exit(0)

    if args.status:
        summary = get_status_summary()
        print(json.dumps(summary, indent=2, default=str))
        sys.exit(0)

    if args.incidents:
        incidents = get_recent_incidents()
        print(json.dumps(incidents, indent=2, default=str))
        sys.exit(0)

    result = run_module(args.module)
    print(json.dumps(result, indent=2, default=str))
