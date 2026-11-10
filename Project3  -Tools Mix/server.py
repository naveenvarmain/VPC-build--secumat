import csv
import posixpath
import base64
import hashlib
import hmac
import ipaddress
import io
import json
import os
import random
import re
import secrets
import shutil
import socket
import sqlite3
import threading
import time
import tarfile
import urllib.request
import urllib.error
import urllib.parse
import uuid
import zipfile
import xml.etree.ElementTree as ET
from email import policy as email_policy
from email.parser import BytesParser
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote, urlsplit
from http.client import HTTPConnection, HTTPSConnection

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover - surfaced through API response
    Fernet = None
    InvalidToken = Exception


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "data" / "sample-soc-report.csv"
DATA_DIR = ROOT / "data"
APP_STATE_DIR = Path(os.getenv("LOCALAPPDATA") or Path.home() / ".local" / "share") / "OTPlatform"
LEGACY_CLAROTY_CREDENTIALS_FILE = DATA_DIR / "claroty_credentials.enc"
LEGACY_CLAROTY_KEY_FILE = DATA_DIR / ".claroty_fernet.key"
CLAROTY_CREDENTIALS_FILE = APP_STATE_DIR / "claroty_credentials.enc"
CLAROTY_KEY_FILE = APP_STATE_DIR / "credentials.fernet.key"
INTEGRATION_CREDENTIALS_FILE = APP_STATE_DIR / "integration-credentials.enc"
RUBRIK_API_TOKEN_CACHE = {}
RUBRIK_API_TOKEN_LOCK = threading.RLock()
HOST = "127.0.0.1"
PORT = 8080
LOCAL_BROWSER_ORIGINS = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
MAX_PROXY_REQUEST_BYTES = 1024 * 1024
MAX_PROXY_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_JSON_REQUEST_BYTES = 1024 * 1024
LOCAL_SESSION_COOKIE = "OTPlatformSession"
LOCAL_SESSION_TTL_SECONDS = 12 * 60 * 60
MAX_SNORT_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_SNORT_RULE_BYTES = 150 * 1024 * 1024
SNORT_ARCHIVE_FILE = APP_STATE_DIR / "snort-rules.tar.gz"
SNORT_COMMUNITY_URL = "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
SNORT_COMMUNITY_FILE = SNORT_ARCHIVE_FILE.with_name("snort3-community-rules.tar.gz")
SNORT_BLACKLIST_FILE = SNORT_ARCHIVE_FILE.with_name("snort-ip-blacklist.txt")
SNORT_WHITELIST_FILE = SNORT_ARCHIVE_FILE.with_name("snort-ip-whitelist.txt")
SNORT_IP_REASONS_FILE = SNORT_ARCHIVE_FILE.with_name("snort-ip-list-reasons.json")
SNORT_INDICATORS_FILE = SNORT_ARCHIVE_FILE.with_name("snort-indicators.json")
MAX_SNORT_BLACKLIST_BYTES = 10 * 1024 * 1024
SNORT_UPDATE_INTERVAL_SECONDS = 24 * 60 * 60
OPENAPPID_ARCHIVE_FILE = SNORT_ARCHIVE_FILE.with_name("snort-openappid.tar.gz")
OPENAPPID_URL = "https://www.snort.org/downloads/openappid/snort-openappid.tar.gz"
MAX_OPENAPPID_ARCHIVE_BYTES = 60 * 1024 * 1024
MAX_OPENAPPID_EXPANDED_BYTES = 200 * 1024 * 1024
ZERO_TRUST_EVENT_FILE = SNORT_ARCHIVE_FILE.with_name("zero-trust-events.jsonl")
ZERO_TRUST_PLAYBOOK_RUN_FILE = SNORT_ARCHIVE_FILE.with_name("zero-trust-playbook-runs.jsonl")
ZERO_TRUST_PROGRAM_FILE = APP_STATE_DIR / "zero-trust-program.json"
MODULE_DATA_FILE = APP_STATE_DIR / "module-data.json"
AUTOMATION_RUNS_FILE = APP_STATE_DIR / "module-automation-runs.json"
ASSESSMENT_REQUESTS_FILE = APP_STATE_DIR / "assessment-testing-requests.json"
ASSESSMENT_REQUESTS_LOCK = threading.RLock()
SECUMAT_UPLOAD_DIR = APP_STATE_DIR / "secumat-uploads"
MAX_SECUMAT_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_SECUMAT_PREVIEW_ROWS = 500
MODULE_DATA_LOCK = threading.RLock()
MODULE_NAMES = {
    "assets": "Devices and assets",
    "vulnerabilities": "Vulnerabilities",
    "alerts": "Alerts",
    "incidents": "Incidents",
    "threat_intel": "Threat intelligence",
    "network_events": "Network events",
    "risk": "Risk management",
    "compliance": "Compliance",
    "secumat_audits": "SECUMAT audits",
    "secumat_uploads": "SECUMAT uploads",
    "audit_assignments": "Audit assignments",
    "audit_responses": "Audit responses",
    "audit_results": "Audit results",
    "custom_templates": "Custom audit templates",
    "audit_workbook_versions": "Audit workbook history",
    "integrations": "Integration events",
    "playbooks": "Playbooks",
    "operations": "Operations",
    "soc_studio": "SOC Studio artifacts",
    "osint_workspace": "OSINT bookmarks and notes",
}
WORKBOOK_ASSIGNMENT_STATE_FIELDS = {
    "status", "question_count", "completed_responses", "pending_items", "progress_percent",
    "compliance_score", "workbook_audit_id", "template_source", "template_file",
    "edited_by", "last_edited_at", "reviewer_score", "reviewer_comments",
    "reviewer_notes", "reviewed_by", "reviewed_at",
}
AUDIT_WORKFLOW_MODULES = {"audit_workbook_versions", "audit_assignments", "audit_responses"}
MODULE_MAX_RECORD_BYTES = 256 * 1024
MODULE_MAX_RECORDS = 25000
SIEM_MODULE_EVENT_WINDOW = 5000
AUTOMATION_MAX_RUNS = 10000
MODULE_SECRET_KEY_PARTS = ("password", "secret", "token", "credential", "apikey", "privatekey")
ZERO_TRUST_MAX_EVENT_BYTES = 64 * 1024
ZERO_TRUST_PROGRAM_MAX_BYTES = 128 * 1024
ZERO_TRUST_DOMAINS = ("identity", "device", "network", "application", "data", "pki", "analytics", "automation", "governance", "risk", "it_ot", "ai")
ZERO_TRUST_PHASES = ("awareness", "concept", "assessment", "governance", "architecture", "initial_controls", "all_domains", "automation", "ai_controls", "continuous_assurance")
ZERO_TRUST_CONTROL_IDS = ("identity_mfa", "identity_least_privilege", "device_posture", "network_segmentation", "sase_access", "application_workload_identity", "data_classification", "pki_certificate_health", "central_event_analytics", "approved_response", "it_ot_asset_mapping")
ZERO_TRUST_AI_CONTROL_IDS = ("ai_inventory", "approved_models", "strong_agent_identity", "least_privilege_tools", "sensitive_data_guardrails", "prompt_input_filtering", "output_validation", "human_approval", "ai_activity_logging", "model_risk_review")
INTEGRATION_CONNECTORS_FILE = SNORT_ARCHIVE_FILE.with_name("integration-connectors.json")
INTEGRATION_FEED_STATE_FILE = SNORT_ARCHIVE_FILE.with_name("integration-feed-state.json")
THREAT_FEED_DB_FILE = APP_STATE_DIR / "threat-indicator-index.sqlite3"
THREAT_FEED_MAX_BYTES = 25 * 1024 * 1024
THREAT_FEED_REFRESH_INTERVAL_SECONDS = 12 * 60 * 60
THREAT_FEED_DAILY_REFRESH_INTERVAL_SECONDS = 24 * 60 * 60
THREAT_INDICATOR_FEEDS = (
    {"id": "malicious-ip-1", "name": "Malicious IP list · part 1", "type": "ip", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/main/Malicious-IP-Threat-List.txt"},
    {"id": "malicious-ip-2", "name": "Malicious IP list · part 2", "type": "ip", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/main/Malicious-IP-Threat-List_aa"},
    {"id": "malicious-domain-1", "name": "Malicious domain list · part 1", "type": "domain", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Domain-Threat-List/main/Blacklisted_Malicious_Domain_Repo.txt"},
    {"id": "malicious-domain-2", "name": "Malicious domain list · part 2", "type": "domain", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Domain-Threat-List/main/Blacklisted_Malicious_Domain_Repo_aa.txt"},
    {"id": "malicious-md5-1", "name": "Malicious MD5 list · part 1", "type": "md5", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/Malicious_md5_hashes_aa.txt"},
    {"id": "malicious-md5-2", "name": "Malicious MD5 list · part 2", "type": "md5", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_md5_hashes_ab.txt"},
    {"id": "malicious-sha1-1", "name": "Malicious SHA-1 list · part 1", "type": "sha1", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA1_hashes-aa.txt"},
    {"id": "malicious-sha256-1", "name": "Malicious SHA-256 list · part 1", "type": "sha256", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_aa.txt"},
    {"id": "malicious-sha256-2", "name": "Malicious SHA-256 list · part 2", "type": "sha256", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_ab.txt"},
    {"id": "malicious-sha256-3", "name": "Malicious SHA-256 list · part 3", "type": "sha256", "url": "https://raw.githubusercontent.com/amitambekar510/Malicious-Hash-Threat-List/main/malicious_SHA256_hashes_ac.txt"},
)
INTEGRATION_TOOL_FIELDS = {
    "swimlane": {"baseUrl", "pat", "appId"},
    "crowdstrike": {"clientId", "clientSecret", "baseUrl", "cid"},
    "trellix": {"baseUrl", "clientId", "clientSecret", "tenantId", "region"},
    "sentinel": {"tenantId", "clientId", "clientSecret", "workspaceId", "subId"},
    "splunk": {"baseUrl", "token", "index"},
    "defender": {"tenantId", "clientId", "clientSecret"},
    "entra": {"tenantId", "clientId", "clientSecret"},
    "servicenow": {"instance", "user", "password"},
    "paloalto": {"hostname", "apiKey", "panorama"},
    "m365": {"tenantId", "clientId", "clientSecret"},
    "qradar": {"baseUrl", "token"},
    "virustotal": {"apiKey"},
    "abuseipdb": {"apiKey"},
    "greynoise": {"apiKey"},
    "tenable": {"baseUrl", "accessKey", "secretKey"},
    "claroty": {"baseUrl", "apiKey", "proxyUrl"},
    "elastic": {"kibanaUrl", "apiKey", "index"},
    "rubrik": {"name", "access_token_uri", "client_id", "client_secret", "baseUrl", "clientId", "clientSecret", "organizationId"},
    "netapp": {"baseUrl", "username", "password", "svm"},
    "nasuni": {"baseUrl", "clientId", "clientSecret", "organizationId"},
    "wazuh": {"baseUrl", "username", "password", "indexerUrl"},
    "opensearch": {"baseUrl", "username", "password", "apiKey", "index"},
    "misp": {"baseUrl", "apiKey"},
    "github": {"organization", "token", "webhookSecret"},
    "gitlab": {"groupId", "token", "webhookSecret"},
    "keycloak": {"baseUrl", "realm", "clientId", "clientSecret"},
    "trivy": {"baseUrl", "token"},
    "bmc": {"baseUrl", "clientId", "clientSecret", "username", "password", "tenantId"},
    "sentinelone": {"baseUrl", "apiToken", "accountId", "siteId"},
    "mcafee-epo": {"baseUrl", "username", "password"},
    "defender-cloud-apps": {"baseUrl", "tenantId", "clientId", "clientSecret"},
    "wiz": {"baseUrl", "clientId", "clientSecret", "tenantId"},
    "prismacloud": {"baseUrl", "accessKey", "secretKey", "tenantId"},
    "cato": {"baseUrl", "apiKey", "accountId"},
    "dc2cloud": {"baseUrl", "tenantId", "clientId", "clientSecret"},
}

CLAROTY_DEFAULT_BASE_URL = "https://eu.api.claroty.com"
CLAROTY_DEFAULT_PROXY_URL = "http://cloudproxy.zf-world.com:8080"
CLAROTY_API_HOST_SUFFIX = ".api.claroty.com"
CLAROTY_DVR_ENDPOINT = "/api/v1/device_vulnerability_relations/"
CLAROTY_DVR_FIELDS = [
    "device_uid", "device_name", "device_ip_list", "device_category", "device_subcategory",
    "device_type", "device_model", "device_site_name", "device_combined_os", "device_retired",
    "vulnerability_id", "vulnerability_name", "vulnerability_type", "vulnerability_cve_ids",
    "vulnerability_cvss_v3_score", "vulnerability_epss_score",
    "vulnerability_adjusted_vulnerability_score", "vulnerability_adjusted_vulnerability_score_level",
    "vulnerability_is_known_exploited", "vulnerability_exploits_count",
    "vulnerability_description", "vulnerability_recommendations",
    "vulnerability_published_date", "vulnerability_last_updated", "vulnerability_relevance",
    "patch_install_date",
]
CLAROTY_FEEDS = {
    "devices": ("/api/v1/devices/", [
        "uid", "device_name", "ip_list", "site_name", "site_group_name", "manufacturer", "device_type", "model",
        "risk_score", "is_online", "device_category", "device_subcategory", "suspicious", "retired",
    ], "devices"),
    "relations": (CLAROTY_DVR_ENDPOINT, CLAROTY_DVR_FIELDS, "devices_vulnerabilities"),
    "alerts": ("/api/v1/alerts/", [
        "id", "alert_name", "alert_type_name", "alert_class", "category", "detected_time", "updated_time",
        "devices_count", "unresolved_devices_count", "medical_devices_count", "iot_devices_count",
        "it_devices_count", "ot_devices_count", "status", "mitre_technique_ics_ids", "mitre_technique_ics_names",
        "mitre_technique_enterprise_ids", "mitre_technique_enterprise_names", "description", "malicious_ip_tags_list",
    ], "alerts"),
    "vulnerabilities": ("/api/v1/vulnerabilities/", [
        "id", "name", "cve_ids", "vulnerability_type", "cvss_v3_score", "epss_score", "is_known_exploited",
        "exploits_count", "adjusted_vulnerability_score", "adjusted_vulnerability_score_level",
        "affected_devices_count", "affected_ot_devices_count", "affected_it_devices_count", "affected_iot_devices_count",
        "affected_confirmed_devices_count", "affected_fixed_devices_count", "published_date", "description",
        "recommendations", "vulnerability_priority_group",
    ], "vulnerabilities"),
    "events": ("/api/v1/events/", [
        "id", "event_type", "timestamp", "alert_id", "alert_type", "protocol", "ip_protocol", "description",
        "internal_or_external", "comm_type", "direction", "selected_port", "malicious_ip_type", "malicious_ip_severity",
        "malicious_ip_confidence", "malicious_ip_source", "malicious_ip_tags_list", "login_username",
        "ot_activity_event_type", "ot_activity_source_username", "device_change_old_value", "device_change_new_value",
        "side_a_ip", "side_a_port", "side_a_name", "side_a_category", "side_a_site_name", "side_a_purdue_level",
        "side_a_risk_score", "side_a_manufacturer", "side_a_geolocation", "side_b_ip", "side_b_port", "side_b_name",
        "side_b_category", "side_b_site_name", "side_b_purdue_level", "side_b_risk_score", "side_b_manufacturer",
        "side_b_geolocation",
    ], "events"),
}

RULES = [
    (r"break glass|bga|max prio", "Privileged Access", "Critical", True),
    (r"ransomware|wannacry|encrypted", "Ransomware", "Critical", False),
    (r"crowdstrike", "EDR (CrowdStrike)", "High", True),
    (r"defender experts", "Defender Experts", "High", True),
    (r"sentinel|graphapi", "SIEM (Sentinel)", "High", True),
    (r"malware|high amount of av", "Malware / AV", "High", True),
    (r"entra id risk|exposed credential", "Identity Risk", "High", True),
    (r"dns tunneling|dns match", "DNS Threats", "Medium", True),
    (r"phishing|suspicious link|harmful files", "Phishing", "Medium", False),
    (r"on hold|blocked|release|attachment|delivery", "Email Security", "Low", False),
]

ALERT_TEMPLATES = [
    ("Phishing email with malicious attachment", "High", "M365 Defender", False),
    ("Ransomware pre-cursor detected", "Critical", "CrowdStrike", True),
    ("Failed login spike on privileged account", "High", "Entra ID", False),
    ("DNS tunneling exfiltration pattern", "Critical", "DNS Monitor", False),
    ("Lateral movement detected", "High", "Sentinel", False),
    ("C2 beacon to known malicious IP", "Critical", "Palo Alto", False),
    ("Endpoint isolation triggered", "Low", "CrowdStrike", True),
    ("Vulnerability scan found actively exploited CVE", "Medium", "Tenable", False),
]
SAMPLE_ALERT_DEVICES = ("OT-PLC-1001", "SCADA-HMI-1002", "OT-ENG-WS-1003", "HIST-SRV-1004")

alert_lock = threading.Lock()
alerts = []
last_alert_at = 0.0
feed_cache = {"expires": 0, "payload": None}
snort_lock = threading.Lock()
snort_catalog = None
snort_update_lock = threading.Lock()
local_session_lock = threading.Lock()
local_browser_sessions = {}
snort_blacklist_lock = threading.Lock()
zero_trust_event_lock = threading.Lock()
zero_trust_program_lock = threading.Lock()
integration_connectors_lock = threading.Lock()
integration_feed_state_lock = threading.Lock()
snort_update_state = {"updating": False, "lastChecked": None, "lastError": None, "source": "not checked"}
openappid_lock = threading.Lock()
openappid_catalog = None
openappid_update_lock = threading.Lock()
openappid_update_state = {"updating": False, "lastChecked": None, "lastError": None, "source": "not checked"}

PUBLIC_FEEDS = {
    "cisa": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5",
    "msrc": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    # abuse.ch retired the unauthenticated URLhaus json_recent endpoint (HTTP 410).
    # Feodo Tracker, FIRST EPSS and CIRCL CVE-Search remain open with no API key.
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "epss": "https://api.first.org/data/v1/epss?limit=50",
    "circl": "https://cve.circl.lu/api/last/15",
}


def today_key():
    return datetime.now(timezone.utc).date().isoformat()


def encryption_available():
    return Fernet is not None


def credential_cipher():
    if Fernet is None:
        raise RuntimeError("Python package 'cryptography' is required. Run: py -m pip install -r requirements.txt")
    APP_STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not CLAROTY_KEY_FILE.exists():
        if LEGACY_CLAROTY_KEY_FILE.exists():
            key = LEGACY_CLAROTY_KEY_FILE.read_bytes()
            Fernet(key)
            CLAROTY_KEY_FILE.write_bytes(key)
            LEGACY_CLAROTY_KEY_FILE.unlink()
        else:
            CLAROTY_KEY_FILE.write_bytes(Fernet.generate_key())
        try:
            CLAROTY_KEY_FILE.chmod(0o600)
        except OSError:
            pass
    return Fernet(CLAROTY_KEY_FILE.read_bytes())


def load_claroty_credentials():
    credential_file = CLAROTY_CREDENTIALS_FILE
    migrating_legacy = False
    if not credential_file.exists() and LEGACY_CLAROTY_CREDENTIALS_FILE.exists():
        credential_file = LEGACY_CLAROTY_CREDENTIALS_FILE
        migrating_legacy = True
    if not credential_file.exists():
        return None
    try:
        cipher = credential_cipher()
        ciphertext = credential_file.read_bytes()
        plaintext = cipher.decrypt(ciphertext)
        config = json.loads(plaintext.decode("utf-8"))
        if migrating_legacy:
            APP_STATE_DIR.mkdir(parents=True, exist_ok=True)
            temporary = CLAROTY_CREDENTIALS_FILE.with_suffix(".tmp")
            temporary.write_bytes(cipher.encrypt(plaintext))
            temporary.replace(CLAROTY_CREDENTIALS_FILE)
            LEGACY_CLAROTY_CREDENTIALS_FILE.unlink()
        return config
    except InvalidToken as error:
        raise RuntimeError("Claroty credential store could not be decrypted with the local key") from error


def save_claroty_credentials(payload):
    existing = load_claroty_credentials() or {}
    api_key = str(payload.get("apiKey") or payload.get("api_key") or "").strip()
    if not api_key:
        api_key = existing.get("apiKey", "")
    if not api_key:
        raise ValueError("Missing Claroty API token")
    base_url = str(payload.get("baseUrl") or existing.get("baseUrl") or CLAROTY_DEFAULT_BASE_URL).strip().rstrip("/")
    if "proxyUrl" in payload:
        # An explicitly empty proxy selects a direct connection; only an absent
        # key inherits the stored value, and only a first save uses the default.
        proxy_url = str(payload.get("proxyUrl") or "").strip().rstrip("/")
    elif "proxyUrl" in existing:
        proxy_url = str(existing.get("proxyUrl") or "").strip().rstrip("/")
    else:
        proxy_url = CLAROTY_DEFAULT_PROXY_URL.rstrip("/")
    if not is_allowed_claroty_base_url(base_url):
        raise ValueError("Claroty base URL must be an HTTPS Claroty API origin")
    if not allowed_claroty_upstream_proxy(proxy_url):
        raise ValueError("Claroty proxy must match the approved proxy or CLAROTY_APPROVED_PROXY_URLS")
    config = {
        "baseUrl": base_url,
        "apiKey": api_key,
        "proxyUrl": proxy_url,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "lastConfirmedOn": today_key(),
    }
    APP_STATE_DIR.mkdir(parents=True, exist_ok=True)
    encrypted = credential_cipher().encrypt(json.dumps(config).encode("utf-8"))
    temporary = CLAROTY_CREDENTIALS_FILE.with_suffix(".tmp")
    temporary.write_bytes(encrypted)
    temporary.replace(CLAROTY_CREDENTIALS_FILE)
    try:
        CLAROTY_CREDENTIALS_FILE.chmod(0o600)
    except OSError:
        pass
    return config


def claroty_credentials_status(config=None):
    config = config if config is not None else load_claroty_credentials()
    configured = bool(config and config.get("apiKey"))
    last_confirmed = (config or {}).get("lastConfirmedOn")
    return {
        "configured": configured,
        "encrypted": configured and CLAROTY_CREDENTIALS_FILE.exists(),
        "baseUrl": (config or {}).get("baseUrl", CLAROTY_DEFAULT_BASE_URL),
        "proxyUrl": (config or {}).get("proxyUrl", CLAROTY_DEFAULT_PROXY_URL),
        "updatedAt": (config or {}).get("updatedAt"),
        "lastConfirmedOn": last_confirmed,
        "needsDailyConfirm": False,
        "backend": "encrypted-fernet" if encryption_available() else "missing-cryptography",
    }


def confirm_claroty_credentials():
    config = load_claroty_credentials()
    if not config or not config.get("apiKey"):
        raise ValueError("Claroty credentials are not configured")
    config["lastConfirmedOn"] = today_key()
    config["updatedAt"] = config.get("updatedAt") or datetime.now(timezone.utc).isoformat()
    encrypted = credential_cipher().encrypt(json.dumps(config).encode("utf-8"))
    temporary = CLAROTY_CREDENTIALS_FILE.with_suffix(".tmp")
    temporary.write_bytes(encrypted)
    temporary.replace(CLAROTY_CREDENTIALS_FILE)
    try:
        CLAROTY_CREDENTIALS_FILE.chmod(0o600)
    except OSError:
        pass
    return config


def delete_claroty_credentials():
    for credential_file in (CLAROTY_CREDENTIALS_FILE, LEGACY_CLAROTY_CREDENTIALS_FILE):
        if credential_file.exists():
            credential_file.unlink()


def load_integration_credential_store():
    if not INTEGRATION_CREDENTIALS_FILE.exists():
        return {}
    try:
        return json.loads(credential_cipher().decrypt(INTEGRATION_CREDENTIALS_FILE.read_bytes()).decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError) as error:
        raise RuntimeError("Integration credential store is unreadable") from error


def save_integration_credentials(payload):
    if not isinstance(payload, dict):
        raise ValueError("Integration credentials must be a JSON object")
    tool_id = str(payload.get("toolId") or "")
    if tool_id not in INTEGRATION_TOOL_FIELDS:
        raise ValueError("Unknown integration tool")
    config = payload.get("config")
    if not isinstance(config, dict):
        raise ValueError("Integration config must be a JSON object")
    allowed_fields = INTEGRATION_TOOL_FIELDS[tool_id]
    clean_config = {}
    for key, value in config.items():
        if key not in allowed_fields or not isinstance(value, str) or len(value) > 4096:
            raise ValueError(f"Invalid integration field: {key}")
        if value.strip():
            clean_config[key] = normalize_base_url(value) if key.lower().endswith(("url", "_uri")) else value.strip()
    if not clean_config:
        raise ValueError("At least one non-empty integration field is required")
    if tool_id == "rubrik":
        for legacy_key, current_key in (
            ("baseUrl", "access_token_uri"),
            ("clientId", "client_id"),
            ("clientSecret", "client_secret"),
        ):
            legacy_value = clean_config.pop(legacy_key, None)
            if current_key not in clean_config and legacy_value:
                clean_config[current_key] = legacy_value
    store = load_integration_credential_store()
    previous_config = store.get(tool_id) or {}
    if tool_id == "rubrik":
        previous_config = {
            **previous_config,
            "name": previous_config.get("name", ""),
            "access_token_uri": previous_config.get("access_token_uri") or previous_config.get("baseUrl", ""),
            "client_id": previous_config.get("client_id") or previous_config.get("clientId", ""),
            "client_secret": previous_config.get("client_secret") or previous_config.get("clientSecret", ""),
        }
        for legacy_key in ("baseUrl", "clientId", "clientSecret"):
            previous_config.pop(legacy_key, None)
    store[tool_id] = {**previous_config, **clean_config}
    APP_STATE_DIR.mkdir(parents=True, exist_ok=True)
    encrypted = credential_cipher().encrypt(json.dumps(store).encode("utf-8"))
    temporary = INTEGRATION_CREDENTIALS_FILE.with_suffix(".tmp")
    temporary.write_bytes(encrypted)
    temporary.replace(INTEGRATION_CREDENTIALS_FILE)
    try:
        INTEGRATION_CREDENTIALS_FILE.chmod(0o600)
    except OSError:
        pass
    if tool_id == "rubrik":
        with RUBRIK_API_TOKEN_LOCK:
            RUBRIK_API_TOKEN_CACHE.clear()
    return tool_id, clean_config


TOOL_CAPABILITY_CATEGORIES = {
    "Endpoint detection & response": ["crowdstrike", "defender", "sentinelone", "trellix", "mcafee-epo", "wazuh"],
    "SIEM / log analytics": ["sentinel", "splunk", "qradar", "elastic", "opensearch", "wazuh"],
    "Vulnerability management": ["tenable", "trivy"],
    "Cloud security posture": ["wiz", "prismacloud", "defender-cloud-apps"],
    "Identity & access": ["entra", "keycloak", "m365"],
    "Network / SASE": ["paloalto", "cato", "dc2cloud"],
    "Threat intelligence": ["virustotal", "abuseipdb", "greynoise", "misp"],
    "ITSM / orchestration": ["servicenow", "bmc", "swimlane"],
    "Backup & recovery": ["rubrik", "netapp", "nasuni"],
    "OT asset visibility": ["claroty"],
}


def tool_overlap_payload():
    """Report capability categories where more than one integration is configured.

    Overlap is derived only from locally saved credentials. It is a configuration
    signal, not a licence audit, and carries no cost estimate.
    """
    try:
        store = load_integration_credential_store()
    except Exception:
        store = {}
    configured_ids = {tool_id for tool_id, config in store.items() if config}
    try:
        claroty_configured = bool(claroty_credentials_status().get("configured"))
    except Exception:
        claroty_configured = False
    if claroty_configured:
        configured_ids.add("claroty")

    categories = []
    for category, tool_ids in TOOL_CAPABILITY_CATEGORIES.items():
        configured = sorted(tool_id for tool_id in tool_ids if tool_id in configured_ids)
        categories.append({
            "category": category,
            "configured": configured,
            "configuredCount": len(configured),
            "candidateCount": len(tool_ids),
            "candidates": tool_ids,
            "overlap": len(configured) > 1,
        })
    categories.sort(key=lambda item: (-item["configuredCount"], item["category"]))
    overlaps = [item for item in categories if item["overlap"]]
    return {
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "categories": categories,
        "overlaps": overlaps,
        "configuredTotal": len(configured_ids),
        "overlapCount": len(overlaps),
        "source": "local-credential-store",
        "note": "Overlap reflects integrations configured in this app only. It is not a licence or spend audit; cost impact requires commercial data this app does not hold.",
    }


def public_integration_credential_status():
    store = load_integration_credential_store()
    secret_names = {"pat", "password", "clientsecret", "secret", "secretkey", "token", "apitoken", "apikey", "accesskey", "webhooksecret"}
    tools = {}
    for tool_id, config in store.items():
        safe_config = {key: value for key, value in config.items() if re.sub(r"[^a-z0-9]", "", key.lower()) not in secret_names}
        tools[tool_id] = {"configured": bool(config), "fields": sorted(config), "safeConfig": safe_config}
    return {"tools": tools, "source": "encrypted-backend"}


INTEGRATION_TEST_TIMEOUT = 15
MAX_INTEGRATION_TEST_BYTES = 256 * 1024

# Per-vendor probe definitions. "auth" selects how the stored credential is presented.
#   oauth2   -> POST client_credentials to `path`; a 2xx with a token proves credentials.
#   basic    -> HTTP Basic against `path`.
#   bearer   -> Authorization: Bearer <field>.
#   header   -> a vendor-specific header name/template.
# Tools absent from this table fall back to an unauthenticated reachability probe.
INTEGRATION_TEST_PROBES = {
    "rubrik": {"auth": "oauth2", "path": "/api/client_token", "base": "access_token_uri", "client": "client_id", "secret": "client_secret", "form": True},
    "keycloak": {"auth": "oauth2", "path": "/realms/{realm}/protocol/openid-connect/token", "base": "baseUrl", "client": "clientId", "secret": "clientSecret"},
    "crowdstrike": {"auth": "oauth2", "path": "/oauth2/token", "base": "baseUrl", "client": "clientId", "secret": "clientSecret", "form": True},
    "nasuni": {"auth": "oauth2", "path": "/oauth2/token", "base": "baseUrl", "client": "clientId", "secret": "clientSecret", "form": True},
    "wiz": {"auth": "oauth2", "path": "/oauth/token", "base": "baseUrl", "client": "clientId", "secret": "clientSecret", "form": True},
    "sentinel": {"auth": "entra", "tenant": "tenantId", "client": "clientId", "secret": "clientSecret", "scope": "https://management.azure.com/.default"},
    "defender": {"auth": "entra", "tenant": "tenantId", "client": "clientId", "secret": "clientSecret", "scope": "https://api.securitycenter.microsoft.com/.default"},
    "entra": {"auth": "entra", "tenant": "tenantId", "client": "clientId", "secret": "clientSecret", "scope": "https://graph.microsoft.com/.default"},
    "m365": {"auth": "entra", "tenant": "tenantId", "client": "clientId", "secret": "clientSecret", "scope": "https://graph.microsoft.com/.default"},
    "defender-cloud-apps": {"auth": "entra", "tenant": "tenantId", "client": "clientId", "secret": "clientSecret", "scope": "https://graph.microsoft.com/.default"},
    "dc2cloud": {"auth": "entra", "tenant": "tenantId", "client": "clientId", "secret": "clientSecret", "scope": "https://graph.microsoft.com/.default"},
    "wazuh": {"auth": "basic", "path": "/security/user/authenticate", "base": "baseUrl", "user": "username", "password": "password"},
    "opensearch": {"auth": "basic", "path": "/", "base": "baseUrl", "user": "username", "password": "password"},
    "servicenow": {"auth": "basic", "path": "/api/now/table/sys_user?sysparm_limit=1", "base": "instance", "user": "user", "password": "password"},
    "netapp": {"auth": "basic", "path": "/api/cluster", "base": "baseUrl", "user": "username", "password": "password"},
    "mcafee-epo": {"auth": "basic", "path": "/remote/core.help", "base": "baseUrl", "user": "username", "password": "password"},
    "splunk": {"auth": "bearer", "path": "/services/server/info?output_mode=json", "base": "baseUrl", "token": "token"},
    "trivy": {"auth": "bearer", "path": "/healthz", "base": "baseUrl", "token": "token"},
    "elastic": {"auth": "header", "path": "/api/status", "base": "kibanaUrl", "header": "Authorization", "template": "ApiKey {apiKey}"},
    "misp": {"auth": "header", "path": "/servers/getVersion", "base": "baseUrl", "header": "Authorization", "template": "{apiKey}"},
    "qradar": {"auth": "header", "path": "/api/system/about", "base": "baseUrl", "header": "SEC", "template": "{token}"},
    "tenable": {"auth": "header", "path": "/server/status", "base": "baseUrl", "header": "X-ApiKeys", "template": "accessKey={accessKey};secretKey={secretKey}"},
    "sentinelone": {"auth": "header", "path": "/web/api/v2.1/system/info", "base": "baseUrl", "header": "Authorization", "template": "ApiToken {apiToken}"},
    "paloalto": {"auth": "header", "path": "/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1", "base": "hostname", "header": "X-PAN-KEY", "template": "{apiKey}"},
    "cato": {"auth": "header", "path": "/api/v1/graphql2", "base": "baseUrl", "header": "x-api-key", "template": "{apiKey}"},
    "virustotal": {"auth": "header", "url": "https://www.virustotal.com/api/v3/users/me", "header": "x-apikey", "template": "{apiKey}"},
    "abuseipdb": {"auth": "header", "url": "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", "header": "Key", "template": "{apiKey}"},
    "greynoise": {"auth": "header", "url": "https://api.greynoise.io/v3/community/8.8.8.8", "header": "key", "template": "{apiKey}"},
}


def assert_public_http_target(url):
    """Reject non-HTTP(S) schemes, loopback, and link-local (cloud metadata) targets.

    RFC1918 private ranges are allowed on purpose: on-prem security tools such as
    Rubrik, Wazuh, OpenSearch and QRadar legitimately live on internal networks.
    Loopback and link-local stay blocked so a stored credential cannot be used to
    reach this server's own admin surface or a cloud instance-metadata endpoint.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Integration endpoint must use http or https")
    if parsed.username or parsed.password:
        raise ValueError("Integration endpoint must not embed credentials")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Integration endpoint is missing a hostname")
    try:
        resolved = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise ValueError(f"DNS lookup failed for {hostname}") from error
    for entry in resolved:
        address = ipaddress.ip_address(entry[4][0])
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
            raise ValueError(f"Integration endpoint resolves to a blocked address ({address})")
    return url


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def perform_integration_probe(url, headers=None, data=None, method="GET"):
    assert_public_http_target(url)
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    opener = urllib.request.build_opener(NoRedirectHandler())
    started = time.monotonic()
    try:
        with opener.open(request, timeout=INTEGRATION_TEST_TIMEOUT) as response:
            response.read(MAX_INTEGRATION_TEST_BYTES)
            return {"status": response.status, "ms": round((time.monotonic() - started) * 1000)}
    except urllib.error.HTTPError as error:
        detail = error.read(2048).decode("utf-8", errors="replace").strip()
        return {"status": error.code, "ms": round((time.monotonic() - started) * 1000), "detail": detail[:300]}


def normalize_base_url(raw, strip_path=None):
    """Clean a user-entered base URL.

    Users frequently paste a value copied out of JSON, so strip stray quotes and
    commas. They also often paste the full token endpoint instead of the host,
    so an already-present probe path is removed to avoid duplicating it.
    """
    value = str(raw or "").strip().strip("\"'").strip().rstrip(",").strip().strip("\"'")
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    value = value.rstrip("/")
    if strip_path:
        suffix = "/" + strip_path.strip("/")
        while suffix != "/" and value.lower().endswith(suffix.lower()):
            value = value[: -len(suffix)].rstrip("/")
    return value


def normalize_rubrik_client_id(value):
    client_id = str(value or "").strip()
    while client_id.endswith((",", ";")):
        client_id = client_id[:-1].rstrip()
    if client_id[:1] in {"'", '"'}:
        client_id = client_id[1:]
    if client_id[-1:] in {"'", '"'}:
        client_id = client_id[:-1]
    return client_id.strip()


def _probe_base(config, probe):
    field = probe.get("base") or "baseUrl"
    path = probe.get("path") or ""
    raw_base = config.get(field)
    if not raw_base and field == "access_token_uri":
        raw_base = config.get("baseUrl")
    base = normalize_base_url(raw_base, None if "{" in path else path)
    if not base:
        raise ValueError(f"Missing {field} in the stored credential")
    return base


def integration_connection_test(tool_id):
    if tool_id not in INTEGRATION_TOOL_FIELDS:
        raise ValueError("Unknown integration tool")
    if tool_id == "claroty":
        return {"toolId": tool_id, "ok": False, "authTested": False,
                "message": "Claroty is tested through its own feed diagnostics endpoint."}
    config = (load_integration_credential_store() or {}).get(tool_id)
    if not config:
        return {"toolId": tool_id, "ok": False, "authTested": False,
                "message": "No credentials stored for this integration."}

    if tool_id in ("github", "gitlab"):
        group_key = "organization" if tool_id == "github" else "groupId"
        if not config.get(group_key) or not config.get("token"):
            return {"toolId": tool_id, "ok": False, "authTested": False,
                    "message": f"{group_key} and API token are required to test the connection."}
        group = urllib.parse.quote(config[group_key], safe="")
        url = f"https://api.github.com/orgs/{group}" if tool_id == "github" else f"https://gitlab.com/api/v4/groups/{group}"
        try:
            git_provider_api_request(tool_id, url, config["token"])
            return {"toolId": tool_id, "ok": True, "authTested": True,
                    "message": "API credentials authorized organization/group metadata; verify individual audit and security feed permissions with Sync Git sources."}
        except (RuntimeError, ValueError) as error:
            return {"toolId": tool_id, "ok": False, "authTested": True, "message": str(error)}

    if tool_id == "cato":
        started = time.monotonic()
        try:
            events, _ = poll_cato_provider(config)
            return {"toolId": tool_id, "ok": True, "authTested": True,
                    "latencyMs": round((time.monotonic() - started) * 1000),
                    "message": f"Cato API key authorized a read-only audit query ({len(events)} record(s))."}
        except (RuntimeError, ValueError, OSError) as error:
            return {"toolId": tool_id, "ok": False, "authTested": True, "message": str(error)[:240]}

    if tool_id == "opensearch" and config.get("apiKey"):
        try:
            url = _probe_base(config, {"base": "baseUrl"}) + "/"
            result = perform_integration_probe(url, {"Authorization": f"ApiKey {config['apiKey']}", "Accept": "application/json"})
            ok = result["status"] < 400
            return {"toolId": tool_id, "ok": ok, "authTested": True, "status": result["status"], "latencyMs": result["ms"],
                    "message": "Authenticated successfully." if ok
                               else f"Authentication failed (HTTP {result['status']}). {result.get('detail', '')}".strip()}
        except (ValueError, urllib.error.URLError, socket.timeout, TimeoutError) as error:
            return {"toolId": tool_id, "ok": False, "authTested": True, "message": str(error)}

    probe = INTEGRATION_TEST_PROBES.get(tool_id)
    try:
        if not probe:
            base = _probe_base(config, {})
            result = perform_integration_probe(base)
            return {"toolId": tool_id, "ok": result["status"] < 500, "authTested": False,
                    "status": result["status"], "latencyMs": result["ms"],
                    "message": f"Endpoint reachable (HTTP {result['status']}). No vendor auth probe is implemented, so this does not prove the credential is valid."}

        auth = probe["auth"]
        if auth == "entra":
            tenant = str(config.get(probe["tenant"]) or "").strip()
            if not tenant:
                raise ValueError(f"Missing {probe['tenant']}")
            url = f"https://login.microsoftonline.com/{urllib.parse.quote(tenant, safe='')}/oauth2/v2.0/token"
            body = urllib.parse.urlencode({
                "grant_type": "client_credentials",
                "client_id": config.get(probe["client"], ""),
                "client_secret": config.get(probe["secret"], ""),
                "scope": probe["scope"],
            }).encode("utf-8")
            result = perform_integration_probe(url, {"Content-Type": "application/x-www-form-urlencoded"}, body, "POST")
            ok = result["status"] == 200
            return {"toolId": tool_id, "ok": ok, "authTested": True, "status": result["status"], "latencyMs": result["ms"],
                    "message": "Entra ID issued a token — client credentials are valid." if ok
                               else f"Entra ID rejected the client credentials (HTTP {result['status']}). {result.get('detail', '')}".strip()}

        if auth == "oauth2":
            path = probe["path"].format(**{key: urllib.parse.quote(str(config.get(key) or ""), safe="") for key in ("realm",)}) if "{realm}" in probe["path"] else probe["path"]
            url = _probe_base(config, probe) + path
            client_id = config.get(probe["client"], "")
            client_secret = config.get(probe["secret"], "")
            if tool_id == "rubrik":
                client_id = normalize_rubrik_client_id(client_id)
                client_id = client_id or normalize_rubrik_client_id(config.get("clientId", ""))
                client_secret = client_secret or config.get("clientSecret", "")
                if not client_id or not client_secret:
                    raise ValueError("Rubrik client_id and client_secret are required to test authentication")
            payload = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
            if probe.get("form"):
                body = urllib.parse.urlencode(payload).encode("utf-8")
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
            else:
                body = json.dumps(payload).encode("utf-8")
                headers = {"Content-Type": "application/json"}
            result = perform_integration_probe(url, headers, body, "POST")
            ok = result["status"] == 200
            if ok:
                message = "Token endpoint accepted the client credentials."
            elif result["status"] == 404:
                message = f"Reached the token endpoint, but the service account was not found (HTTP 404) — check the client ID and that the service account still exists. {result.get('detail', '')}".strip()
            elif result["status"] in (401, 403):
                message = f"Token endpoint rejected the credentials (HTTP {result['status']}) — the client secret is wrong, expired or revoked. {result.get('detail', '')}".strip()
            else:
                message = f"Token request failed (HTTP {result['status']}). {result.get('detail', '')}".strip()
            return {"toolId": tool_id, "ok": ok, "authTested": True, "status": result["status"], "latencyMs": result["ms"],
                    "message": message}

        if auth == "basic":
            url = _probe_base(config, probe) + probe["path"]
            token = base64.b64encode(f"{config.get(probe['user'], '')}:{config.get(probe['password'], '')}".encode("utf-8")).decode("ascii")
            result = perform_integration_probe(url, {"Authorization": f"Basic {token}", "Accept": "application/json"})
            ok = result["status"] < 400
            return {"toolId": tool_id, "ok": ok, "authTested": True, "status": result["status"], "latencyMs": result["ms"],
                    "message": "Authenticated successfully." if ok
                               else f"Authentication failed (HTTP {result['status']}). {result.get('detail', '')}".strip()}

        if auth == "bearer":
            url = _probe_base(config, probe) + probe["path"]
            result = perform_integration_probe(url, {"Authorization": f"Bearer {config.get(probe['token'], '')}", "Accept": "application/json"})
            ok = result["status"] < 400
            return {"toolId": tool_id, "ok": ok, "authTested": True, "status": result["status"], "latencyMs": result["ms"],
                    "message": "Authenticated successfully." if ok
                               else f"Authentication failed (HTTP {result['status']}). {result.get('detail', '')}".strip()}

        if auth == "header":
            url = probe["url"] if probe.get("url") else _probe_base(config, probe) + probe["path"]
            missing = [token for token in re.findall(r"\{(\w+)\}", probe["template"]) if not config.get(token)]
            if missing:
                raise ValueError(f"Missing {', '.join(missing)}")
            value = probe["template"].format(**{key: config.get(key, "") for key in re.findall(r"\{(\w+)\}", probe["template"])})
            result = perform_integration_probe(url, {probe["header"]: value, "Accept": "application/json"})
            ok = result["status"] < 400
            return {"toolId": tool_id, "ok": ok, "authTested": True, "status": result["status"], "latencyMs": result["ms"],
                    "message": "Authenticated successfully." if ok
                               else f"Authentication failed (HTTP {result['status']}). {result.get('detail', '')}".strip()}

        raise ValueError("Unsupported probe type")
    except ValueError as error:
        return {"toolId": tool_id, "ok": False, "authTested": False, "message": str(error)}
    except urllib.error.URLError as error:
        return {"toolId": tool_id, "ok": False, "authTested": False, "message": f"Connection failed: {getattr(error, 'reason', error)}"}
    except (socket.timeout, TimeoutError):
        return {"toolId": tool_id, "ok": False, "authTested": False, "message": f"Connection timed out after {INTEGRATION_TEST_TIMEOUT}s"}
    except Exception as error:
        return {"toolId": tool_id, "ok": False, "authTested": False, "message": f"Connection failed: {error}"}


def rubrik_api_origin(config):
    token_uri = str(config.get("access_token_uri") or config.get("baseUrl") or "").strip()
    parsed = urlparse(token_uri)
    if (parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.casefold().endswith(".my.rubrik.com")
            or parsed.username or parsed.password
            or parsed.port not in (None, 443)
            or parsed.path.rstrip("/") not in ("", "/api/client_token")
            or parsed.query or parsed.fragment):
        raise ValueError("Rubrik access_token_uri must be an HTTPS Rubrik Security Cloud token endpoint")
    return f"https://{parsed.hostname}"


def rubrik_access_token(config):
    origin = rubrik_api_origin(config)
    client_id = normalize_rubrik_client_id(config.get("client_id") or config.get("clientId"))
    client_secret = str(config.get("client_secret") or config.get("clientSecret") or "")
    if not client_id or not client_secret:
        raise ValueError("Rubrik client_id and client_secret are required")
    cache_key = (origin, client_id)
    with RUBRIK_API_TOKEN_LOCK:
        cached = RUBRIK_API_TOKEN_CACHE.get(cache_key)
        if cached and cached["expires_at"] > time.monotonic():
            return origin, cached["access_token"]
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }).encode("utf-8")
        request = urllib.request.Request(
            origin + "/api/client_token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=INTEGRATION_TEST_TIMEOUT) as response:
                token_payload = json.loads(response.read())
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Rubrik token request failed (HTTP {error.code})") from None
        except (urllib.error.URLError, socket.timeout, TimeoutError) as error:
            raise RuntimeError(f"Rubrik token endpoint is unavailable: {getattr(error, 'reason', error)}") from None
        access_token = token_payload.get("access_token") if isinstance(token_payload, dict) else None
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("Rubrik token endpoint returned no access token")
        try:
            expires_in = max(0, int(token_payload.get("expires_in", 3600)))
        except (TypeError, ValueError):
            expires_in = 3600
        RUBRIK_API_TOKEN_CACHE[cache_key] = {
            "access_token": access_token,
            "expires_at": time.monotonic() + max(0, expires_in - 60),
        }
        return origin, access_token


def rubrik_graphql_query(config, query, variables):
    origin, access_token = rubrik_access_token(config)
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    request = urllib.request.Request(
        origin + "/api/graphql",
        data=body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=INTEGRATION_TEST_TIMEOUT) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Rubrik GraphQL request failed (HTTP {error.code})") from None
    except (urllib.error.URLError, socket.timeout, TimeoutError) as error:
        raise RuntimeError(f"Rubrik GraphQL endpoint is unavailable: {getattr(error, 'reason', error)}") from None
    if not isinstance(result, dict):
        raise RuntimeError("Rubrik GraphQL returned an invalid response")
    errors = result.get("errors")
    if errors:
        messages = [str(item.get("message") or "GraphQL error")[:300] for item in errors[:3] if isinstance(item, dict)]
        raise RuntimeError("Rubrik GraphQL query failed: " + "; ".join(messages))
    data = result.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("Rubrik GraphQL returned no data")
    return data


RUBRIK_PAGE_SIZE = 50

RUBRIK_ACTIVITY_QUERY = """
query RubrikRecentEvents($first: Int, $activityAfter: String, $auditAfter: String, $includeActivity: Boolean!, $includeAudit: Boolean!, $activityFilters: ActivitySeriesFilter, $auditFilters: UserAuditFilter) {
  activitySeriesConnection(first: $first, after: $activityAfter, filters: $activityFilters) @include(if: $includeActivity) {
    nodes {
      activitySeriesId
      lastActivityStatus
      lastActivityType
      lastActivityMessage
      lastUpdated
      lastEventAddedAt
      startTime
      objectId
      objectName
      objectType
      orgName
      clusterName
      severity
      failureReason
      causeErrorCode
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
  userAuditConnection(first: $first, after: $auditAfter, filters: $auditFilters) @include(if: $includeAudit) {
    nodes {
      actorType
      auditType
      id
      message
      objectId
      objectName
      objectType
      orgName
      severity
      status
      time
      userName
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


def rubrik_recent_activity_payload(lookback_minutes=1440, activity_after=None, audit_after=None,
                                   activity_done=False, audit_done=False):
    try:
        lookback_minutes = int(lookback_minutes)
    except (TypeError, ValueError) as error:
        raise ValueError("lookback_minutes must be an integer") from error
    if not 1 <= lookback_minutes <= 90 * 24 * 60:
        raise ValueError("lookback_minutes must be between 1 and 129600")
    for cursor in (activity_after, audit_after):
        if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 2048):
            raise ValueError("Rubrik pagination cursor is invalid")
    if activity_done and audit_done:
        raise ValueError("At least one Rubrik event stream must remain active")
    config = (load_integration_credential_store() or {}).get("rubrik")
    if not config:
        raise ValueError("Rubrik API credentials are not configured")
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat().replace("+00:00", "Z")
    filters = {"lastUpdatedTimeGt": cutoff}
    audit_filters = {"timeGt": cutoff}
    data = rubrik_graphql_query(config, RUBRIK_ACTIVITY_QUERY, {
        "first": RUBRIK_PAGE_SIZE,
        "activityAfter": activity_after,
        "auditAfter": audit_after,
        "includeActivity": not activity_done,
        "includeAudit": not audit_done,
        "activityFilters": filters,
        "auditFilters": audit_filters,
    })
    activity_nodes = []
    audit_nodes = []
    activity_connection = data.get("activitySeriesConnection") if not activity_done else None
    audit_connection = data.get("userAuditConnection") if not audit_done else None
    if not activity_done and (
        not isinstance(activity_connection, dict)
        or not isinstance(activity_connection.get("nodes"), list)
        or not isinstance(activity_connection.get("pageInfo"), dict)
    ):
        raise RuntimeError("Rubrik GraphQL returned incomplete workload activity events")
    if not audit_done and (
        not isinstance(audit_connection, dict)
        or not isinstance(audit_connection.get("nodes"), list)
        or not isinstance(audit_connection.get("pageInfo"), dict)
    ):
        raise RuntimeError("Rubrik GraphQL returned incomplete audit events")
    next_activity_cursor = None
    next_audit_cursor = None
    has_more_activities = False
    has_more_audit_events = False
    if activity_connection:
        activity_nodes = activity_connection["nodes"]
        page_info = activity_connection["pageInfo"]
        has_more_activities = bool(page_info.get("hasNextPage"))
        next_activity_cursor = page_info.get("endCursor") if has_more_activities else None
        if has_more_activities and (not next_activity_cursor or next_activity_cursor == activity_after):
            raise RuntimeError("Rubrik workload activity pagination returned no advancing cursor")
    if audit_connection:
        audit_nodes = audit_connection["nodes"]
        page_info = audit_connection["pageInfo"]
        has_more_audit_events = bool(page_info.get("hasNextPage"))
        next_audit_cursor = page_info.get("endCursor") if has_more_audit_events else None
        if has_more_audit_events and (not next_audit_cursor or next_audit_cursor == audit_after):
            raise RuntimeError("Rubrik audit pagination returned no advancing cursor")
    events = []
    for item in activity_nodes:
        if not isinstance(item, dict):
            continue
        timestamp = item.get("lastUpdated") or item.get("lastEventAddedAt") or item.get("startTime")
        if not timestamp:
            continue
        status = str(item.get("lastActivityStatus") or "UNKNOWN")
        severity = str(item.get("severity") or "UNKNOWN")
        events.append({
            "id": str(item.get("activitySeriesId") or item.get("objectId") or ""),
            "eventClass": "Workload activity",
            "time": str(timestamp),
            "activityType": str(item.get("lastActivityType") or "UNKNOWN"),
            "title": str(item.get("lastActivityMessage") or item.get("lastActivityType") or "Rubrik activity")[:1000],
            "status": status,
            "severity": severity,
            "objectName": str(item.get("objectName") or ""),
            "objectType": str(item.get("objectType") or ""),
            "clusterName": str(item.get("clusterName") or ""),
            "organization": str(item.get("orgName") or ""),
            "failureReason": str(item.get("failureReason") or "")[:1000],
            "errorCode": str(item.get("causeErrorCode") or "")[:200],
            "source": "Rubrik Security Cloud API",
            "deviceName": str(item.get("objectName") or ""),
            "deviceType": str(item.get("objectType") or ""),
            "path": "",
            "indicators": [],
        })
    for item in audit_nodes:
        if not isinstance(item, dict) or not item.get("time"):
            continue
        events.append({
            "id": str(item.get("id") or item.get("objectId") or ""),
            "eventClass": "Audit event",
            "time": str(item["time"]),
            "activityType": str(item.get("auditType") or "AUDIT"),
            "title": str(item.get("message") or item.get("auditType") or "Rubrik audit event")[:1000],
            "status": str(item.get("status") or "UNKNOWN"),
            "severity": str(item.get("severity") or "UNKNOWN"),
            "objectName": str(item.get("objectName") or ""),
            "objectType": str(item.get("objectType") or ""),
            "clusterName": "",
            "organization": str(item.get("orgName") or ""),
            "actor": str(item.get("userName") or ""),
            "failureReason": "",
            "errorCode": "",
            "source": "Rubrik Security Cloud API",
            "deviceName": str(item.get("objectName") or ""),
            "deviceType": str(item.get("objectType") or ""),
            "path": "",
            "indicators": [],
        })
    def event_time_key(item):
        try:
            return datetime.fromisoformat(item["time"].replace("Z", "+00:00")).timestamp()
        except (ValueError, OverflowError):
            return 0

    events.sort(key=event_time_key, reverse=True)
    canonical_events = []
    for item in events:
        external_id = str(item.get("id") or "")
        stable_id = external_id or hashlib.sha256(
            json.dumps(item, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        is_audit = item["eventClass"] == "Audit event"
        event = {
            "event_id": f"rubrik-api:{item['eventClass']}:{stable_id}",
            "event_type": "rubrik.audit.event" if is_audit else "rubrik.workload.activity",
            "event_time": item["time"],
            "source": {"system": "Rubrik Security Cloud", "transport": "rubrik_api"},
            "device": {
                "device_id": external_id,
                "device_name": item.get("deviceName") or "",
                "device_type": item.get("deviceType") or "",
            },
            "subject": {"identity_id": item.get("actor") or ""},
            "outcome": str(item.get("status") or "observed").casefold(),
            "details": {
                "summary": item.get("title") or "",
                "activity_type": item.get("activityType") or "",
                "event_class": item.get("eventClass") or "",
                "status": item.get("status") or "",
                "severity": item.get("severity") or "",
                "object_name": item.get("objectName") or "",
                "object_type": item.get("objectType") or "",
                "cluster_name": item.get("clusterName") or "",
                "organization": item.get("organization") or "",
                "actor": item.get("actor") or "",
                "failure_reason": item.get("failureReason") or "",
                "error_code": item.get("errorCode") or "",
                "path": "",
                "indicators": [],
            },
        }
        canonical_events.append(event)
    routed_events = save_integration_events(canonical_events)
    for item, routing in zip(events, routed_events):
        item["category"] = routing["category"]
        item["routedModules"] = routing["modules"]
    return {
        "source": "rubrik-security-cloud-api",
        "syncedAt": datetime.now(timezone.utc).isoformat(),
        "lookbackMinutes": lookback_minutes,
        "count": len(events),
        "activityCount": len(activity_nodes),
        "auditCount": len(audit_nodes),
        "hasMoreActivities": has_more_activities,
        "hasMoreAuditEvents": has_more_audit_events,
        "partial": has_more_activities or has_more_audit_events,
        "nextActivityCursor": next_activity_cursor,
        "nextAuditCursor": next_audit_cursor,
        "events": events,
        "routedCount": len(routed_events),
    }


def delete_integration_credentials(tool_id):
    if tool_id not in INTEGRATION_TOOL_FIELDS:
        raise ValueError("Unknown integration tool")
    store = load_integration_credential_store()
    removed = store.pop(tool_id, None) is not None
    if removed:
        encrypted = credential_cipher().encrypt(json.dumps(store).encode("utf-8"))
        temporary = INTEGRATION_CREDENTIALS_FILE.with_suffix(".tmp")
        temporary.write_bytes(encrypted)
        temporary.replace(INTEGRATION_CREDENTIALS_FILE)
        if tool_id == "rubrik":
            with RUBRIK_API_TOKEN_LOCK:
                RUBRIK_API_TOKEN_CACHE.clear()
    return removed


def swimlane_request(payload):
    if not isinstance(payload, dict):
        raise ValueError("Swimlane request must be a JSON object")
    store = load_integration_credential_store()
    config = store.get("swimlane") or {}
    if not all(config.get(key) for key in ("baseUrl", "pat", "appId")):
        raise PermissionError("Swimlane server-side credentials are not configured")
    method = str(payload.get("method") or "GET").upper()
    path = str(payload.get("path") or "")
    app_id = str(config["appId"])
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", app_id):
        raise ValueError("Swimlane app ID contains unsupported characters")
    if method == "GET" and path == "/api/user/authorize":
        pass
    elif method == "POST" and path == f"/api/app/{app_id}/record/search":
        pass
    else:
        raise ValueError("Swimlane endpoint or method is not allowlisted")
    base_url = str(config["baseUrl"]).rstrip("/")
    parsed_base = urlparse(base_url)
    if parsed_base.scheme != "https" or not parsed_base.hostname or parsed_base.username or parsed_base.password or parsed_base.path not in ("", "/") or parsed_base.query or parsed_base.fragment:
        raise ValueError("Swimlane base URL must be an HTTPS origin")
    body = None
    if method == "POST":
        body = json.dumps(payload.get("body") or {}).encode("utf-8")
        if len(body) > MAX_PROXY_REQUEST_BYTES:
            raise ValueError("Swimlane request exceeds the 1 MB limit")
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        method=method,
        headers={"Content-Type": "application/json", "Private-Token": str(config["pat"]), "User-Agent": "OTPlatform-Swimlane-Proxy/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response_body = response.read(MAX_PROXY_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_PROXY_RESPONSE_BYTES:
                raise ValueError("Swimlane response exceeds the 20 MB limit")
            return json.loads(response_body.decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Swimlane returned HTTP {error.code}") from error


def claroty_headers(api_key):
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    if not re.match(r"^eyJ[\w-]+\.[\w-]+\.[\w-]+$", api_key):
        headers["X-API-KEY"] = api_key
    return headers


def is_trusted_local_origin(origin, host=None):
    if not origin or origin in LOCAL_BROWSER_ORIGINS:
        return True
    try:
        parsed = urlparse(origin)
        return (
            parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1"}
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.params
            and not parsed.query
            and not parsed.fragment
            and host is not None
            and parsed.netloc.casefold() == host.casefold()
        )
    except ValueError:
        return False


def get_local_session_token(cookie_header):
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header or "")
        return cookie.get(LOCAL_SESSION_COOKIE).value if cookie.get(LOCAL_SESSION_COOKIE) else ""
    except Exception:
        return ""


def refresh_local_browser_session(cookie_header):
    now = time.time()
    token = get_local_session_token(cookie_header)
    with local_session_lock:
        expired = [value for value, expires in local_browser_sessions.items() if expires <= now]
        for value in expired:
            local_browser_sessions.pop(value, None)
        if not token or token not in local_browser_sessions:
            token = secrets.token_urlsafe(32)
        local_browser_sessions[token] = now + LOCAL_SESSION_TTL_SECONDS
    return token


def has_local_browser_session(cookie_header):
    token = get_local_session_token(cookie_header)
    now = time.time()
    with local_session_lock:
        expires = local_browser_sessions.get(token)
        if not expires:
            return False
        if expires <= now:
            local_browser_sessions.pop(token, None)
            return False
        local_browser_sessions[token] = now + LOCAL_SESSION_TTL_SECONDS
        return True


def is_allowed_claroty_target(target_url):
    try:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        return (
            parsed.scheme == "https"
            and not parsed.username
            and not parsed.password
            and (hostname.endswith(CLAROTY_API_HOST_SUFFIX) or hostname == "api.claroty.com")
            and port in (None, 443)
            and parsed.path.startswith("/api/v1/")
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False


def is_allowed_claroty_base_url(base_url):
    try:
        parsed = urlparse(base_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        return (
            parsed.scheme == "https"
            and not parsed.username
            and not parsed.password
            and (hostname.endswith(CLAROTY_API_HOST_SUFFIX) or hostname == "api.claroty.com")
            and parsed.port in (None, 443)
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False


def allowed_claroty_upstream_proxy(proxy_url):
    if not proxy_url:
        return True
    allowed = {CLAROTY_DEFAULT_PROXY_URL.rstrip("/")}
    allowed.update(value.strip().rstrip("/") for value in os.getenv("CLAROTY_APPROVED_PROXY_URLS", "").split(",") if value.strip())
    return proxy_url.rstrip("/") in allowed


class ClarotyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        if not is_allowed_claroty_target(new_url):
            return None
        if urlparse(new_url).hostname != urlparse(request.full_url).hostname:
            return None
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def claroty_request(config, endpoint, payload):
    endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    target_url = config["baseUrl"].rstrip("/") + endpoint
    if not is_allowed_claroty_target(target_url):
        raise ValueError("Claroty endpoint is outside the allowed HTTPS API path")
    proxy_url = str(config.get("proxyUrl") or "").strip().rstrip("/")
    if not allowed_claroty_upstream_proxy(proxy_url):
        raise ValueError("Claroty proxy is not approved")
    body = json.dumps(payload or {}).encode("utf-8")
    if len(body) > MAX_PROXY_REQUEST_BYTES:
        raise ValueError("Claroty request exceeds the 1 MB limit")
    request = urllib.request.Request(target_url, data=body, headers=claroty_headers(config["apiKey"]), method="POST")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        , ClarotyRedirectHandler()
    ) if proxy_url else urllib.request.build_opener(ClarotyRedirectHandler())
    with opener.open(request, timeout=30) as response:
        response_body = response.read(MAX_PROXY_RESPONSE_BYTES + 1)
    if len(response_body) > MAX_PROXY_RESPONSE_BYTES:
        raise ValueError("Claroty response exceeds the 20 MB limit")
    return json.loads(response_body.decode("utf-8"))


def claroty_feed_records(payload, response_key):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return None
    for key in (response_key, "items", "data", "results", "objects", "records", "payload", "result"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            records = claroty_feed_records(value, response_key)
            if records is not None:
                return records
    return None


def classify(title):
    for pattern, category, severity, automated in RULES:
        if re.search(pattern, title, re.IGNORECASE):
            return category, severity, automated
    return "Other", "Low", False


def load_incidents(range_days=30):
    now = datetime.now(timezone.utc)
    with DATA_FILE.open(encoding="utf-8-sig", newline="") as source:
        rows = list(csv.DictReader(source))
    incidents = []
    denominator = max(1, len(rows) - 1)
    for index, row in enumerate(rows):
        title = (row.get("BMC Incident Title") or "Incident").strip()
        category, severity, automated = classify(title)
        created = now - timedelta(days=(index / denominator) * range_days)
        status = "Closed" if "close" in (row.get("Case Status") or "").lower() else "Open"
        incidents.append({
            "id": (row.get("Tracking Id") or f"REC-{index}").strip(),
            "title": title,
            "status": status,
            "severity": severity,
            "category": category,
            "automated": automated,
            "source": category,
            "created": created.isoformat(),
            "assignee": "SOC Analyst",
        })
    return incidents


def dashboard_summary(incidents):
    severity = {name: 0 for name in ("Critical", "High", "Medium", "Low")}
    categories = {}
    for incident in incidents:
        severity[incident["severity"]] += 1
        categories[incident["category"]] = categories.get(incident["category"], 0) + 1
    closed = sum(incident["status"] == "Closed" for incident in incidents)
    automated = sum(incident["automated"] for incident in incidents)
    total = len(incidents)
    return {
        "total": total,
        "open": total - closed,
        "closed": closed,
        "closureRate": round(closed / total * 100) if total else 0,
        "automationRate": round(automated / total * 100) if total else 0,
        "severity": severity,
        "categories": sorted(categories.items(), key=lambda item: item[1], reverse=True),
    }


def new_alert():
    title, severity, source, automated = random.choice(ALERT_TEMPLATES)
    now = datetime.now(timezone.utc)
    return {
        "id": f"ALT-{int(now.timestamp() * 1000)}-{random.randint(10, 99)}",
        "title": title,
        "sev": severity,
        "src": source,
        "device_name": random.choice(SAMPLE_ALERT_DEVICES),
        "data_source": "sample",
        "auto": automated,
        "time": now.astimezone().strftime("%I:%M:%S %p"),
        "timestamp": now.isoformat(),
        "state": "Contained" if automated else "New",
        "owner": "Automation" if automated else None,
        "ticket": None,
    }


def current_alerts():
    global last_alert_at
    with alert_lock:
        if not alerts:
            alerts.extend(new_alert() for _ in range(15))
        now = time.time()
        if now - last_alert_at >= 5:
            alerts.extend(new_alert() for _ in range(random.randint(1, 2)))
            del alerts[:-200]
            last_alert_at = now
        return list(alerts)


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "SOC-Dashboard/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


DOTNET_FEED_URL = "https://devblogs.microsoft.com/dotnet/feed/"
PINNED_ADVISORIES = [
    {"source": "Microsoft MSRC", "id": "CVE-2026-111497", "title": "Microsoft Security Advisory CVE-2026-111497", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111497"},
    {"source": ".NET Security", "id": "OOB Oct 2026", "title": ".NET October 2026 out-of-band security updates", "url": "https://devblogs.microsoft.com/dotnet/dotnet-october-2026-oob-security-updates/"},
    {"source": "Vulnerability tracking (external, unverified)", "id": "broccoli2shell.com", "title": "broccoli2shell.com vulnerability tracking", "url": "https://broccoli2shell.com/"},
]


def fetch_dotnet_security_feed():
    request = urllib.request.Request(DOTNET_FEED_URL, headers={"User-Agent": "SOC-Dashboard/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        root = ET.fromstring(response.read(2_000_000))
    items = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        categories = [(node.text or "").lower() for node in item.findall("category")]
        if not link.startswith("https://devblogs.microsoft.com/"):
            continue
        if "security" in title.lower() or "cve-" in title.lower() or "security" in categories:
            items.append({"title": title, "link": link, "published": (item.findtext("pubDate") or "").strip()})
    return items[:8]


def parse_snort_archive(archive_bytes):
    if len(archive_bytes) > MAX_SNORT_ARCHIVE_BYTES:
        raise ValueError("Snort archive exceeds the 50 MB upload limit")
    records = []
    file_count = 0
    expanded_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile() or not member.name.lower().endswith(".rules"):
                    continue
                expanded_bytes += member.size
                if expanded_bytes > MAX_SNORT_RULE_BYTES:
                    raise ValueError("Snort rules exceed the 150 MB expanded limit")
                source = archive.extractfile(member)
                if source is None:
                    continue
                file_count += 1
                pending = ""
                for line in source.read().decode("utf-8", errors="replace").splitlines():
                    part = line.strip()
                    pending += part[:-1] + " " if part.endswith("\\") else part
                    if part.endswith("\\"):
                        continue
                    rule = pending
                    pending = ""
                    enabled = not rule.startswith("#")
                    candidate = rule.lstrip("# ").strip()
                    action = re.match(r"^(alert|block|drop|reject|pass|log|sdrop|activate|dynamic)\s+", candidate)
                    if not action:
                        continue
                    sid = re.search(r"\bsid\s*:\s*(\d+)\s*;", candidate)
                    message = re.search(r'\bmsg\s*:\s*"((?:\\.|[^"\\])*)"', candidate)
                    records.append({
                        "id": len(records), "sid": sid.group(1) if sid else "",
                        "message": message.group(1) if message else "",
                        "action": action.group(1), "file": member.name,
                        "enabled": enabled, "rule": candidate,
                    })
    except tarfile.TarError as error:
        raise ValueError("Invalid Snort .tar.gz archive") from error
    if not records:
        raise ValueError("No Snort rules found in the archive")
    return records, file_count


def current_snort_catalog():
    global snort_catalog
    with snort_lock:
        if snort_catalog is None:
            records = []
            sources = []
            for label, archive_path in (("Community", SNORT_COMMUNITY_FILE), ("Imported", SNORT_ARCHIVE_FILE)):
                if not archive_path.exists():
                    continue
                source_records, file_count = parse_snort_archive(archive_path.read_bytes())
                updated_at = datetime.fromtimestamp(archive_path.stat().st_mtime, timezone.utc).isoformat()
                sources.append({"name": label, "files": file_count, "updatedAt": updated_at})
                for record in source_records:
                    record["id"] = len(records)
                    record["source"] = label
                    records.append(record)
            if sources:
                snort_catalog = {
                    "records": records,
                    "files": sum(source["files"] for source in sources),
                    "updatedAt": max(source["updatedAt"] for source in sources),
                    "sources": sources,
                }
        return snort_catalog


def snort_update_status():
    with snort_update_lock:
        return dict(snort_update_state)


def snort_engine_status_payload():
    configured_path = os.getenv("SNORT_ENGINE_PATH", "").strip()
    engine_path = None
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.is_file():
            engine_path = str(candidate.resolve())
    if not engine_path:
        engine_path = shutil.which("snort") or shutil.which("snort.exe")
    suricata_path = shutil.which("suricata") or shutil.which("suricata.exe")
    catalog = current_snort_catalog()
    records = catalog["records"] if catalog else []
    return {
        "engine": {"available": bool(engine_path), "path": engine_path},
        "alternatives": {"suricata": {"available": bool(suricata_path), "path": suricata_path}},
        "rules": {
            "configured": bool(catalog),
            "total": len(records),
            "enabled": sum(bool(record["enabled"]) for record in records),
            "files": catalog["files"] if catalog else 0,
            "sources": catalog["sources"] if catalog else [],
        },
        "openAppId": openappid_status_payload(),
        "runtimeValidation": "not_run",
    }


def update_snort_community_rules(force=False):
    global snort_catalog
    with snort_update_lock:
        if snort_update_state["updating"]:
            return dict(snort_update_state)
        if not force and SNORT_COMMUNITY_FILE.exists():
            age = time.time() - SNORT_COMMUNITY_FILE.stat().st_mtime
            if age < SNORT_UPDATE_INTERVAL_SECONDS:
                return dict(snort_update_state)
        snort_update_state.update({"updating": True, "lastError": None, "source": "Snort 3 Community"})

    try:
        request = urllib.request.Request(SNORT_COMMUNITY_URL, headers={"User-Agent": "OTPlatform-Snort-Rule-Updater/1.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            archive_bytes = response.read(MAX_SNORT_ARCHIVE_BYTES + 1)
        if len(archive_bytes) > MAX_SNORT_ARCHIVE_BYTES:
            raise ValueError("Snort Community archive exceeds the 50 MB download limit")
        records, file_count = parse_snort_archive(archive_bytes)
        SNORT_COMMUNITY_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = SNORT_COMMUNITY_FILE.with_suffix(".tmp")
        temporary.write_bytes(archive_bytes)
        temporary.replace(SNORT_COMMUNITY_FILE)
        with snort_lock:
            snort_catalog = None
        with snort_update_lock:
            snort_update_state.update({
                "updating": False,
                "lastChecked": datetime.now(timezone.utc).isoformat(),
                "lastError": None,
                "source": "Snort 3 Community",
                "rules": len(records),
                "files": file_count,
            })
    except Exception as error:
        with snort_update_lock:
            snort_update_state.update({
                "updating": False,
                "lastChecked": datetime.now(timezone.utc).isoformat(),
                "lastError": str(error),
                "source": "Snort 3 Community",
            })
    return snort_update_status()


def snort_update_worker():
    while True:
        update_snort_community_rules()
        threading.Event().wait(6 * 60 * 60)


OPENAPPID_DETECTOR_KINDS = ("client", "service", "payload", "ssl", "content")


def parse_openappid_archive(archive_bytes):
    """Parse a snort-openappid.tar.gz ODP package into applications and detector metadata."""
    if len(archive_bytes) > MAX_OPENAPPID_ARCHIVE_BYTES:
        raise ValueError("OpenAppID package exceeds the 60 MB upload limit")
    applications = []
    detectors = []
    version = ""
    expanded_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                expanded_bytes += member.size
                if expanded_bytes > MAX_OPENAPPID_EXPANDED_BYTES:
                    raise ValueError("OpenAppID package exceeds the 200 MB expanded limit")
                name = member.name.replace("\\", "/")
                leaf = name.rsplit("/", 1)[-1]
                if leaf == "version.conf":
                    text = archive.extractfile(member).read().decode("utf-8", errors="replace")
                    match = re.search(r"VERSION\s*=\s*(\S+)", text)
                    version = match.group(1) if match else text.strip()[:32]
                elif leaf == "appMapping.data":
                    text = archive.extractfile(member).read().decode("utf-8", errors="replace")
                    for line in text.splitlines():
                        columns = line.rstrip("\n").split("\t")
                        if len(columns) < 2 or not columns[0].strip().isdigit():
                            continue
                        applications.append({
                            "appId": int(columns[0].strip()),
                            "name": columns[1].strip(),
                            "serviceId": _openappid_int(columns, 2),
                            "clientId": _openappid_int(columns, 3),
                            "payloadId": _openappid_int(columns, 4),
                            "snortName": (columns[5].strip() if len(columns) > 5 and columns[5].strip() != "~" else ""),
                            "label": columns[6].strip() if len(columns) > 6 else "",
                        })
                elif leaf.endswith(".lua"):
                    kind = next((prefix for prefix in OPENAPPID_DETECTOR_KINDS if leaf.startswith(prefix + "_")), "other")
                    detectors.append({"name": leaf[:-4], "kind": kind, "file": name, "bytes": member.size})
    except tarfile.TarError as error:
        raise ValueError("Invalid OpenAppID .tar.gz package") from error
    if not applications:
        raise ValueError("No appMapping.data entries found in the OpenAppID package")
    applications.sort(key=lambda row: row["name"].casefold())
    detectors.sort(key=lambda row: (row["kind"], row["name"].casefold()))
    return {"version": version, "applications": applications, "detectors": detectors}


def _openappid_int(columns, index):
    if len(columns) <= index:
        return 0
    value = columns[index].strip()
    return int(value) if value.isdigit() else 0


def current_openappid_catalog():
    global openappid_catalog
    with openappid_lock:
        if openappid_catalog is None and OPENAPPID_ARCHIVE_FILE.exists():
            parsed = parse_openappid_archive(OPENAPPID_ARCHIVE_FILE.read_bytes())
            parsed["updatedAt"] = datetime.fromtimestamp(OPENAPPID_ARCHIVE_FILE.stat().st_mtime, timezone.utc).isoformat()
            parsed["sha256"] = hashlib.sha256(OPENAPPID_ARCHIVE_FILE.read_bytes()).hexdigest()
            openappid_catalog = parsed
        return openappid_catalog


def openappid_status_payload():
    catalog = current_openappid_catalog()
    detectors = catalog["detectors"] if catalog else []
    applications = catalog["applications"] if catalog else []
    by_kind = {kind: sum(1 for row in detectors if row["kind"] == kind) for kind in OPENAPPID_DETECTOR_KINDS}
    by_kind["other"] = sum(1 for row in detectors if row["kind"] == "other")
    with openappid_update_lock:
        update = dict(openappid_update_state)
    return {
        "configured": catalog is not None,
        "version": catalog["version"] if catalog else "",
        "updatedAt": catalog.get("updatedAt") if catalog else None,
        "sha256": catalog.get("sha256") if catalog else None,
        "applications": len(applications),
        "detectors": len(detectors),
        "detectorsByKind": by_kind,
        "mappedToSnort": sum(1 for row in applications if row["snortName"]),
        "update": update,
        "note": "OpenAppID classifies application traffic inside a Snort sensor. This package is indexed locally; application identification requires a Snort sensor with packet capture.",
    }


def update_openappid_package(force=False):
    global openappid_catalog
    with openappid_update_lock:
        if openappid_update_state["updating"]:
            return dict(openappid_update_state)
        if not force and OPENAPPID_ARCHIVE_FILE.exists():
            age = time.time() - OPENAPPID_ARCHIVE_FILE.stat().st_mtime
            if age < SNORT_UPDATE_INTERVAL_SECONDS:
                return dict(openappid_update_state)
        openappid_update_state.update({"updating": True, "lastError": None, "source": "Snort OpenAppID ODP"})

    try:
        request = urllib.request.Request(OPENAPPID_URL, headers={"User-Agent": "OTPlatform-OpenAppID-Updater/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            archive_bytes = response.read(MAX_OPENAPPID_ARCHIVE_BYTES + 1)
        if len(archive_bytes) > MAX_OPENAPPID_ARCHIVE_BYTES:
            raise ValueError("OpenAppID package exceeds the 60 MB download limit")
        parsed = parse_openappid_archive(archive_bytes)
        OPENAPPID_ARCHIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = OPENAPPID_ARCHIVE_FILE.with_suffix(".tmp")
        temporary.write_bytes(archive_bytes)
        temporary.replace(OPENAPPID_ARCHIVE_FILE)
        with openappid_lock:
            openappid_catalog = None
        with openappid_update_lock:
            openappid_update_state.update({
                "updating": False,
                "lastChecked": datetime.now(timezone.utc).isoformat(),
                "lastError": None,
                "source": "Snort OpenAppID ODP",
                "version": parsed["version"],
                "applications": len(parsed["applications"]),
                "detectors": len(parsed["detectors"]),
            })
    except Exception as error:
        with openappid_update_lock:
            openappid_update_state.update({
                "updating": False,
                "lastChecked": datetime.now(timezone.utc).isoformat(),
                "lastError": str(error),
                "source": "Snort OpenAppID ODP",
            })
    with openappid_update_lock:
        return dict(openappid_update_state)


def parse_snort_ip_filter(raw_bytes):
    if len(raw_bytes) > MAX_SNORT_BLACKLIST_BYTES:
        raise ValueError("Snort IP list exceeds the 10 MB upload limit")
    # .blf lists are text, but may be saved as UTF-16 or a legacy 8-bit codepage.
    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw_bytes.decode("utf-16", errors="replace")
    else:
        try:
            text = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw_bytes.decode("latin-1")
    if "\x00" in text:
        raise ValueError("IP list contains binary data and is not a text .blf/.txt list")

    addresses = set()
    pattern = re.compile(r"(?<![A-Za-z0-9:.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:.]*(?:/\d{1,3})?(?![A-Fa-f0-9:])")
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        for candidate in pattern.findall(line):
            try:
                address = str(ipaddress.ip_network(candidate, strict=False)) if "/" in candidate else str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            addresses.add(address)
    if not addresses:
        raise ValueError("No valid IPv4, IPv6, or CIDR entries found in the text list")
    return sorted(addresses)


def load_network_ip_list(path):
    return parse_snort_ip_filter(path.read_bytes()) if path.exists() and path.stat().st_size else []


def save_network_ip_list(path, addresses):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(addresses) + ("\n" if addresses else ""), encoding="utf-8")
    temporary.replace(path)


def read_json_store(path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


def write_json_store(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    temporary.replace(path)


def module_store_payload():
    store = read_json_store(MODULE_DATA_FILE, {"schema_version": 1, "modules": {}})
    if not isinstance(store, dict) or not isinstance(store.get("modules", {}), dict):
        raise ValueError("Module data store has an invalid shape")
    modules = store.setdefault("modules", {})
    for module_name in MODULE_NAMES:
        records = modules.setdefault(module_name, [])
        if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
            raise ValueError(f"Module data for {module_name} has an invalid shape")
    store["schema_version"] = 1
    return store


def validate_module_record(payload):
    if not isinstance(payload, dict):
        raise ValueError("Module record must be a JSON object")

    def inspect(value, path="record"):
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if any(part in normalized for part in MODULE_SECRET_KEY_PARTS):
                    raise ValueError(f"Secret-like fields are not accepted in module records ({path}.{key})")
                inspect(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect(child, f"{path}[{index}]")

    inspect(payload)
    try:
        encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("Module record must contain JSON-compatible values") from error
    if len(encoded) > MODULE_MAX_RECORD_BYTES:
        raise ValueError(f"Module record exceeds {MODULE_MAX_RECORD_BYTES} bytes")
    return json.loads(encoded.decode("utf-8"))


def validate_module_id(value):
    record_id = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", record_id):
        raise ValueError("Record ID must be 1-128 safe URL characters")
    return record_id


def next_module_numeric_id(module_name):
    if module_name not in MODULE_NAMES:
        raise KeyError(module_name)
    with MODULE_DATA_LOCK:
        records = module_store_payload()["modules"][module_name]
        numeric_ids = []
        for record in records:
            try:
                numeric_ids.append(int(record.get("id")))
            except (TypeError, ValueError):
                continue
        return max(numeric_ids, default=0) + 1


def list_module_records(module_name, query_text="", limit=100, offset=0):
    if module_name not in MODULE_NAMES:
        raise KeyError(module_name)
    query_text = str(query_text or "").strip().casefold()
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    with MODULE_DATA_LOCK:
        records = list(module_store_payload()["modules"][module_name])
    if query_text:
        records = [record for record in records if query_text in json.dumps(record, ensure_ascii=True).casefold()]
    records.sort(key=lambda record: str(record.get("updated_at") or record.get("created_at") or ""), reverse=True)
    return {"records": records[offset:offset + limit], "total": len(records), "limit": limit, "offset": offset, "source": "local-module-store"}


def get_module_record(module_name, record_id):
    if module_name not in MODULE_NAMES:
        raise KeyError(module_name)
    record_id = validate_module_id(record_id)
    with MODULE_DATA_LOCK:
        return next((dict(record) for record in module_store_payload()["modules"][module_name] if str(record.get("id")) == record_id), None)


def save_module_record(module_name, payload, record_id=None):
    if module_name not in MODULE_NAMES:
        raise KeyError(module_name)
    record = validate_module_record(payload)
    existing_id = validate_module_id(record_id or record.get("id") or uuid.uuid4().hex)
    now = datetime.now(timezone.utc).isoformat()
    with MODULE_DATA_LOCK:
        store = module_store_payload()
        records = store["modules"][module_name]
        existing_index = next((index for index, item in enumerate(records) if str(item.get("id")) == existing_id), None)
        if existing_index is None:
            if record_id is not None:
                return None
            if len(records) >= MODULE_MAX_RECORDS:
                raise ValueError(f"Module {module_name} reached its {MODULE_MAX_RECORDS} record limit")
            record["id"] = existing_id
            record["created_at"] = record.get("created_at") or now
            record["updated_at"] = now
            records.append(record)
        else:
            previous = records[existing_index]
            record["id"] = existing_id
            record["created_at"] = previous.get("created_at") or now
            record["updated_at"] = now
            records[existing_index] = record
        write_json_store(MODULE_DATA_FILE, store)
    return record


threat_feed_refresh_lock = threading.Lock()


def threat_feed_database():
    THREAT_FEED_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(THREAT_FEED_DB_FILE), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS indicators (
            feed_id TEXT NOT NULL,
            feed_name TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            value TEXT NOT NULL,
            refreshed_at TEXT NOT NULL,
            PRIMARY KEY (feed_id, indicator_type, value)
        );
        CREATE INDEX IF NOT EXISTS idx_indicators_value
            ON indicators(indicator_type, value);
        CREATE TABLE IF NOT EXISTS feed_status (
            feed_id TEXT PRIMARY KEY,
            last_attempt TEXT,
            last_success TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            indicator_count INTEGER NOT NULL DEFAULT 0,
            error TEXT
        );
    """)
    return connection


def normalize_feed_indicator(value, indicator_type):
    value = str(value or "").strip().strip("\"'").rstrip(".")
    kind = str(indicator_type or "").casefold()
    if kind == "ip":
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return None
    if kind == "domain":
        domain = value.casefold()
        if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", domain):
            return None
        return domain
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    if kind in lengths and re.fullmatch(rf"[a-f0-9]{{{lengths[kind]}}}", value, re.IGNORECASE):
        return value.casefold()
    return None


def parse_threat_feed(text, indicator_type):
    entries = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", ";")):
            continue
        for candidate in line.split():
            normalized = normalize_feed_indicator(candidate, indicator_type)
            if normalized:
                entries.add(normalized)
                break
    return sorted(entries)


def get_threat_feed_status():
    connection = threat_feed_database()
    try:
        total = connection.execute("SELECT COUNT(DISTINCT indicator_type || ':' || value) FROM indicators").fetchone()[0]
        stored = {row["feed_id"]: dict(row) for row in connection.execute("SELECT * FROM feed_status")}
        feeds = []
        for feed in THREAT_INDICATOR_FEEDS:
            status = stored.get(feed["id"], {})
            feeds.append({
                "id": feed["id"],
                "name": feed["name"],
                "type": feed["type"],
                "status": status.get("status", "pending"),
                "indicatorCount": int(status.get("indicator_count") or 0),
                "refreshIntervalSeconds": THREAT_FEED_REFRESH_INTERVAL_SECONDS if feed["type"] == "ip" else THREAT_FEED_DAILY_REFRESH_INTERVAL_SECONDS,
                "lastAttempt": status.get("last_attempt"),
                "lastSuccess": status.get("last_success"),
                "error": status.get("error"),
            })
        last_success = max((feed["lastSuccess"] for feed in feeds if feed["lastSuccess"]), default=None)
        return {
            "feeds": feeds,
            "feedCount": len(feeds),
            "indicatorCount": int(total or 0),
            "lastSuccess": last_success,
            "refreshIntervalSeconds": THREAT_FEED_REFRESH_INTERVAL_SECONDS,
            "source": "local-threat-feed-index",
        }
    finally:
        connection.close()


def refresh_threat_indicator_feeds(feed_ids=None):
    if not threat_feed_refresh_lock.acquire(blocking=False):
        return {**get_threat_feed_status(), "refreshing": True}
    try:
        results = []
        selected_ids = set(feed_ids) if feed_ids is not None else None
        selected_feeds = [
            feed for feed in THREAT_INDICATOR_FEEDS
            if selected_ids is None or feed["id"] in selected_ids
        ]
        connection = threat_feed_database()
        try:
            for feed in selected_feeds:
                attempted_at = datetime.now(timezone.utc).isoformat()
                try:
                    request = urllib.request.Request(
                        feed["url"],
                        headers={"User-Agent": "OTPlatform-ThreatFeed-Indexer/1.0", "Accept": "text/plain"},
                    )
                    with urllib.request.urlopen(request, timeout=30) as response:
                        body = response.read(THREAT_FEED_MAX_BYTES + 1)
                    if len(body) > THREAT_FEED_MAX_BYTES:
                        raise ValueError("Feed response exceeds the 25 MB safety limit")
                    entries = parse_threat_feed(body.decode("utf-8-sig"), feed["type"])
                    if not entries:
                        raise ValueError("Feed contained no valid indicators; the previous index was kept")
                    successful_at = datetime.now(timezone.utc).isoformat()
                    with connection:
                        connection.execute("DELETE FROM indicators WHERE feed_id = ?", (feed["id"],))
                        connection.executemany(
                            "INSERT INTO indicators(feed_id, feed_name, indicator_type, value, refreshed_at) VALUES (?, ?, ?, ?, ?)",
                            ((feed["id"], feed["name"], feed["type"], value, successful_at) for value in entries),
                        )
                        connection.execute(
                            """INSERT INTO feed_status(feed_id, last_attempt, last_success, status, indicator_count, error)
                               VALUES (?, ?, ?, 'live', ?, NULL)
                               ON CONFLICT(feed_id) DO UPDATE SET
                                   last_attempt=excluded.last_attempt, last_success=excluded.last_success,
                                   status='live', indicator_count=excluded.indicator_count, error=NULL""",
                            (feed["id"], attempted_at, successful_at, len(entries)),
                        )
                    results.append({"id": feed["id"], "status": "live", "indicatorCount": len(entries)})
                except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, ValueError) as error:
                    message = str(error)[:500]
                    with connection:
                        connection.execute(
                            """INSERT INTO feed_status(feed_id, last_attempt, status, error)
                               VALUES (?, ?, 'error', ?)
                               ON CONFLICT(feed_id) DO UPDATE SET
                                   last_attempt=excluded.last_attempt, status='error', error=excluded.error""",
                            (feed["id"], attempted_at, message),
                        )
                    results.append({"id": feed["id"], "status": "error", "error": message})
        finally:
            connection.close()
        summary = get_threat_feed_status()
        summary["refreshing"] = False
        summary["results"] = results
        summary["failedFeedCount"] = sum(1 for item in results if item["status"] != "live")
        return summary
    finally:
        threat_feed_refresh_lock.release()


def due_threat_feed_ids():
    status = get_threat_feed_status()
    by_id = {feed["id"]: feed for feed in status["feeds"]}
    now = datetime.now(timezone.utc)
    due = []
    for feed in THREAT_INDICATOR_FEEDS:
        interval = THREAT_FEED_REFRESH_INTERVAL_SECONDS if feed["type"] == "ip" else THREAT_FEED_DAILY_REFRESH_INTERVAL_SECONDS
        stamp = by_id.get(feed["id"], {}).get("lastAttempt") or by_id.get(feed["id"], {}).get("lastSuccess")
        if not stamp:
            due.append(feed["id"])
            continue
        try:
            attempted = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        except ValueError:
            due.append(feed["id"])
            continue
        if (now - attempted).total_seconds() >= interval:
            due.append(feed["id"])
    return due


def threat_feed_update_worker():
    while True:
        try:
            due = due_threat_feed_ids()
            if due:
                result = refresh_threat_indicator_feeds(due)
                if result.get("failedFeedCount"):
                    print(f"Threat feed refresh completed with {result['failedFeedCount']} failed source(s)")
        except (OSError, sqlite3.Error, ValueError) as error:
            print(f"Threat feed refresh scheduler failed: {error}")
        time.sleep(15 * 60)


def lookup_threat_indicators(value, indicator_type=""):
    requested_type = str(indicator_type or "").strip().casefold()
    if requested_type in {"url", "uri"}:
        raw_url = str(value or "").strip()
        try:
            parsed_url = urlsplit(raw_url)
            host = parsed_url.hostname
            if not host and not parsed_url.scheme:
                host = urlsplit(f"//{raw_url}").hostname
        except ValueError:
            host = None
        if not host:
            raise ValueError("Enter a valid URL with a hostname")
        try:
            ipaddress.ip_address(host)
            host_type = "ip"
        except ValueError:
            host_type = "domain"
        return lookup_threat_indicators(host, host_type)
    candidate_types = (requested_type,) if requested_type else ("ip", "domain", "md5", "sha1", "sha256")
    normalized = None
    resolved_type = None
    for candidate_type in candidate_types:
        normalized = normalize_feed_indicator(value, candidate_type)
        if normalized:
            resolved_type = candidate_type
            break
    if not normalized:
        raise ValueError("Enter a valid IP address, domain, MD5, SHA-1, or SHA-256 indicator")
    connection = threat_feed_database()
    try:
        rows = connection.execute(
            "SELECT feed_id, feed_name, indicator_type, value, refreshed_at FROM indicators WHERE indicator_type = ? AND value = ? ORDER BY feed_name",
            (resolved_type, normalized),
        ).fetchall()
    finally:
        connection.close()
    return {
        "indicator": normalized,
        "type": resolved_type,
        "matched": bool(rows),
        "sources": [{"id": row["feed_id"], "name": row["feed_name"], "lastRefreshed": row["refreshed_at"]} for row in rows],
        "source": "local-threat-feed-index",
    }


def event_threat_feed_matches(event):
    if not THREAT_FEED_DB_FILE.exists():
        return []

    candidates = []
    indicator_fields = {
        "ioc": "",
        "ip": "ip",
        "srcip": "ip",
        "sourceip": "ip",
        "dstip": "ip",
        "destinationip": "ip",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "uri": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "filehash": "",
        "hash": "",
    }

    def collect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                normalized_key = re.sub(r"[^a-z0-9]", "", str(key).casefold())
                indicator_type = indicator_fields.get(normalized_key)
                if normalized_key in indicator_fields and isinstance(child, str):
                    candidates.append((child, indicator_type))
                elif isinstance(child, (dict, list)):
                    collect(child)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, (dict, list)):
                    collect(child)

    collect(event)
    for item in event.get("indicators", []) if isinstance(event.get("indicators"), list) else []:
        if isinstance(item, dict):
            candidates.append((item.get("value"), item.get("type") or item.get("indicator_type") or ""))
        elif isinstance(item, str):
            candidates.append((item, ""))
    matches = {}
    for value, indicator_type in candidates:
        if not isinstance(value, str):
            continue
        try:
            lookup_type = str(indicator_type or "").casefold()
            result = lookup_threat_indicators(value, lookup_type)
        except ValueError:
            if lookup_type not in {"url", "uri"} and re.match(r"^https?://", value, re.IGNORECASE):
                try:
                    result = lookup_threat_indicators(value, "url")
                except ValueError:
                    continue
            else:
                continue
        if result["matched"]:
            key = f"{result['type']}:{result['indicator']}"
            match = dict(result)
            if value.strip() != result["indicator"]:
                match["observedIndicator"] = value.strip()[:2048]
            matches[key] = match
    return list(matches.values())


def integration_event_route(event):
    event_type = str(event.get("event_type") or "").casefold()
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    indicators = event.get("indicators") if isinstance(event.get("indicators"), list) else []
    searchable = json.dumps({"event_type": event_type, "details": details, "indicators": indicators}, ensure_ascii=True).casefold()
    if "audit" in event_type or "audit" in searchable:
        return "audit", ["integrations"]
    if re.search(r"\bcve-\d{4}-\d+\b", searchable) or any(term in event_type for term in ("vulnerability", "vuln.finding")):
        destinations = ["integrations", "vulnerabilities"]
        if event.get("threat_feed_matches"):
            destinations.append("alerts")
            return "threat", destinations
        return "vulnerability", destinations
    if event.get("threat_feed_matches") or any(term in event_type for term in ("threat", "malware", "intrusion", "attack", "security.alert")):
        return "threat", ["integrations", "alerts"]
    if any(str((item or {}).get("type") or "").casefold() in {"malware", "threat", "attack"} for item in indicators if isinstance(item, dict)):
        return "threat", ["integrations", "alerts"]
    return "operational", ["integrations"]


def save_integration_events(events):
    results = []
    module_updates = []
    for original_event in events:
        event = validate_zero_trust_event(original_event)
        feed_matches = event_threat_feed_matches(event)
        if feed_matches:
            source_details = event.get("details") if isinstance(event.get("details"), dict) else {}
            source_severity = str(event.get("severity") or source_details.get("severity") or "").casefold()
            event["threat_feed_matches"] = feed_matches
            event["severity"] = "critical" if source_severity == "critical" else "high"
            event["detection"] = {
                "rule_id": "local-threat-feed-match",
                "title": "Inbound event matched a malicious indicator feed",
                "severity": "high",
                "matched_indicator_count": len(feed_matches),
                "response_mode": "recommendation_only",
            }
        category, destinations = integration_event_route(event)
        event["routing"] = {"category": category, "modules": destinations}
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        identity = str(event.get("event_id") or "")
        record_id = hashlib.sha256(f"{source.get('system', '')}:{identity}".encode("utf-8")).hexdigest()
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        device = event.get("device") if isinstance(event.get("device"), dict) else {}
        resource = event.get("resource") if isinstance(event.get("resource"), dict) else {}
        indicators = event.get("indicators") if isinstance(event.get("indicators"), list) else []
        network = event.get("network") if isinstance(event.get("network"), dict) else {}
        path_value = event.get("path") or network.get("request_path") or details.get("request_path") or ""
        log_record = {
            "id": record_id,
            "event_id": identity,
            "event_type": event.get("event_type"),
            "event_time": event.get("event_time"),
            "received_at": event.get("received_at"),
            "category": category,
            "routed_modules": destinations,
            "source": source,
            "device": device,
            "resource": resource,
            "path": str(path_value)[:1000],
            "indicators": indicators,
            "action": event.get("action"),
            "outcome": event.get("outcome"),
            "reason_code": event.get("reason_code"),
            "detection": event.get("detection"),
            "detection_rule_id": (event.get("detection") or {}).get("rule_id") if isinstance(event.get("detection"), dict) else None,
            "details": details,
            "event": event,
        }
        for module_name in destinations:
            module_record = dict(log_record)
            if module_name == "alerts":
                module_record["title"] = str(details.get("summary") or details.get("message") or event.get("event_type") or "Security alert")[:500]
                module_record["severity"] = str(
                    (event.get("detection") or {}).get("severity")
                    or details.get("severity")
                    or "unknown"
                )[:40]
                module_record["detection_rule_id"] = log_record["detection_rule_id"]
                module_record["description"] = json.dumps(details, ensure_ascii=True)[:4000]
            elif module_name == "vulnerabilities":
                match = re.search(r"\bCVE-\d{4}-\d+\b", json.dumps(details, ensure_ascii=True), re.IGNORECASE)
                module_record["cve"] = match.group(0).upper() if match else ""
                module_record["name"] = str(details.get("summary") or details.get("message") or event.get("event_type") or "Vulnerability finding")[:500]
                module_record["severity"] = str(details.get("severity") or "unknown")[:40]
            module_updates.append((module_name, validate_module_record(module_record), record_id))
        original_event.clear()
        original_event.update(event)
        results.append({"category": category, "modules": destinations, "record_id": record_id})

    if module_updates:
        with MODULE_DATA_LOCK:
            store = module_store_payload()
            now = datetime.now(timezone.utc).isoformat()
            indexes = {
                module_name: {str(record.get("id")): index for index, record in enumerate(store["modules"][module_name])}
                for module_name in MODULE_NAMES
            }
            for module_name, module_record, record_id in module_updates:
                record_id = validate_module_id(record_id)
                records = store["modules"][module_name]
                existing_index = indexes[module_name].get(record_id)
                module_record["id"] = record_id
                if existing_index is None:
                    if len(records) >= MODULE_MAX_RECORDS:
                        raise ValueError(f"Module {module_name} reached its {MODULE_MAX_RECORDS} record limit")
                    module_record["created_at"] = module_record.get("created_at") or now
                    module_record["updated_at"] = now
                    indexes[module_name][record_id] = len(records)
                    records.append(module_record)
                else:
                    previous = records[existing_index]
                    module_record["created_at"] = previous.get("created_at") or now
                    module_record["updated_at"] = now
                    records[existing_index] = module_record
            write_json_store(MODULE_DATA_FILE, store)
    return results


def save_integration_event(event):
    return save_integration_events([event])[0]


GIT_PROVIDER_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
GIT_PROVIDER_MAX_WEBHOOK_BYTES = 1024 * 1024
GIT_PROVIDER_PAGE_SIZE = 100


def git_provider_api_request(provider, url, token):
    expected_host = "api.github.com" if provider == "github" else "gitlab.com"
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != expected_host or parsed.username or parsed.password:
        raise ValueError("Git provider API URL is not allowed")
    headers = {"Accept": "application/json", "User-Agent": "OTPlatform-Security-Dashboard"}
    if provider == "github":
        headers.update({"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"})
    else:
        headers["PRIVATE-TOKEN"] = token
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(GIT_PROVIDER_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{provider} API request failed (HTTP {error.code})") from None
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError(f"{provider} API is unavailable: {getattr(error, 'reason', error)}") from None
    if len(body) > GIT_PROVIDER_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"{provider} API response exceeded the size limit")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{provider} API returned invalid JSON") from error


INTEGRATION_PROVIDER_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
INTEGRATION_PROVIDER_PAGE_SIZE = 100


def integration_provider_api_request(config, path, method="GET", body=None, headers=None):
    base = normalize_base_url(config.get("baseUrl"))
    if not base:
        raise ValueError("A provider API URL is required")
    parsed_base = urllib.parse.urlsplit(base)
    if parsed_base.scheme != "https" or parsed_base.query or parsed_base.fragment or parsed_base.username or parsed_base.password:
        raise ValueError("Provider API base URL must use HTTPS and must not embed credentials or query parameters")
    url = base + path
    parsed_url = urllib.parse.urlsplit(url)
    if (parsed_url.scheme != parsed_base.scheme or parsed_url.hostname != parsed_base.hostname
            or parsed_url.port != parsed_base.port or parsed_url.username or parsed_url.password):
        raise ValueError("Provider API URL is not allowed")
    assert_public_http_target(url)
    request_headers = {"Accept": "application/json", "User-Agent": "OTPlatform-Security-Dashboard"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=INTEGRATION_TEST_TIMEOUT) as response:
            raw = response.read(INTEGRATION_PROVIDER_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Provider API request failed (HTTP {error.code})") from None
    except (OSError, urllib.error.URLError, socket.timeout, TimeoutError) as error:
        raise RuntimeError(f"Provider API is unavailable: {getattr(error, 'reason', error)}") from None
    if len(raw) > INTEGRATION_PROVIDER_MAX_RESPONSE_BYTES:
        raise RuntimeError("Provider API response exceeded the size limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Provider API returned invalid JSON") from error


def integration_provider_event(provider, source_system, kind, upstream_id, timestamp, summary, details, severity="unknown", outcome="observed", indicators=None):
    safe_details = {str(key)[:80]: str(value)[:500] for key, value in details.items() if value is not None and str(value).strip()}
    identity = str(upstream_id or "").strip()
    if not identity:
        identity = hashlib.sha256(json.dumps([provider, kind, timestamp, safe_details], sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "event_id": f"{provider}:{identity}"[:200],
        "event_type": f"{provider}.{kind}"[:160],
        "event_time": git_provider_time(timestamp),
        "source": {"system": source_system[:100], "transport": "api"},
        "severity": str(severity or "unknown")[:40],
        "outcome": str(outcome or "unknown")[:80],
        "details": {"summary": str(summary or kind)[:500], **safe_details},
        "indicators": indicators or [],
    }


def git_provider_records(payload, keys=()):
    if isinstance(payload, list):
        return payload[:GIT_PROVIDER_PAGE_SIZE]
    if isinstance(payload, dict):
        for key in keys:
            records = payload.get(key)
            if isinstance(records, list):
                return records[:GIT_PROVIDER_PAGE_SIZE]
    raise RuntimeError("Git provider returned an unsupported record shape")


def git_provider_time(value):
    if isinstance(value, (int, float)):
        stamp = float(value)
        if stamp > 100000000000:
            stamp /= 1000
        return datetime.fromtimestamp(stamp, timezone.utc).isoformat()
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def git_provider_event(provider, kind, upstream_id, timestamp, summary, details, severity="unknown", outcome="unknown"):
    safe_details = {str(key)[:80]: str(value)[:500] for key, value in details.items() if value is not None and str(value).strip()}
    identity = str(upstream_id or "").strip()
    if not identity:
        identity = hashlib.sha256(json.dumps([provider, kind, timestamp, safe_details], sort_keys=True).encode("utf-8")).hexdigest()
    event_type = f"{provider}.{kind}"
    return {
        "event_id": f"{provider}:{identity}"[:200],
        "event_type": event_type[:160],
        "event_time": git_provider_time(timestamp),
        "source": {"system": "GitHub" if provider == "github" else "GitLab", "transport": "api"},
        "severity": str(severity or "unknown")[:40],
        "outcome": str(outcome or "unknown")[:80],
        "details": {"summary": str(summary or event_type)[:500], **safe_details},
    }


def poll_github_provider(config):
    organization = urllib.parse.quote(config["organization"], safe="")
    token = config["token"]
    root = f"https://api.github.com/orgs/{organization}"
    sources = (
        ("audit-log", f"{root}/audit-log?include=all&order=desc&per_page={GIT_PROVIDER_PAGE_SIZE}&page=1", (), "audit.event"),
        ("dependabot-alerts", f"{root}/dependabot/alerts?state=open&per_page={GIT_PROVIDER_PAGE_SIZE}&page=1", (), "vulnerability.finding"),
        ("secret-scanning-alerts", f"{root}/secret-scanning/alerts?state=open&per_page={GIT_PROVIDER_PAGE_SIZE}&page=1", (), "security.alert"),
        ("code-scanning-alerts", f"{root}/code-scanning/alerts?state=open&per_page={GIT_PROVIDER_PAGE_SIZE}&page=1", (), "vulnerability.finding"),
    )
    events = []
    source_results = []
    for source_name, url, envelope_keys, event_kind in sources:
        try:
            records = git_provider_records(git_provider_api_request("github", url, token), envelope_keys)
            for record in records:
                repository = record.get("repository") if isinstance(record.get("repository"), dict) else {}
                advisory = record.get("security_advisory") if isinstance(record.get("security_advisory"), dict) else {}
                vulnerability = record.get("security_vulnerability") if isinstance(record.get("security_vulnerability"), dict) else {}
                rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
                summary = record.get("action") or advisory.get("summary") or rule.get("description") or record.get("secret_type") or source_name
                severity = vulnerability.get("severity") or advisory.get("severity") or rule.get("security_severity_level") or rule.get("severity")
                if not severity and source_name == "secret-scanning-alerts":
                    severity = "high"
                details = {
                    "action": record.get("action"), "actor": record.get("actor") or record.get("actor_login"),
                    "repository": repository.get("full_name") or record.get("repo"),
                    "package": (vulnerability.get("package") or {}).get("name") if isinstance(vulnerability.get("package"), dict) else None,
                    "alert_number": record.get("number"), "state": record.get("state"),
                    "url": record.get("html_url"), "source_feed": source_name,
                }
                timestamp = record.get("@timestamp") or record.get("created_at") or record.get("updated_at")
                upstream_id = f"{source_name}:{record.get('@id') or record.get('id') or record.get('number')}"
                events.append(git_provider_event("github", event_kind, upstream_id, timestamp, summary, details, severity or "unknown", record.get("state") or "observed"))
            source_results.append({"source": source_name, "status": "live", "count": len(records)})
        except (RuntimeError, ValueError, OSError) as error:
            source_results.append({"source": source_name, "status": "error", "count": 0, "error": str(error)[:240]})
    return events, source_results


def poll_misp_provider(config):
    api_key = str(config.get("apiKey") or "").strip()
    if not api_key:
        raise ValueError("MISP API key is required")
    body = json.dumps({"returnFormat": "json", "limit": INTEGRATION_PROVIDER_PAGE_SIZE}).encode("utf-8")
    payload = integration_provider_api_request(
        config,
        "/attributes/restSearch",
        method="POST",
        body=body,
        headers={"Authorization": api_key, "Content-Type": "application/json"},
    )
    response = payload.get("response") if isinstance(payload, dict) else None
    attributes = response.get("Attribute") if isinstance(response, dict) else None
    if attributes is None and isinstance(payload, dict):
        attributes = payload.get("Attribute") or payload.get("attributes")
    if not isinstance(attributes, list):
        raise RuntimeError("MISP returned an unsupported attribute response shape")

    events = []
    for attribute in attributes[:INTEGRATION_PROVIDER_PAGE_SIZE]:
        if not isinstance(attribute, dict):
            continue
        value = str(attribute.get("value") or "").strip()
        indicator_type = str(attribute.get("type") or "unknown").strip()
        indicators = [{"type": indicator_type[:80], "value": value[:2048]}] if value else []
        event = attribute.get("Event") if isinstance(attribute.get("Event"), dict) else {}
        events.append(integration_provider_event(
            "misp",
            "MISP",
            "indicator.observed",
            attribute.get("uuid") or attribute.get("id"),
            attribute.get("timestamp") or event.get("date"),
            attribute.get("comment") or f"MISP {indicator_type} attribute",
            {
                "attribute_id": attribute.get("id"),
                "event_id": attribute.get("event_id"),
                "event_info": event.get("info"),
                "category": attribute.get("category"),
                "to_ids": attribute.get("to_ids"),
            },
            outcome="to_ids" if str(attribute.get("to_ids", "")).casefold() in {"1", "true"} else "observed",
            indicators=indicators,
        ))
    return events, [{"source": "attributes", "status": "live", "count": len(events)}]


def poll_keycloak_provider(config):
    realm = urllib.parse.quote(str(config.get("realm") or "").strip(), safe="")
    client_id = str(config.get("clientId") or "").strip()
    client_secret = str(config.get("clientSecret") or "")
    if not realm or not client_id or not client_secret:
        raise ValueError("Keycloak realm, client ID, and client secret are required")
    token_payload = integration_provider_api_request(
        config,
        f"/realms/{realm}/protocol/openid-connect/token",
        method="POST",
        body=urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    access_token = token_payload.get("access_token") if isinstance(token_payload, dict) else None
    if not isinstance(access_token, str) or not access_token:
        raise RuntimeError("Keycloak token endpoint returned no access token")

    query = "first=0&max=100&direction=desc"
    headers = {"Authorization": f"Bearer {access_token}"}
    feeds = (
        ("admin-events", f"/admin/realms/{realm}/admin-events?{query}", "admin.audit"),
        ("user-events", f"/admin/realms/{realm}/events?{query}", "auth.event"),
    )
    events = []
    sources = []
    for source_name, path, kind in feeds:
        try:
            records = integration_provider_api_request(config, path, headers=headers)
            if not isinstance(records, list):
                raise RuntimeError("Keycloak returned an unsupported event response shape")
            records = records[:INTEGRATION_PROVIDER_PAGE_SIZE]
            for record in records:
                if not isinstance(record, dict):
                    continue
                details = {
                    "event_id": record.get("id"),
                    "event_type": record.get("operationType") or record.get("type"),
                    "resource_type": record.get("resourceType"),
                    "resource_path": record.get("resourcePath"),
                    "client_id": record.get("clientId") or (record.get("authDetails") or {}).get("clientId"),
                    "user_id": record.get("userId") or (record.get("authDetails") or {}).get("userId"),
                    "ip_address": record.get("ipAddress") or (record.get("authDetails") or {}).get("ipAddress"),
                    "error": record.get("error"),
                }
                event_kind = "security.alert" if record.get("error") else kind
                events.append(integration_provider_event(
                    "keycloak",
                    "Keycloak",
                    event_kind,
                    record.get("id") or json.dumps([source_name, record.get("time"), details], sort_keys=True),
                    record.get("time"),
                    record.get("operationType") or record.get("type") or source_name,
                    details,
                    severity="medium" if record.get("error") else "unknown",
                    outcome="failure" if record.get("error") else "observed",
                ))
            sources.append({"source": source_name, "status": "live", "count": len(records)})
        except (RuntimeError, ValueError, OSError) as error:
            sources.append({"source": source_name, "status": "error", "count": 0, "error": str(error)[:240]})
    return events, sources


def poll_search_index_provider(provider, config, index, headers):
    if not index:
        raise ValueError(f"{provider} index or pattern is required")
    encoded_index = urllib.parse.quote(str(index).strip(), safe="*,-_.")
    path = f"/{encoded_index}/_search"
    body = json.dumps({"size": INTEGRATION_PROVIDER_PAGE_SIZE, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], "query": {"match_all": {}}}).encode("utf-8")
    payload = integration_provider_api_request(
        config,
        path,
        method="POST",
        body=body,
        headers={"Content-Type": "application/json", **headers},
    )
    hits = payload.get("hits", {}).get("hits") if isinstance(payload, dict) else None
    if not isinstance(hits, list):
        raise RuntimeError(f"{provider} returned an unsupported search response shape")
    events = []
    for hit in hits[:INTEGRATION_PROVIDER_PAGE_SIZE]:
        source = hit.get("_source") if isinstance(hit, dict) and isinstance(hit.get("_source"), dict) else {}
        event = source.get("event") if isinstance(source.get("event"), dict) else {}
        host = source.get("host") if isinstance(source.get("host"), dict) else {}
        rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
        source_ip = (source.get("source") or {}).get("ip") if isinstance(source.get("source"), dict) else None
        destination_ip = (source.get("destination") or {}).get("ip") if isinstance(source.get("destination"), dict) else None
        details = {
            "action": event.get("action"),
            "category": ", ".join(event.get("category", [])) if isinstance(event.get("category"), list) else event.get("category"),
            "dataset": event.get("dataset"),
            "host": host.get("name"),
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name"),
            "message": source.get("message"),
        }
        indicators = [{"type": "ip", "value": value} for value in (source_ip, destination_ip) if isinstance(value, str) and value]
        severity = source.get("severity") or event.get("severity") or rule.get("severity") or "unknown"
        events.append(integration_provider_event(
            provider,
            "OpenSearch" if provider == "opensearch" else "Wazuh Indexer",
            "security.alert" if rule.get("id") or rule.get("name") else "security.event",
            hit.get("_id") if isinstance(hit, dict) else None,
            source.get("@timestamp") or event.get("created") or source.get("timestamp"),
            source.get("message") or event.get("action") or f"{provider} indexed security event",
            details,
            severity=severity,
            outcome=event.get("outcome") or "observed",
            indicators=indicators,
        ))
    return events, [{"source": "search", "status": "live", "count": len(events)}]


def poll_opensearch_provider(config):
    if config.get("apiKey"):
        auth = {"Authorization": f"ApiKey {config['apiKey']}"}
    elif config.get("username") and config.get("password"):
        value = base64.b64encode(f"{config['username']}:{config['password']}".encode("utf-8")).decode("ascii")
        auth = {"Authorization": f"Basic {value}"}
    else:
        raise ValueError("OpenSearch API key or username and password are required")
    return poll_search_index_provider("opensearch", config, config.get("index"), auth)


def poll_wazuh_provider(config):
    indexer_url = str(config.get("indexerUrl") or "").strip()
    if not indexer_url or not config.get("username") or not config.get("password"):
        raise ValueError("Wazuh Indexer URL, username, and password are required for alert polling")
    value = base64.b64encode(f"{config['username']}:{config['password']}".encode("utf-8")).decode("ascii")
    indexer_config = {**config, "baseUrl": indexer_url}
    return poll_search_index_provider("wazuh", indexer_config, "wazuh-alerts-*", {"Authorization": f"Basic {value}"})


def poll_sentinelone_provider(config):
    api_token = str(config.get("apiToken") or "").strip()
    if not api_token:
        raise ValueError("SentinelOne API token is required")
    payload = integration_provider_api_request(
        config,
        f"/web/api/v2.1/threats?limit={INTEGRATION_PROVIDER_PAGE_SIZE}&sortBy=createdAt&sortOrder=desc",
        headers={"Authorization": f"ApiToken {api_token}"},
    )
    records = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise RuntimeError("SentinelOne returned an unsupported threat response shape")
    events = []
    for record in records[:INTEGRATION_PROVIDER_PAGE_SIZE]:
        if not isinstance(record, dict):
            continue
        threat = record.get("threatInfo") if isinstance(record.get("threatInfo"), dict) else {}
        agent = record.get("agentDetectionInfo") if isinstance(record.get("agentDetectionInfo"), dict) else {}
        events.append(integration_provider_event(
            "sentinelone",
            "SentinelOne",
            "security.alert",
            record.get("id"),
            record.get("createdAt") or record.get("updatedAt"),
            threat.get("threatName") or threat.get("classification") or "SentinelOne threat",
            {
                "classification": threat.get("classification"),
                "detection_type": threat.get("detectionType"),
                "mitigation_status": threat.get("mitigationStatus"),
                "agent_name": agent.get("agentName"),
                "agent_id": record.get("agentId"),
                "status": record.get("status"),
            },
            severity=threat.get("confidenceLevel") or "unknown",
            outcome=record.get("status") or threat.get("mitigationStatus") or "observed",
        ))
    return events, [{"source": "threats", "status": "live", "count": len(events)}]


def entra_client_credentials_token(config, scope):
    tenant = str(config.get("tenantId") or "").strip()
    client_id = str(config.get("clientId") or "").strip()
    client_secret = str(config.get("clientSecret") or "")
    if not tenant or not client_id or not client_secret:
        raise ValueError("Tenant ID, application ID, and client secret are required")
    token_config = {"baseUrl": f"https://login.microsoftonline.com/{urllib.parse.quote(tenant, safe='')}"}
    payload = integration_provider_api_request(
        token_config,
        "/oauth2/v2.0/token",
        method="POST",
        body=urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        }).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("Microsoft identity platform returned no access token")
    return token


def poll_defender_cloud_apps_provider(config):
    token = entra_client_credentials_token(config, "https://graph.microsoft.com/.default")
    graph_config = {"baseUrl": "https://graph.microsoft.com/v1.0"}
    path = "/security/alerts_v2?$top=100&$filter=serviceSource%20eq%20'microsoftDefenderForCloudApps'"
    payload = integration_provider_api_request(graph_config, path, headers={"Authorization": f"Bearer {token}"})
    records = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise RuntimeError("Microsoft Graph returned an unsupported alerts response shape")
    events = []
    for record in records[:INTEGRATION_PROVIDER_PAGE_SIZE]:
        if not isinstance(record, dict):
            continue
        events.append(integration_provider_event(
            "defender-cloud-apps",
            "Microsoft Defender for Cloud Apps",
            "security.alert",
            record.get("id") or record.get("providerAlertId"),
            record.get("createdDateTime") or record.get("lastUpdateDateTime"),
            record.get("title") or "Microsoft Defender for Cloud Apps alert",
            {
                "incident_id": record.get("incidentId"),
                "service_source": record.get("serviceSource"),
                "detection_source": record.get("detectionSource"),
                "category": record.get("category"),
                "classification": record.get("classification"),
                "status": record.get("status"),
                "alert_url": record.get("alertWebUrl"),
            },
            severity=record.get("severity") or "unknown",
            outcome=record.get("status") or "observed",
        ))
    return events, [{"source": "security-alerts-v2", "status": "live", "count": len(events)}]


def poll_prisma_cloud_provider(config):
    access_key = str(config.get("accessKey") or "").strip()
    secret_key = str(config.get("secretKey") or "")
    if not access_key or not secret_key:
        raise ValueError("Prisma Cloud access key and secret key are required")
    login = integration_provider_api_request(
        config,
        "/login",
        method="POST",
        body=json.dumps({"username": access_key, "password": secret_key}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    token = login.get("token") if isinstance(login, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("Prisma Cloud login returned no API token")
    payload = integration_provider_api_request(
        config,
        "/alert?timeRange=24h&detailed=false",
        headers={"x-redlock-auth": token},
    )
    records = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(records, list) and isinstance(payload, dict):
        records = payload.get("alerts")
    if not isinstance(records, list):
        raise RuntimeError("Prisma Cloud returned an unsupported alert response shape")
    events = []
    for record in records[:INTEGRATION_PROVIDER_PAGE_SIZE]:
        if not isinstance(record, dict):
            continue
        policy = record.get("policy") if isinstance(record.get("policy"), dict) else {}
        resource = record.get("resource") if isinstance(record.get("resource"), dict) else {}
        events.append(integration_provider_event(
            "prismacloud",
            "Palo Alto Prisma Cloud",
            "security.alert",
            record.get("id"),
            record.get("firstSeen") or record.get("lastSeen") or record.get("alertTime"),
            policy.get("name") or record.get("alertType") or "Prisma Cloud alert",
            {
                "policy_name": policy.get("name"),
                "policy_type": policy.get("policyType"),
                "resource_name": resource.get("name") or record.get("resourceName"),
                "resource_type": resource.get("resourceType") or record.get("resourceType"),
                "cloud_type": resource.get("cloudType") or record.get("cloudType"),
                "status": record.get("status"),
                "account_name": record.get("accountName"),
            },
            severity=policy.get("severity") or record.get("severity") or "unknown",
            outcome=record.get("status") or "open",
        ))
    return events, [{"source": "alerts", "status": "live", "count": len(events)}]


def poll_netapp_provider(config):
    username = str(config.get("username") or "")
    password = str(config.get("password") or "")
    if not username or not password:
        raise ValueError("NetApp ONTAP API username and password are required")
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    payload = integration_provider_api_request(
        config,
        f"/api/security/audit/messages?max_records={INTEGRATION_PROVIDER_PAGE_SIZE}",
        headers={"Authorization": f"Basic {credential}"},
    )
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise RuntimeError("ONTAP returned an unsupported audit message response shape")
    events = []
    for record in records[:INTEGRATION_PROVIDER_PAGE_SIZE]:
        if not isinstance(record, dict):
            continue
        events.append(integration_provider_event(
            "netapp",
            "NetApp ONTAP",
            "audit.event",
            record.get("uuid") or record.get("id"),
            record.get("time") or record.get("timestamp"),
            record.get("message") or record.get("action") or "ONTAP audit message",
            {
                "action": record.get("action"),
                "application": record.get("application"),
                "user": record.get("user"),
                "address": record.get("address"),
                "state": record.get("state"),
                "message": record.get("message"),
            },
            outcome=record.get("state") or "observed",
        ))
    return events, [{"source": "audit-messages", "status": "live", "count": len(events)}]


CATO_AUDIT_QUERY = """
query auditFeed($accountIDs: [ID!], $timeFrame: TimeFrame!, $filters: [AuditFieldFilterInput!], $marker: String) {
  auditFeed(accountIDs: $accountIDs, timeFrame: $timeFrame, filters: $filters, marker: $marker) {
    marker
    fetchedCount
    hasMore
    accounts {
      id
      records {
        time
        fieldsMap
        flatFields
      }
    }
  }
}
""".strip()


def poll_cato_provider(config):
    api_key = str(config.get("apiKey") or "").strip()
    account_id = str(config.get("accountId") or "").strip()
    if not api_key or not account_id:
        raise ValueError("Cato API key and account ID are required")
    api_config = {"baseUrl": "https://api.catonetworks.com/api/v1/graphql2"}
    marker = ""
    events_by_id = {}
    for _ in range(3):
        payload = integration_provider_api_request(
            api_config,
            "",
            method="POST",
            body=json.dumps({
                "query": CATO_AUDIT_QUERY,
                "operationName": "auditFeed",
                "variables": {"accountIDs": [account_id], "timeFrame": "last.P1D", "marker": marker},
            }).encode("utf-8"),
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
        )
        if not isinstance(payload, dict) or payload.get("errors"):
            messages = [str(error.get("message") or "GraphQL error")[:240] for error in (payload.get("errors") or []) if isinstance(error, dict)] if isinstance(payload, dict) else []
            raise RuntimeError("Cato auditFeed query failed" + (": " + "; ".join(messages) if messages else ""))
        audit_feed = (payload.get("data") or {}).get("auditFeed") if isinstance(payload.get("data"), dict) else None
        if not isinstance(audit_feed, dict):
            raise RuntimeError("Cato returned an unsupported auditFeed response shape")
        for account in audit_feed.get("accounts") or []:
            if not isinstance(account, dict):
                continue
            for record in account.get("records") or []:
                if not isinstance(record, dict):
                    continue
                fields = record.get("fieldsMap") if isinstance(record.get("fieldsMap"), dict) else {}
                if not fields:
                    flat_fields = record.get("flatFields")
                    if isinstance(flat_fields, list):
                        for item in flat_fields:
                            if isinstance(item, (list, tuple)) and len(item) >= 2:
                                fields[str(item[0])] = item[1]
                            elif isinstance(item, dict):
                                key = item.get("name") or item.get("fieldName") or item.get("key")
                                if key is not None:
                                    fields[str(key)] = item.get("value")
                normalized = {str(key).casefold().replace(" ", "_"): value for key, value in fields.items()}
                details = {
                    key: normalized[alias]
                    for key, aliases in {
                        "action": ("action", "change_type", "event_type"),
                        "actor": ("actor", "user", "username", "initiated_by"),
                        "resource": ("resource", "object", "target", "entity"),
                        "application": ("application", "app"),
                        "source_ip": ("source_ip", "ip_address", "client_ip"),
                        "status": ("status", "state", "result"),
                    }.items()
                    for alias in aliases if alias in normalized and normalized[alias] is not None
                }
                identity = json.dumps([account.get("id"), record.get("time"), details], sort_keys=True, ensure_ascii=True)
                normalized_event = integration_provider_event(
                    "cato",
                    "Cato Networks",
                    "audit.event",
                    identity,
                    record.get("time"),
                    details.get("action") or "Cato audit event",
                    {"account_id": account.get("id"), **details},
                    outcome=details.get("status") or "observed",
                )
                events_by_id[normalized_event["event_id"]] = normalized_event
        next_marker = str(audit_feed.get("marker") or "")
        if not audit_feed.get("hasMore") or not next_marker or next_marker == marker:
            break
        marker = next_marker
    events = list(events_by_id.values())
    return events, [{"source": "auditFeed", "status": "live", "count": len(events)}]


def refresh_configured_api_feeds():
    credentials = load_integration_credential_store()
    providers = (
        ("github", poll_github_provider, ("organization", "token")),
        ("gitlab", poll_gitlab_provider, ("groupId", "token")),
        ("misp", poll_misp_provider, ("baseUrl", "apiKey")),
        ("keycloak", poll_keycloak_provider, ("baseUrl", "realm", "clientId", "clientSecret")),
        ("opensearch", poll_opensearch_provider, ("baseUrl", "index")),
        ("wazuh", poll_wazuh_provider, ("indexerUrl", "username", "password")),
        ("sentinelone", poll_sentinelone_provider, ("baseUrl", "apiToken")),
        ("defender-cloud-apps", poll_defender_cloud_apps_provider, ("tenantId", "clientId", "clientSecret")),
        ("prismacloud", poll_prisma_cloud_provider, ("baseUrl", "accessKey", "secretKey")),
        ("netapp", poll_netapp_provider, ("baseUrl", "username", "password")),
        ("cato", poll_cato_provider, ("apiKey", "accountId")),
    )
    all_events = []
    results = []
    for provider, poller, required_fields in providers:
        config = credentials.get(provider) or {}
        if not all(config.get(field) for field in required_fields):
            results.append({"provider": provider, "status": "not_configured", "count": 0, "sources": []})
            continue
        try:
            events, sources = poller(config)
            all_events.extend(events)
            results.append({
                "provider": provider,
                "status": "live" if any(item.get("status") == "live" for item in sources) else "error",
                "count": len(events),
                "sources": sources,
            })
        except (RuntimeError, ValueError, OSError) as error:
            results.append({"provider": provider, "status": "error", "count": 0, "sources": [], "error": str(error)[:240]})
    routed = save_integration_events(all_events) if all_events else []
    return {
        "source": "read-only-provider-api",
        "syncedAt": datetime.now(timezone.utc).isoformat(),
        "count": len(all_events),
        "routedCount": len(routed),
        "providers": results,
    }


def poll_gitlab_provider(config):
    group = urllib.parse.quote(config["groupId"], safe="")
    root = f"https://gitlab.com/api/v4/groups/{group}"
    sources = (
        ("audit-events", f"{root}/audit_events?per_page={GIT_PROVIDER_PAGE_SIZE}&page=1", (), "audit.event"),
        ("vulnerability-report", f"{root}/vulnerability_report?per_page={GIT_PROVIDER_PAGE_SIZE}", ("vulnerabilities", "results"), "vulnerability.finding"),
    )
    events = []
    source_results = []
    for source_name, url, envelope_keys, event_kind in sources:
        try:
            records = git_provider_records(git_provider_api_request("gitlab", url, config["token"]), envelope_keys)
            for record in records:
                author = record.get("author") if isinstance(record.get("author"), dict) else {}
                project = record.get("project") if isinstance(record.get("project"), dict) else {}
                details = {
                    "action": record.get("event_type") or record.get("action") or record.get("state"),
                    "actor": author.get("name") or record.get("author_name"),
                    "project": project.get("name_with_namespace") or project.get("name") or record.get("entity_path"),
                    "severity": record.get("severity"), "report_type": record.get("report_type"),
                    "url": record.get("web_url"), "source_feed": source_name,
                }
                summary = record.get("title") or record.get("event_type") or source_name
                timestamp = record.get("created_at") or record.get("updated_at")
                upstream_id = f"{source_name}:{record.get('id') or record.get('event_id')}"
                events.append(git_provider_event("gitlab", event_kind, upstream_id, timestamp, summary, details, record.get("severity") or "unknown", record.get("state") or "observed"))
            source_results.append({"source": source_name, "status": "live", "count": len(records)})
        except (RuntimeError, ValueError, OSError) as error:
            source_results.append({"source": source_name, "status": "error", "count": 0, "error": str(error)[:240]})
    return events, source_results


def refresh_git_provider_feeds():
    credentials = load_integration_credential_store()
    provider_results = []
    all_events = []
    for provider, poller, required_fields in (
        ("github", poll_github_provider, ("organization", "token")),
        ("gitlab", poll_gitlab_provider, ("groupId", "token")),
    ):
        config = credentials.get(provider) or {}
        if not all(config.get(field) for field in required_fields):
            provider_results.append({"provider": provider, "status": "not_configured", "count": 0, "sources": []})
            continue
        try:
            events, sources = poller(config)
            all_events.extend(events)
            provider_results.append({"provider": provider, "status": "live" if any(item["status"] == "live" for item in sources) else "error", "count": len(events), "sources": sources})
        except (RuntimeError, ValueError, OSError) as error:
            provider_results.append({"provider": provider, "status": "error", "count": 0, "sources": [], "error": str(error)[:240]})
    routed = save_integration_events(all_events) if all_events else []
    return {"source": "git-provider-api", "syncedAt": datetime.now(timezone.utc).isoformat(), "count": len(all_events), "routedCount": len(routed), "providers": provider_results}


def normalize_git_webhook(provider, event_name, payload, delivery_id):
    if not isinstance(payload, dict):
        raise ValueError("Webhook body must be a JSON object")
    event_name = str(event_name or "unknown").strip()[:100]
    attributes = payload.get("object_attributes") if isinstance(payload.get("object_attributes"), dict) else {}
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    vulnerability = payload.get("vulnerability") if isinstance(payload.get("vulnerability"), dict) else {}
    workflow = payload.get("workflow_run") if isinstance(payload.get("workflow_run"), dict) else {}
    repository = payload.get("repository") if isinstance(payload.get("repository"), dict) else {}
    project = payload.get("project") if isinstance(payload.get("project"), dict) else {}
    subject = vulnerability or alert or workflow or attributes
    is_audit = "audit" in event_name.casefold()
    is_vulnerability = any(term in event_name.casefold() for term in ("vulnerability", "dependabot", "code_scanning", "secret_scanning")) or bool(vulnerability or alert)
    event_kind = "audit.event" if is_audit else "vulnerability.finding" if is_vulnerability else "webhook.event"
    details = {
        "event_name": event_name, "action": payload.get("action") or attributes.get("action") or attributes.get("state"),
        "summary": subject.get("title") or subject.get("summary") or workflow.get("name") or event_name,
        "repository": repository.get("full_name") or repository.get("name"),
        "project": project.get("path_with_namespace") or project.get("name"),
        "severity": subject.get("severity"), "state": subject.get("state") or attributes.get("state"),
        "url": subject.get("html_url") or subject.get("web_url") or attributes.get("url"),
    }
    timestamp = subject.get("created_at") or attributes.get("created_at") or workflow.get("updated_at") or payload.get("created_at")
    upstream_id = f"webhook:{delivery_id or payload.get('event_uuid') or subject.get('number') or subject.get('id') or attributes.get('id')}"
    event = git_provider_event(provider, event_kind, upstream_id, timestamp, details["summary"], details, details["severity"], details["state"] or "observed")
    event["source"]["transport"] = "webhook"
    return event


def authenticate_git_webhook(provider, headers, raw_body):
    config = (load_integration_credential_store().get(provider) or {})
    secret = str(config.get("webhookSecret") or "")
    if not secret:
        raise PermissionError(f"{provider} webhook secret is not configured")
    if provider == "github":
        supplied = str(headers.get("X-Hub-Signature-256") or "")
        expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    else:
        supplied = str(headers.get("X-Gitlab-Token") or "")
        expected = secret
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise PermissionError("Webhook authentication failed")


def delete_module_record(module_name, record_id):
    if module_name not in MODULE_NAMES:
        raise KeyError(module_name)
    record_id = validate_module_id(record_id)
    with MODULE_DATA_LOCK:
        store = module_store_payload()
        records = store["modules"][module_name]
        updated = [record for record in records if str(record.get("id")) != record_id]
        if len(updated) == len(records):
            return False
        store["modules"][module_name] = updated
        write_json_store(MODULE_DATA_FILE, store)
        return True


def module_analytics_payload():
    with MODULE_DATA_LOCK:
        modules = module_store_payload()["modules"]
    counts = {name: len(records) for name, records in modules.items()}
    alerts = modules.get("alerts", [])
    vulnerabilities = modules.get("vulnerabilities", [])
    audits = modules.get("secumat_audits", [])
    assignments = modules.get("audit_assignments", [])
    by_severity = Counter(str(item.get("severity") or "unknown").lower() for item in [*alerts, *vulnerabilities])
    by_status = Counter(str(item.get("status") or item.get("state") or "unknown").lower() for item in [*alerts, *assignments])
    scores = [float(item["score"]) for item in modules.get("risk", []) if isinstance(item.get("score"), (int, float))]
    return {
        "source": "local-module-store",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modules": counts,
        "totals": {
            "alerts": counts.get("alerts", 0),
            "vulnerabilities": counts.get("vulnerabilities", 0),
            "assets": counts.get("assets", 0),
            "open_items": sum(count for status, count in by_status.items() if status in {"open", "new", "active", "in_progress", "investigating"}),
            "audits": len(audits),
            "assignments": len(assignments),
            "average_risk_score": round(sum(scores) / len(scores), 1) if scores else None,
        },
        "by_severity": dict(by_severity),
        "by_status": dict(by_status),
        "live_connectivity": "not_checked_by_local_analytics",
    }


def module_threat_analytics_payload():
    with MODULE_DATA_LOCK:
        modules = module_store_payload()["modules"]
    records = [*modules.get("threat_intel", []), *modules.get("network_events", []), *modules.get("alerts", []), *modules.get("vulnerabilities", [])]
    indicators = read_json_store(SNORT_INDICATORS_FILE, [])
    rules = current_snort_catalog()
    severity = Counter(str(item.get("severity") or "unknown").lower() for item in records)
    types = Counter(str(item.get("event_type") or item.get("kind") or item.get("category") or "unknown").lower() for item in records)
    return {
        "source": "local-module-store",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "observed_records": len(records),
        "counts": {
            "threat_intel": len(modules.get("threat_intel", [])),
            "network_events": len(modules.get("network_events", [])),
            "alerts": len(modules.get("alerts", [])),
            "vulnerabilities": len(modules.get("vulnerabilities", [])),
            "indicators": len(indicators) if isinstance(indicators, list) else 0,
            "snort_rules": len(rules.get("records", [])) if rules else 0,
        },
        "by_severity": dict(severity),
        "by_type": dict(types),
        "live_sources": {"claroty": "requires_network_and_credentials", "public_feeds": "see /api/public-feeds", "vendor_connectors": "not_connected"},
    }


SIEM_FRAMEWORKS = (
    {"id": "iso27001", "name": "ISO/IEC 27001", "aliases": ("iso 27001", "iso/iec 27001", "iso27001")},
    {"id": "pci_dss", "name": "PCI DSS", "aliases": ("pci dss", "pci-dss", "pci")},
    {"id": "gdpr", "name": "GDPR", "aliases": ("gdpr",)},
    {"id": "nist_csf", "name": "NIST CSF", "aliases": ("nist csf", "nist cybersecurity framework")},
    {"id": "cis", "name": "CIS Controls", "aliases": ("cis controls", "cis v", "cis controls v", "cis")},
    {"id": "sebi_cscrf", "name": "SEBI CSCRF", "aliases": ("sebi cscrf", "cscrf")},
)


def siem_dashboard_payload():
    with MODULE_DATA_LOCK:
        modules = module_store_payload()["modules"]
    event_log = read_zero_trust_events(5000)
    combined = []
    seen = set()

    def add_record(record, module_name=""):
        if not isinstance(record, dict):
            return
        canonical = record.get("event") if isinstance(record.get("event"), dict) else record
        normalized = dict(canonical)
        if module_name:
            normalized.setdefault("module", module_name)
        identity = str(normalized.get("event_id") or normalized.get("id") or "")
        fingerprint = identity or hashlib.sha256(json.dumps(normalized, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        combined.append(normalized)

    for event in event_log:
        add_record(event)
    for module_name in ("integrations", "alerts", "vulnerabilities", "network_events", "threat_intel", "incidents"):
        for record in modules.get(module_name, [])[-SIEM_MODULE_EVENT_WINDOW:]:
            add_record(record, module_name)

    source_counts = Counter()
    severity_counts = Counter()
    status_counts = Counter()
    daily_volume = Counter()
    observed_techniques = Counter()
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    recent_count = 0
    for record in combined:
        source = record.get("source") if isinstance(record.get("source"), dict) else {}
        source_name = str(source.get("system") or record.get("source_system") or record.get("source") or record.get("module") or "Unspecified")
        source_counts[source_name[:100]] += 1
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        severity = str(record.get("severity") or details.get("severity") or "unknown").strip().casefold()
        severity_counts[severity[:40]] += 1
        status = str(record.get("status") or record.get("outcome") or "unknown").strip().casefold()
        status_counts[status[:40]] += 1
        raw_time = str(record.get("event_time") or record.get("created_at") or record.get("created") or record.get("detected") or "")
        try:
            stamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            stamp = stamp.astimezone(timezone.utc)
            if stamp >= cutoff_24h:
                recent_count += 1
            if stamp >= now - timedelta(days=14):
                daily_volume[stamp.date().isoformat()] += 1
        except ValueError:
            pass
        searchable = json.dumps(record, ensure_ascii=True).upper()
        for technique in set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", searchable)):
            observed_techniques[technique.split(".")[0]] += 1

    feed_matched_events = [
        record for record in combined
        if isinstance(record.get("threat_feed_matches"), list) and record["threat_feed_matches"]
    ]
    feed_matched_indicators = {
        f"{match.get('type', '')}:{match.get('indicator', '')}"
        for record in feed_matched_events
        for match in record.get("threat_feed_matches", [])
        if isinstance(match, dict) and match.get("indicator")
    }

    coverage = snort_attack_coverage()
    tactic_by_id = {row["tacticId"]: row for row in coverage.get("tactics", [])}
    observed_rows = []
    explicit = set(coverage.get("explicitTechniqueRules", []))
    for technique, occurrences in observed_techniques.most_common(100):
        tactic_id = ATTACK_TECHNIQUE_TACTICS.get(technique)
        tactic = tactic_by_id.get(tactic_id or "")
        if technique in explicit:
            evidence = "technique_rule"
        elif tactic and tactic.get("enabledCount"):
            evidence = "tactic_rules_only"
        else:
            evidence = "gap_or_unmapped"
        observed_rows.append({
            "techniqueId": technique,
            "occurrences": occurrences,
            "tactic": ATTACK_TACTIC_NAMES.get(tactic_id),
            "catalogueEvidence": evidence,
        })

    assignments = modules.get("audit_assignments", [])
    frameworks = []
    for framework in SIEM_FRAMEWORKS:
        matches = [
            item for item in assignments
            if any(alias in str(item.get("framework") or "").casefold() for alias in framework["aliases"])
        ]
        reviewed = sum(1 for item in matches if item.get("reviewed_at"))
        in_progress = sum(1 for item in matches if str(item.get("status") or "").casefold() in {"in_progress", "submitted"})
        frameworks.append({
            "id": framework["id"],
            "name": framework["name"],
            "assignmentCount": len(matches),
            "reviewedCount": reviewed,
            "inProgressCount": in_progress,
            "status": "reviewed_evidence" if reviewed else "in_progress" if in_progress else "not_assessed",
        })

    alerts = modules.get("alerts", [])
    vulnerabilities = modules.get("vulnerabilities", [])
    feed_status = get_threat_feed_status() if THREAT_FEED_DB_FILE.exists() else {
        "indicatorCount": 0, "feedCount": len(THREAT_INDICATOR_FEEDS), "feeds": [], "source": "local-threat-feed-index"
    }
    connectors = load_integration_connectors()
    received_connectors = sum(1 for connector in connectors if int(connector.get("eventCount") or 0) > 0)
    try:
        vulnerability_feeds = public_feed_payload().get("sources", [])
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        vulnerability_feeds = [{"id": "public-vulnerability-feeds", "name": "Public vulnerability feeds", "status": "error", "error": str(error)[:300]}]
    return {
        "source": "local-records-and-feed-index",
        "generatedAt": now.isoformat(),
        "counts": {
            "events": len(combined),
            "eventsLast24Hours": recent_count,
            "alerts": len(alerts),
            "vulnerabilities": len(vulnerabilities),
            "incidents": len(modules.get("incidents", [])),
            "assets": len(modules.get("assets", [])),
            "audits": len(modules.get("secumat_audits", [])),
            "auditAssignments": len(assignments),
            "integrationEvents": len(modules.get("integrations", [])),
            "sources": len(source_counts),
            "indicators": int(feed_status.get("indicatorCount") or 0),
            "feedMatchedAlerts": len(feed_matched_events),
            "feedMatchedIndicators": len(feed_matched_indicators),
            "ruleDetections": sum(1 for record in combined if isinstance(record.get("detection"), dict) or record.get("detection_rule_id")),
            "githubEvents": source_counts.get("GitHub", 0),
            "gitlabEvents": source_counts.get("GitLab", 0),
        },
        "bySource": [{"source": key, "count": value} for key, value in source_counts.most_common(20)],
        "bySeverity": dict(severity_counts),
        "byStatus": dict(status_counts),
        "dailyVolume": [
            {"date": (now - timedelta(days=offset)).date().isoformat(),
             "count": daily_volume.get((now - timedelta(days=offset)).date().isoformat(), 0)}
            for offset in range(13, -1, -1)
        ],
        "attack": {
            "catalogueTacticsCovered": coverage.get("tacticsCovered", 0),
            "catalogueTacticsTotal": coverage.get("tacticsTotal", 0),
            "catalogueRules": coverage.get("totalRules", 0),
            "observedTechniques": observed_rows,
            "evidenceNote": coverage.get("method"),
        },
        "frameworks": frameworks,
        "feeds": {
            "indicatorCount": int(feed_status.get("indicatorCount") or 0),
            "feedCount": int(feed_status.get("feedCount") or 0),
            "lastSuccess": feed_status.get("lastSuccess"),
            "source": feed_status.get("source"),
            "indicatorPartitions": feed_status.get("feeds", []),
            "vulnerabilitySources": vulnerability_feeds,
        },
        "detectionEngine": snort_engine_status_payload(),
        "connectors": {
            "configured": len(connectors),
            "receiving": received_connectors,
            "rubrikApiEnabled": load_integration_feed_state()["rubrikApiEnabled"],
        },
        "method": "Counts and trends are derived from local canonical events, local modules, the feed index, and the loaded Snort catalogue. Framework rows report audit assignment evidence, not certification. Catalogue coverage does not prove a running sensor or detected activity.",
    }


def siem_event_search_payload(query_text="", limit=100, offset=0):
    try:
        limit = max(1, min(200, int(limit)))
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("limit must be an integer from 1 to 200") from error
    try:
        offset = max(0, min(1000000, int(offset)))
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("offset must be a non-negative integer") from error
    raw_query = str(query_text or "").strip()[:500]
    filters = {}
    free_terms = []
    for match in re.finditer(r'\b(source|severity|event_type|device|ioc|category|module):(?:"([^"]{1,100})"|(\S{1,100}))', raw_query, re.IGNORECASE):
        filters[match.group(1).casefold()] = (match.group(2) or match.group(3)).casefold()
    remainder = re.sub(r'\b(?:source|severity|event_type|device|ioc|category|module):(?:"[^"]{1,100}"|\S{1,100})', " ", raw_query, flags=re.IGNORECASE)
    free_terms = [term.casefold() for term in remainder.split()[:12]]

    with MODULE_DATA_LOCK:
        modules = module_store_payload()["modules"]
    candidates = []
    seen = set()
    for event in read_zero_trust_events(5000):
        candidates.append(event)
    for module_name in ("integrations", "alerts", "vulnerabilities", "network_events", "threat_intel", "incidents"):
        candidates.extend(modules.get(module_name, [])[-SIEM_MODULE_EVENT_WINDOW:])

    rows = []
    source_options = {"Rubrik Security Cloud"}
    source_summary = {}
    origin_labels = {
        "rubrik_api": "Rubrik GraphQL API poll",
        "rubrik": "Rubrik PD-CEF webhook",
        "syslog": "Syslog bridge",
        "wazuh": "Wazuh adapter",
    }
    for record in candidates:
        if not isinstance(record, dict):
            continue
        event = record.get("event") if isinstance(record.get("event"), dict) else record
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        device = event.get("device") if isinstance(event.get("device"), dict) else {}
        indicators = event.get("indicators") if isinstance(event.get("indicators"), list) else []
        ioc_values = [str(item.get("value") or "") if isinstance(item, dict) else str(item) for item in indicators]
        ioc_values.extend(str(event.get(key) or details.get(key) or "") for key in ("ioc", "ip", "domain", "md5", "sha1", "sha256", "file_hash"))
        row = {
            "id": str(event.get("event_id") or event.get("id") or record.get("id") or ""),
            "time": str(event.get("event_time") or event.get("created_at") or event.get("created") or event.get("detected") or ""),
            "eventType": str(event.get("event_type") or event.get("kind") or "unknown"),
            "source": str(source.get("system") or event.get("source_system") or event.get("source") or event.get("module") or "Unspecified"),
            "severity": str(event.get("severity") or details.get("severity") or "unknown"),
            "status": str(event.get("status") or event.get("outcome") or "unknown"),
            "device": str(device.get("device_name") or device.get("device_id") or ""),
            "path": str(event.get("path") or ((event.get("network") or {}).get("request_path") if isinstance(event.get("network"), dict) else "") or details.get("request_path") or ""),
            "iocs": ioc_values,
            "summary": str(details.get("summary") or details.get("message") or event.get("title") or event.get("description") or row_title(event))[:1000],
            "module": str(record.get("module") or ""),
            "category": str(((event.get("routing") or {}).get("category") if isinstance(event.get("routing"), dict) else None) or record.get("category") or record.get("module") or "other"),
            "details": details,
            "routedModules": (event.get("routing") or {}).get("modules", []) if isinstance(event.get("routing"), dict) else record.get("routed_modules", []),
        }
        transport = str(source.get("transport") or "")
        row["transport"] = transport
        row["origin"] = origin_labels.get(transport, transport or "Not reported")
        if not row["path"] and transport == "rubrik_api":
            row["path"] = "/api/graphql (Rubrik Security Cloud)"
        source_options.add(row["source"])
        identity = row["id"] or hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
        if identity in seen:
            continue
        seen.add(identity)
        searchable = json.dumps(row, ensure_ascii=True).casefold()
        if any(term not in searchable for term in free_terms):
            continue
        if filters.get("source") and filters["source"] not in row["source"].casefold():
            continue
        if filters.get("severity") and filters["severity"] not in row["severity"].casefold():
            continue
        if filters.get("event_type") and filters["event_type"] not in row["eventType"].casefold():
            continue
        if filters.get("device") and filters["device"] not in row["device"].casefold():
            continue
        if filters.get("ioc") and not any(filters["ioc"] in value.casefold() for value in ioc_values):
            continue
        if filters.get("category") and filters["category"] not in row["category"].casefold():
            continue
        if filters.get("module") and filters["module"] not in row["module"].casefold() and filters["module"] not in " ".join(row["routedModules"]).casefold():
            continue
        rows.append(row)
        summary = source_summary.setdefault(row["source"], {"count": 0, "origins": {}, "paths": set(), "latest": ""})
        summary["count"] += 1
        summary["origins"][row["origin"]] = summary["origins"].get(row["origin"], 0) + 1
        if row["path"] and len(summary["paths"]) < 10:
            summary["paths"].add(row["path"])
        summary["latest"] = max(summary["latest"], row["time"])
    rows.sort(key=lambda row: row["time"], reverse=True)
    return {
        "query": raw_query,
        "filters": filters,
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "sourceOptions": sorted(source_options, key=str.casefold),
        "sourceSummary": {name: {**value, "paths": sorted(value["paths"])} for name, value in source_summary.items()},
        "records": rows[offset:offset + limit],
        "source": "local-events-and-modules",
    }


def row_title(record):
    return str(record.get("summary") or record.get("event_type") or record.get("name") or record.get("title") or "Security event")


def analyze_soc_studio_payload(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("sources", []), list):
        raise ValueError("Analysis payload must contain a sources list")
    sources = payload.get("sources", [])
    if len(sources) > 12:
        raise ValueError("At most 12 data sources can be analyzed at once")
    analyzed = []
    total_records = 0
    for item in sources:
        if not isinstance(item, dict) or not isinstance(item.get("records", []), list):
            raise ValueError("Each analysis source must contain a records list")
        records = item.get("records", [])
        total_records += len(records)
        if total_records > 5000:
            raise ValueError("At most 5,000 records can be analyzed at once")
        severity = Counter()
        status = Counter()
        techniques = Counter()
        days = Counter()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Analysis records must be JSON objects")
            level = str(record.get("severity") or "Unknown").strip().title()[:40] or "Unknown"
            state = str(record.get("status") or "Unknown").strip().lower()[:40] or "unknown"
            severity[level] += 1
            if state in {"closed", "resolved", "complete", "completed"}:
                status["closed"] += 1
            elif state in {"open", "new", "active", "investigating", "in_progress", "acknowledged"}:
                status["open"] += 1
            else:
                status["other"] += 1
            for technique in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(record.get("mitre") or "").upper())[:20]:
                techniques[technique] += 1
            timestamp = str(record.get("created") or record.get("detected") or "")[:40]
            try:
                day = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).date().isoformat()
                days[day] += 1
            except ValueError:
                pass
        source_name = str(item.get("name") or "Data source").strip()[:80] or "Data source"
        source_state = str(item.get("source") or "unavailable").strip().lower()
        if source_state not in {"live", "mock", "sample", "pending", "unavailable", "local"}:
            source_state = "unavailable"
        try:
            loaded_count = max(len(records), min(1000000, int(item.get("record_count", len(records)))))
        except (TypeError, ValueError, OverflowError):
            loaded_count = len(records)
        analyzed.append({
            "name": source_name,
            "source": source_state,
            "complete": bool(item.get("complete", True)),
            "record_count": loaded_count,
            "analyzed_count": len(records),
            "severity": dict(severity),
            "status": dict(status),
            "mitre_techniques": dict(techniques.most_common(12)),
            "daily_volume": dict(sorted(days.items())[-14:]),
        })
    return {
        "source": "local-backend-analysis",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_count": total_records,
        "sources": analyzed,
        "persistence": "none",
    }


def module_automation_dashboard_payload(query=None):
    query = query or {}
    modules = module_store_payload()["modules"]
    alerts = list(modules.get("alerts", [])) + list(modules.get("incidents", []))
    vulnerabilities = list(modules.get("vulnerabilities", []))
    days = max(1, min(365, int(query.get("days", 30) or 30)))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    def within_window(item):
        value = item.get("created_at") or item.get("event_time")
        if not value:
            return True
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed >= cutoff
        except ValueError:
            return False

    alerts = [item for item in alerts if within_window(item)]
    severity_filter = str(query.get("severity") or "").strip().casefold()
    category_filter = str(query.get("category") or "").strip().casefold()
    state_filter = str(query.get("state") or "").strip().casefold()
    search = str(query.get("q") or "").strip().casefold()
    if severity_filter:
        alerts = [item for item in alerts if str(item.get("severity") or "").casefold() == severity_filter]
    if category_filter:
        alerts = [item for item in alerts if str(item.get("category") or "").casefold() == category_filter]
    if state_filter:
        alerts = [item for item in alerts if str(item.get("state") or item.get("status") or "").casefold() == state_filter]
    if search:
        alerts = [item for item in alerts if search in json.dumps(item, ensure_ascii=True).casefold()]

    closed = sum(1 for item in alerts if str(item.get("state") or item.get("status") or "").casefold() in {"closed", "resolved", "completed"})
    open_count = sum(1 for item in alerts if str(item.get("state") or item.get("status") or "open").casefold() not in {"closed", "resolved", "completed"})
    automated = sum(1 for item in alerts if item.get("automated") is True or item.get("automation_mode") == "dry-run")
    measured_mttd = [float(item["mttd_minutes"]) for item in alerts if isinstance(item.get("mttd_minutes"), (int, float))]
    measured_mttr = [float(item["mttr_minutes"]) for item in alerts if isinstance(item.get("mttr_minutes"), (int, float))]
    saved_hours = [float(item["hours_saved"]) for item in alerts if isinstance(item.get("hours_saved"), (int, float))]
    risk_scores = [float(item["score"]) for item in modules.get("risk", []) if isinstance(item.get("score"), (int, float))]
    severity_counts = Counter(str(item.get("severity") or "unknown").title() for item in alerts)
    vulnerability_counts = Counter(str(item.get("severity") or "unknown").title() for item in vulnerabilities)
    by_source = Counter(str(item.get("source") or "unspecified") for item in alerts)
    by_day = Counter(str(item.get("created_at") or item.get("event_time") or "")[:10] for item in alerts if item.get("created_at") or item.get("event_time"))
    runs = automation_catalog_payload()["runs"]
    return {
        "source": "local-module-store" if alerts or vulnerabilities else ("local-dry-run-store" if runs else "empty"),
        "source_label": "Local persisted records; vendor actions not connected",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "external_actions_enabled": False,
        "kpis": {
            "mttd_hours": round(sum(measured_mttd) / len(measured_mttd) / 60, 2) if measured_mttd else None,
            "mttr_hours": round(sum(measured_mttr) / len(measured_mttr) / 60, 2) if measured_mttr else None,
            "automation_rate_percent": round(automated / len(alerts) * 100, 1) if alerts else None,
            "open_incidents": open_count,
            "hours_saved": round(sum(saved_hours), 1) if saved_hours else None,
            "posture_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else None,
        },
        "charts": {
            "incident_trends": [{"label": day, "incidents": value} for day, value in sorted(by_day.items())],
            "severity": [{"label": label, "value": value} for label, value in severity_counts.items()],
            "closure_rate": [{"label": "Closed", "value": closed}, {"label": "Open", "value": open_count}],
            "mitre_attack": [],
            "automation_success": [{"label": "Dry-run records", "value": len(runs)}],
            "siem_alerts": [{"label": label, "value": value} for label, value in by_source.items()],
            "vulnerabilities": [{"label": label, "value": value} for label, value in vulnerability_counts.items()],
            "roi": [{"label": "Measured hours saved", "value": round(sum(saved_hours), 1)}] if saved_hours else [],
        },
        "alerts": alerts[:500],
    }


def parse_secumat_multipart(content_type, raw_body):
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    message = BytesParser(policy=email_policy.default).parsebytes(header + raw_body)
    if not message.is_multipart():
        raise ValueError("Compliance uploads must use multipart/form-data")
    fields = {}
    uploaded_file = None
    for part in message.iter_parts():
        field_name = part.get_param("name", header="content-disposition")
        if not field_name:
            continue
        part_bytes = part.get_payload(decode=True) or b""
        file_name = part.get_filename()
        if file_name:
            if uploaded_file is not None:
                raise ValueError("Upload one questionnaire file at a time")
            uploaded_file = {"filename": Path(file_name.replace("\\", "/")).name, "bytes": part_bytes}
        else:
            charset = part.get_content_charset() or "utf-8"
            fields[field_name] = part_bytes.decode(charset, errors="replace").strip()
    if not uploaded_file or not uploaded_file["filename"]:
        raise ValueError("Questionnaire file is required")
    if not uploaded_file["bytes"] or len(uploaded_file["bytes"]) > MAX_SECUMAT_UPLOAD_BYTES:
        raise ValueError(f"Questionnaire file must be between 1 byte and {MAX_SECUMAT_UPLOAD_BYTES} bytes")
    if Path(uploaded_file["filename"]).suffix.casefold() not in {".xlsx", ".xlsm", ".csv"}:
        raise ValueError("Supported SECUMAT uploads are .xlsx, .xlsm, and .csv")
    return fields, uploaded_file


def excel_column_index(reference):
    letters = re.match(r"([A-Za-z]+)", str(reference or ""))
    if not letters:
        return None
    result = 0
    for character in letters.group(1).upper():
        result = result * 26 + ord(character) - ord("A") + 1
    return result - 1


def parse_secumat_workbook(filename, file_bytes):
    extension = Path(filename).suffix.casefold()
    if extension == ".csv":
        text = file_bytes.decode("utf-8-sig", errors="replace")
        raw_rows = list(csv.reader(io.StringIO(text)))
        sheet_name = Path(filename).stem[:31] or "Sheet1"
        rows = [{"row_number": index + 1, "cells": row[:80]} for index, row in enumerate(raw_rows[:MAX_SECUMAT_PREVIEW_ROWS])]
        width = max((len(row["cells"]) for row in rows), default=0)
        sheets = [{"sheet_name": sheet_name, "row_count": len(raw_rows), "column_count": width, "rows": rows}]
    else:
        main_ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        rel_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        package_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
        namespaces = {"m": main_ns, "r": rel_ns, "p": package_ns}
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as archive:
                names = set(archive.namelist())
                if "xl/workbook.xml" not in names or "xl/_rels/workbook.xml.rels" not in names:
                    raise ValueError("The workbook package is missing required worksheet metadata")
                workbook = ET.fromstring(archive.read("xl/workbook.xml"))
                relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
                targets = {item.attrib.get("Id"): item.attrib.get("Target", "") for item in relationships.findall("p:Relationship", namespaces)}
                shared_strings = []
                if "xl/sharedStrings.xml" in names:
                    shared_root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
                    shared_strings = ["".join(node.itertext()) for node in shared_root.findall("m:si", namespaces)]
                sheets = []
                for sheet in workbook.findall("m:sheets/m:sheet", namespaces)[:100]:
                    target = targets.get(sheet.attrib.get(f"{{{rel_ns}}}id"), "")
                    if target.startswith("/"):
                        target = target.lstrip("/")
                    elif not target.startswith("xl/"):
                        target = posixpath.normpath(posixpath.join("xl", target))
                    if not target.startswith("xl/worksheets/") or target not in names:
                        continue
                    worksheet = ET.fromstring(archive.read(target))
                    raw_rows = []
                    width = 0
                    sheet_data = worksheet.find("m:sheetData", namespaces)
                    for row in list(sheet_data)[:100000] if sheet_data is not None else []:
                        cells = []
                        for cell in row.findall("m:c", namespaces):
                            index = excel_column_index(cell.attrib.get("r"))
                            if index is None or index >= 80:
                                continue
                            value_node = cell.find("m:v", namespaces)
                            value = "" if value_node is None else (value_node.text or "")
                            if cell.attrib.get("t") == "s" and value:
                                try:
                                    value = shared_strings[int(value)]
                                except (ValueError, IndexError):
                                    value = ""
                            elif cell.attrib.get("t") == "inlineStr":
                                inline = cell.find("m:is", namespaces)
                                value = "" if inline is None else "".join(inline.itertext())
                            while len(cells) <= index:
                                cells.append("")
                            cells[index] = value
                        width = max(width, len(cells))
                        if any(str(value).strip() for value in cells):
                            raw_rows.append({"row_number": int(row.attrib.get("r", len(raw_rows) + 1)), "cells": cells})
                    sheets.append({"sheet_name": sheet.attrib.get("name", "Sheet"), "row_count": len(raw_rows), "column_count": width, "rows": raw_rows[:MAX_SECUMAT_PREVIEW_ROWS]})
        except (zipfile.BadZipFile, ET.ParseError, KeyError) as error:
            raise ValueError(f"Could not read questionnaire workbook: {error}") from error
    sheets = [sheet for sheet in sheets if sheet["sheet_name"].strip().casefold() != "- disclaimer -"]
    informational = {"overview", "summary", "how to use", "instructions", "lookups", "read me"}
    applicable = [sheet for sheet in sheets if sheet["sheet_name"].strip().casefold() not in informational]
    total_rows = sum(max(0, sheet["row_count"] - 1) for sheet in applicable)
    sheet_details = []
    for sheet in sheets:
        headers = sheet["rows"][0]["cells"] if sheet["rows"] else []
        sheet_details.append({"sheet_name": sheet["sheet_name"], "detected_columns": [str(value) for value in headers if str(value).strip()][:80]})
    breakdown = [{"sheet_name": sheet["sheet_name"], "row_count": sheet["row_count"]} for sheet in sheets]
    return {
        "sheets": sheets,
        "sheet_count": len(sheets),
        "sheet_breakdown": breakdown,
        "sheet_details": sheet_details,
        "total_questions": total_rows,
        "total_controls": total_rows,
        "template_coverage": {"uploaded_sheets": len(sheets), "expected_sheets": len(sheets), "is_complete": True},
        "mapping_summary": {},
    }


def load_secumat_upload_preview(upload):
    stored_name = str(upload.get("storage_name") or "")
    if not re.fullmatch(r"[a-f0-9]{32}\.(xlsx|xlsm|csv)", stored_name):
        raise ValueError("Stored upload reference is invalid")
    path = SECUMAT_UPLOAD_DIR / stored_name
    if not path.is_file() or path.stat().st_size > MAX_SECUMAT_UPLOAD_BYTES:
        raise FileNotFoundError("Stored questionnaire file is unavailable")
    return parse_secumat_workbook(upload.get("filename") or stored_name, path.read_bytes())


def secumat_template_files():
    folder = ROOT / "Audit Templates & Question Bank"
    if not folder.is_dir():
        return []
    allowed_extensions = {".xlsx", ".xls", ".csv", ".pdf", ".docx", ".pptx", ".html"}
    files = []
    for path in sorted(folder.iterdir(), key=lambda item: item.name.casefold()):
        if path.name.casefold() == "ic-iso-27001-sample-form-10838.xlsx":
            continue
        if not path.is_file() or path.suffix.casefold() not in allowed_extensions:
            continue
        framework = "Database Security" if "database security" in path.name.casefold() else "ZF Security Requirements" if "zf security requirements" in path.name.casefold() else "ISO 27001" if "27001" in path.name else "ISO 42001" if "42001" in path.name else "IT Risk" if "risk" in path.name.casefold() else "Questionnaire"
        description = (
            "Browser-only database security assessment; ratings are stored in this browser and are not submitted to the platform."
            if path.name.casefold() == "database security audit tool.html"
            else "Loadable 37-control Database Security audit workbook template for SECUMAT assignments and response tracking."
            if path.name.casefold() == "database security audit controls.csv"
            else "Deduplicated ZF security measures for Audit Setup, filtered question-bank review, guidance, and audit assignment."
            if path.name.casefold() == "zf security requirements control library.csv"
            else "Local questionnaire resource; question content is read from the workbook when loaded."
        )
        files.append({
            "id": re.sub(r"[^a-z0-9]+", "-", path.stem.casefold()).strip("-")[:96],
            "name": path.name,
            "framework": framework,
            "version": "file",
            "description": description,
            "control_count": None,
            "source": "Audit questionnaire folder",
            "extension": path.suffix.lstrip(".").lower(),
            "size_bytes": path.stat().st_size,
        })
    return files


def secumat_zf_control_catalog():
    path = ROOT / "Audit Templates & Question Bank" / "ZF Security Requirements Control Library.csv"
    if not path.is_file():
        return [], []
    controls = []
    seen = set()
    focus_groups = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            raw = " ".join(str(row.get("Control") or "").split())
            if not raw:
                continue
            for misspelling, correction in (("Priviledged", "Privileged"), ("Sing Sing-On", "Single Sign-On"), ("Vulnerabilites", "Vulnerabilities")):
                raw = re.sub(misspelling, correction, raw, flags=re.IGNORECASE)
            tsi_match = re.match(r"^(TSI\s*01\s*-\s*\d{3})\s+(.+)$", raw, re.IGNORECASE)
            if tsi_match:
                control_id, measure = tsi_match.groups()
            else:
                control_id, separator, measure = raw.partition(" - ")
                if not separator:
                    control_id, measure = raw, raw
            key = re.sub(r"[^a-z0-9]+", "", control_id.casefold()) + "|" + re.sub(r"[^a-z0-9]+", " ", measure.casefold()).strip()
            if key in seen:
                continue
            seen.add(key)
            normalized = raw.casefold()
            if normalized.startswith(("gl-aap", "gl-aar")):
                focus = "Cloud Access and Identity"
            elif normalized.startswith(("si-01", "tsi 01-1", "tsi 01 - 1")):
                focus = "Asset Ownership and Inventory"
            elif normalized.startswith(("si-02", "tsi 01 - 2")) or "vulnerabilit" in normalized or "patch" in normalized:
                focus = "Vulnerability and Patch Management"
            elif normalized.startswith(("si-03", "tsi03")) or "access" in normalized or "password" in normalized or "identity" in normalized:
                focus = "Identity and Access Management"
            elif normalized.startswith(("si-04", "tsi 01 - 1")) or "hardening" in normalized or "configuration" in normalized:
                focus = "Configuration and Hardening"
            elif normalized.startswith(("si-05", "si-18-c", "tsi 01 - 3")) or "logging" in normalized or "event recording" in normalized or "log retention" in normalized:
                focus = "Logging and Monitoring"
            elif normalized.startswith(("si-08",)) or "backup" in normalized:
                focus = "Backup and Recovery"
            elif normalized.startswith(("si-09", "si-10", "si-18-i")) or any(term in normalized for term in ("network", "remote access", "vpn", "wlan", "traffic", "proxy")):
                focus = "Network and Remote Access"
            elif normalized.startswith(("si-11",)) or any(term in normalized for term in ("cryptography", "encryption", "certificate", "key /")):
                focus = "Cryptography and Physical Security"
            elif normalized.startswith(("si-13", "si26", "tsi 01 - 4")) or any(term in normalized for term in ("application", "software", "secure development", "api gateway", "third party components")):
                focus = "Application and Product Security"
            elif normalized.startswith(("si-15", "tsi 01 - 5")) or any(term in normalized for term in ("penetration test", "pentest", "offensive exercise")):
                focus = "Security Testing and Remediation"
            elif normalized.startswith(("si-16", "si-21")) or "supplier" in normalized or "vendor" in normalized:
                focus = "Supplier and Third-Party Security"
            elif normalized.startswith(("si-18", "si-20", "si-22", "ps ", "wicf", "wig")) or any(term in normalized for term in ("risk", "compliance", "change-management", "operating procedures")):
                focus = "Risk, Governance, and Change Management"
            else:
                focus = "General Security Requirements"
            item = {
                "id": f"zf-control-{len(controls) + 1}",
                "questionnaire_id": "zf-security-requirements",
                "control_id": control_id.strip(),
                "title": control_id.strip(),
                "question": measure.strip(),
                "industry": "All",
                "audit_type": "All",
                "framework": "ZF Security Requirements",
                "os_platform": "All",
                "focus_area": focus,
                "source": "ZF Security Requirements",
            }
            controls.append(item)
            focus_groups.setdefault(focus, []).append(f"{item['control_id']} - {item['question']}")
    return controls, [{"category": f"ZF Controls - {category}", "points": points} for category, points in sorted(focus_groups.items())]


def secumat_database_control_catalog():
    path = ROOT / "Audit Templates & Question Bank" / "Database Security Audit Controls.csv"
    if not path.is_file():
        return [], []
    controls = []
    groups = {}
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            section = " ".join(str(row.get("Section") or "Database Security").split())
            control_id = " ".join(str(row.get("Control ID") or "").split())
            question = " ".join(str(row.get("Control") or "").split())
            if not question:
                continue
            controls.append({
                "id": f"database-control-{control_id.casefold()}",
                "questionnaire_id": "database-security-audit",
                "control_id": control_id or f"DB-{len(controls) + 1:02d}",
                "title": control_id or section,
                "question": question,
                "industry": "All",
                "audit_type": "All",
                "framework": "Database Security",
                "os_platform": "All",
                "focus_area": section,
                "source": "Database Security Audit",
            })
            groups.setdefault(section, []).append(f"{control_id} - {question}" if control_id else question)
    return controls, [{"category": f"Database Security - {section}", "points": points} for section, points in groups.items()]


def save_audit_workbook_version(payload, editor):
    if not isinstance(payload, dict):
        raise ValueError("Workbook submission must be an object")
    source = str(payload.get("source") or "")
    if source not in {item["name"] for item in secumat_template_files() if item["extension"] in {"xlsx", "xls", "csv"}}:
        raise ValueError("Choose a spreadsheet from the audit template library")
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 160:
        raise ValueError("Audit name must be 1-160 characters")
    status = payload.get("status")
    if not isinstance(status, str) or status not in {"draft", "submitted"}:
        raise ValueError("Audit status must be draft or submitted")
    expected_version = payload.get("expectedVersion", 0)
    if type(expected_version) is not int or expected_version < 0:
        raise ValueError("Expected audit version must be a non-negative integer")
    changes = payload.get("changes", {})
    ratings = payload.get("ratings", {})
    if not isinstance(changes, dict) or not isinstance(ratings, dict) or len(changes) > 100 or len(ratings) > 100:
        raise ValueError("Workbook changes must be grouped by worksheet")
    for sheet, cells in changes.items():
        if not isinstance(sheet, str) or not 1 <= len(sheet) <= 31 or not isinstance(cells, dict) or len(cells) > 10000:
            raise ValueError("Invalid worksheet changes")
        for address, value in cells.items():
            if not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]{0,6}", address) or not isinstance(value, str) or len(value) > 10000:
                raise ValueError("Invalid workbook cell")
    for sheet, rows in ratings.items():
        if not isinstance(sheet, str) or not 1 <= len(sheet) <= 31 or not isinstance(rows, dict) or len(rows) > 10000:
            raise ValueError("Invalid worksheet ratings")
        for row, entry in rows.items():
            if not re.fullmatch(r"[1-9][0-9]{0,6}", row) or not isinstance(entry, dict) or not isinstance(entry.get("rating"), str) or entry["rating"] not in {"", "compliant", "compensating_control", "partial", "non_compliant", "needs_review", "deferred", "not_applicable"} or not isinstance(entry.get("evidence"), str) or len(entry["evidence"]) > 10000:
                raise ValueError("Invalid audit rating or evidence")
    audit_id = validate_module_id(payload.get("auditId") or uuid.uuid4().hex)
    assignment_id = validate_module_id(payload["assignmentId"]) if payload.get("assignmentId") else None
    with MODULE_DATA_LOCK:
        versions = [item for item in module_store_payload()["modules"]["audit_workbook_versions"] if item.get("audit_id") == audit_id]
        latest = max(versions, key=lambda item: item["version"], default=None)
        if latest and (latest["source"] != source or latest["status"] == "submitted"):
            raise ValueError("Submitted audits cannot be edited; use Save As for a new draft")
        if expected_version != (latest["version"] if latest else 0):
            raise ValueError("This audit changed since it was loaded; reload its latest version")
        if latest and latest.get("assignment_id") and assignment_id != latest["assignment_id"]:
            raise ValueError("This audit belongs to another assignment")
        assignment = get_module_record("audit_assignments", assignment_id) if assignment_id else None
        if assignment_id and (not assignment or assignment.get("template_file") != source):
            raise ValueError("Assignment does not match this workbook")
        if assignment and assignment.get("workbook_audit_id") not in (None, audit_id):
            raise ValueError("Assignment already belongs to another audit")
        record = save_module_record("audit_workbook_versions", {
            "audit_id": audit_id, "source": source, "name": name, "status": status,
            "version": (latest["version"] if latest else 0) + 1,
            "edited_by": editor, "assignment_id": assignment_id,
            "changes": changes, "ratings": ratings,
        })
        if assignment:
            completed = min(int(assignment.get("question_count") or 0), sum(
                1 for rows in ratings.values() for row, entry in rows.items()
                if int(row) > 1 and entry["rating"]
            ))
            total = int(assignment.get("question_count") or 0)
            score_map = {"compliant": 100, "compensating_control": 75, "partial": 50,
                         "non_compliant": 0, "needs_review": 0, "deferred": 0}
            scores = [score_map[entry["rating"]] for rows in ratings.values() for entry in rows.values()
                      if entry["rating"] in score_map]
            assignment.update({
                "workbook_audit_id": audit_id, "status": "submitted" if status == "submitted" else "in_progress",
                "completed_responses": completed, "pending_items": max(0, total - completed),
                "progress_percent": round(completed / total * 100, 2) if total else 0.0,
                "compliance_score": round(sum(scores) / len(scores), 2) if scores else None,
                "edited_by": editor, "last_edited_at": record["updated_at"],
            })
            save_module_record("audit_assignments", assignment, assignment["id"])
    return record


def validate_template_sheets(sheets):
    if sheets is None:
        return []
    if not isinstance(sheets, list) or len(sheets) > 50:
        raise ValueError("A template can contain up to 50 worksheets")
    cleaned = []
    for sheet in sheets:
        name = str(sheet.get("name") or "").strip()[:31] if isinstance(sheet, dict) else ""
        rows = sheet.get("rows") if isinstance(sheet, dict) else None
        if not name or not isinstance(rows, list) or len(rows) > 5000:
            raise ValueError("Each worksheet needs a name and up to 5,000 rows")
        grid = []
        for row in rows:
            if not isinstance(row, list) or len(row) > 80 or any(not isinstance(cell, str) or len(cell) > 10000 for cell in row):
                raise ValueError("Invalid worksheet row")
            grid.append(row)
        cleaned.append({"name": name, "rows": grid})
    return cleaned


def audit_workbook_history(source="", audit_id=""):
    with MODULE_DATA_LOCK:
        versions = [item for item in module_store_payload()["modules"]["audit_workbook_versions"]
                    if (not source or item.get("source") == source) and (not audit_id or item.get("audit_id") == audit_id)]
    versions.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
    return [{key: item.get(key) for key in ("id", "audit_id", "source", "name", "status", "version", "edited_by", "assignment_id", "updated_at")} for item in versions]


def secumat_workspace_payload():
    audits = list_module_records("secumat_audits", limit=500)["records"]
    assignments = list_module_records("audit_assignments", limit=500)["records"]
    uploads = list_module_records("secumat_uploads", limit=500)["records"]
    custom_templates = list_module_records("custom_templates", limit=500)["records"]
    files = secumat_template_files()
    zf_controls, zf_guidance = secumat_zf_control_catalog()
    database_controls, database_guidance = secumat_database_control_catalog()
    template_library = [{
        "id": f"template-resource-{item['id']}",
        "title": item["name"],
        "question": f"{item['framework']} template resource ({item['extension'].upper()}). Open this item in the template catalog to view or load its source file.",
        "industry": "All",
        "audit_type": "All",
        "framework": item["framework"],
        "os_platform": "All",
        "focus_area": "Template Resource",
        "source": "Template Library",
        "questionnaire_id": None,
        "template_resource": True,
        "template_name": item["name"],
        "template_extension": item["extension"],
        "template_assignable": item["extension"] in {"xlsx", "csv"},
    } for item in files]
    custom_library = []
    for template in custom_templates:
        questionnaire_id = f"custom_{template.get('id')}"
        for index, question in enumerate(template.get("questions") or []):
            if not isinstance(question, dict):
                continue
            prompt = str(question.get("question") or question.get("title") or "").strip()
            if not prompt:
                continue
            control_id = str(question.get("control_id") or question.get("id") or f"Q-{index + 1}").strip()
            custom_library.append({
                "id": f"{questionnaire_id}-{index + 1}",
                "questionnaire_id": questionnaire_id,
                "control_id": control_id,
                "title": str(question.get("title") or control_id),
                "question": prompt,
                "industry": question.get("industry") or template.get("industry") or "All",
                "audit_type": question.get("audit_type") or "All",
                "framework": template.get("framework") or "Custom",
                "os_platform": question.get("os_platform") or "All",
                "focus_area": question.get("category") or question.get("section") or "Custom Questionnaire",
                "source": "Custom / Manual",
            })
    questionnaires = [{
        "id": f"custom_{item.get('id')}",
        "db_id": item.get("id"),
        "name": item.get("name") or "Custom questionnaire",
        "framework": item.get("framework") or "CUSTOM",
        "version": item.get("version") or "1.0",
        "description": item.get("description") or "",
        "source": "Custom / Manual",
        "question_count": len(item.get("questions") or []),
        "questions": item.get("questions") or [],
        "has_sheets": bool(item.get("sheets")),
        "is_custom": True,
    } for item in custom_templates]
    if zf_controls:
        questionnaires.append({
            "id": "zf-security-requirements",
            "name": "ZF Security Requirements Control Library",
            "framework": "ZF Security Requirements",
            "version": "local catalog",
            "description": "Deduplicated measures from the supplied ZF control list.",
            "source": "ZF Security Requirements",
            "question_count": len(zf_controls),
            "questions": [{
                "control_id": item["control_id"],
                "question": item["question"],
                "guidance": item["focus_area"],
            } for item in zf_controls],
        })
    if database_controls:
        questionnaires.append({
            "id": "database-security-audit",
            "name": "Database Security Audit",
            "framework": "Database Security",
            "version": "1.0",
            "description": "Complete 37-control database assessment covering access, encryption, network security, audit monitoring, backup and recovery.",
            "source": "Database Security Audit",
            "question_count": len(database_controls),
            "questions": [{
                "control_id": item["control_id"],
                "question": item["question"],
                "guidance": item["focus_area"],
            } for item in database_controls],
        })
    return {
        "options": {
            "frameworks": ["CIS", "NIST", "ISO", "SOC 2", "PCI-DSS", "HIPAA", "GDPR", "ZF Security Requirements", "Database Security", "Custom"],
            "audit_types": ["Internal", "External", "Compliance", "VAPT", "Cloud Security", "Database Security Audit"],
            "industries": ["Automotive", "OT/ICS", "Database Systems", "Healthcare", "Finance", "Critical Infrastructure", "Manufacturing", "Technology", "Government", "Energy", "Retail", "Custom"],
            "operating_systems": ["Windows", "Linux", "macOS", "Multi-OS", "Cloud Native", "OT/ICS Mixed", "Other"],
            "divisions": ["Corporate IT", "SOC", "Engineering", "Plant Operations", "Cloud Operations", "Risk & Compliance", "Other"],
            "quarters": ["Quarter 1", "Quarter 2", "Quarter 3", "Quarter 4"],
            "audit_cycles": [f"Audit-{index}" for index in range(1, 21)],
            "questionnaire_modes": ["Master Questionnaire", "Customized Questionnaire", "SECUMAT Security Questionnaire", "CIS Controls v8", "NIST SP 800-53", "ISO 27001", "Cloud Security", "ZF Security Requirements", "Database Security Audit"],
        },
        "resources": [{"name": item["name"], "description": item["description"], "target_type": "file", "target": item["name"]} for item in files],
        "questionnaire_library": zf_controls + database_controls + custom_library + template_library,
        "questionnaires": questionnaires,
        "guidance": [{"category": "Compliance and Audit Evidence", "points": [
            "Select the applicable legal, contractual, regulatory, and internal control requirements before assessment.",
            "Record control owner, scope, evidence source, review date, and exceptions for each finding.",
            "Validate ratings through configuration review, interviews, and evidence sampling; a questionnaire score is not certification.",
            "Track remediation owners and due dates, and retain reviewed workbook versions for audit traceability.",
        ]}] + zf_guidance + database_guidance,
        "templates": files,
        "audits": audits,
        "assignments": assignments,
        "uploads": uploads,
        "fallback_mode": True,
        "source": "local-file-and-module-store",
    }


def automation_catalog_payload():
    catalog = [
        {"id": "triage_alert", "name": "Alert triage", "modules": ["alerts", "threat_intel"], "mode": "dry-run"},
        {"id": "vulnerability_review", "name": "Vulnerability review", "modules": ["vulnerabilities", "assets", "risk"], "mode": "dry-run"},
        {"id": "audit_followup", "name": "Audit follow-up", "modules": ["secumat_audits", "audit_assignments", "compliance"], "mode": "dry-run"},
        {"id": "network_indicator_review", "name": "Network indicator review", "modules": ["network_events", "threat_intel"], "mode": "dry-run"},
    ]
    runs = read_json_store(AUTOMATION_RUNS_FILE, [])
    if not isinstance(runs, list):
        runs = []
    return {"playbooks": catalog, "runs": list(reversed(runs[-200:])), "source": "local-dry-run-store", "external_actions_enabled": False}


def run_module_automation(payload):
    if not isinstance(payload, dict):
        raise ValueError("Automation request must be a JSON object")
    module_name = str(payload.get("module") or "all").strip().lower()
    catalog = automation_catalog_payload()["playbooks"]
    selected = [item for item in catalog if module_name in {"all", item["id"]} or module_name in item["modules"]]
    if not selected:
        raise ValueError("Choose a known module or automation playbook")
    analytics = module_analytics_payload()
    run = {
        "id": uuid.uuid4().hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "requested_module": module_name,
        "mode": "dry-run",
        "source": "local-module-store",
        "external_actions_executed": False,
        "analytics_snapshot": analytics["totals"],
        "playbooks": [{"id": item["id"], "name": item["name"], "status": "planned", "actions": item["modules"]} for item in selected],
    }
    with MODULE_DATA_LOCK:
        runs = read_json_store(AUTOMATION_RUNS_FILE, [])
        if not isinstance(runs, list):
            runs = []
        runs.append(run)
        write_json_store(AUTOMATION_RUNS_FILE, runs[-AUTOMATION_MAX_RUNS:])
    return run


def secumat_assignment_result(assignment_id):
    assignment = get_module_record("audit_assignments", assignment_id)
    if not assignment:
        return None
    if assignment.get("template_source") == "workbook":
        versions = [item for item in module_store_payload()["modules"]["audit_workbook_versions"]
                    if item.get("audit_id") == assignment.get("workbook_audit_id")]
        latest = max(versions, key=lambda item: item["version"], default=None)
        preview_rows = {}
        if latest:
            template_name = assignment.get("template_file")
            allowed = {item["name"] for item in secumat_template_files() if item["extension"] in {"xlsx", "xls", "csv"}}
            source = ROOT / "Audit Templates & Question Bank" / template_name if template_name in allowed else None
            if source and source.is_file() and source.stat().st_size <= MAX_SECUMAT_UPLOAD_BYTES:
                preview = parse_secumat_workbook(source.name, source.read_bytes())
                preview_rows = {(sheet["sheet_name"], str(row["row_number"])): row["cells"]
                                for sheet in preview["sheets"] for row in sheet["rows"]}
        score_map = {"compliant": 100, "compensating_control": 75, "partial": 50,
                     "non_compliant": 0, "needs_review": 0, "deferred": 0, "not_applicable": None}
        responses = []
        for sheet, rows in (latest or {}).get("ratings", {}).items():
            for row_number, entry in rows.items():
                values = list(preview_rows.get((sheet, row_number), []))
                for address, value in (latest.get("changes", {}).get(sheet) or {}).items():
                    if re.fullmatch(r"[A-Z]+" + re.escape(row_number), address):
                        column = excel_column_index(address)
                        if column is not None and column < 80:
                            while len(values) <= column:
                                values.append("")
                            values[column] = value
                responses.append({"question_id": f"{sheet}!{row_number}",
                                  "question_text": " | ".join(str(value) for value in values if str(value).strip())[:1000] or f"{sheet} row {row_number}",
                                  "response_status": entry["rating"] or "pending", "evidence": entry["evidence"],
                                  "comments": "", "mapping_score": score_map.get(entry["rating"])})
        scored = [item["mapping_score"] for item in responses if item["mapping_score"] is not None]
        score = round(sum(scored) / len(scored), 2) if scored else None
        breakdown = dict(Counter(item["response_status"] for item in responses))
        report = {key: assignment.get(key) for key in (
            "id", "assessment_name", "status", "question_count", "completed_responses",
            "pending_items", "progress_percent", "assigned_to", "edited_by", "last_edited_at",
            "template_file", "workbook_audit_id", "framework", "assigned_to_type", "assignment_date",
            "reviewer_score", "reviewer_comments", "reviewer_notes", "reviewed_by", "reviewed_at",
        )}
        report.update({"questionnaire": assignment.get("questionnaire_name"),
                       "total_questions": assignment.get("question_count"), "compliance_score": score,
                       "status_breakdown": breakdown})
        return {"assignment": report, "report": report, "responses": responses, "status_counts": breakdown,
                "compliance_score": score,
                "progress_percent": assignment.get("progress_percent", 0), "source": "local-workbook-audit"}
    response_rows = list_module_records("audit_responses", limit=MODULE_MAX_RECORDS)["records"]
    responses = [item for item in response_rows if str(item.get("assignment_id")) == str(assignment_id)]
    score_map = {
        "compliant": 100, "partial": 50, "non_compliant": 0,
        "not_applicable": 100, "needs_review": 25, "deferred": 10,
        "compensating_control": 75, "pending": 0,
    }
    for item in responses:
        status = str(item.get("response_status") or item.get("response") or "pending").lower()
        item["response_status"] = status
        item["mapping_score"] = score_map.get(status, 0)
    completed = sum(1 for item in responses if str(item.get("response_status")) not in {"", "pending"})
    question_count = max(0, int(assignment.get("question_count") or 0))
    progress = round(completed / question_count * 100, 2) if question_count else 0.0
    scored = [item["mapping_score"] for item in responses if item["response_status"] != "pending"]
    score = round(sum(scored) / len(scored), 2) if scored else 0.0
    status_counts = dict(Counter(item["response_status"] for item in responses))
    report = {
        "id": assignment_id,
        "assessment_name": assignment.get("assessment_name") or assignment.get("questionnaire_name") or "SECUMAT audit",
        "questionnaire": assignment.get("questionnaire_name") or assignment.get("assessment_name"),
        "status": assignment.get("status") or "pending",
        "question_count": question_count,
        "total_questions": question_count,
        "completed_responses": completed,
        "progress_percent": progress,
        "compliance_score": score,
        "reviewer_score": assignment.get("reviewer_score", 0),
        "reviewer_comments": assignment.get("reviewer_comments", ""),
        "reviewer_notes": assignment.get("reviewer_notes", ""),
        "reviewed_by": assignment.get("reviewed_by"),
        "reviewed_at": assignment.get("reviewed_at"),
        "status_breakdown": status_counts,
        "assigned_to": assignment.get("assigned_to", ""),
        "assigned_to_type": assignment.get("assigned_to_type"),
        "assignment_date": assignment.get("assignment_date"),
        "framework": assignment.get("framework", ""),
    }
    return {"assignment": report, "report": report, "responses": responses, "status_counts": status_counts, "compliance_score": score, "progress_percent": progress, "source": "local-module-store"}


def audit_results_analytics_payload():
    with MODULE_DATA_LOCK:
        modules = module_store_payload()["modules"]
        assignments = list(modules["audit_assignments"])
        responses = list(modules["audit_responses"])
        versions = list(modules["audit_workbook_versions"])
    latest = {}
    for revision in versions:
        audit_id = revision.get("audit_id")
        if audit_id and (audit_id not in latest or revision.get("version", 0) > latest[audit_id].get("version", 0)):
            latest[audit_id] = revision
    status_counts = Counter()
    finding_counts = Counter()
    framework_counts = Counter()
    timeline = {}
    rows = []
    reviewed_scores = []
    today = datetime.now(timezone.utc).date().isoformat()

    def day_record(value):
        day = str(value or "")[:10]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            return None
        return timeline.setdefault(day, {"date": day, "assigned": 0, "submitted": 0, "reviewed": 0, "reviewedScores": []})

    responses_by_assignment = {}
    for response in responses:
        responses_by_assignment.setdefault(str(response.get("assignment_id")), []).append(response)
    for assignment in assignments:
        status = str(assignment.get("status") or "pending").lower()
        status_counts[status] += 1
        framework = str(assignment.get("framework") or "Unspecified")
        framework_counts[framework] += 1
        total = max(0, int(assignment.get("question_count") or 0))
        complete = min(total, max(0, int(assignment.get("completed_responses") or 0)))
        reviewed = bool(assignment.get("reviewed_at"))
        score = assignment.get("reviewer_score") if reviewed else None
        if reviewed and isinstance(score, (int, float)):
            reviewed_scores.append(float(score))
        overdue = bool(assignment.get("due_date") and str(assignment["due_date"])[:10] < today and status not in {"completed", "closed", "cancelled"})
        revision = latest.get(assignment.get("workbook_audit_id"))
        if revision:
            for rated_rows in revision.get("ratings", {}).values():
                finding_counts.update(entry.get("rating") or "pending" for entry in rated_rows.values())
            if revision.get("status") == "submitted":
                event = day_record(revision.get("updated_at"))
                if event:
                    event["submitted"] += 1
        else:
            finding_counts.update(str(item.get("response_status") or "pending") for item in responses_by_assignment.get(str(assignment.get("id")), []))
        event = day_record(assignment.get("assignment_date") or assignment.get("created_at"))
        if event:
            event["assigned"] += 1
        if reviewed:
            event = day_record(assignment.get("reviewed_at"))
            if event:
                event["reviewed"] += 1
                if isinstance(score, (int, float)):
                    event["reviewedScores"].append(float(score))
        rows.append({"id": assignment.get("id"), "name": assignment.get("assessment_name") or assignment.get("questionnaire_name"),
                     "framework": framework, "assignedTo": assignment.get("assigned_to"), "status": status,
                     "total": total, "completed": complete, "pending": total - complete,
                     "progressPercent": round(complete / total * 100, 2) if total else 0,
                     "overdue": overdue, "editedBy": assignment.get("edited_by"),
                     "reviewedBy": assignment.get("reviewed_by"), "reviewedAt": assignment.get("reviewed_at"),
                     "reviewerScore": score, "dueDate": assignment.get("due_date"),
                     "assignedAt": assignment.get("assignment_date") or assignment.get("created_at")})
    trends = [{"date": day, "assigned": event["assigned"], "submitted": event["submitted"],
               "reviewed": event["reviewed"], "averageReviewedScore": round(sum(event["reviewedScores"]) / len(event["reviewedScores"]), 2) if event["reviewedScores"] else None}
              for day, event in sorted(timeline.items())]
    return {"source": "local-audit-store", "updatedAt": datetime.now(timezone.utc).isoformat(),
            "summary": {"total": len(rows), "awaitingReview": status_counts["submitted"],
                        "reviewed": sum(bool(row["reviewedAt"]) for row in rows),
                        "overdue": sum(row["overdue"] for row in rows),
                        "pendingItems": sum(row["pending"] for row in rows),
                        "completionPercent": round(sum(row["completed"] for row in rows) / sum(row["total"] for row in rows) * 100, 2) if sum(row["total"] for row in rows) else None,
                        "averageReviewedScore": round(sum(reviewed_scores) / len(reviewed_scores), 2) if reviewed_scores else None},
            "statuses": dict(status_counts), "findings": dict(finding_counts),
            "frameworks": [{"name": name, "count": count} for name, count in framework_counts.most_common()],
            "trends": trends, "assignments": rows}


def safe_audit_csv_cell(value):
    return f"'{value}" if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value


def normalize_network_indicator(kind, value):
    kind = str(kind or "").strip().lower()
    value = str(value or "").strip()
    if not value or len(value) > 4096 or "\x00" in value:
        raise ValueError("Indicator is required and must be at most 4096 characters")
    if kind == "domain":
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses belong in the IP list, not the domain list")
        labels = domain.split(".")
        if len(domain) > 253 or any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            raise ValueError("Enter a valid domain name")
        return domain
    if kind == "url":
        parsed = urlparse(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL indicators must use HTTP/HTTPS and must not include credentials")
        return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
    if kind == "sha256":
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", value):
            raise ValueError("SHA-256 indicators must contain exactly 64 hexadecimal characters")
        return value.lower()
    if kind == "file_path":
        is_windows_absolute = bool(re.match(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)", value))
        if not value.startswith("/") and not is_windows_absolute:
            raise ValueError("File path indicators must be absolute Windows or POSIX paths")
        return value
    raise ValueError("Indicator type must be domain, url, sha256, or file_path")


def update_network_indicators(payload):
    if not isinstance(payload, dict):
        raise ValueError("Indicator request must be a JSON object")
    list_name = payload.get("list")
    action = payload.get("action")
    kind = payload.get("kind")
    reason = str(payload.get("reason") or "").strip()
    raw_values = payload.get("values", payload.get("value", []))
    if isinstance(raw_values, str):
        raw_values = [line.strip() for line in re.split(r"[\r\n,]+", raw_values) if line.strip()]
    if list_name not in ("blacklist", "whitelist") or action not in ("add", "remove"):
        raise ValueError("Choose a whitelist or blacklist and an add or remove action")
    if not isinstance(raw_values, list) or not raw_values:
        raise ValueError("Provide one or more indicators")
    normalized = list(dict.fromkeys(normalize_network_indicator(kind, value) for value in raw_values))
    if action == "add" and (len(reason) < 3 or len(reason) > 500):
        raise ValueError("Reason is required and must be between 3 and 500 characters")
    with snort_blacklist_lock:
        entries = read_json_store(SNORT_INDICATORS_FILE, [])
        key = lambda entry: (entry.get("list"), entry.get("kind"), entry.get("value"))
        requested = {(list_name, kind, value) for value in normalized}
        if action == "add":
            current = {key(entry): entry for entry in entries if isinstance(entry, dict)}
            for value in normalized:
                identity = (list_name, kind, value)
                current[identity] = {
                    "list": list_name,
                    "kind": kind,
                    "value": value,
                    "reason": reason,
                    "addedAt": datetime.now(timezone.utc).isoformat(),
                }
            entries = sorted(current.values(), key=lambda entry: (entry["list"], entry["kind"], entry["value"]))
        else:
            entries = [entry for entry in entries if key(entry) not in requested]
        write_json_store(SNORT_INDICATORS_FILE, entries)
    return {"list": list_name, "kind": kind, "action": action, "total": len(entries), "entries": entries}


def classify_observed_ip(address, whitelist, blacklist):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return {"address": address, "status": "invalid", "matchedBy": []}
    matches = {
        name: [entry for entry in entries if parsed in ipaddress.ip_network(entry, strict=False)]
        for name, entries in (("whitelist", whitelist), ("blacklist", blacklist))
    }
    matched = [name for name, entries in matches.items() if entries]
    status = "conflict" if len(matched) == 2 else {"whitelist": "whitelisted", "blacklist": "blacklisted"}.get(matched[0], "unlisted") if matched else "unlisted"
    return {"address": str(parsed), "status": status, "matchedBy": [entry for entries in matches.values() for entry in entries]}


def public_feed_payload():
    now = time.time()
    if feed_cache["payload"] and feed_cache["expires"] > now:
        return feed_cache["payload"]
    results = {}
    errors = {}
    with ThreadPoolExecutor(max_workers=len(PUBLIC_FEEDS) + 1) as pool:
        futures = {name: pool.submit(fetch_json, url) for name, url in PUBLIC_FEEDS.items()}
        futures["dotnet"] = pool.submit(fetch_dotnet_security_feed)
        for name, future in futures.items():
            try:
                results[name] = future.result()
            except Exception as error:
                errors[name] = str(error)

    cisa = results.get("cisa", {})
    msrc = results.get("msrc", {})
    nvd = results.get("nvd", {})
    msrc_items = sorted(msrc.get("value", []), key=lambda item: item.get("CurrentReleaseDate", ""), reverse=True)

    feodo_raw = results.get("feodo", [])
    feodo_items = sorted(
        (item for item in (feodo_raw if isinstance(feodo_raw, list) else []) if isinstance(item, dict)),
        key=lambda item: item.get("first_seen_utc") or "",
        reverse=True,
    )
    epss_raw = results.get("epss", {})
    epss_items = sorted(
        (item for item in (epss_raw.get("data") or []) if isinstance(item, dict)),
        key=lambda item: float(item.get("epss") or 0),
        reverse=True,
    )
    circl_raw = results.get("circl", [])
    circl_items = [item for item in (circl_raw if isinstance(circl_raw, list) else []) if isinstance(item, dict)]

    payload = {
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "cacheSeconds": 900,
        "sources": [
            {"id": "cisa", "name": "CISA KEV", "status": "live" if "cisa" in results else "error", "count": cisa.get("count", 0), "updated": cisa.get("dateReleased"), "error": errors.get("cisa")},
            {"id": "nvd", "name": "NIST NVD", "status": "live" if "nvd" in results else "error", "count": nvd.get("totalResults", 0), "updated": nvd.get("timestamp"), "error": errors.get("nvd")},
            {"id": "msrc", "name": "Microsoft MSRC", "status": "live" if "msrc" in results else "error", "count": len(msrc.get("value", [])), "updated": msrc_items[0].get("CurrentReleaseDate") if msrc_items else None, "error": errors.get("msrc")},
            {"id": "feodo", "name": "Feodo Tracker C2", "status": "live" if "feodo" in results else "error", "count": len(feodo_items), "updated": feodo_items[0].get("first_seen_utc") if feodo_items else None, "error": errors.get("feodo")},
            {"id": "epss", "name": "FIRST EPSS", "status": "live" if "epss" in results else "error", "count": int(epss_raw.get("total") or len(epss_items)), "updated": epss_raw.get("status-code") and epss_items[0].get("date") if epss_items else None, "error": errors.get("epss")},
            {"id": "circl", "name": "CIRCL CVE-Search", "status": "live" if "circl" in results else "error", "count": len(circl_items), "updated": circl_items[0].get("Published") if circl_items else None, "error": errors.get("circl")},
            {"id": "dotnet", "name": ".NET Security Updates", "status": "live" if "dotnet" in results else "error", "count": len(results.get("dotnet", [])), "updated": results["dotnet"][0]["published"] if results.get("dotnet") else None, "error": errors.get("dotnet")},
        ],
        "latest": {
            "cisa": cisa.get("vulnerabilities", [])[:8],
            "nvd": [item.get("cve", {}) for item in nvd.get("vulnerabilities", [])[:5]],
            "msrc": msrc_items[:8],
            "feodo": feodo_items[:8],
            "epss": epss_items[:8],
            "circl": circl_items[:8],
            "dotnet": results.get("dotnet", []),
            "pinned": PINNED_ADVISORIES,
        },
    }
    feed_cache.update({"expires": now + 900, "payload": payload})
    return payload


intel_index_cache = {"expires": 0, "payload": None}
intel_index_lock = threading.Lock()

MAX_CORRELATE_ITEMS = 2000
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def build_intel_match_index():
    """Full-catalogue index of the open threat feeds used for correlation.

    public_feed_payload only exposes the newest handful of rows for display.
    Correlation needs every CISA KEV CVE and every Feodo C2 address, so this is
    fetched and cached separately.
    """
    now = time.time()
    with intel_index_lock:
        if intel_index_cache["payload"] and intel_index_cache["expires"] > now:
            return intel_index_cache["payload"]

    kev = {}
    c2 = {}
    errors = {}
    try:
        catalogue = fetch_json(PUBLIC_FEEDS["cisa"])
        for row in catalogue.get("vulnerabilities", []) or []:
            cve = str(row.get("cveID") or "").strip().upper()
            if cve:
                kev[cve] = {
                    "cve": cve,
                    "vendor": row.get("vendorProject"),
                    "product": row.get("product"),
                    "name": row.get("vulnerabilityName"),
                    "dateAdded": row.get("dateAdded"),
                    "dueDate": row.get("dueDate"),
                    "knownRansomware": str(row.get("knownRansomwareCampaignUse") or "").lower() == "known",
                }
    except Exception as error:
        errors["cisa"] = str(error)

    try:
        blocklist = fetch_json(PUBLIC_FEEDS["feodo"])
        for row in blocklist if isinstance(blocklist, list) else []:
            if not isinstance(row, dict):
                continue
            address = str(row.get("ip_address") or "").strip()
            if address:
                c2[address] = {
                    "ip": address,
                    "malware": row.get("malware"),
                    "port": row.get("port"),
                    "firstSeen": row.get("first_seen_utc"),
                    "lastOnline": row.get("last_online"),
                    "status": row.get("status"),
                }
    except Exception as error:
        errors["feodo"] = str(error)

    payload = {
        "kev": kev,
        "c2": c2,
        "errors": errors,
        "builtAt": datetime.now(timezone.utc).isoformat(),
    }
    with intel_index_lock:
        intel_index_cache.update({"expires": now + 900, "payload": payload})
    return payload


def fetch_epss_scores(cves):
    """Look up EPSS exploit-probability scores for specific CVEs."""
    scores = {}
    ordered = sorted(cves)
    for start in range(0, len(ordered), 100):
        batch = ordered[start:start + 100]
        url = f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(','.join(batch), safe=',')}"
        try:
            for row in (fetch_json(url).get("data") or []):
                cve = str(row.get("cve") or "").upper()
                if cve:
                    scores[cve] = {"epss": float(row.get("epss") or 0), "percentile": float(row.get("percentile") or 0)}
        except Exception:
            continue
    return scores


def intel_correlation_payload(request_body):
    """Match live asset CVEs and observed IPs against the open threat feeds."""
    if not isinstance(request_body, dict):
        raise ValueError("Correlation request must be a JSON object")

    raw_cves = request_body.get("cves") or []
    raw_ips = request_body.get("ips") or []
    if not isinstance(raw_cves, list) or not isinstance(raw_ips, list):
        raise ValueError("cves and ips must be arrays")
    if len(raw_cves) > MAX_CORRELATE_ITEMS or len(raw_ips) > MAX_CORRELATE_ITEMS:
        raise ValueError(f"At most {MAX_CORRELATE_ITEMS} cves and {MAX_CORRELATE_ITEMS} ips may be correlated per request")

    cves = {str(value).strip().upper() for value in raw_cves if CVE_PATTERN.match(str(value).strip())}
    ips = set()
    for value in raw_ips:
        try:
            ips.add(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue

    index = build_intel_match_index()
    kev_hits = [dict(index["kev"][cve]) for cve in sorted(cves) if cve in index["kev"]]
    if kev_hits:
        scores = fetch_epss_scores({hit["cve"] for hit in kev_hits})
        for hit in kev_hits:
            hit["epss"] = scores.get(hit["cve"], {}).get("epss")
            hit["epssPercentile"] = scores.get(hit["cve"], {}).get("percentile")
        kev_hits.sort(key=lambda hit: (hit.get("epss") or 0, hit.get("knownRansomware")), reverse=True)

    c2_hits = [dict(index["c2"][address]) for address in sorted(ips) if address in index["c2"]]

    return {
        "builtAt": index["builtAt"],
        "feedErrors": index["errors"],
        "submitted": {"cves": len(cves), "ips": len(ips)},
        "catalogue": {"kev": len(index["kev"]), "c2": len(index["c2"])},
        "summary": {
            "kevMatches": len(kev_hits),
            "ransomwareLinked": sum(1 for hit in kev_hits if hit.get("knownRansomware")),
            "c2Matches": len(c2_hits),
        },
        "kevMatches": kev_hits[:500],
        "c2Matches": c2_hits[:500],
    }


# ---------------------------------------------------------------------------
# OSINT Navigator
#
# A technique catalogue organised by the evidence an investigator starts with,
# rather than a directory of third-party sites. Each entry records the inputs
# it consumes, the outputs it produces, the access tier it normally requires,
# and whether this platform can run the step locally. Entries marked
# "local" execute here; every other entry is a documented manual procedure and
# is explicitly not an automated lookup.
# ---------------------------------------------------------------------------

OSINT_ACCESS_TIERS = ("local", "free", "registration", "paid")
OSINT_INPUT_TYPES = (
    "ip", "domain", "url", "email", "username", "person", "company",
    "hash", "cve", "phone", "crypto_address", "image", "document", "coordinates",
)

OSINT_CATEGORIES = (
    {"id": "people-identity", "name": "People and identity research", "summary": "Resolve a person, alias, or account across public identity surfaces."},
    {"id": "domain-infrastructure", "name": "Domain and infrastructure intelligence", "summary": "Map naming, certificate, routing, and hosting evidence for an estate."},
    {"id": "threat-intelligence", "name": "Threat intelligence and security", "summary": "Qualify an indicator against malicious-activity and exposure evidence."},
    {"id": "email-investigation", "name": "Email investigation", "summary": "Validate, expand, and attribute email addresses and message headers."},
    {"id": "media-verification", "name": "Media and information verification", "summary": "Test whether an image, video, or document is authentic and original."},
    {"id": "geolocation-physical", "name": "Geolocation and physical-world research", "summary": "Place an entity in a physical location or corporate registry."},
    {"id": "specialised-osint", "name": "Specialised OSINT", "summary": "Blockchain, dark web, mobile, and community-sourced collection."},
    {"id": "investigation-support", "name": "Investigation support", "summary": "Capture, decode, and preserve evidence to an auditable standard."},
)
OSINT_CATEGORY_IDS = {category["id"] for category in OSINT_CATEGORIES}

OSINT_TECHNIQUES = (
    # --- people and identity -------------------------------------------------
    {"id": "people-search-aggregation", "category": "people-identity", "subcategory": "People search", "name": "Public records aggregation",
     "description": "Collate electoral, directory, and civil-record mentions for a named person to establish candidate identities before deeper work.",
     "inputs": ["person"], "outputs": ["aliases", "locations", "associates"], "access": "registration", "local": False,
     "useCase": "Confirm an insider-threat subject is the same person named in an HR referral."},
    {"id": "username-enumeration", "category": "people-identity", "subcategory": "Usernames", "name": "Username reuse enumeration",
     "description": "Test a handle across public account namespaces to find reused identities that link separate personas.",
     "inputs": ["username"], "outputs": ["accounts", "aliases"], "access": "free", "local": False,
     "useCase": "Pivot from a leaked forum handle to other accounts operated by the same actor."},
    {"id": "social-graph-mapping", "category": "people-identity", "subcategory": "Social networks", "name": "Social relationship mapping",
     "description": "Record publicly visible connections and interaction patterns to infer an actor's working relationships.",
     "inputs": ["username", "person"], "outputs": ["associates", "timeline"], "access": "registration", "local": False,
     "useCase": "Establish whether a supplier contact is connected to a known fraud network."},
    {"id": "telephone-attribution", "category": "people-identity", "subcategory": "Telephone numbers", "name": "Telephone number attribution",
     "description": "Resolve a number to its country, carrier type, and public business or directory listings.",
     "inputs": ["phone"], "outputs": ["carrier", "locations", "company"], "access": "free", "local": False,
     "useCase": "Qualify the callback number used in a vishing attempt against plant operations."},
    {"id": "breach-exposure-review", "category": "people-identity", "subcategory": "Breach data", "name": "Credential exposure review",
     "description": "Determine whether an identity appears in previously disclosed breach corpora, and which attributes were exposed.",
     "inputs": ["email", "username"], "outputs": ["exposure", "timeline"], "access": "registration", "local": False,
     "useCase": "Decide whether a privileged OT account needs a forced credential rotation."},

    # --- domain and infrastructure ------------------------------------------
    {"id": "whois-registration", "category": "domain-infrastructure", "subcategory": "WHOIS and registration", "name": "Registration record review",
     "description": "Read registrar, creation, and contact history for a domain to judge age and ownership stability.",
     "inputs": ["domain"], "outputs": ["registrant", "timeline"], "access": "free", "local": False,
     "useCase": "Flag a newly registered lookalike domain impersonating the plant portal."},
    {"id": "subdomain-discovery", "category": "domain-infrastructure", "subcategory": "Subdomains", "name": "Subdomain discovery",
     "description": "Enumerate published hostnames for a parent domain to reveal unmanaged or forgotten estate.",
     "inputs": ["domain"], "outputs": ["hostnames", "infrastructure"], "access": "free", "local": False,
     "useCase": "Find an exposed engineering interface outside the sanctioned asset register."},
    {"id": "certificate-transparency", "category": "domain-infrastructure", "subcategory": "Certificate search", "name": "Certificate transparency search",
     "description": "Search issued-certificate logs for names covering a domain, exposing hosts that never appeared in DNS answers.",
     "inputs": ["domain"], "outputs": ["hostnames", "timeline"], "access": "free", "local": False,
     "useCase": "Detect a certificate issued for a subdomain nobody in operations recognises."},
    {"id": "passive-dns-history", "category": "domain-infrastructure", "subcategory": "PassiveDNS", "name": "Passive DNS history",
     "description": "Review historic name-to-address mappings to show infrastructure reuse and rotation behaviour.",
     "inputs": ["domain", "ip"], "outputs": ["infrastructure", "timeline"], "access": "registration", "local": False,
     "useCase": "Show that a phishing domain reuses hosting previously tied to a known campaign."},
    {"id": "dnssec-posture", "category": "domain-infrastructure", "subcategory": "DNSSEC", "name": "DNSSEC validation posture",
     "description": "Check whether a zone is signed and validating, establishing exposure to response spoofing.",
     "inputs": ["domain"], "outputs": ["posture"], "access": "free", "local": False,
     "useCase": "Record DNS integrity posture for a Zero Trust network control review."},
    {"id": "ip-ownership", "category": "domain-infrastructure", "subcategory": "IP and MAC addresses", "name": "Address allocation and ownership",
     "description": "Resolve an address to its allocation, autonomous system, and responsible operator.",
     "inputs": ["ip"], "outputs": ["owner", "asn", "locations"], "access": "free", "local": False,
     "useCase": "Decide whether outbound OT traffic is leaving for an expected provider network."},
    {"id": "cloud-surface-review", "category": "domain-infrastructure", "subcategory": "Cloud infrastructure", "name": "Cloud tenancy surface review",
     "description": "Identify publicly reachable storage, API, and workload endpoints associated with an organisation.",
     "inputs": ["domain", "company"], "outputs": ["infrastructure", "exposure"], "access": "free", "local": False,
     "useCase": "Locate an unsecured bucket holding historian exports."},
    {"id": "domain-reputation-local", "category": "domain-infrastructure", "subcategory": "Domain reputation", "name": "Local domain reputation lookup",
     "description": "Check a domain against the locally indexed malicious-domain partitions held by this platform.",
     "inputs": ["domain"], "outputs": ["verdict", "sources"], "access": "local", "local": True,
     "linkedModule": "threat_intel", "apiRoute": "/api/osint/pivot",
     "useCase": "Qualify a domain seen in proxy logs without sending the name to a third party."},
    {"id": "blocklist-membership-local", "category": "domain-infrastructure", "subcategory": "Blacklists", "name": "Local blocklist membership",
     "description": "Check an address against the locally indexed malicious-IP partitions held by this platform.",
     "inputs": ["ip"], "outputs": ["verdict", "sources"], "access": "local", "local": True,
     "linkedModule": "threat_intel", "apiRoute": "/api/osint/pivot",
     "useCase": "Confirm whether a scanning source is already catalogued as malicious."},

    # --- threat intelligence -------------------------------------------------
    {"id": "indicator-feed-correlation", "category": "threat-intelligence", "subcategory": "Cyber threat intelligence", "name": "Indicator feed correlation",
     "description": "Match an observable against every locally indexed indicator partition and report which feeds carry it.",
     "inputs": ["ip", "domain", "hash"], "outputs": ["verdict", "sources"], "access": "local", "local": True,
     "linkedModule": "threat_intel", "apiRoute": "/api/osint/pivot",
     "useCase": "Triage an alert indicator against all loaded feeds in one step."},
    {"id": "kev-exposure-check", "category": "threat-intelligence", "subcategory": "Vulnerabilities", "name": "Known-exploited exposure check",
     "description": "Test a CVE against the known-exploited catalogue and exploit-prediction scoring held by this platform.",
     "inputs": ["cve"], "outputs": ["exploitation", "priority"], "access": "local", "local": True,
     "linkedModule": "vulnerabilities", "apiRoute": "/api/osint/pivot",
     "useCase": "Decide whether a plant-floor CVE warrants an emergency change window."},
    {"id": "c2-infrastructure-match", "category": "threat-intelligence", "subcategory": "Cyber threat intelligence", "name": "Command-and-control match",
     "description": "Compare an address against tracked command-and-control infrastructure recorded locally.",
     "inputs": ["ip"], "outputs": ["verdict", "campaign"], "access": "local", "local": True,
     "linkedModule": "threat_intel", "apiRoute": "/api/osint/pivot",
     "useCase": "Establish whether an egress destination is a tracked controller."},
    {"id": "local-event-pivot", "category": "threat-intelligence", "subcategory": "Cyber threat intelligence", "name": "Local event sighting pivot",
     "description": "Search stored canonical events and module records for prior sightings of the same observable.",
     "inputs": ["ip", "domain", "hash", "email", "username", "url"], "outputs": ["sightings", "timeline", "devices"],
     "access": "local", "local": True, "linkedModule": "integrations", "apiRoute": "/api/osint/pivot",
     "useCase": "Determine whether an indicator has been seen before in this estate and on which devices."},
    {"id": "malicious-file-triage", "category": "threat-intelligence", "subcategory": "Malicious file analysis", "name": "Malicious file triage",
     "description": "Characterise a sample by hash reputation, declared capability, and observed behaviour before escalating.",
     "inputs": ["hash"], "outputs": ["verdict", "behaviour"], "access": "free", "local": False,
     "useCase": "Decide whether a quarantined engineering-workstation binary needs full analysis."},
    {"id": "malicious-site-assessment", "category": "threat-intelligence", "subcategory": "Malicious sites", "name": "Suspicious site assessment",
     "description": "Examine page content, redirect chains, and hosting without visiting the site from a production endpoint.",
     "inputs": ["url", "domain"], "outputs": ["verdict", "infrastructure"], "access": "free", "local": False,
     "useCase": "Safely evaluate a link reported by an operator."},
    {"id": "opsec-collection-hygiene", "category": "threat-intelligence", "subcategory": "OpSec", "name": "Collection operational security",
     "description": "Separate attribution, network path, and account identity so that collection does not disclose the investigation.",
     "inputs": [], "outputs": ["procedure"], "access": "free", "local": False,
     "useCase": "Avoid alerting an actor while researching their infrastructure."},

    # --- email investigation -------------------------------------------------
    {"id": "email-deliverability-validation", "category": "email-investigation", "subcategory": "Email verification", "name": "Address validity check",
     "description": "Establish whether an address is routable and whether its domain accepts mail, without sending a message.",
     "inputs": ["email"], "outputs": ["validity", "infrastructure"], "access": "free", "local": False,
     "useCase": "Test whether a supplier invoice address is a real mailbox."},
    {"id": "email-format-inference", "category": "email-investigation", "subcategory": "Common email formats", "name": "Address convention inference",
     "description": "Infer an organisation's address pattern from known examples to predict and verify further addresses.",
     "inputs": ["company", "domain"], "outputs": ["pattern"], "access": "free", "local": False,
     "useCase": "Judge whether a sender address is plausible for the claimed organisation."},
    {"id": "mail-header-analysis", "category": "email-investigation", "subcategory": "Email search", "name": "Message header analysis",
     "description": "Read received chains, authentication results, and originating infrastructure from raw headers.",
     "inputs": ["document"], "outputs": ["infrastructure", "authentication", "timeline"], "access": "free", "local": False,
     "useCase": "Prove a payment-redirect message did not originate from the supplier's tenancy."},
    {"id": "mail-domain-authentication", "category": "email-investigation", "subcategory": "Mail blacklists", "name": "Sending-domain authentication posture",
     "description": "Review published sender-authentication and alignment policy for a domain to judge spoofability.",
     "inputs": ["domain"], "outputs": ["posture"], "access": "free", "local": False,
     "useCase": "Explain why a spoofed message passed perimeter checks."},

    # --- media verification --------------------------------------------------
    {"id": "reverse-image-provenance", "category": "media-verification", "subcategory": "Images and video", "name": "Reverse image provenance",
     "description": "Find earlier publications of an image to establish first appearance and original context.",
     "inputs": ["image"], "outputs": ["provenance", "timeline"], "access": "free", "local": False,
     "useCase": "Test whether a claimed breach screenshot is recycled from an older incident."},
    {"id": "media-metadata-extraction", "category": "media-verification", "subcategory": "Documents", "name": "Embedded metadata extraction",
     "description": "Read embedded capture, authoring, and revision metadata, recognising that it is trivially editable.",
     "inputs": ["image", "document"], "outputs": ["metadata", "timeline", "coordinates"], "access": "free", "local": False,
     "useCase": "Recover authoring details from a document attached to a suspicious message."},
    {"id": "manipulation-assessment", "category": "media-verification", "subcategory": "Disinformation", "name": "Manipulation assessment",
     "description": "Test an asset for editing, generation, or recompression artefacts, reporting confidence rather than a verdict.",
     "inputs": ["image", "document"], "outputs": ["assessment"], "access": "free", "local": False,
     "useCase": "Assess a video purporting to show a physical plant intrusion."},
    {"id": "archive-retrieval", "category": "media-verification", "subcategory": "Archives", "name": "Historic page retrieval",
     "description": "Retrieve previous states of a page to recover content removed after disclosure.",
     "inputs": ["url", "domain"], "outputs": ["provenance", "timeline"], "access": "free", "local": False,
     "useCase": "Recover a leak-site listing that has since been deleted."},
    {"id": "change-detection", "category": "media-verification", "subcategory": "Change detection", "name": "Monitored change detection",
     "description": "Record a baseline of a public page and detect subsequent modification over time.",
     "inputs": ["url"], "outputs": ["timeline"], "access": "free", "local": False,
     "useCase": "Watch a leak site for the appearance of the organisation's name."},

    # --- geolocation and physical -------------------------------------------
    {"id": "imagery-geolocation", "category": "geolocation-physical", "subcategory": "Geolocation and maps", "name": "Imagery geolocation",
     "description": "Place imagery using terrain, signage, shadow, and structural features rather than relying on metadata.",
     "inputs": ["image"], "outputs": ["coordinates", "locations"], "access": "free", "local": False,
     "useCase": "Locate a photograph taken inside a restricted plant area."},
    {"id": "corporate-registry-research", "category": "geolocation-physical", "subcategory": "Business records", "name": "Corporate registry research",
     "description": "Retrieve filings, officers, and ownership structure from statutory registers.",
     "inputs": ["company"], "outputs": ["officers", "ownership", "locations"], "access": "free", "local": False,
     "useCase": "Verify that a new OT supplier is a trading entity with filed accounts."},
    {"id": "site-perimeter-review", "category": "geolocation-physical", "subcategory": "Geolocation and maps", "name": "Site perimeter review",
     "description": "Assess publicly visible approaches, access points, and overlooks for a physical site.",
     "inputs": ["coordinates", "company"], "outputs": ["locations", "exposure"], "access": "free", "local": False,
     "useCase": "Support a physical security assessment of a substation."},
    {"id": "transport-movement-tracking", "category": "geolocation-physical", "subcategory": "Transportation", "name": "Transport movement research",
     "description": "Use published vessel, aircraft, and fleet reporting to corroborate movement claims.",
     "inputs": ["company", "coordinates"], "outputs": ["timeline", "locations"], "access": "free", "local": False,
     "useCase": "Corroborate a logistics claim made during a supplier fraud investigation."},

    # --- specialised ---------------------------------------------------------
    {"id": "blockchain-flow-tracing", "category": "specialised-osint", "subcategory": "Blockchain", "name": "Transaction flow tracing",
     "description": "Follow value between addresses on a public ledger and cluster addresses under common control.",
     "inputs": ["crypto_address"], "outputs": ["timeline", "associates", "amounts"], "access": "free", "local": False,
     "useCase": "Trace an extortion payment address presented in a ransom note."},
    {"id": "leak-site-monitoring", "category": "specialised-osint", "subcategory": "Dark Web", "name": "Leak site monitoring",
     "description": "Track extortion and marketplace listings for mentions of the organisation, its brands, or its suppliers.",
     "inputs": ["company", "domain"], "outputs": ["exposure", "timeline"], "access": "registration", "local": False,
     "useCase": "Detect a supplier compromise that exposes plant documentation."},
    {"id": "mobile-application-review", "category": "specialised-osint", "subcategory": "Mobile OSINT", "name": "Mobile application review",
     "description": "Examine published application metadata, permissions, and declared endpoints before deployment.",
     "inputs": ["company", "domain"], "outputs": ["infrastructure", "exposure"], "access": "free", "local": False,
     "useCase": "Review a vendor maintenance app requested for field engineer handsets."},
    {"id": "community-source-monitoring", "category": "specialised-osint", "subcategory": "Online communities", "name": "Community source monitoring",
     "description": "Follow technical forums and discussion groups where exposure and exploit detail commonly appear first.",
     "inputs": ["company", "domain", "cve"], "outputs": ["exposure", "timeline"], "access": "free", "local": False,
     "useCase": "Catch discussion of an unpatched controller flaw before an advisory is published."},
    {"id": "classified-listing-research", "category": "specialised-osint", "subcategory": "Classifieds", "name": "Second-hand listing research",
     "description": "Search resale listings for decommissioned equipment that may still carry configuration or credentials.",
     "inputs": ["company"], "outputs": ["exposure"], "access": "free", "local": False,
     "useCase": "Find retired plant hardware offered for sale with configuration intact."},

    # --- investigation support ----------------------------------------------
    {"id": "evidence-capture", "category": "investigation-support", "subcategory": "Documentation and evidence capture", "name": "Defensible evidence capture",
     "description": "Capture source, timestamp, hash, and collector for every artefact so findings survive challenge.",
     "inputs": ["url", "document", "image"], "outputs": ["evidence"], "access": "free", "local": False,
     "useCase": "Preserve a leak-site listing for a regulatory notification."},
    {"id": "encoding-decoding", "category": "investigation-support", "subcategory": "Encoding and decoding", "name": "Encoding and obfuscation decoding",
     "description": "Decode layered encodings in URLs, scripts, and messages to expose the underlying indicator.",
     "inputs": ["url", "document"], "outputs": ["indicators"], "access": "free", "local": False,
     "useCase": "Recover the true destination from an obfuscated phishing link."},
    {"id": "url-expansion", "category": "investigation-support", "subcategory": "URL expansion", "name": "Shortened URL expansion",
     "description": "Resolve redirect chains without executing destination content on an analyst endpoint.",
     "inputs": ["url"], "outputs": ["infrastructure", "indicators"], "access": "free", "local": False,
     "useCase": "Reveal the landing page behind a shortened link sent to operations staff."},
    {"id": "typosquat-discovery", "category": "investigation-support", "subcategory": "Typosquatting", "name": "Typosquat discovery",
     "description": "Generate and test plausible misspellings of a brand domain to find impersonation infrastructure.",
     "inputs": ["domain"], "outputs": ["hostnames", "exposure"], "access": "free", "local": False,
     "useCase": "Pre-emptively find lookalike domains targeting the corporate portal."},
    {"id": "analytics-identifier-pivot", "category": "investigation-support", "subcategory": "Analytics", "name": "Tracking identifier pivot",
     "description": "Use shared analytics or advertising identifiers to link otherwise unrelated sites to one operator.",
     "inputs": ["domain", "url"], "outputs": ["infrastructure", "associates"], "access": "free", "local": False,
     "useCase": "Link a cluster of phishing sites to a single operator."},
    {"id": "investigation-training", "category": "investigation-support", "subcategory": "Training", "name": "Analyst tradecraft development",
     "description": "Structured practice in source evaluation, hypothesis testing, and bias control for investigators.",
     "inputs": [], "outputs": ["capability"], "access": "free", "local": False,
     "useCase": "Raise consistency across a rotating OT analyst roster."},
)

OSINT_INPUT_PATTERNS = (
    ("cve", lambda value: bool(CVE_PATTERN.match(value))),
    ("email", lambda value: bool(re.fullmatch(r"[^@\s]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,24}", value, re.IGNORECASE))),
    ("url", lambda value: bool(re.match(r"^https?://", value, re.IGNORECASE))),
    ("crypto_address", lambda value: bool(re.fullmatch(r"0x[a-f0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,71}", value, re.IGNORECASE))),
    ("phone", lambda value: bool(re.fullmatch(r"\+?\d[\d\s().-]{6,18}\d", value))),
)


def detect_osint_input_type(value):
    """Classify a raw observable. Returns (type, normalised_value)."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Provide an observable to pivot on")
    if len(raw) > 512:
        raise ValueError("Observable must be 512 characters or fewer")
    for indicator_type in ("ip", "domain", "md5", "sha1", "sha256"):
        normalised = normalize_feed_indicator(raw, indicator_type)
        if normalised:
            return ("hash" if indicator_type in {"md5", "sha1", "sha256"} else indicator_type), normalised
    for input_type, matches in OSINT_INPUT_PATTERNS:
        if matches(raw):
            return input_type, raw.casefold() if input_type in {"email", "url"} else raw
    if re.fullmatch(r"[A-Za-z0-9._-]{3,64}", raw):
        return "username", raw
    return "person", raw


def osint_technique_view(technique):
    category = next((item for item in OSINT_CATEGORIES if item["id"] == technique["category"]), None)
    return {
        "id": technique["id"],
        "name": technique["name"],
        "category": technique["category"],
        "categoryName": category["name"] if category else technique["category"],
        "subcategory": technique["subcategory"],
        "description": technique["description"],
        "inputs": list(technique["inputs"]),
        "outputs": list(technique["outputs"]),
        "access": technique["access"],
        "runsLocally": bool(technique.get("local")),
        "linkedModule": technique.get("linkedModule", ""),
        "apiRoute": technique.get("apiRoute", ""),
        "useCase": technique.get("useCase", ""),
    }


def osint_framework_payload():
    techniques = [osint_technique_view(item) for item in OSINT_TECHNIQUES]
    categories = []
    for category in OSINT_CATEGORIES:
        members = [item for item in techniques if item["category"] == category["id"]]
        subcategories = []
        for name in dict.fromkeys(item["subcategory"] for item in members):
            subcategories.append({
                "name": name,
                "techniqueCount": sum(1 for item in members if item["subcategory"] == name),
            })
        categories.append({
            **category,
            "techniqueCount": len(members),
            "localTechniqueCount": sum(1 for item in members if item["runsLocally"]),
            "subcategories": subcategories,
        })
    return {
        "categories": categories,
        "techniques": techniques,
        "inputTypes": list(OSINT_INPUT_TYPES),
        "accessTiers": list(OSINT_ACCESS_TIERS),
        "summary": {
            "categories": len(categories),
            "techniques": len(techniques),
            "runsLocally": sum(1 for item in techniques if item["runsLocally"]),
            "manualProcedures": sum(1 for item in techniques if not item["runsLocally"]),
        },
        "method": (
            "Techniques are organised by the evidence an investigation starts with. Entries marked as running "
            "locally execute against this platform's own indexes; all other entries are documented manual "
            "procedures and perform no automated lookup."
        ),
        "source": "local-osint-catalogue",
    }


def osint_search_payload(query_text="", category="", input_type="", access=""):
    term = str(query_text or "").strip().casefold()[:200]
    category = str(category or "").strip().casefold()
    input_type = str(input_type or "").strip().casefold()
    access = str(access or "").strip().casefold()
    if category and category not in OSINT_CATEGORY_IDS:
        raise ValueError(f"Unknown category: {category}")
    if input_type and input_type not in OSINT_INPUT_TYPES:
        raise ValueError(f"Unknown input type: {input_type}")
    if access and access not in OSINT_ACCESS_TIERS:
        raise ValueError(f"Unknown access tier: {access}")

    results = []
    for technique in (osint_technique_view(item) for item in OSINT_TECHNIQUES):
        if category and technique["category"] != category:
            continue
        if input_type and input_type not in technique["inputs"]:
            continue
        if access and technique["access"] != access:
            continue
        if term:
            haystack = " ".join([
                technique["name"], technique["description"], technique["subcategory"],
                technique["categoryName"], technique["useCase"],
                " ".join(technique["inputs"]), " ".join(technique["outputs"]),
            ]).casefold()
            if term not in haystack:
                continue
        results.append(technique)
    return {
        "query": str(query_text or "").strip()[:200],
        "filters": {"category": category, "input": input_type, "access": access},
        "count": len(results),
        "techniques": results,
        "source": "local-osint-catalogue",
    }


def osint_pivot_payload(request_body):
    """Classify an observable, list applicable techniques, and run the local ones."""
    if not isinstance(request_body, dict):
        raise ValueError("Pivot request must be a JSON object")
    input_type, value = detect_osint_input_type(request_body.get("value"))

    techniques = [
        technique for technique in (osint_technique_view(item) for item in OSINT_TECHNIQUES)
        if input_type in technique["inputs"]
    ]

    enrichment = []
    errors = []

    if input_type in {"ip", "domain", "hash"}:
        try:
            match = lookup_threat_indicators(value)
            enrichment.append({
                "technique": "indicator-feed-correlation",
                "name": "Indicator feed correlation",
                "matched": match["matched"],
                "detail": (
                    f"Present in {len(match['sources'])} locally indexed feed partition(s)."
                    if match["matched"] else "Not present in any locally indexed feed partition."
                ),
                "sources": match["sources"],
            })
        except (ValueError, OSError, sqlite3.Error) as error:
            errors.append(f"Threat feed index unavailable: {error}")

    if input_type == "cve":
        try:
            correlation = intel_correlation_payload({"cves": [value], "ips": []})
            hits = correlation.get("kevMatches", [])
            enrichment.append({
                "technique": "kev-exposure-check",
                "name": "Known-exploited exposure check",
                "matched": bool(hits),
                "detail": (
                    "Listed in the known-exploited catalogue." if hits
                    else "Not listed in the known-exploited catalogue; this does not mean it is unexploitable."
                ),
                "sources": hits[:5],
            })
        except (ValueError, OSError, RuntimeError) as error:
            errors.append(f"Vulnerability correlation unavailable: {error}")

    try:
        sightings = siem_event_search_payload(value, 25)
        enrichment.append({
            "technique": "local-event-pivot",
            "name": "Local event sighting pivot",
            "matched": bool(sightings["count"]),
            "detail": (
                f"{sightings['count']} stored local record(s) reference this observable."
                if sightings["count"] else "No stored local record references this observable."
            ),
            "records": sightings["records"][:10],
        })
    except (ValueError, OSError, sqlite3.Error, RuntimeError) as error:
        errors.append(f"Local event search unavailable: {error}")

    return {
        "observable": value,
        "inputType": input_type,
        "techniques": techniques,
        "techniqueCount": len(techniques),
        "enrichment": enrichment,
        "errors": errors,
        "summary": {
            "localChecksRun": len(enrichment),
            "localHits": sum(1 for item in enrichment if item["matched"]),
            "manualProcedures": sum(1 for item in techniques if not item["runsLocally"]),
        },
        "method": (
            "Only the local checks listed under enrichment were executed. Techniques that do not run locally are "
            "listed as next manual steps and were not performed."
        ),
        "source": "local-osint-pivot",
    }


ATTACK_TACTICS = [
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"),
    ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
ATTACK_TACTIC_NAMES = dict(ATTACK_TACTICS)

# Talos rule-category prefix -> ATT&CK tactics. Category-level, not technique-level:
# a SERVER-WEBAPP rule evidences Initial Access coverage, it does not pin a technique.
SNORT_CATEGORY_TACTICS = {
    "SERVER-WEBAPP": ["TA0001"], "SERVER-IIS": ["TA0001"], "SERVER-APACHE": ["TA0001"],
    "SERVER-ORACLE": ["TA0001"], "SERVER-MYSQL": ["TA0001"], "SERVER-MAIL": ["TA0001"],
    "SERVER-OTHER": ["TA0001"], "SERVER-SAMBA": ["TA0001", "TA0008"], "BROWSER-IE": ["TA0001"],
    "BROWSER-FIREFOX": ["TA0001"], "BROWSER-CHROME": ["TA0001"], "BROWSER-WEBKIT": ["TA0001"],
    "BROWSER-PLUGINS": ["TA0001"], "BROWSER-OTHER": ["TA0001"], "EXPLOIT-KIT": ["TA0001", "TA0002"],
    "FILE-PDF": ["TA0001", "TA0002"], "FILE-OFFICE": ["TA0001", "TA0002"],
    "FILE-FLASH": ["TA0001", "TA0002"], "FILE-JAVA": ["TA0001", "TA0002"],
    "FILE-MULTIMEDIA": ["TA0001", "TA0002"], "FILE-IMAGE": ["TA0001", "TA0002"],
    "FILE-EXECUTABLE": ["TA0002"], "FILE-OTHER": ["TA0002"], "FILE-IDENTIFY": ["TA0002"],
    "INDICATOR-SHELLCODE": ["TA0002"], "OS-WINDOWS": ["TA0002", "TA0004"], "OS-LINUX": ["TA0002", "TA0004"],
    "OS-OTHER": ["TA0002"], "OS-SOLARIS": ["TA0002"], "OS-MOBILE": ["TA0002"],
    "MALWARE-CNC": ["TA0011"], "MALWARE-BACKDOOR": ["TA0011", "TA0003"],
    "MALWARE-TOOLS": ["TA0011"], "MALWARE-OTHER": ["TA0011"], "PUA-ADWARE": ["TA0011"],
    "PUA-TOOLBARS": ["TA0011"], "PUA-P2P": ["TA0011"], "PUA-OTHER": ["TA0011"],
    "INDICATOR-COMPROMISE": ["TA0011", "TA0040"], "INDICATOR-OBFUSCATION": ["TA0005"],
    "INDICATOR-SCAN": ["TA0043", "TA0007"], "POLICY-SPAM": ["TA0001"],
    "POLICY-SOCIAL": ["TA0001"], "POLICY-MULTIMEDIA": ["TA0005"], "POLICY-OTHER": ["TA0005"],
    "PROTOCOL-SCADA": ["TA0040", "TA0008"], "PROTOCOL-ICMP": ["TA0043", "TA0007"],
    "PROTOCOL-DNS": ["TA0011", "TA0010"], "PROTOCOL-FTP": ["TA0010", "TA0008"],
    "PROTOCOL-TELNET": ["TA0008"], "PROTOCOL-SSH": ["TA0008"], "PROTOCOL-RPC": ["TA0008"],
    "PROTOCOL-NNTP": ["TA0010"], "PROTOCOL-POP": ["TA0009"], "PROTOCOL-IMAP": ["TA0009"],
    "PROTOCOL-SERVICES": ["TA0008"], "PROTOCOL-VOIP": ["TA0009"], "PROTOCOL-TFTP": ["TA0010"],
    "PROTOCOL-FINGER": ["TA0007"], "PROTOCOL-OTHER": ["TA0008"], "NETBIOS": ["TA0008", "TA0007"],
    "SQL": ["TA0001", "TA0009"], "APP-DETECT": ["TA0007"], "X11": ["TA0008"],
    "DELETED": [], "3PC": [], "CONTENT-REPLACE": ["TA0005"],
}

SNORT_CLASSTYPE_TACTICS = {
    "trojan-activity": ["TA0011"], "attempted-admin": ["TA0004"], "attempted-user": ["TA0001"],
    "successful-admin": ["TA0004"], "successful-user": ["TA0001"],
    "attempted-recon": ["TA0043", "TA0007"], "successful-recon-limited": ["TA0007"],
    "successful-recon-largescale": ["TA0007"], "network-scan": ["TA0043"],
    "attempted-dos": ["TA0040"], "successful-dos": ["TA0040"], "denial-of-service": ["TA0040"],
    "web-application-attack": ["TA0001"], "web-application-activity": ["TA0001"],
    "shellcode-detect": ["TA0002"], "suspicious-filename-detect": ["TA0005"],
    "suspicious-login": ["TA0006"], "unsuccessful-user": ["TA0006"],
    "system-call-detect": ["TA0002"], "policy-violation": ["TA0005"],
    "protocol-command-decode": ["TA0007"], "misc-attack": ["TA0008"], "misc-activity": [],
    "rpc-portmap-decode": ["TA0007"], "bad-unknown": [], "string-detect": [],
    "default-login-attempt": ["TA0006"], "credential-theft": ["TA0006"],
}

# ATT&CK technique -> tactic, for techniques xDome actually emits (enterprise + ICS).
ATTACK_TECHNIQUE_TACTICS = {
    "T1595": "TA0043", "T1590": "TA0043", "T1592": "TA0043", "T1589": "TA0043",
    "T1190": "TA0001", "T1133": "TA0001", "T1566": "TA0001", "T1200": "TA0001", "T1078": "TA0001",
    "T1059": "TA0002", "T1203": "TA0002", "T1204": "TA0002", "T1569": "TA0002", "T1047": "TA0002",
    "T1543": "TA0003", "T1547": "TA0003", "T1136": "TA0003", "T1505": "TA0003", "T1053": "TA0003",
    "T1068": "TA0004", "T1134": "TA0004", "T1548": "TA0004",
    "T1070": "TA0005", "T1027": "TA0005", "T1562": "TA0005", "T1036": "TA0005", "T1218": "TA0005",
    "T1110": "TA0006", "T1003": "TA0006", "T1555": "TA0006", "T1552": "TA0006", "T1558": "TA0006",
    "T1046": "TA0007", "T1018": "TA0007", "T1082": "TA0007", "T1016": "TA0007", "T1087": "TA0007",
    "T1021": "TA0008", "T1210": "TA0008", "T1550": "TA0008", "T1534": "TA0008", "T1570": "TA0008",
    "T1005": "TA0009", "T1119": "TA0009", "T1114": "TA0009", "T1056": "TA0009",
    "T1071": "TA0011", "T1095": "TA0011", "T1573": "TA0011", "T1105": "TA0011",
    "T1102": "TA0011", "T1572": "TA0011", "T1090": "TA0011", "T1568": "TA0011",
    "T1041": "TA0010", "T1048": "TA0010", "T1567": "TA0010", "T1030": "TA0010",
    "T1486": "TA0040", "T1489": "TA0040", "T1490": "TA0040", "T1498": "TA0040", "T1499": "TA0040",
    "T1649": "TA0006", "T1556": "TA0006",
    # ICS (ATT&CK for ICS)
    "T0859": "TA0006", "T0886": "TA0001", "T0822": "TA0001", "T0883": "TA0001", "T0866": "TA0001",
    "T0812": "TA0006", "T0807": "TA0002", "T0853": "TA0002", "T0823": "TA0002",
    "T0836": "TA0040", "T0831": "TA0040", "T0813": "TA0040", "T0815": "TA0040", "T0826": "TA0040",
    "T0814": "TA0040", "T0816": "TA0040", "T0879": "TA0040", "T0880": "TA0040",
    "T0842": "TA0007", "T0846": "TA0007", "T0840": "TA0007", "T0888": "TA0007", "T0887": "TA0007",
    "T0885": "TA0011", "T0869": "TA0011", "T0884": "TA0009", "T0802": "TA0009", "T0861": "TA0009",
    "T0867": "TA0008", "T0843": "TA0008", "T0858": "TA0005", "T0856": "TA0005", "T0872": "TA0005",
}

attack_coverage_cache = {"fingerprint": None, "payload": None}
attack_coverage_lock = threading.Lock()


def _rule_tactics(rule):
    """Resolve the ATT&CK tactics a Snort rule contributes coverage for."""
    text = rule.get("rule") or ""
    message = rule.get("message") or ""
    explicit = {f"T{match}" for match in re.findall(r"\bT(\d{4})\b", text)}
    tactics = set()
    techniques = set()
    for technique in explicit:
        if technique in ATTACK_TECHNIQUE_TACTICS:
            techniques.add(technique)
            tactics.add(ATTACK_TECHNIQUE_TACTICS[technique])
    prefix = re.match(r"^([A-Z0-9\-]+)\s", message)
    if prefix:
        tactics.update(SNORT_CATEGORY_TACTICS.get(prefix.group(1), []))
    classtype = re.search(r"classtype\s*:\s*([a-z0-9\-]+)", text)
    if classtype:
        tactics.update(SNORT_CLASSTYPE_TACTICS.get(classtype.group(1), []))
    return tactics, techniques


def snort_attack_coverage():
    """ATT&CK tactic coverage derived from the locally loaded Snort rule catalogue."""
    try:
        catalog = current_snort_catalog()
    except Exception:
        catalog = None
    if isinstance(catalog, dict):
        candidates = catalog.get("records") or []
    elif isinstance(catalog, list):
        candidates = catalog
    else:
        candidates = []
    rules = [rule for rule in candidates if isinstance(rule, dict)]
    fingerprint = f"{len(rules)}:{sum(1 for rule in rules if rule.get('enabled'))}"
    with attack_coverage_lock:
        if attack_coverage_cache["fingerprint"] == fingerprint and attack_coverage_cache["payload"]:
            return attack_coverage_cache["payload"]

    by_tactic = {tactic: {"rules": 0, "enabled": 0, "techniques": set(), "samples": []} for tactic, _ in ATTACK_TACTICS}
    explicit_techniques = set()
    unmapped = 0
    for rule in rules:
        tactics, techniques = _rule_tactics(rule)
        explicit_techniques.update(techniques)
        if not tactics:
            unmapped += 1
            continue
        for tactic in tactics:
            bucket = by_tactic.setdefault(tactic, {"rules": 0, "enabled": 0, "techniques": set(), "samples": []})
            bucket["rules"] += 1
            if rule.get("enabled"):
                bucket["enabled"] += 1
            bucket["techniques"].update(techniques)
            if len(bucket["samples"]) < 3 and rule.get("message"):
                bucket["samples"].append({"sid": rule.get("sid"), "message": rule.get("message")})

    tactics_payload = []
    for tactic, name in ATTACK_TACTICS:
        bucket = by_tactic.get(tactic, {"rules": 0, "enabled": 0, "techniques": set(), "samples": []})
        tactics_payload.append({
            "tacticId": tactic, "tactic": name,
            "ruleCount": bucket["rules"], "enabledCount": bucket["enabled"],
            "techniqueIds": sorted(bucket["techniques"]),
            "covered": bucket["enabled"] > 0,
            "sampleRules": bucket["samples"],
        })

    covered = sum(1 for row in tactics_payload if row["covered"])
    payload = {
        "source": "Snort community rule catalogue loaded on this server",
        "totalRules": len(rules),
        "unmappedRules": unmapped,
        "explicitTechniqueRules": sorted(explicit_techniques),
        "tacticsCovered": covered,
        "tacticsTotal": len(ATTACK_TACTICS),
        "coveragePercent": round(covered / len(ATTACK_TACTICS) * 100, 1) if ATTACK_TACTICS else 0,
        "tactics": tactics_payload,
        "method": "Coverage is mapped at ATT&CK tactic level from Talos rule categories and Snort classtypes. "
                  "Only rules carrying an explicit Txxxx reference give technique-level evidence. "
                  "A mapped rule means signature coverage exists in the catalogue, not that a sensor is inspecting traffic.",
    }
    with attack_coverage_lock:
        attack_coverage_cache.update({"fingerprint": fingerprint, "payload": payload})
    return payload


OFFSEC_DOMAINS = [
    {
        "id": "recon_osint", "name": "Reconnaissance & Attack Surface",
        "objective": "Enumerate externally reachable and unmanaged assets before an adversary does.",
        "passiveEvidence": ["Claroty xDome device inventory", "observed event peer addresses", "Feodo C2 blocklist"],
        "activeTesting": ["DNS/subdomain enumeration", "external port and service sweeps", "technology fingerprinting"],
        "tools": ["claroty"],
    },
    {
        "id": "network", "name": "Network Security & Segmentation",
        "objective": "Validate segmentation, exposed services and lateral-movement reachability.",
        "passiveEvidence": ["xDome communication events", "Snort PROTOCOL-* and NETBIOS rules", "local IP allow/deny lists"],
        "activeTesting": ["firewall rule-set traversal testing", "VLAN hopping", "NAC bypass attempts"],
        "tools": ["claroty", "cato"],
    },
    {
        "id": "web_api", "name": "Web & API Security",
        "objective": "Identify injection, access-control and session weaknesses in exposed applications.",
        "passiveEvidence": ["Snort SERVER-WEBAPP/SERVER-IIS signature coverage", "KEV matches on web stacks"],
        "activeTesting": ["authenticated application testing", "OWASP Top 10 exploitation", "business-logic abuse"],
        "tools": ["trivy"],
    },
    {
        "id": "identity", "name": "Identity, AD & Kerberos",
        "objective": "Find credential exposure, Kerberos weaknesses and excessive privilege.",
        "passiveEvidence": ["Credential Access tactic coverage", "xDome identity-risk alerts", "configured IdP connectors"],
        "activeTesting": ["Kerberoasting / AS-REP roasting", "password spraying", "delegation abuse", "ACL path analysis"],
        "tools": ["entra", "keycloak", "defender", "sentinel"],
    },
    {
        "id": "cloud", "name": "Cloud & Workload Identity",
        "objective": "Detect IAM misconfiguration, public exposure and metadata-service risk.",
        "passiveEvidence": ["configured cloud connectors", "KEV matches on cloud-hosted products"],
        "activeTesting": ["IAM privilege-escalation path enumeration", "storage exposure checks", "workload identity abuse"],
        "tools": ["wiz", "defender-cloud-apps", "m365", "dc2cloud"],
    },
    {
        "id": "ot_ics", "name": "OT / ICS Offensive Security",
        "objective": "Assess Purdue-level boundaries and industrial protocol exposure without affecting availability.",
        "passiveEvidence": ["xDome OT asset inventory and risk scores", "Snort PROTOCOL-SCADA rules", "ATT&CK for ICS alerts"],
        "activeTesting": ["PLC/HMI interaction", "protocol fuzzing", "engineering-workstation assessment"],
        "safety": "Active OT testing must stay in a lab, digital twin or an approved maintenance window.",
        "tools": ["claroty"],
    },
    {
        "id": "supply_chain", "name": "Supply Chain & Third-Party",
        "objective": "Assess dependency, vendor-access and software-provenance risk.",
        "passiveEvidence": ["KEV and EPSS matches on installed products", "configured backup/vendor connectors"],
        "activeTesting": ["SBOM provenance review", "CI/CD compromise-path testing", "vendor remote-access validation"],
        "tools": ["trivy", "rubrik", "netapp", "nasuni"],
    },
    {
        "id": "ai_llm", "name": "AI / LLM & Agentic Security",
        "objective": "Assess prompt injection, excessive agency and AI supply-chain exposure.",
        "passiveEvidence": ["locally recorded AI/agent events, when a model gateway forwards them"],
        "activeTesting": ["prompt and indirect prompt injection", "jailbreak probing", "RAG poisoning", "tool/agent privilege abuse", "system-prompt leakage"],
        "tools": [],
    },
    {
        "id": "detection_engineering", "name": "Detection Engineering",
        "objective": "Measure what the defensive stack can actually observe.",
        "passiveEvidence": ["Snort rule catalogue", "OpenAppID detector package", "configured SIEM/EDR connectors"],
        "activeTesting": ["telemetry gap validation against executed techniques"],
        "tools": ["wazuh", "opensearch", "sentinel", "defender", "crowdstrike", "sentinelone"],
    },
    {
        "id": "purple_team", "name": "Purple Teaming",
        "objective": "Correlate executed or observed techniques against detection coverage and response.",
        "passiveEvidence": ["xDome alert MITRE techniques", "Snort tactic coverage", "configured SOAR connectors"],
        "activeTesting": ["adversary emulation runs", "detection validation exercises"],
        "tools": ["swimlane", "sentinel", "misp"],
    },
]


OFFSEC_DOMAIN_SLUGS = {
    "recon_osint": "recon-osint", "network": "network-security",
    "web_api": "web-api", "identity": "identity-ad", "cloud": "cloud-iam",
    "ot_ics": "ot-ics", "supply_chain": "supply-chain",
    "ai_llm": "ai-llm", "detection_engineering": "detection-engineering",
    "purple_team": "purple-team",
}
OFFSEC_DEFERRED_KPIS = (
    ("testCoveragePercentage", "Test Coverage %"),
    ("passFailRate", "Pass / Fail Rate"),
    ("criticalHighFindings", "Critical / High Findings"),
    ("controlEffectivenessPercentage", "Control Effectiveness %"),
    ("retestCompletionPercentage", "Retest Completion %"),
    ("residualRisk", "Residual Risk"),
    ("evidenceFreshness", "Evidence Freshness"),
)


def assessment_deferred_kpis():
    return [
        {"key": key, "label": label, "value": None, "status": "DEFERRED",
         "requires": "AUTHORIZED_ACTIVE_TESTING",
         "reason": ("Control effectiveness has not been established through authorized active testing."
                    if key == "residualRisk" else "No verified authorized active-testing evidence exists.")}
        for key, label in OFFSEC_DEFERRED_KPIS
    ]


def assessment_domain(slug):
    return next((item for item in OFFSEC_DOMAINS if OFFSEC_DOMAIN_SLUGS[item["id"]] == slug), None)


def assessment_requests():
    with ASSESSMENT_REQUESTS_LOCK:
        requests = read_json_store(ASSESSMENT_REQUESTS_FILE, [])
    if not isinstance(requests, list) or any(not isinstance(item, dict) for item in requests):
        raise ValueError("Assessment request store has an invalid shape")
    return requests


def request_assessment_testing(slug, payload):
    if assessment_domain(slug) is None:
        raise KeyError(slug)
    if not isinstance(payload, dict) or set(payload) != {
        "testType", "scope", "authorizationReference", "requestedBy", "scheduledStart"
    }:
        raise ValueError("testType, scope, authorizationReference, requestedBy and scheduledStart are required")
    if payload["testType"] != "AUTHORIZED_ACTIVE_TEST":
        raise ValueError("Only AUTHORIZED_ACTIVE_TEST requests are accepted")
    for field in ("scope", "authorizationReference", "requestedBy"):
        if not isinstance(payload[field], str) or not 1 <= len(payload[field].strip()) <= 200:
            raise ValueError(f"{field} must be 1-200 characters")
    if not isinstance(payload["scheduledStart"], str):
        raise ValueError("scheduledStart must be an ISO 8601 timestamp with timezone")
    try:
        start = datetime.fromisoformat(payload["scheduledStart"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("scheduledStart must be an ISO 8601 timestamp with timezone") from error
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("scheduledStart must include a timezone")
    with ASSESSMENT_REQUESTS_LOCK:
        requests = assessment_requests()
        if len(requests) >= 1000:
            raise ValueError("Assessment request store is full")
        record = {
            "id": uuid.uuid4().hex, "domainId": slug, "status": "REQUESTED",
            "authorizationVerified": False, "validationStatus": "PENDING",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            **{field: payload[field].strip() for field in ("scope", "authorizationReference", "requestedBy")},
            "testType": payload["testType"], "scheduledStart": start.isoformat(),
            "note": "Authorization reference is unverified. No test, approval, evidence review or validation is performed.",
        }
        requests.append(record)
        write_json_store(ASSESSMENT_REQUESTS_FILE, requests)
    return record


def offsec_methodology_payload():
    """Assessment-domain readiness derived from configured connectors and loaded data.

    This reports what each domain can be assessed with from evidence already held.
    It never implies that active testing was performed - this platform has no
    scanning engine and no authorized target list.
    """
    configured = set((load_integration_credential_store() or {}).keys())
    if claroty_credentials_status().get("configured"):
        configured.add("claroty")
    coverage = snort_attack_coverage()
    rules_loaded = coverage["totalRules"] > 0
    openappid_loaded = bool(current_openappid_catalog())

    domains = []
    for domain in OFFSEC_DOMAINS:
        present = sorted(tool for tool in domain["tools"] if tool in configured)
        missing = sorted(tool for tool in domain["tools"] if tool not in configured)
        sources = []
        if rules_loaded and domain["id"] in {"web_api", "detection_engineering", "network"}:
            sources.append({"source": "Snort rule catalogue", "type": "PASSIVE_RULE_CONTENT",
                            "evidenceCount": coverage["totalRules"], "lastObservedAt": None})
        if openappid_loaded and domain["id"] == "detection_engineering":
            sources.append({"source": "OpenAppID detector catalogue", "type": "PASSIVE_RULE_CONTENT",
                            "evidenceCount": None, "lastObservedAt": None})
        evidence_ready = bool(sources)
        evidence_count = sum(source["evidenceCount"] for source in sources if source["evidenceCount"] is not None)
        active_required = bool(domain["activeTesting"])
        domains.append({
            "id": domain["id"], "name": domain["name"],
            "domainId": OFFSEC_DOMAIN_SLUGS[domain["id"]], "domainName": domain["name"],
            "objective": domain["objective"],
            "passiveEvidence": domain["passiveEvidence"],
            "activeTesting": domain["activeTesting"],
            "safety": domain.get("safety"),
            "connectorsConfigured": present,
            "connectorsMissing": missing,
            "status": "evidence_available" if evidence_ready else "no_local_evidence",
            "assessable": "passive_evidence_only",
            "evidenceStatus": "PARTIALLY_EVIDENCED" if evidence_ready else "NO_LOCAL_EVIDENCE",
            "evidenceMethod": "PASSIVE" if evidence_ready else "NONE",
            "evidenceAvailable": evidence_ready,
            "evidenceCount": evidence_count if evidence_ready else None,
            "lastEvidenceAt": None,
            "evidenceSources": sources,
            "validationStatus": "NOT_VALIDATED" if evidence_ready else "PENDING",
            "validationReason": ("Passive rule content is not evidence of control effectiveness or authorized validation."
                                 if evidence_ready else "No authoritative local evidence source is currently connected."),
            "assessmentStatus": "PASSIVE_ASSESSMENT_ONLY" if evidence_ready else "ASSESSMENT_PENDING",
            "coverageStatus": "Partially Evidenced (Passive)" if evidence_ready else "Not Validated",
            "activeTestingRequired": active_required,
            "activeTestingRequiredLabel": "Yes" if active_required else "No",
            "riskStatus": "Passive Assessment Only" if evidence_ready else "Assessment Pending",
            "kpisAvailable": False,
            "deferredKpis": assessment_deferred_kpis(),
            "kpiNote": "Quantitative KPIs are withheld until active testing produces evidence; "
                       "metrics without underlying evidence would imply assurance that does not exist.",
        })

    ready = sum(1 for domain in domains if domain["status"] == "evidence_available")
    pending = [domain["name"] for domain in domains if domain["riskStatus"] == "Assessment Pending"]
    validated = sum(1 for domain in domains if domain["validationStatus"] == "VALIDATED")
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "kpis": {
            "domainsTotal": len(domains),
            "domainsWithEvidence": ready,
            "evidenceCoveragePercent": round(ready / len(domains) * 100, 1) if domains else 0,
            "connectorsConfigured": len(configured),
            "attackTacticsCovered": coverage["tacticsCovered"],
            "attackTacticsTotal": coverage["tacticsTotal"],
            "detectionRulesLoaded": coverage["totalRules"],
            "domainsAssessmentPending": len(pending),
            "domainsValidated": validated,
            "domainsRequiringActiveTesting": sum(1 for domain in domains if domain["activeTestingRequired"]),
        },
        "assessmentPending": pending,
        "deferredKpis": assessment_deferred_kpis(),
        "domains": domains,
        "limits": "No scanning engine and no authorized-target list are configured, so every result here is "
                  "passive assessment of telemetry and configuration already held. Items listed under "
                  "activeTesting require an authorized engagement and are not executed by this platform. "
                  "Connector configuration alone is not evidence; browser-only xDome feeds are not server-side "
                  "domain evidence. No domain is validated, and quantitative KPIs remain deferred until "
                  "trusted authorization, evidence verification and human review are implemented.",
    }


def security_assessment_summary(methodology):
    domains = methodology["domains"]
    total = len(domains)
    validated = sum(item["validationStatus"] == "VALIDATED" for item in domains)
    pending = [item["domainName"] for item in domains if item["assessmentStatus"] == "ASSESSMENT_PENDING"]
    required = sum(item["activeTestingRequired"] for item in domains)
    return {
        "totalDomains": total, "domainsValidated": validated, "domainsPending": len(pending),
        "domainsPassiveOnly": sum(item["assessmentStatus"] == "PASSIVE_ASSESSMENT_ONLY" for item in domains),
        "domainsRequiringActiveTesting": required,
        "validationPercentage": round(validated / total * 100, 1) if total else 0,
        "activeTestingCoveragePercentage": None,
        "summary": f"{len(pending)} pending · {validated} of {total} validated · {required} require authorized active testing",
        "pendingDomains": pending, "deferredKpis": methodology["deferredKpis"],
        "note": "Testing requests are not authorizations. Active-testing coverage cannot be calculated without verified tests and scope.",
    }


def security_assessment_domain_detail(domain):
    return {
        **domain,
        "evidence": {"status": domain["evidenceStatus"], "method": domain["evidenceMethod"],
                     "sources": domain["evidenceSources"], "count": domain["evidenceCount"],
                     "lastEvidenceAt": domain["lastEvidenceAt"]},
        "validation": {"status": domain["validationStatus"],
                       "activeTestingRequired": domain["activeTestingRequired"],
                       "reason": domain["validationReason"]},
        "testingRequests": [item for item in assessment_requests() if item["domainId"] == domain["domainId"]],
    }


def _offsec_band(score):
    return "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low"


def offsec_attack_paths_payload(request_body):
    """Score adversary attack paths from live asset exposure and KEV/EPSS evidence."""
    if not isinstance(request_body, dict):
        raise ValueError("Attack path request must be a JSON object")
    assets = request_body.get("assets")
    if not isinstance(assets, list):
        raise ValueError("assets must be an array")
    if len(assets) > MAX_CORRELATE_ITEMS:
        raise ValueError(f"At most {MAX_CORRELATE_ITEMS} assets may be scored per request")

    index = build_intel_match_index()
    normalized = []
    all_cves = set()
    for entry in assets:
        if not isinstance(entry, dict):
            continue
        cves = set()
        for value in (entry.get("cves") or []):
            text = str(value).strip().upper()
            if CVE_PATTERN.match(text):
                cves.add(text)
        ips = []
        for value in (entry.get("ips") or []):
            try:
                ips.append(str(ipaddress.ip_address(str(value).strip())))
            except ValueError:
                continue
        all_cves.update(cves)
        normalized.append({
            "id": str(entry.get("id") or entry.get("name") or "")[:200],
            "name": str(entry.get("name") or "Unknown asset")[:200],
            "site": str(entry.get("site") or "")[:200],
            "type": str(entry.get("type") or "")[:120],
            "online": entry.get("online"),
            "riskScore": entry.get("riskScore"),
            "cves": cves, "ips": ips,
        })

    kev_cves = {cve for cve in all_cves if cve in index["kev"]}
    epss = fetch_epss_scores(kev_cves) if kev_cves else {}

    paths = []
    for asset in normalized:
        kev_hits = sorted(asset["cves"] & kev_cves)
        if not kev_hits:
            continue
        ransomware = [cve for cve in kev_hits if index["kev"][cve].get("knownRansomware")]
        top_epss = max((epss.get(cve, {}).get("epss") or 0) for cve in kev_hits)
        c2_hits = [address for address in asset["ips"] if address in index["c2"]]

        # Weighted, documented scoring - no invented values.
        exploitability = top_epss * 40
        kev_weight = min(len(kev_hits), 5) * 4
        ransomware_weight = 15 if ransomware else 0
        reachability = 15 if asset["online"] is True else 5 if asset["online"] is None else 0
        try:
            asset_risk = min(float(asset["riskScore"]), 100) * 0.15
        except (TypeError, ValueError):
            asset_risk = 0
        active_c2 = 15 if c2_hits else 0
        score = round(min(exploitability + kev_weight + ransomware_weight + reachability + asset_risk + active_c2, 100), 1)

        stages = [{"tacticId": "TA0043", "tactic": "Reconnaissance",
                   "detail": f"Asset reachable on {len(asset['ips'])} observed address(es)" if asset["ips"] else "Asset present in OT inventory"},
                  {"tacticId": "TA0001", "tactic": "Initial Access",
                   "detail": f"{len(kev_hits)} known-exploited CVE(s): {', '.join(kev_hits[:4])}"}]
        if active_c2:
            stages.append({"tacticId": "TA0011", "tactic": "Command and Control",
                           "detail": f"Observed address on Feodo C2 blocklist: {', '.join(c2_hits[:3])}"})
        if ransomware:
            stages.append({"tacticId": "TA0040", "tactic": "Impact",
                           "detail": f"CISA records ransomware campaign use for {', '.join(ransomware[:3])}"})

        paths.append({
            "assetId": asset["id"], "asset": asset["name"], "site": asset["site"], "type": asset["type"],
            "online": asset["online"], "score": score, "band": _offsec_band(score),
            "kevCves": kev_hits[:10], "kevCount": len(kev_hits),
            "ransomwareCves": ransomware[:10], "c2Addresses": c2_hits[:5],
            "topEpss": round(top_epss, 5),
            "stages": stages,
            "scoring": {"exploitability": round(exploitability, 1), "kevVolume": kev_weight,
                        "ransomware": ransomware_weight, "reachability": reachability,
                        "assetRisk": round(asset_risk, 1), "activeC2": active_c2},
        })

    paths.sort(key=lambda path: path["score"], reverse=True)
    bands = {band: sum(1 for path in paths if path["band"] == band) for band in ("Critical", "High", "Medium", "Low")}
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "assetsSubmitted": len(normalized),
        "assetsWithPath": len(paths),
        "kpis": {
            "criticalPaths": bands["Critical"], "highPaths": bands["High"],
            "ransomwareExposedAssets": sum(1 for path in paths if path["ransomwareCves"]),
            "c2LinkedAssets": sum(1 for path in paths if path["c2Addresses"]),
            "maxScore": paths[0]["score"] if paths else 0,
        },
        "bands": bands,
        "paths": paths[:300],
        "method": "Score = EPSS exploit probability (40) + KEV volume (20) + ransomware use (15) + "
                  "network reachability (15) + xDome asset risk (15) + observed C2 contact (15), capped at 100. "
                  "Derived entirely from loaded inventory and open feeds; no exploitation is attempted.",
    }


def offsec_purple_team_payload(request_body):
    """Validate observed ATT&CK techniques against local detection coverage."""
    if not isinstance(request_body, dict):
        raise ValueError("Purple team request must be a JSON object")
    observed = request_body.get("techniques")
    if not isinstance(observed, list):
        raise ValueError("techniques must be an array")
    if len(observed) > MAX_CORRELATE_ITEMS:
        raise ValueError(f"At most {MAX_CORRELATE_ITEMS} techniques may be validated per request")

    coverage = snort_attack_coverage()
    by_tactic = {row["tacticId"]: row for row in coverage["tactics"]}
    explicit = set(coverage["explicitTechniqueRules"])
    try:
        configured = set((load_integration_credential_store() or {}).keys())
    except Exception:
        configured = set()
    try:
        if claroty_credentials_status().get("configured"):
            configured.add("claroty")
    except Exception:
        pass
    detection_tools = sorted(configured & {"wazuh", "opensearch", "sentinel", "defender", "crowdstrike", "sentinelone", "misp"})

    counts = {}
    for value in observed:
        technique = str(value).strip().upper()
        if re.match(r"^T\d{4}(\.\d{3})?$", technique):
            counts[technique.split(".")[0]] = counts.get(technique.split(".")[0], 0) + 1

    results = []
    for technique, occurrences in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        tactic = ATTACK_TECHNIQUE_TACTICS.get(technique)
        tactic_row = by_tactic.get(tactic) if tactic else None
        if technique in explicit:
            status, detail = "technique_rule", "A loaded Snort rule references this technique directly."
        elif tactic_row and tactic_row["enabledCount"]:
            status, detail = "tactic_rules", f"{tactic_row['enabledCount']} enabled rule(s) cover the {tactic_row['tactic']} tactic, but none name this technique."
        elif tactic:
            status, detail = "gap", f"No loaded rule covers the {ATTACK_TACTIC_NAMES.get(tactic, tactic)} tactic."
        else:
            status, detail = "unmapped", "Technique is not in the local ATT&CK tactic map."
        results.append({
            "techniqueId": technique, "occurrences": occurrences,
            "tacticId": tactic, "tactic": ATTACK_TACTIC_NAMES.get(tactic) if tactic else None,
            "status": status, "detail": detail,
            "tacticRuleCount": tactic_row["enabledCount"] if tactic_row else 0,
        })

    validated = sum(1 for row in results if row["status"] == "technique_rule")
    partial = sum(1 for row in results if row["status"] == "tactic_rules")
    gaps = sum(1 for row in results if row["status"] in ("gap", "unmapped"))
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "techniquesObserved": len(results),
        "kpis": {
            "techniqueLevelCoverage": validated,
            "tacticLevelCoverage": partial,
            "detectionGaps": gaps,
            "coveragePercent": round((validated + partial) / len(results) * 100, 1) if results else 0,
            "detectionConnectors": len(detection_tools),
        },
        "detectionConnectors": detection_tools,
        "techniques": results[:500],
        "tacticCoverage": coverage["tactics"],
        "method": "Observed techniques come from live xDome alerts. Coverage is evidence that a matching rule is "
                  "loaded locally - it is not proof the technique would be detected, which requires a sensor "
                  "inspecting traffic and a validated emulation run.",
    }


ZERO_TRUST_CONNECTORS = [
    {"pillar": "Identity", "capability": "Workforce identity, SSO, MFA, conditional access", "providers": "Keycloak, Microsoft Entra ID, Okta, Ping Identity", "integration": "OIDC / OAuth 2.0, SAML, SCIM, risk events"},
    {"pillar": "Identity", "capability": "Privileged access and JIT", "providers": "CyberArk, BeyondTrust, Entra PIM", "integration": "Scoped API, approval and session audit"},
    {"pillar": "Identity", "capability": "Identity governance and lifecycle", "providers": "Entra ID Governance, SailPoint, Saviynt, HR", "integration": "SCIM, lifecycle events, access reviews"},
    {"pillar": "PKI", "capability": "User and device certificates", "providers": "IDnomic/OpenTrust CMS, EJBCA Community, OpenXPKI, Microsoft AD CS", "integration": "Enrollment, status, revocation events; never ingest private keys"},
    {"pillar": "Devices", "capability": "OT asset inventory and risk", "providers": "Claroty xDome", "integration": "Encrypted backend credential and live xDome feeds", "claroty": True},
    {"pillar": "Devices", "capability": "MDM compliance and encryption posture", "providers": "Microsoft Intune, MECM, Workspace ONE", "integration": "Device posture API and change events"},
    {"pillar": "Devices", "capability": "Endpoint detection and vulnerability posture", "providers": "Wazuh, Microsoft Defender, CrowdStrike, SentinelOne, Tenable", "integration": "Risk APIs, findings and containment audit"},
    {"pillar": "Devices", "capability": "Container runtime and image security", "providers": "Falco, Trivy", "integration": "Runtime alerts, image scan and SBOM results"},
    {"pillar": "Networks", "capability": "ZTNA, network admission and segmentation", "providers": "OpenZiti, NetBird, Zscaler ZPA, Prisma Access, Cisco ISE, Illumio", "integration": "Session decisions, posture context, policy actions"},
    {"pillar": "Networks", "capability": "SASE security fabric, secure access and network threat analytics", "providers": "Cato Networks SASE", "integration": "Cato GraphQL API, account scope, and registered webhook events", "tool_id": "cato"},
    {"pillar": "Applications & Workloads", "capability": "Data-center-to-cloud transformation security", "providers": "DC2Cloud", "integration": "Provider API, tenant scope, canonical event mapping, and policy connector", "tool_id": "dc2cloud"},
    {"pillar": "Applications & Workloads", "capability": "Application proxy, API gateway and workload identity", "providers": "Kong Gateway, Entra Private Access, Azure API Management, Apigee, SPIFFE", "integration": "OIDC, OAuth 2.0, mTLS, workload events"},
    {"pillar": "Data", "capability": "Classification, DLP, encryption and data authorization", "providers": "OpenDLP, Apache Ranger, Microsoft Purview, Symantec DLP, Thales, cloud KMS", "integration": "Classification lookup, DLP events, key status"},
    {"pillar": "Visibility & Analytics", "capability": "SIEM, search, detection and threat intelligence", "providers": "Wazuh SIEM, OpenSearch, Elastic, Sentinel, Splunk, MISP, OpenCTI", "integration": "Canonical security events, detections, enrichment"},
    {"pillar": "Automation & Orchestration", "capability": "Containment and response", "providers": "Shuffle, StackStorm, Sentinel playbooks, Cortex XSOAR", "integration": "Approved actions, idempotency, rollback and audit"},
    {"pillar": "Governance", "capability": "CMDB, control evidence and case management", "providers": "GLPI, Jira, ServiceNow, Archer", "integration": "Asset owners, control evidence, cases and approvals"},
    {"pillar": "Risk & Resilience", "capability": "Cybersecurity risk analytics and recovery readiness", "providers": "Claroty, Wazuh, CrowdStrike, SentinelOne, Rubrik", "integration": "Risk findings, incident evidence, backup/recovery events", "tool_ids": ["wazuh", "crowdstrike", "sentinelone", "rubrik"]},
    {"pillar": "IT/OT Convergence", "capability": "Cross-domain identity, asset, network and workload correlation", "providers": "Claroty xDome, Cato SASE, DC2Cloud, Wazuh", "integration": "Canonical events and entity/asset mapping", "tool_ids": ["cato", "dc2cloud", "wazuh"]},
]

OPEN_SOURCE_ENGINE_CATALOG = [
    {"id": "wazuh", "name": "Wazuh", "aliases": ["wazuh", "wazuh manager", "wazuh siem"]},
    {"id": "opensearch", "name": "OpenSearch", "aliases": ["opensearch", "opensearch security"]},
    {"id": "suricata", "name": "Suricata", "aliases": ["suricata", "eve json"]},
    {"id": "zeek", "name": "Zeek", "aliases": ["zeek", "bro"]},
    {"id": "misp", "name": "MISP", "aliases": ["misp", "misp threat sharing"]},
    {"id": "keycloak", "name": "Keycloak", "aliases": ["keycloak", "keycloak iam"]},
    {"id": "falco", "name": "Falco", "aliases": ["falco", "falco runtime"]},
    {"id": "trivy", "name": "Trivy", "aliases": ["trivy", "aquasecurity trivy"]},
    {"id": "snort_openappid", "name": "Snort OpenAppID", "aliases": ["snort", "snort openappid", "openappid"], "package": "openappid"},
]

ZERO_TRUST_SENSITIVE_EVENT_KEYS = {
    "pin", "puk", "privatekey", "privatekeypem", "clientsecret", "accesstoken",
    "refreshtoken", "apikey", "password", "credentialsecret",
}


def zero_trust_integrations_payload():
    try:
        claroty = claroty_credentials_status()
    except Exception as error:
        claroty = {"configured": False, "error": str(error)}
    try:
        event_connectors = [public_integration_connector(item) for item in load_integration_connectors()]
    except Exception:
        event_connectors = []
    try:
        credential_store = load_integration_credential_store()
    except Exception:
        credential_store = {}
    try:
        canonical_events = read_zero_trust_events(1000)
    except Exception:
        canonical_events = []
    open_source_engines = []
    for engine in OPEN_SOURCE_ENGINE_CATALOG:
        aliases = [str(alias).casefold() for alias in engine["aliases"]]
        receiver = next((item for item in event_connectors if str(item.get("name") or "").casefold() in aliases), None)
        matched_events = [event for event in canonical_events if str((event.get("source") or {}).get("system") or "").casefold() in aliases]
        credentials_configured = bool(credential_store.get(engine["id"]))
        receiver_events = int((receiver or {}).get("eventCount") or 0)
        status = "telemetry_received" if receiver_events or matched_events else "event_receiver_registered" if receiver else "credentials_configured" if credentials_configured else "candidate_not_connected"
        record = {
            **engine,
            "status": status,
            "eventCount": max(receiver_events, len(matched_events)),
            "lastReceivedAt": (receiver or {}).get("lastReceivedAt") or max((event.get("event_time", "") for event in matched_events), default=None),
            "transport": (receiver or {}).get("transport"),
            "source": "local-event-store" if receiver_events or matched_events else "readiness-only",
            "externalActionsEnabled": False,
        }
        if engine.get("package") == "openappid":
            try:
                package = openappid_status_payload()
            except Exception as error:
                package = {"configured": False, "error": str(error)}
            record["package"] = package
            if package.get("configured"):
                record["status"] = "package_loaded"
                record["source"] = "local-package"
                record["lastReceivedAt"] = package.get("updatedAt")
                record["detail"] = f"ODP {package.get('version') or 'unknown'} · {package.get('applications', 0)} applications · {package.get('detectors', 0)} detectors"
        open_source_engines.append(record)
    records = []
    for index, connector in enumerate(ZERO_TRUST_CONNECTORS, start=1):
        tool_ids = [connector.get("tool_id"), *(connector.get("tool_ids") or [])]
        provider_names = {name.strip().casefold() for name in str(connector.get("providers") or "").split(",")}
        if "rubrik" in tool_ids:
            provider_names.add("rubrik security cloud")
        event_connector = next((item for item in event_connectors if str(item.get("name") or "").casefold() in provider_names), None)
        configured_tool_ids = [tool_id for tool_id in tool_ids if tool_id and credential_store.get(tool_id)]
        provider_configured = bool(configured_tool_ids)
        matched_events = [event for event in canonical_events if str((event.get("source") or {}).get("system") or "").casefold() in provider_names]
        receiver_event_count = int((event_connector or {}).get("eventCount") or 0)
        telemetry_received = receiver_event_count > 0 or bool(matched_events)
        status = "telemetry_received" if telemetry_received else "credentials_configured" if connector.get("claroty") and claroty.get("configured") or provider_configured else "event_receiver_registered" if event_connector else "connector_required"
        record = {"id": f"zt-{index}", **connector, "status": status}
        if configured_tool_ids:
            record["configuredTools"] = configured_tool_ids
        if event_connector:
            record["eventReceiver"] = {
                "transport": event_connector.get("transport"),
                "eventCount": max(receiver_event_count, len(matched_events)),
                "lastReceivedAt": event_connector.get("lastReceivedAt"),
            }
        records.append(record)
    return {
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "claroty": {key: claroty.get(key) for key in ("configured", "encrypted", "backend")},
        "connectors": records,
        "eventConnectors": event_connectors,
        "openSourceEngines": open_source_engines,
        "policyEnforcement": "not_connected",
        "note": "Connector readiness is not proof of a live vendor connection. Zero Trust decisions from this API are simulations and do not grant or revoke access.",
    }


def default_zero_trust_program():
    return {
        "owner": "",
        "executive_sponsor": "",
        "review_date": "",
        "maturity": {domain: None for domain in ZERO_TRUST_DOMAINS},
        "targets": {domain: 4 for domain in ZERO_TRUST_DOMAINS},
        "phases": {phase: "not_started" for phase in ZERO_TRUST_PHASES},
        "controls": {control: False for control in ZERO_TRUST_CONTROL_IDS},
        "ai_controls": {control: False for control in ZERO_TRUST_AI_CONTROL_IDS},
        "updated_at": None,
    }


def validate_zero_trust_program(payload):
    if not isinstance(payload, dict):
        raise ValueError("UDP program profile must be a JSON object")
    _reject_sensitive_event_fields(payload)
    if len(json.dumps(payload, ensure_ascii=True)) > ZERO_TRUST_PROGRAM_MAX_BYTES:
        raise ValueError("UDP program profile exceeds the 128 KB limit")
    defaults = default_zero_trust_program()
    text_fields = {}
    for field in ("owner", "executive_sponsor", "review_date"):
        value = str(payload.get(field) or "").strip()
        if len(value) > 160:
            raise ValueError(f"{field} must be at most 160 characters")
        text_fields[field] = value
    maturity = payload.get("maturity", {})
    targets = payload.get("targets", {})
    phases = payload.get("phases", {})
    controls = payload.get("controls", {})
    ai_controls = payload.get("ai_controls", {})
    for field, values in (("maturity", maturity), ("targets", targets), ("phases", phases), ("controls", controls), ("ai_controls", ai_controls)):
        if not isinstance(values, dict):
            raise ValueError(f"{field} must be an object")
    normalized_maturity = {}
    normalized_targets = {}
    for domain in ZERO_TRUST_DOMAINS:
        current = maturity.get(domain, defaults["maturity"][domain])
        target = targets.get(domain, defaults["targets"][domain])
        if current is not None and (isinstance(current, bool) or not isinstance(current, int) or not 0 <= current <= 5):
            raise ValueError(f"maturity.{domain} must be null or an integer from 0 to 5")
        if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target <= 5:
            raise ValueError(f"targets.{domain} must be an integer from 0 to 5")
        normalized_maturity[domain] = current
        normalized_targets[domain] = target
    allowed_phase_states = {"not_started", "planned", "in_progress", "complete", "blocked"}
    normalized_phases = {}
    for phase in ZERO_TRUST_PHASES:
        state = str(phases.get(phase, defaults["phases"][phase]))
        if state not in allowed_phase_states:
            raise ValueError(f"phases.{phase} is not a supported status")
        normalized_phases[phase] = state
    normalized_controls = {}
    for control in ZERO_TRUST_CONTROL_IDS:
        value = controls.get(control, False)
        if not isinstance(value, bool):
            raise ValueError(f"controls.{control} must be a boolean")
        normalized_controls[control] = value
    normalized_ai_controls = {}
    for control in ZERO_TRUST_AI_CONTROL_IDS:
        value = ai_controls.get(control, False)
        if not isinstance(value, bool):
            raise ValueError(f"ai_controls.{control} must be a boolean")
        normalized_ai_controls[control] = value
    review_date = text_fields["review_date"]
    if review_date:
        try:
            datetime.strptime(review_date, "%Y-%m-%d")
        except ValueError as error:
            raise ValueError("review_date must be YYYY-MM-DD") from error
    return {
        **text_fields,
        "maturity": normalized_maturity,
        "targets": normalized_targets,
        "phases": normalized_phases,
        "controls": normalized_controls,
        "ai_controls": normalized_ai_controls,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def load_zero_trust_program():
    with zero_trust_program_lock:
        stored = read_json_store(ZERO_TRUST_PROGRAM_FILE, {})
    defaults = default_zero_trust_program()
    if not isinstance(stored, dict):
        return defaults
    merged = {**defaults, **stored}
    merged["maturity"] = {**defaults["maturity"], **(stored.get("maturity") or {})}
    merged["targets"] = {**defaults["targets"], **(stored.get("targets") or {})}
    merged["phases"] = {**defaults["phases"], **(stored.get("phases") or {})}
    merged["controls"] = {**defaults["controls"], **(stored.get("controls") or {})}
    merged["ai_controls"] = {**defaults["ai_controls"], **(stored.get("ai_controls") or {})}
    return merged


def save_zero_trust_program(payload):
    profile = validate_zero_trust_program(payload)
    with zero_trust_program_lock:
        write_json_store(ZERO_TRUST_PROGRAM_FILE, profile)
        try:
            ZERO_TRUST_PROGRAM_FILE.chmod(0o600)
        except OSError:
            pass
    return profile


def _reject_sensitive_event_fields(value, path="event"):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in ZERO_TRUST_SENSITIVE_EVENT_KEYS:
                raise ValueError(f"Sensitive field '{key}' is not allowed in security events")
            _reject_sensitive_event_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_event_fields(child, f"{path}[{index}]")


def validate_zero_trust_event(payload):
    if not isinstance(payload, dict):
        raise ValueError("Event body must be a JSON object")
    _reject_sensitive_event_fields(payload)
    event_type = str(payload.get("event_type") or "").strip()
    source = payload.get("source")
    event_time = str(payload.get("event_time") or "").strip()
    if not event_type or len(event_type) > 160:
        raise ValueError("event_type is required and must be at most 160 characters")
    if not isinstance(source, dict) or not str(source.get("system") or "").strip():
        raise ValueError("source.system is required")
    try:
        parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("event_time must be an ISO 8601 timestamp") from error
    if parsed_time.tzinfo is None:
        raise ValueError("event_time must include a timezone")
    event = dict(payload)
    event["event_id"] = str(event.get("event_id") or uuid.uuid4())
    event["event_version"] = str(event.get("event_version") or "1.0")
    event["event_type"] = event_type
    event["event_time"] = parsed_time.astimezone(timezone.utc).isoformat()
    event["received_at"] = datetime.now(timezone.utc).isoformat()
    if len(json.dumps(event, ensure_ascii=True).encode("utf-8")) > ZERO_TRUST_MAX_EVENT_BYTES:
        raise ValueError("Event exceeds the 64 KB size limit")
    return event


def append_zero_trust_event(event):
    ZERO_TRUST_EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with zero_trust_event_lock, ZERO_TRUST_EVENT_FILE.open("a", encoding="utf-8") as destination:
        destination.write(json.dumps(event, separators=(",", ":")) + "\n")


def read_zero_trust_events(limit=100, event_type=""):
    if not ZERO_TRUST_EVENT_FILE.exists():
        return []
    with zero_trust_event_lock, ZERO_TRUST_EVENT_FILE.open("r", encoding="utf-8") as source:
        lines = source.readlines()
    records = []
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event_type and event_type.casefold() not in str(event.get("event_type") or "").casefold():
            continue
        records.append(event)
        if len(records) >= limit:
            break
    return records


def evaluate_zero_trust_policy(payload):
    if not isinstance(payload, dict):
        raise ValueError("Decision request must be a JSON object")
    subject = payload.get("subject")
    device = payload.get("device")
    resource = payload.get("resource")
    context = payload.get("context") or {}
    action = str(payload.get("action") or "").strip()
    if not all(isinstance(part, dict) for part in (subject, device, resource, context)) or not action:
        raise ValueError("subject, device, resource, context objects and action are required")
    reasons = []
    obligations = ["record_audit_event"]
    denied = False
    step_up = False
    device_risk = str(device.get("edr_risk") or "unknown").lower()
    identity_risk = str(subject.get("risk") or "unknown").lower()
    certificate = str(device.get("certificate_status") or "unknown").lower()
    auth_strength = str(subject.get("authentication_strength") or "none").lower()

    if device.get("managed") is False or device.get("compliant") is False:
        denied = True
        reasons.append("DEVICE_NOT_MANAGED_OR_COMPLIANT")
    if device_risk in ("high", "critical"):
        denied = True
        reasons.append("ENDPOINT_RISK_TOO_HIGH")
    if certificate in ("expired", "revoked", "invalid"):
        denied = True
        reasons.append("DEVICE_CERTIFICATE_INVALID")
    if identity_risk == "critical":
        denied = True
        reasons.append("IDENTITY_RISK_CRITICAL")
    elif identity_risk in ("high", "unknown"):
        step_up = True
        reasons.append("IDENTITY_RISK_REQUIRES_REVIEW")
    if auth_strength not in ("phishing-resistant", "certificate", "fido2"):
        step_up = True
        reasons.append("PHISHING_RESISTANT_AUTH_REQUIRED")
    if device.get("managed") is None or device.get("compliant") is None:
        step_up = True
        reasons.append("DEVICE_POSTURE_UNVERIFIED")
    if certificate == "unknown":
        step_up = True
        reasons.append("CERTIFICATE_STATUS_UNVERIFIED")
    if device_risk == "unknown":
        step_up = True
        reasons.append("ENDPOINT_RISK_UNAVAILABLE")

    classification = str(resource.get("classification") or "unknown").lower()
    network_zone = str(context.get("network_zone") or "unknown").lower()
    session_age = context.get("session_age_minutes")
    if classification in ("confidential", "restricted", "high"):
        obligations.extend(["disable_unapproved_download", "record_sensitive_access"])
    if network_zone not in ("trusted", "managed"):
        obligations.append("restrict_to_application_resource")
        reasons.append("UNTRUSTED_OR_UNKNOWN_NETWORK_ZONE")
    if isinstance(session_age, (int, float)) and session_age > 30:
        step_up = True
        reasons.append("SESSION_REAUTHENTICATION_REQUIRED")

    decision = "deny" if denied else "step_up" if step_up else "allow_with_controls" if len(obligations) > 1 else "allow"
    now = datetime.now(timezone.utc)
    response = {
        "decision": decision,
        "decision_id": str(uuid.uuid4()),
        "policy_version": "zt-baseline-v1",
        "decided_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "expires_in_seconds": 300,
        "reason_codes": reasons or ["BASELINE_POLICY_SATISFIED"],
        "obligations": list(dict.fromkeys(obligations)),
        "enforcement": "simulation_only",
    }
    response["audit_event"] = {
        "event_version": "1.0",
        "event_type": "access.decision",
        "event_time": now.isoformat(),
        "source": {"system": "zero-trust-policy", "environment": "local"},
        "subject": {"identity_id": str(subject.get("id") or "unknown")},
        "device": {"device_id": str(device.get("id") or "unknown")},
        "resource": {"resource_id": str(resource.get("id") or "unknown")},
        "action": action,
        "outcome": decision,
        "decision_id": response["decision_id"],
        "policy_version": response["policy_version"],
        "reason_codes": reasons or ["BASELINE_POLICY_SATISFIED"],
    }
    return response


def _zt_event_text(event):
    values = []
    def collect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                values.append(str(key))
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
        elif value is not None:
            values.append(str(value))
    collect(event)
    return " ".join(values).casefold()


def _zt_event_actor(event):
    subject = event.get("subject") if isinstance(event.get("subject"), dict) else {}
    return str(subject.get("identity_id") or event.get("user_id") or event.get("username") or "unknown")


def _zt_event_timestamp(event):
    value = str(event.get("event_time") or "")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def zero_trust_detections_payload(lookback_minutes=30):
    lookback_minutes = max(1, min(30 * 24 * 60, int(lookback_minutes)))
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=lookback_minutes)
    events = [event for event in read_zero_trust_events(50000) if (stamp := _zt_event_timestamp(event)) and stamp >= cutoff]
    detections = []
    normalized_text = {str(event.get("event_id") or index): re.sub(r"[_\-.]+", " ", _zt_event_text(event)) for index, event in enumerate(events)}

    def text_for(event):
        return normalized_text[str(event.get("event_id") or events.index(event))]

    def add_detection(rule_id, title, severity, matching, explanation, playbook_id=None):
        if not matching:
            return
        event_ids = sorted({str(event.get("event_id") or "") for event in matching if event.get("event_id")})
        evidence = ":".join(event_ids) or str(len(matching))
        detection_id = hashlib.sha256(f"{rule_id}:{evidence}".encode("utf-8")).hexdigest()[:20]
        detections.append({
            "detection_id": detection_id,
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "matched_count": len(matching),
            "subjects": sorted({_zt_event_actor(event) for event in matching}),
            "evidence_event_ids": event_ids,
            "first_seen": min((_zt_event_timestamp(event) for event in matching if _zt_event_timestamp(event)), default=None).isoformat() if matching else None,
            "last_seen": max((_zt_event_timestamp(event) for event in matching if _zt_event_timestamp(event)), default=None).isoformat() if matching else None,
            "explanation": explanation,
            "playbook_id": playbook_id,
            "response_mode": "recommendation_only",
        })

    feed_match_events = [
        event for event in events
        if isinstance(event.get("threat_feed_matches"), list) and event["threat_feed_matches"]
    ]
    add_detection(
        "local-threat-feed-match",
        "Inbound event matched a malicious indicator feed",
        "high",
        feed_match_events,
        "An inbound event contains one or more IP, domain/URL-host, or file-hash indicators present in the local threat-feed index.",
        "threat-indicator-triage",
    )

    enrollment_failures = [event for event in events if "enroll" in text_for(event) and any(term in text_for(event) for term in ("fail", "wrong signature", "error"))]
    enrollment_by_device = {}
    for event in enrollment_failures:
        device_id = str((event.get("device") or {}).get("device_id") or event.get("device_id") or "unknown")
        enrollment_by_device.setdefault(device_id, []).append(event)
    repeated_enrollment = [event for device_events in enrollment_by_device.values() if len(device_events) >= 5 for event in device_events]
    if repeated_enrollment:
        add_detection("enrollment-failures", "Five or more enrollment failures on one device", "high", repeated_enrollment, "At least 5 enrollment failures were recorded for the same device in the lookback window.", "enrollment-failure")

    wrong_signatures = [event for event in events if "wrong signature" in text_for(event) or "signature validation failed" in text_for(event)]
    if len(wrong_signatures) > 3:
        add_detection("wrong-signature", "Repeated certificate signature failures", "high", wrong_signatures, "More than 3 wrong-signature events were recorded in the lookback window.", "signature-failure")

    mfa_bypass = [event for event in events if "mfa" in text_for(event) and any(term in text_for(event) for term in ("bypass", "disabled", "skip"))]
    add_detection("mfa-bypass", "MFA bypass or disable attempt", "critical", mfa_bypass, "An event indicates MFA bypass, disablement, or skip attempt.")

    discarded_card = [event for event in events if "discard" in text_for(event) and any(term in text_for(event) for term in ("card", "credential", "authentication", "attempt"))]
    add_detection("discarded-card-use", "Discarded card use attempt", "critical", discarded_card, "A discarded-card or credential use attempt was recorded.", "discarded-card")

    def device_object(event):
        return event.get("device") if isinstance(event.get("device"), dict) else {}
    high_device_risk = [event for event in events if ("device" in str(event.get("event_type") or "").casefold() and "risk" in str(event.get("event_type") or "").casefold() and str(device_object(event).get("risk") or event.get("risk") or "").casefold() in ("high", "critical")) or "edr risk high" in text_for(event)]
    add_detection("high-risk-device", "High-risk endpoint signal", "high", high_device_risk, "An endpoint or device risk event reports high/critical risk.", "high-risk-device")

    certificate_events = [event for event in events if "certificate.issued" in str(event.get("event_type") or "").casefold() or "certificate issued" in _zt_event_text(event)]
    by_actor = {}
    for event in certificate_events:
        by_actor.setdefault(_zt_event_actor(event), []).append(event)
    duplicate_certificate = []
    for actor_events in by_actor.values():
        ordered = sorted((event for event in actor_events if _zt_event_timestamp(event)), key=_zt_event_timestamp)
        for start in range(len(ordered)):
            group = [event for event in ordered[start:] if (_zt_event_timestamp(event) - _zt_event_timestamp(ordered[start])).total_seconds() <= 600]
            if len(group) > 1:
                duplicate_certificate.extend(group)
                break
    add_detection("multiple-certificates", "Multiple certificates issued to one identity", "high", duplicate_certificate, "One identity received multiple certificates within 10 minutes.", "enrollment-failure")

    role_changes = [event for event in events if "role" in str(event.get("event_type") or "").casefold() and any(term in str(event.get("event_type") or "").casefold() for term in ("change", "assign", "grant")) and (event.get("context") or {}).get("within_change_window") is False]
    add_detection("privilege-escalation", "Privilege change outside approved window", "critical", role_changes, "A role/privilege change was explicitly marked outside its change window.")

    downloads = [event for event in events if "download" in str(event.get("event_type") or "").casefold() or str(event.get("action") or "").casefold() == "download"]
    download_totals = {}
    for event in downloads:
        actor = _zt_event_actor(event)
        try:
            count_value = max(1, int(event.get("count") or event.get("file_count") or 1))
        except (TypeError, ValueError):
            count_value = 1
        download_totals[actor] = download_totals.get(actor, 0) + count_value
    mass_download_events = [event for event in downloads if download_totals.get(_zt_event_actor(event), 0) > 500]
    add_detection("mass-download", "Mass download activity", "high", mass_download_events, "More than 500 download actions were recorded for one identity in the lookback window.")

    travel_groups = {}
    for event in events:
        event_type = str(event.get("event_type") or "").casefold()
        if not ("login" in event_type and any(term in event_type for term in ("success", "succeeded", "authenticated"))):
            continue
        context = event.get("context") if isinstance(event.get("context"), dict) else {}
        location = context.get("location") or event.get("location") or {}
        country = location.get("country") if isinstance(location, dict) else str(location)
        if country:
            travel_groups.setdefault(_zt_event_actor(event), []).append((event, str(country).casefold()))
    impossible_travel = []
    for logins in travel_groups.values():
        logins.sort(key=lambda item: _zt_event_timestamp(item[0]) or datetime.min.replace(tzinfo=timezone.utc))
        for (previous, prev_country), (current, curr_country) in zip(logins, logins[1:]):
            elapsed = (_zt_event_timestamp(current) - _zt_event_timestamp(previous)).total_seconds()
            if prev_country != curr_country and 0 <= elapsed <= 30 * 60:
                impossible_travel.extend((previous, current))
    add_detection("impossible-travel", "Rapid cross-country sign-ins", "high", impossible_travel, "Sign-ins from different reported countries occurred within 30 minutes; verify location precision before action.")

    wazuh_rules = {
        "110010": ("Credential enrollment/activation failure", "medium", "enrollment-failure"),
        "110011": ("Wrong signature or invalid signer certificate", "high", "signature-failure"),
        "110012": ("Repeated enrollment failures on one device", "high", "enrollment-burst"),
        "110020": ("Discarded or revoked credential use", "critical", "terminal-credential-use"),
        "110030": ("Credential/card discarded or revoked", "medium", "terminal-credential-use"),
        "110031": ("Certificate issued outside change window", "high", "unapproved-admin-change"),
        "110032": ("Mass credential issuance", "high", "issuance-burst"),
        "110040": ("CA/OCSP/PKI connector failure", "high", "pki-outage"),
        "110041": ("Certificate expiring within 30 days", "medium", "certificate-expiry"),
        "110050": ("Unapproved administrator/card/CA profile change", "critical", "unapproved-admin-change"),
    }
    for rule_id, (title, severity, playbook_id) in wazuh_rules.items():
        matching = [event for event in events if str((event.get("details") or {}).get("rule_id") or event.get("rule_id") or "") == rule_id or str(event.get("reason_code") or "") == f"WAZUH_RULE_{rule_id}"]
        add_detection(f"wazuh-{rule_id}", title, severity, matching, f"Matched Wazuh custom rule {rule_id}.", playbook_id)

    return {"lookback_minutes": lookback_minutes, "evaluated_at": now.isoformat(), "events_evaluated": len(events), "source": "local-event-store", "rules_evaluated": 19, "detections": detections}


def zero_trust_analytics_payload(lookback_hours=24):
    lookback_hours = max(1, min(24 * 90, int(lookback_hours)))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    events = [event for event in read_zero_trust_events(50000) if (stamp := _zt_event_timestamp(event)) and stamp >= cutoff]
    def find(predicate):
        matches = [event for event in events if predicate(event)]
        return {"value": len(matches) if matches else None, "observedEvents": len(matches), "status": "observed" if matches else "no_telemetry"}
    def event_type(event):
        return str(event.get("event_type") or "").casefold()
    def source_system(event):
        return str((event.get("source") or {}).get("system") or "").casefold()
    def event_text(event):
        return re.sub(r"[_\-.]+", " ", _zt_event_text(event))
    def unavailable(reason):
        return {"value": None, "observedEvents": 0, "status": "requires_source", "required_source": reason}
    metrics = {
        "failed_logins": find(lambda event: "login" in event_type(event) and ("fail" in event_type(event) or str(event.get("outcome") or "").casefold() in ("failure", "failed"))),
        "mfa_bypass_attempts": find(lambda event: "mfa" in event_text(event) and any(term in event_text(event) for term in ("bypass", "disabled", "skip"))),
        "privilege_escalations": find(lambda event: "role" in event_type(event) and any(term in event_type(event) for term in ("change", "assign", "grant"))),
        "dormant_accounts": find(lambda event: "dormant" in event_type(event) or "dormant account" in event_text(event)),
        "excess_access_requests": find(lambda event: "access.request" in event_type(event) and str(event.get("outcome") or "").casefold() in ("rejected", "denied", "excessive")),
        "service_account_misuse": find(lambda event: "service" in event_text(event) and any(term in event_text(event) for term in ("misuse", "anomalous", "unauthorized"))),
        "smart_card_misuse": find(lambda event: any(term in event_text(event) for term in ("smart card", "smartcard", "virtual card")) and any(term in event_text(event) for term in ("misuse", "discard", "failed", "attempt"))),
        "enrollment_failures": find(lambda event: "enroll" in event_text(event) and any(term in event_text(event) for term in ("fail", "wrong signature", "error"))),
        "wrong_signatures": find(lambda event: "wrong signature" in event_text(event) or "signature validation failed" in event_text(event)),
        "certificate_issues": find(lambda event: "certificate" in event_type(event) and any(term in event_type(event) for term in ("issued", "expired", "revoked", "status"))),
        "certificate_enrollment_pending": find(lambda event: "enrollment.pending" in event_type(event) or "certificate pending" in event_text(event)),
        "discarded_cards": find(lambda event: "discard" in event_text(event) and "card" in event_text(event)),
        "device_patch_status": find(lambda event: "patch" in event_type(event) or "patch level" in event_text(event)),
        "edr_health": find(lambda event: "edr" in event_text(event) and any(term in event_text(event) for term in ("healthy", "unhealthy", "risk"))),
        "device_compliance": find(lambda event: "compliance" in event_type(event) or "compliant" in event_text(event)),
        "disk_encryption": find(lambda event: "encryption" in event_text(event) and "disk" in event_text(event)),
        "rooted_or_jailbroken": find(lambda event: any(term in event_text(event) for term in ("rooted", "jailbroken"))),
        "malware_detections": find(lambda event: "malware" in event_type(event) or "malware detection" in event_text(event)),
        "network_sessions": find(lambda event: any(term in event_type(event) for term in ("network.session", "ztna.session", "vpn.session"))),
        "sase_access_sessions": find(lambda event: any(term in event_type(event) for term in ("sase", "ztna.session", "vpn.session")) or "cato" in source_system(event) or "sase" in source_system(event)),
        "sase_denials": find(lambda event: ("sase" in event_type(event) or "cato" in source_system(event) or "sase" in source_system(event)) and str(event.get("outcome") or "").casefold() in ("denied", "blocked", "failure", "rejected")),
        "dc2cloud_security_events": find(lambda event: "dc2cloud" in event_type(event) or "dc2cloud" in source_system(event)),
        "zero_trust_policy_decisions": find(lambda event: "access.policy.decided" in event_type(event) or source_system(event) == "zero-trust-policy"),
        "ai_security_events": find(lambda event: any(term in event_type(event) for term in ("ai.", "llm", "agent.")) or any(term in event_text(event) for term in ("prompt injection", "model abuse", "ai tool invocation"))),
        "lateral_movement": find(lambda event: "lateral" in event_text(event)),
        "dns_anomalies": find(lambda event: "dns" in event_type(event) and any(term in event_text(event) for term in ("anomaly", "tunnel", "malicious"))),
        "data_downloads": find(lambda event: "download" in event_type(event) or str(event.get("action") or "").casefold() == "download"),
        "data_uploads": find(lambda event: "upload" in event_type(event) or str(event.get("action") or "").casefold() == "upload"),
        "data_copy_print_usb_email": find(lambda event: any(term in event_text(event) for term in ("copy", "print", "usb", "email attachment"))),
        "mfa_coverage": unavailable("IAM directory plus enrolled-user denominator"),
        "device_compliance_percent": unavailable("MDM compliance API plus managed-device denominator"),
        "healthy_devices": unavailable("EDR health API"),
        "mean_time_to_detect": unavailable("incident lifecycle timestamps from SIEM/ITSM"),
        "mean_time_to_respond": unavailable("incident resolution timestamps from SIEM/ITSM"),
    }
    detection_result = zero_trust_detections_payload(lookback_hours * 60)
    metrics["impossible_travel"] = {"value": sum(item["rule_id"] == "impossible-travel" for item in detection_result["detections"]), "observedEvents": sum(item["matched_count"] for item in detection_result["detections"] if item["rule_id"] == "impossible-travel"), "status": "observed" if any(item["rule_id"] == "impossible-travel" for item in detection_result["detections"]) else "no_telemetry"}
    return {"lookback_hours": lookback_hours, "evaluated_at": datetime.now(timezone.utc).isoformat(), "events_evaluated": len(events), "source": "local-event-store", "metrics": metrics, "limitations": ["Counts require canonical events from the corresponding provider. No telemetry means unavailable, not zero activity.", "MFA coverage, device compliance percentage, healthy-device totals, and MTTD/MTTR require authoritative IAM/MDM/EDR/ITSM denominators and lifecycle records."]}


def zero_trust_risk_score(payload):
    fields = ("identity", "device", "application", "data", "location")
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), dict):
        raise ValueError("components object is required")
    components = {}
    for field in fields:
        value = payload["components"].get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
            raise ValueError(f"{field} risk must be a number between 0 and 100")
        components[field] = round(value)
    raw_total = sum(components.values())
    score = min(100, raw_total)
    decision = "block" if score >= 80 else "step_up" if score >= 60 else "allow_with_controls" if score >= 30 else "allow"
    return {"components": components, "raw_total": raw_total, "score": score, "decision": decision, "method": "deterministic_sum_capped_at_100", "enforcement": "simulation_only", "evaluated_at": datetime.now(timezone.utc).isoformat()}


PLAYBOOK_PROVIDER_CONNECTORS = {
    "Wazuh": {"tools": ["wazuh"], "aliases": ["wazuh"]},
    "Wazuh/OpenSearch": {"tools": ["wazuh", "opensearch"], "aliases": ["wazuh", "opensearch"]},
    "Wazuh/EDR": {"tools": ["wazuh", "crowdstrike", "defender", "sentinelone"], "aliases": ["wazuh"]},
    "MISP/OpenCTI": {"tools": ["misp"], "aliases": ["misp", "opencti"]},
    "Keycloak/IAM": {"tools": ["keycloak", "entra"], "aliases": ["keycloak"]},
    "IDnomic CMS/EJBCA": {"tools": [], "aliases": ["idnomic", "ejbca"]},
    "IDnomic CMS": {"tools": [], "aliases": ["idnomic"]},
    "EJBCA/IDnomic CMS": {"tools": [], "aliases": ["ejbca", "idnomic"]},
    "GLPI/Jira": {"tools": ["bmc", "servicenow"], "aliases": ["glpi", "jira"]},
    "OpenZiti/NetBird": {"tools": [], "aliases": ["openziti", "netbird"]},
    "PKI operator": {"tools": [], "aliases": [], "manual": True},
}


def resolve_playbook_provider(provider, credential_store, event_connectors):
    """Report how a playbook provider could be reached locally.

    Saved credentials and registered receivers are configuration only; neither
    proves a verified live vendor connection, so no action is ever executable.
    """
    mapping = PLAYBOOK_PROVIDER_CONNECTORS.get(provider, {})
    configured = [tool for tool in mapping.get("tools", []) if credential_store.get(tool)]
    aliases = [str(alias).casefold() for alias in mapping.get("aliases", [])]
    receivers = [
        str(item.get("name"))
        for item in event_connectors
        if any(alias in str(item.get("name") or "").casefold() for alias in aliases)
    ]
    if configured:
        availability = "credentials_configured"
    elif receivers:
        availability = "event_receiver_registered"
    elif mapping.get("manual"):
        availability = "manual_human_step"
    else:
        availability = "connector_required"
    return {
        "provider": provider,
        "availability": availability,
        "configured_tools": configured,
        "event_receivers": receivers,
        "executable": False,
    }


def playbook_provider_context():
    try:
        credential_store = load_integration_credential_store()
    except Exception:
        credential_store = {}
    try:
        event_connectors = [public_integration_connector(item) for item in load_integration_connectors()]
    except Exception:
        event_connectors = []
    return credential_store, event_connectors


def zero_trust_playbook_catalog():
    credential_store, event_connectors = playbook_provider_context()
    catalog = _zero_trust_playbook_definitions()
    for playbook in catalog:
        statuses = [resolve_playbook_provider(provider, credential_store, event_connectors) for provider in playbook["requires"]]
        playbook["provider_status"] = statuses
        playbook["connected_providers"] = sum(1 for item in statuses if item["availability"] in ("credentials_configured", "event_receiver_registered"))
        playbook["total_providers"] = len(statuses)
    return catalog


def _zero_trust_playbook_definitions():
    return [
        {"id": "signature-failure", "name": "Signature Validation Failure", "trigger": "Wazuh rule 110011", "actions": ["Validate alert schema", "Deduplicate CMS correlation ID", "Collect CMS/EJBCA/OCSP evidence", "Create high-severity PKI incident", "Block credential activation"], "requires": ["Wazuh", "IDnomic CMS/EJBCA", "IDnomic CMS/EJBCA", "GLPI/Jira", "IDnomic CMS"], "approval_required": [4]},
        {"id": "enrollment-burst", "name": "Repeated Enrollment Failures", "trigger": "Wazuh rule 110012 or more than 5 failures per device in 30 minutes", "actions": ["Review actor/device history", "Enrich source IP", "Create critical SOC incident", "Apply 30-minute enrollment freeze", "Notify SOC and PKI"], "requires": ["Wazuh", "MISP/OpenCTI", "GLPI/Jira", "IDnomic CMS", "Wazuh"], "approval_required": [3]},
        {"id": "terminal-credential-use", "name": "Discarded or Revoked Credential Use", "trigger": "Wazuh rule 110020", "actions": ["Deny authentication", "Revoke active sessions", "Verify certificate revocation", "Create critical incident", "Notify SOC"], "requires": ["Keycloak/IAM", "Keycloak/IAM", "EJBCA/IDnomic CMS", "GLPI/Jira", "Wazuh"], "approval_required": [1, 2]},
        {"id": "issuance-burst", "name": "Credential Issuance Burst", "trigger": "Wazuh rule 110032", "actions": ["Check approved change request", "List operator-issued credentials", "Create critical PKI incident", "Freeze issuance capability", "Review/revoke issued certificates"], "requires": ["GLPI/Jira", "IDnomic CMS/EJBCA", "GLPI/Jira", "IDnomic CMS/EJBCA", "EJBCA/IDnomic CMS"], "approval_required": [3, 4]},
        {"id": "pki-outage", "name": "PKI or CA Service Failure", "trigger": "Wazuh rule 110040", "actions": ["Check CMS/CA/OCSP/HSM health", "Correlate outage evidence", "Create PKI platform incident", "Notify PKI on-call", "Approve failover or connector restart"], "requires": ["IDnomic CMS/EJBCA", "Wazuh/OpenSearch", "GLPI/Jira", "Wazuh", "PKI operator"], "approval_required": [4]},
        {"id": "certificate-expiry", "name": "Certificate Expiration", "trigger": "Wazuh rule 110041 or certificate expiration event", "actions": ["Identify certificate owner and dependent service", "Notify PKI owner", "Create renewal ticket", "Renew certificate after approval"], "requires": ["IDnomic CMS/EJBCA", "Wazuh", "GLPI/Jira", "EJBCA/IDnomic CMS"], "approval_required": [3]},
        {"id": "unapproved-admin-change", "name": "Unapproved Administrative Change", "trigger": "Wazuh rule 110050", "actions": ["Verify change request", "Snapshot profile configuration", "Create critical SOC incident", "Revoke administrative sessions", "Review/rollback configuration"], "requires": ["GLPI/Jira", "IDnomic CMS/EJBCA", "GLPI/Jira", "Keycloak/IAM", "PKI operator"], "approval_required": [3, 4]},
        {"id": "enrollment-failure", "name": "Enrollment Failure", "trigger": "Wazuh rule 110010 or enrollment failure event", "actions": ["Collect enrollment evidence", "Create PKI incident", "Notify PKI team"], "requires": ["IDnomic CMS/EJBCA", "GLPI/Jira", "Wazuh"]},
        {"id": "high-risk-device", "name": "High-Risk Device", "trigger": "EDR risk reported high or critical", "actions": ["Revoke sessions", "Disconnect ZTNA", "Quarantine endpoint", "Open ticket"], "requires": ["Keycloak/IAM", "OpenZiti/NetBird", "Wazuh/EDR", "GLPI/Jira"], "approval_required": [0, 1, 2]},
    ]


def record_zero_trust_playbook_run(payload):
    if not isinstance(payload, dict):
        raise ValueError("Playbook request must be a JSON object")
    playbook = next((item for item in zero_trust_playbook_catalog() if item["id"] == payload.get("playbook_id")), None)
    if not playbook:
        raise ValueError("Unknown playbook_id")
    now = datetime.now(timezone.utc).isoformat()
    provider_status = playbook.get("provider_status") or []
    actions = []
    for index, (action, provider) in enumerate(zip(playbook["actions"], playbook["requires"])):
        requires_approval = index in playbook.get("approval_required", [])
        status_entry = provider_status[index] if index < len(provider_status) else {"availability": "connector_required"}
        actions.append({
            "name": action,
            "provider": provider,
            "status": "approval_and_connector_required" if requires_approval else "connector_required",
            "provider_availability": status_entry.get("availability"),
            "configured_tools": status_entry.get("configured_tools", []),
            "event_receivers": status_entry.get("event_receivers", []),
            "requires_approval": requires_approval,
            "executed": False,
        })
    run = {
        "run_id": str(uuid.uuid4()),
        "playbook_id": playbook["id"],
        "playbook_name": playbook["name"],
        "trigger": str(payload.get("trigger") or "manual dry run")[:500],
        "created_at": now,
        "mode": "dry_run",
        "external_actions_executed": False,
        "connected_providers": playbook.get("connected_providers", 0),
        "total_providers": playbook.get("total_providers", len(playbook["requires"])),
        "actions": actions,
    }
    with zero_trust_event_lock, ZERO_TRUST_PLAYBOOK_RUN_FILE.open("a", encoding="utf-8") as destination:
        destination.write(json.dumps(run, separators=(",", ":")) + "\n")
    append_zero_trust_event(validate_zero_trust_event({
        "event_type": "automation.playbook.dry_run",
        "event_time": now,
        "source": {"system": "zero-trust-playbook", "environment": "local"},
        "outcome": "simulated",
        "playbook": {"id": playbook["id"], "name": playbook["name"]},
        "run_id": run["run_id"],
        "trigger": run["trigger"],
        "external_actions_executed": False,
    }))
    return run


def read_zero_trust_playbook_runs(limit=100):
    if not ZERO_TRUST_PLAYBOOK_RUN_FILE.exists():
        return []
    with zero_trust_event_lock, ZERO_TRUST_PLAYBOOK_RUN_FILE.open("r", encoding="utf-8") as source:
        lines = source.readlines()
    result = []
    for line in reversed(lines):
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(result) >= limit:
            break
    return result


def load_integration_connectors():
    return read_json_store(INTEGRATION_CONNECTORS_FILE, [])


def load_integration_feed_state():
    state = read_json_store(INTEGRATION_FEED_STATE_FILE, {})
    if not isinstance(state, dict):
        raise ValueError("Integration feed state has an invalid shape")
    return {"rubrikApiEnabled": state.get("rubrikApiEnabled", True) is not False}


def save_integration_feed_state(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("rubrikApiEnabled"), bool):
        raise ValueError("rubrikApiEnabled must be a boolean")
    state = {"rubrikApiEnabled": payload["rubrikApiEnabled"]}
    with integration_feed_state_lock:
        write_json_store(INTEGRATION_FEED_STATE_FILE, state)
    return state


def public_integration_connector(connector):
    return {key: value for key, value in connector.items() if key != "tokenHash"}


def create_integration_connector(payload):
    if not isinstance(payload, dict):
        raise ValueError("Connector body must be a JSON object")
    transport = str(payload.get("transport") or "").strip().lower()
    if transport not in ("syslog", "wazuh", "idnomic", "rubrik", "webhook", "api", "other"):
        raise ValueError("Transport must be syslog, Wazuh JSON, IDnomic JSON, Rubrik PD-CEF, webhook, API, or other")
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 100:
        raise ValueError("Connector name is required and must be at most 100 characters")
    token = secrets.token_urlsafe(32)
    connector = {
        "id": str(uuid.uuid4()),
        "name": name,
        "transport": transport,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "lastReceivedAt": None,
        "eventCount": 0,
        "enabled": True,
        "tokenHash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }
    with integration_connectors_lock:
        connectors = load_integration_connectors()
        connectors.append(connector)
        write_json_store(INTEGRATION_CONNECTORS_FILE, connectors)
    endpoint = f"/api/integrations/connectors/{connector['id']}/ingest"
    return {**public_integration_connector(connector), "token": token, "endpoint": endpoint}


def set_integration_connector_enabled(connector_id, enabled):
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    with integration_connectors_lock:
        connectors = load_integration_connectors()
        for connector in connectors:
            if connector.get("id") == connector_id:
                connector["enabled"] = enabled
                write_json_store(INTEGRATION_CONNECTORS_FILE, connectors)
                return public_integration_connector(connector)
    return None


def authenticate_integration_connector(connector_id, authorization):
    scheme, _, token = str(authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with integration_connectors_lock:
        connector = next((item for item in load_integration_connectors() if item.get("id") == connector_id), None)
    if not connector or not hmac.compare_digest(str(connector.get("tokenHash") or ""), token_hash):
        return None
    if connector.get("enabled", True) is False:
        raise PermissionError("Integration connector is disabled")
    return connector


def parse_syslog_events(raw_text, connector_name):
    events = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        rfc5424 = re.match(r"^<(\d{1,3})>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line)
        rfc3164 = re.match(r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$", line)
        if rfc5424:
            priority = int(rfc5424.group(1))
            timestamp = rfc5424.group(2)
            hostname, app_name, process_id, message_id, structured_data, message = rfc5424.groups()[2:]
            try:
                event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).isoformat()
            except ValueError:
                event_time = datetime.now(timezone.utc).isoformat()
        elif rfc3164:
            priority = int(rfc3164.group(1))
            try:
                parsed = datetime.strptime(f"{datetime.now(timezone.utc).year} {rfc3164.group(2)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                event_time = parsed.isoformat()
            except ValueError:
                event_time = datetime.now(timezone.utc).isoformat()
            hostname, app_name, message = rfc3164.group(3), rfc3164.group(4), rfc3164.group(5)
            process_id, message_id, structured_data = "-", "-", "-"
        else:
            raise ValueError("Syslog input must contain RFC 5424 or RFC 3164 messages")
        events.append({
            "event_version": "1.0",
            "event_type": "syslog.message",
            "event_time": event_time,
            "source": {"system": connector_name, "transport": "syslog"},
            "outcome": "observed",
            "syslog": {
                "priority": priority,
                "facility": priority // 8,
                "severity": priority % 8,
                "hostname": hostname,
                "app_name": app_name,
                "process_id": process_id,
                "message_id": message_id,
                "structured_data": structured_data,
                "message": message or "",
            },
        })
    if not events:
        raise ValueError("No syslog messages found")
    if len(events) > 100:
        raise ValueError("A syslog request may contain at most 100 lines")
    return events


def normalize_idnomic_event(item, connector_name):
    if not isinstance(item, dict):
        raise ValueError("IDnomic event must be a JSON object")
    sources = [item]
    for key in ("event", "actor", "subject", "device", "credential", "observer", "source", "http", "process"):
        nested = item.get(key)
        if isinstance(nested, dict):
            sources.append(nested)
    normalized_fields = {}
    for source in sources:
        for key, value in source.items():
            normalized_fields[re.sub(r"[^a-z0-9]", "", str(key).casefold())] = value

    def pick(*names):
        for name in names:
            value = normalized_fields.get(re.sub(r"[^a-z0-9]", "", name.casefold()))
            if value not in (None, ""):
                return value
        return None

    action = str(pick("event.action", "action", "title", "internal title") or "IDnomic audit event")
    code = str(pick("event.code", "event code", "identifier", "code") or "")
    raw_reason = str(pick("reason_code", "reason code", "wrong signature") or "")
    wrong_signature_value = pick("wrong signature", "wrong_signature")
    wrong_signature = str(wrong_signature_value or "").strip().casefold() in ("true", "yes", "1", "wrong signature", "invalid")
    combined = f"{action} {code} {raw_reason}".casefold().replace("_", " ").replace("-", " ")
    if wrong_signature or code == "110011" or "wrong signature" in combined or "invalid signer" in combined:
        event_type, reason_code = "credential.enrollment.failed", "WRONG_SIGNATURE"
    elif "enroll" in combined and any(term in combined for term in ("fail", "error")):
        event_type, reason_code = "credential.enrollment.failed", raw_reason or "ENROLLMENT_FAILED"
    elif "discard" in combined and "card" in combined:
        event_type, reason_code = "credential.discarded_card.authentication_attempt", raw_reason or "DISCARDED_CARD_USE"
    elif "certificate" in combined and any(term in combined for term in ("revoke", "revoked")):
        event_type, reason_code = "certificate.revoked", raw_reason or "CERTIFICATE_REVOKED"
    else:
        event_type, reason_code = "idnomic.audit.event", raw_reason or code or None

    raw_time = pick("event_time", "date utc", "date_utc", "timestamp") or datetime.now(timezone.utc).isoformat()
    try:
        event_time = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        event_time = event_time.astimezone(timezone.utc).isoformat()
    except ValueError:
        event_time = datetime.now(timezone.utc).isoformat()
    serial = pick("device.serial_number", "device serial number", "serial_number")
    serial_token = hashlib.sha256(str(serial).encode("utf-8")).hexdigest()[:16] if serial and str(serial).upper() not in ("TOKENIZED", "REDACTED") else str(serial or "TOKENIZED")
    outcome = str(pick("outcome") or ("failure" if event_type.endswith("failed") or "failed" in combined else "observed"))
    return validate_zero_trust_event({
        "event_version": "1.0",
        "event_type": event_type,
        "event_time": event_time,
        "source": {"system": connector_name, "ip": str(pick("source.ip", "remote host", "remote_host") or "")},
        "observer": {"product": "IDnomic/OpenTrust CMS", "product_version": str(pick("application version", "product_version") or ""), "hostname": str(pick("observer.hostname", "dns name", "hostname") or "")},
        "actor": {"identity_id": str(pick("actor.identity_id", "system user id", "user_id") or "unknown"), "realm": str(pick("actor.realm", "system user realm", "user realm") or "unknown")},
        "subject": {"identity_id": str(pick("subject.identity_id", "device holder id", "device_holder_id") or "unknown")},
        "device": {"device_id": str(pick("device.device_id", "device unique id", "device_id") or "unknown"), "serial_number": serial_token},
        "credential": {"status": str(pick("credential.status", "device status", "credential status") or "unknown"), "profile": str(pick("credential.profile", "device management profile", "management profile") or "unknown")},
        "outcome": outcome,
        "reason_code": reason_code,
        "correlation_id": str(pick("correlation_id", "cms error reference", "cms correlation reference") or ""),
        "details": {"event_code": code, "event_action": action[:200], "request_path": str(pick("http.request.path", "uri") or "")[:500], "process_id": str(pick("process.pid", "process identifier", "pid") or "")},
    })


def normalize_rubrik_event(item):
    """Map Rubrik's PagerDuty Common Event Format webhook into a safe canonical event."""
    payload = item.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Rubrik webhook event must contain a PD-CEF payload object")
    summary = str(payload.get("summary") or "").strip()
    if not summary:
        raise ValueError("Rubrik PD-CEF payload.summary is required")

    action = str(item.get("event_action") or "trigger").strip().casefold()
    if action not in {"trigger", "resolve", "acknowledge"}:
        action = "notification"
    severity = str(payload.get("severity") or "unknown").strip().casefold()[:40]
    outcome = "failure" if severity in {"critical", "error"} else "observed"
    raw_time = str(payload.get("timestamp") or datetime.now(timezone.utc).isoformat())

    custom = payload.get("custom_details")
    if not isinstance(custom, dict):
        custom = {}
    safe_detail_names = {
        "object_name", "object_type", "operation", "status", "error_message",
        "cluster_name", "sla_domain", "policy_name", "location",
    }
    details = {
        key: str(value)[:1000]
        for key, value in custom.items()
        if str(key).casefold() in safe_detail_names and isinstance(value, (str, int, float, bool))
    }
    details.update({
        "summary": summary[:2000],
        "severity": severity,
        "event_action": action,
    })
    source_name = payload.get("source")
    return validate_zero_trust_event({
        "event_version": "1.0",
        "event_type": f"rubrik.alert.{action}",
        "event_time": raw_time,
        "source": {
            "system": "Rubrik Security Cloud",
            "transport": "rubrik",
            "environment": "production",
            "provider": str(source_name)[:200] if isinstance(source_name, str) else "Rubrik Security Cloud",
        },
        "outcome": outcome,
        "details": details,
    })


def connector_json_events(payload, connector):
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        events = payload["events"]
    elif isinstance(payload, dict) and isinstance(payload.get("event"), dict):
        events = [payload["event"]]
    elif isinstance(payload, dict):
        events = [payload]
    else:
        raise ValueError("Webhook/API body must be a JSON event object or an events array")
    if not events or len(events) > 100:
        raise ValueError("A webhook/API request must contain 1 to 100 events")
    normalized = []
    for item in events:
        if not isinstance(item, dict):
            raise ValueError("Every event must be a JSON object")
        if connector.get("transport") == "idnomic":
            normalized.append(normalize_idnomic_event(item, connector["name"]))
            continue
        if connector.get("transport") == "rubrik":
            normalized.append(normalize_rubrik_event(item))
            continue
        if connector.get("transport") == "wazuh" and isinstance(item.get("rule"), dict):
            rule = item["rule"]
            agent = item.get("agent") if isinstance(item.get("agent"), dict) else {}
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            rule_id = str(rule.get("id") or "")
            event_types = {
                "110010": "credential.enrollment.failed",
                "110011": "certificate.signature.invalid",
                "110012": "credential.enrollment.failed",
                "110020": "credential.discarded_card.authentication_attempt",
                "110030": "credential.card.discarded",
                "110031": "certificate.issued.outside_change_window",
                "110032": "certificate.issued.mass",
                "110040": "certificate.pki_connector.failure",
                "110041": "certificate.expiring",
                "110050": "identity.role.changed.outside_change_window",
            }
            stamp = str(item.get("timestamp") or datetime.now(timezone.utc).isoformat())
            subject_id = str(data.get("user") or data.get("username") or data.get("srcuser") or "unknown")
            device_id = str(data.get("device_id") or agent.get("id") or "unknown")
            try:
                level = int(rule.get("level") or 0)
            except (TypeError, ValueError):
                level = 0
            event = {
                "event_version": "1.0",
                "event_type": event_types.get(rule_id, "security.alert"),
                "event_time": stamp,
                "source": {"system": connector["name"], "transport": "wazuh", "environment": "production"},
                "subject": {"identity_id": subject_id},
                "device": {"device_id": device_id, "device_name": str(agent.get("name") or data.get("device_name") or "unknown"), "ip": str(agent.get("ip") or "")},
                "outcome": "failure" if level >= 10 else "observed",
                "reason_code": f"WAZUH_RULE_{rule_id}" if rule_id else "WAZUH_ALERT",
                "details": {
                    "rule_id": rule_id,
                    "rule_level": level,
                    "rule_description": str(rule.get("description") or "")[:500],
                    "rule_groups": [str(group)[:80] for group in (rule.get("groups") or [])[:20]],
                    "agent_id": str(agent.get("id") or ""),
                    "agent_name": str(agent.get("name") or ""),
                    "location": str(item.get("location") or "")[:300],
                },
            }
            normalized.append(validate_zero_trust_event(event))
            continue
        event = dict(item)
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        event["source"] = {**source, "system": connector["name"], "transport": connector["transport"]}
        normalized.append(validate_zero_trust_event(event))
    return normalized


def record_connector_receive(connector_id, event_count):
    with integration_connectors_lock:
        connectors = load_integration_connectors()
        for connector in connectors:
            if connector.get("id") == connector_id:
                connector["lastReceivedAt"] = datetime.now(timezone.utc).isoformat()
                connector["eventCount"] = int(connector.get("eventCount") or 0) + event_count
                break
        write_json_store(INTEGRATION_CONNECTORS_FILE, connectors)


def delete_integration_connector(connector_id):
    with integration_connectors_lock:
        connectors = load_integration_connectors()
        updated = [connector for connector in connectors if connector.get("id") != connector_id]
        if len(updated) == len(connectors):
            return False
        write_json_store(INTEGRATION_CONNECTORS_FILE, updated)
        return True


def rotate_integration_connector_token(connector_id):
    with integration_connectors_lock:
        connectors = load_integration_connectors()
        connector = next((item for item in connectors if item.get("id") == connector_id), None)
        if connector is None:
            return None
        token = secrets.token_urlsafe(32)
        connector["tokenHash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
        write_json_store(INTEGRATION_CONNECTORS_FILE, connectors)
    endpoint = f"/api/integrations/connectors/{connector_id}/ingest"
    return {**public_integration_connector(connector), "token": token, "endpoint": endpoint}


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_head(self):
        segments = [unquote(segment) for segment in urlparse(self.path).path.split("/") if segment]
        blocked_extensions = {".py", ".pyc", ".enc", ".key", ".pem", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3", ".jsonl", ".log"}
        if any(segment.startswith(".") or segment.casefold() in {"__pycache__", "tests"} or Path(segment).suffix.casefold() in blocked_extensions for segment in segments):
            self.send_error(403, "Static resource is not available")
            return None
        return super().send_head()

    def list_directory(self, path):
        self.send_error(403, "Directory listings are not available")
        return None

    def end_headers(self):
        if not self.path.startswith("/api/"):
            token = refresh_local_browser_session(self.headers.get("Cookie"))
            self.send_header("Set-Cookie", f"{LOCAL_SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={LOCAL_SESSION_TTL_SECONDS}")
        super().end_headers()

    def require_local_session(self):
        if has_local_browser_session(self.headers.get("Cookie")):
            return True
        self.send_json({"error": "Local browser session missing or expired; reload the dashboard"}, 401)
        return False

    def handle_proxy(self, parsed):
        query = parse_qs(parsed.query)
        target_url = query.get("target", [None])[0]
        if not target_url:
            return self.send_json({"error": "Missing target URL"}, 400)
        if self.command not in ("GET", "POST"):
            return self.send_json({"error": "Proxy method is not allowed"}, 405)
        if not is_allowed_claroty_target(target_url):
            return self.send_json({"error": "Proxy target must be an HTTPS Claroty v1 API endpoint"}, 403)
        upstream_proxy = query.get("upstream_proxy", [""])[0].strip()
        if not allowed_claroty_upstream_proxy(upstream_proxy):
            return self.send_json({"error": "Upstream proxy is not approved for Claroty requests"}, 403)
        try:
            headers = {name: self.headers[name] for name in ("Content-Type", "Accept", "Authorization", "X-API-KEY", "User-Agent") if self.headers.get(name)}
            body = None
            if self.command == "POST":
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_PROXY_REQUEST_BYTES:
                    return self.send_json({"error": "Proxy request exceeds the 1 MB limit"}, 413)
                body = self.rfile.read(length) if length else None

            request = urllib.request.Request(target_url, data=body, headers=headers, method=self.command)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": upstream_proxy, "https": upstream_proxy})
                , ClarotyRedirectHandler()
            ) if upstream_proxy else urllib.request.build_opener(ClarotyRedirectHandler())

            with opener.open(request, timeout=30) as response:
                response_data = response.read(MAX_PROXY_RESPONSE_BYTES + 1)
                response_headers = dict(response.headers)
            if len(response_data) > MAX_PROXY_RESPONSE_BYTES:
                return self.send_json({"error": "Claroty response exceeds the 20 MB proxy limit"}, 502)

            self.send_response(response.status)
            self.send_header("Content-Type", response_headers.get("Content-Type", "application/json"))
            self.add_local_cors_headers()
            self.send_header("Content-Length", str(len(response_data)))
            self.end_headers()
            self.wfile.write(response_data)
            return
        except urllib.error.HTTPError as error:
            error_body = error.read().decode("utf-8", errors="ignore")
            return self.send_json({"error": f"Proxy error {error.code}", "detail": error_body}, error.code)
        except Exception as error:
            return self.send_json({"error": "Proxy failed", "detail": str(error)}, 502)

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.add_local_cors_headers()
        try:
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            return

    def add_local_cors_headers(self):
        origin = self.headers.get("Origin")
        if origin in LOCAL_BROWSER_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-KEY")

    def read_json(self, max_bytes=MAX_JSON_REQUEST_BYTES):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > max_bytes:
            raise ValueError(f"JSON request exceeds the {max_bytes} byte limit")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            return super().do_GET()
        query = parse_qs(parsed.query)
        if parsed.path == "/api/health":
            return self.send_json({"status": "ok", "service": "soc-dashboard", "time": datetime.now(timezone.utc).isoformat()})
        if not self.require_local_session():
            return

        if parsed.path == "/api/audit_results/analytics":
            return self.send_json(audit_results_analytics_payload())
        if parsed.path == "/api/audit_results/analytics.csv":
            report = audit_results_analytics_payload()
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            fields = ("id", "name", "framework", "assignedTo", "status", "total", "completed", "pending",
                      "progressPercent", "overdue", "editedBy", "reviewedBy", "reviewedAt", "reviewerScore", "dueDate", "assignedAt")
            writer.writerow(fields)
            for item in report["assignments"]:
                writer.writerow([safe_audit_csv_cell(item.get(field)) for field in fields])
            body = buffer.getvalue().encode("utf-8-sig")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=secumat-audit-results.csv")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api/audit/workbooks":
            return self.send_json({"history": audit_workbook_history(source=query.get("source", [""])[0]), "source": "local-audit-store"})
        version_match = re.fullmatch(r"/api/audit/workbooks/versions/([a-f0-9]{32})", parsed.path)
        if version_match:
            version = get_module_record("audit_workbook_versions", version_match.group(1))
            return self.send_json({"revision": version}, 200) if version else self.send_json({"error": "Version not found"}, 404)

        if parsed.path == "/api/modules":
            return self.send_json({"modules": [{"id": name, "name": label, "writable": name not in AUDIT_WORKFLOW_MODULES} for name, label in MODULE_NAMES.items()], "source": "local-module-store"})
        if parsed.path == "/api/analytics/modules":
            return self.send_json(module_analytics_payload())
        if parsed.path == "/api/analytics/threats":
            return self.send_json(module_threat_analytics_payload())
        if parsed.path == "/api/osint/framework":
            try:
                return self.send_json(osint_framework_payload())
            except (OSError, ValueError, RuntimeError) as error:
                return self.send_json({"error": f"OSINT catalogue unavailable: {error}"}, 500)
        if parsed.path == "/api/osint/search":
            try:
                return self.send_json(osint_search_payload(
                    query.get("q", [""])[0],
                    query.get("category", [""])[0],
                    query.get("input", [""])[0],
                    query.get("access", [""])[0],
                ))
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
        if parsed.path == "/api/siem/dashboard":
            try:
                return self.send_json(siem_dashboard_payload())
            except (OSError, sqlite3.Error, ValueError, RuntimeError) as error:
                return self.send_json({"error": f"SIEM dashboard data unavailable: {error}"}, 500)
        if parsed.path == "/api/siem/events":
            try:
                return self.send_json(siem_event_search_payload(
                    query.get("q", [""])[0],
                    query.get("limit", [100])[0],
                    query.get("offset", [0])[0],
                ))
            except (OSError, sqlite3.Error, ValueError, RuntimeError) as error:
                return self.send_json({"error": f"SIEM event search failed: {error}"}, 400)
        if parsed.path == "/api/soc-studio/summary":
            with MODULE_DATA_LOCK:
                modules = module_store_payload()["modules"]
            credentials = public_integration_credential_status().get("tools", {})
            connector_ids = ("swimlane", "sentinel", "elastic", "rubrik", "entra", "defender", "crowdstrike", "sentinelone", "m365", "wiz", "prismacloud", "paloalto", "splunk", "tenable")
            connector_status = {
                tool_id: ("configured_not_verified" if credentials.get(tool_id, {}).get("configured") else "not_configured")
                for tool_id in connector_ids
            }
            connector_status["claroty"] = "configured_not_verified" if claroty_credentials_status().get("configured") else "not_configured"
            return self.send_json({
                "source": "local-configuration",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "local_records": {name: len(modules.get(name, [])) for name in ("incidents", "alerts", "vulnerabilities", "threat_intel", "network_events")},
                "saved_artifacts": len(modules.get("soc_studio", [])),
                "connectors": connector_status,
            })
        if parsed.path == "/api/automation/playbooks":
            return self.send_json(automation_catalog_payload())
        if parsed.path in {"/api/automation/runs", "/api/v1/automation/status"}:
            catalog = automation_catalog_payload()
            return self.send_json({"runs": catalog["runs"], "playbooks": catalog["playbooks"], "source": catalog["source"], "external_actions_enabled": False})
        if parsed.path == "/api/v1/automation/dashboard":
            return self.send_json(module_automation_dashboard_payload({key: values[-1] for key, values in query.items()}))
        if parsed.path == "/api/v1/automation/incidents":
            incidents = list_module_records("incidents", limit=1000)["records"]
            module_filter = query.get("module", [""])[0].strip()
            if module_filter:
                incidents = [item for item in incidents if str(item.get("module") or "") == module_filter]
            return self.send_json({"incidents": incidents, "source": "local-module-store", "external_actions_enabled": False})
        if parsed.path == "/api/v1/automation/readiness":
            credentials = public_integration_credential_status().get("tools", {})
            return self.send_json({"source": "local-configuration", "external_actions_enabled": False, "tools": credentials})
        if parsed.path == "/api/v1/automation/integrations":
            return self.send_json(zero_trust_integrations_payload())
        if parsed.path == "/api/v1/automation/tools/live_summary":
            return self.send_json({"source": "local-module-store", "live_connected": False, "analytics": module_analytics_payload()})

        if parsed.path == "/api/secumat_workspace":
            try:
                return self.send_json(secumat_workspace_payload())
            except (OSError, ValueError) as error:
                return self.send_json({"error": str(error)}, 500)
        if parsed.path == "/api/secumat_templates":
            templates = secumat_template_files()
            return self.send_json({"templates": templates, "total_templates": len(templates), "source": "local-questionnaire-folder"})
        if parsed.path in {"/api/custom_questionnaire_templates", "/api/custom_templates"}:
            templates = list_module_records("custom_templates", limit=500)["records"]
            return self.send_json({"templates": [{**item, "question_count": len(item.get("questions") or [])} for item in templates], "source": "local-module-store"})
        custom_template_match = re.fullmatch(r"/api/(?:custom_questionnaire_templates|custom_templates)/([^/]+)(?:/questions)?", parsed.path)
        if custom_template_match:
            template = get_module_record("custom_templates", unquote(custom_template_match.group(1)))
            if not template:
                return self.send_json({"error": "Template not found"}, 404)
            return self.send_json({"template": template, "questions": template.get("questions") or [], "source": "local-module-store"})
        if parsed.path == "/api/secumat_audits":
            return self.send_json({"audits": list_module_records("secumat_audits", limit=500)["records"], "source": "local-module-store"})
        if parsed.path == "/api/audit_assignments":
            assignments = list_module_records("audit_assignments", limit=500)["records"]
            assignments.sort(key=lambda item: str(item.get("assignment_date") or item.get("created_at") or ""), reverse=True)
            return self.send_json({"assignments": assignments, "source": "local-module-store"})
        if parsed.path == "/api/audit_assignment_responses":
            assignment_id = query.get("assignment_id", [""])[0]
            responses = list_module_records("audit_responses", limit=MODULE_MAX_RECORDS)["records"]
            if assignment_id:
                responses = [item for item in responses if str(item.get("assignment_id")) == assignment_id]
            return self.send_json({"responses": responses, "source": "local-module-store"})
        if parsed.path in {"/api/compliance_uploads", "/api/reports"}:
            uploads = list_module_records("secumat_uploads", limit=500)["records"]
            key = "uploads" if parsed.path == "/api/compliance_uploads" else "reports"
            return self.send_json({key: uploads, "source": "local-module-store"})
        if parsed.path == "/api/compliance_audit":
            uploads = list_module_records("secumat_uploads", limit=500)["records"]
            upload_id = query.get("upload_id", [""])[0]
            assignment_id = query.get("assignment_id", [""])[0]
            if assignment_id:
                result = secumat_assignment_result(assignment_id)
                if result is None:
                    return self.send_json({"error": "Audit assignment not found"}, 404)
                stats = {"total_questions": result["assignment"]["question_count"], "coverage_percent": result["progress_percent"], "total_controls": len(result["responses"]), **result["status_counts"]}
                return self.send_json({"upload": {"id": assignment_id, "upload_name": result["assignment"]["assessment_name"], "framework": result["assignment"].get("framework", ""), "total_questions": stats["total_questions"], "preview_available": False}, "uploads": uploads, "stats": stats, "controls": [], "responses": result["responses"], "source": "local-module-store"})
            upload = next((item for item in uploads if str(item.get("id")) == upload_id), None) if upload_id else (uploads[0] if uploads else None)
            if upload:
                try:
                    preview = load_secumat_upload_preview(upload)
                except (OSError, ValueError, zipfile.BadZipFile) as error:
                    return self.send_json({"error": str(error)}, 500)
                stats = {"total_questions": upload.get("total_questions", 0), "total_controls": upload.get("total_controls", 0), "coverage_percent": 0, "compliant": 0}
                return self.send_json({**preview, "upload": upload, "uploads": uploads, "stats": stats, "controls": [], "responses": [], "source": "local-upload-store"})
            return self.send_json({"upload": {}, "uploads": [], "stats": {"total_questions": 0, "total_controls": 0, "coverage_percent": 0, "compliant": 0}, "controls": [], "responses": [], "source": "local-upload-store"})
        upload_preview_match = re.fullmatch(r"/api/compliance_audit/([^/]+)/preview", parsed.path)
        if upload_preview_match:
            upload = get_module_record("secumat_uploads", unquote(upload_preview_match.group(1)))
            if not upload:
                return self.send_json({"error": "Questionnaire upload not found"}, 404)
            try:
                preview = load_secumat_upload_preview(upload)
                return self.send_json({"upload": upload, **preview, "source": "local-upload-store"})
            except (OSError, ValueError, zipfile.BadZipFile) as error:
                return self.send_json({"error": str(error)}, 500)
        if parsed.path == "/api/compliance":
            records = list_module_records("compliance", limit=MODULE_MAX_RECORDS)["records"]
            statuses = Counter(str(item.get("status") or item.get("response_status") or "unknown").lower() for item in records)
            return self.send_json({"records": records, "summary": {"total": len(records), "by_status": dict(statuses)}, "source": "local-module-store"})

        result_download_match = re.fullmatch(r"/api/audit_results/([^/]+)/download", parsed.path)
        if result_download_match:
            result = secumat_assignment_result(unquote(result_download_match.group(1)))
            if not result:
                return self.send_json({"error": "Audit assignment not found"}, 404)
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["Question ID", "Question", "Response", "Evidence", "Comments", "Score"])
            for item in result["responses"]:
                writer.writerow([safe_audit_csv_cell(item.get(field)) for field in ("question_id", "question_text", "response_status", "evidence", "comments", "mapping_score")])
            body = buffer.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename=secumat-audit-{result['assignment']['id']}.csv")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        module_match = re.fullmatch(r"/api/modules/([a-z_]+)(?:/([^/]+))?", parsed.path)
        if module_match:
            module_name, record_id = module_match.groups()
            if module_name not in MODULE_NAMES:
                return self.send_json({"error": "Unknown module"}, 404)
            try:
                if record_id is not None:
                    record = get_module_record(module_name, unquote(record_id))
                    return self.send_json(record if record else {"error": "Record not found"}, 200 if record else 404)
                result = list_module_records(module_name, query.get("q", [""])[0], query.get("limit", [100])[0], query.get("offset", [0])[0])
                result["module"] = {"id": module_name, "name": MODULE_NAMES[module_name]}
                return self.send_json(result)
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        record_match = re.fullmatch(r"/api/(secumat_audits|audit_assignments|audit_results)/([^/]+)", parsed.path)
        if record_match:
            collection, record_id = record_match.groups()
            if collection == "audit_results":
                result = secumat_assignment_result(unquote(record_id))
                return self.send_json(result if result else {"error": "Audit assignment not found"}, 200 if result else 404)
            module_name = "secumat_audits" if collection == "secumat_audits" else "audit_assignments"
            record = get_module_record(module_name, unquote(record_id))
            return self.send_json(record if record else {"error": "Record not found"}, 200 if record else 404)

        if parsed.path == "/api/integrations/credentials":
            try:
                return self.send_json(public_integration_credential_status())
            except Exception as error:
                return self.send_json({"error": str(error)}, 500)

        if parsed.path == "/api/optimization/tool-overlap":
            try:
                return self.send_json(tool_overlap_payload())
            except Exception as error:
                return self.send_json({"error": str(error)}, 500)

        if parsed.path == "/api/offsec/methodology":
            try:
                return self.send_json(offsec_methodology_payload())
            except Exception as error:
                return self.send_json({"error": f"Methodology assessment failed: {error}"}, 500)

        if parsed.path in ("/api/v1/security-assessment/summary", "/api/v1/security-assessment/domains"):
            try:
                methodology = offsec_methodology_payload()
                if parsed.path.endswith("/summary"):
                    return self.send_json(security_assessment_summary(methodology))
                return self.send_json({"items": methodology["domains"], "total": len(methodology["domains"]),
                                       "deferredKpis": methodology["deferredKpis"]})
            except Exception as error:
                return self.send_json({"error": f"Security assessment failed: {error}"}, 500)
        domain_match = re.fullmatch(r"/api/v1/security-assessment/domains/([a-z0-9-]+)", parsed.path)
        if domain_match:
            if not assessment_domain(domain_match.group(1)):
                return self.send_json({"error": "Unknown assessment domain"}, 404)
            try:
                domain = next(item for item in offsec_methodology_payload()["domains"]
                              if item["domainId"] == domain_match.group(1))
                return self.send_json(security_assessment_domain_detail(domain))
            except Exception as error:
                return self.send_json({"error": f"Security assessment failed: {error}"}, 500)

        if parsed.path == "/api/offsec/attack-coverage":
            try:
                return self.send_json(snort_attack_coverage())
            except Exception as error:
                return self.send_json({"error": f"Coverage mapping failed: {error}"}, 500)

        if parsed.path == "/api/snort/engine-status":
            return self.send_json(snort_engine_status_payload())

        if parsed.path == "/api/snort/openappid":
            try:
                status = openappid_status_payload()
                catalog = current_openappid_catalog()
                rows = catalog["applications"] if catalog else []
                query_text = query.get("query", [""])[0].strip().casefold()
                kind = query.get("kind", ["all"])[0]
                if kind not in ("all", "mapped", "unmapped"):
                    return self.send_json({"error": "Invalid OpenAppID filter"}, 400)
                matched = [
                    row for row in rows
                    if (kind == "all" or (bool(row["snortName"]) == (kind == "mapped")))
                    and (not query_text or query_text in row["name"].casefold() or query_text in row["snortName"].casefold() or query_text == str(row["appId"]))
                ]
                offset = max(0, int(query.get("offset", [0])[0]))
                limit = max(1, min(500, int(query.get("limit", [100])[0])))
                status.update({
                    "matched": len(matched), "offset": offset, "limit": limit,
                    "records": matched[offset:offset + limit],
                    "detectorSamples": (catalog["detectors"][:25] if catalog else []),
                })
                return self.send_json(status)
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/snort/rules" or parsed.path.startswith("/api/snort/rules/"):
            try:
                catalog = current_snort_catalog()
                if parsed.path != "/api/snort/rules":
                    rule_id = int(parsed.path.removeprefix("/api/snort/rules/"))
                    records = catalog["records"] if catalog else []
                    if rule_id < 0 or rule_id >= len(records):
                        return self.send_json({"error": "Snort rule not found"}, 404)
                    return self.send_json(records[rule_id])
                records = catalog["records"] if catalog else []
                query_text = query.get("query", [""])[0].strip().casefold()
                state = query.get("state", ["all"])[0]
                if state not in ("all", "enabled", "disabled"):
                    return self.send_json({"error": "Invalid rule state"}, 400)
                matched = [row for row in records if (state == "all" or row["enabled"] == (state == "enabled")) and (not query_text or any(query_text in str(row[key]).casefold() for key in ("sid", "message", "action", "file")))]
                offset = max(0, int(query.get("offset", [0])[0]))
                limit = max(1, min(200, int(query.get("limit", [100])[0])))
                return self.send_json({
                    "configured": catalog is not None, "total": len(records), "matched": len(matched),
                    "enabled": sum(row["enabled"] for row in records), "files": catalog["files"] if catalog else 0,
                    "updatedAt": catalog["updatedAt"] if catalog else None, "offset": offset, "limit": limit,
                    "sources": catalog["sources"] if catalog else [], "update": snort_update_status(),
                    "records": [{key: value for key, value in row.items() if key != "rule"} for row in matched[offset:offset + limit]],
                })
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/snort/blacklist":
            try:
                addresses = load_network_ip_list(SNORT_BLACKLIST_FILE)
                query_text = query.get("query", [""])[0].strip().casefold()
                matched = [address for address in addresses if not query_text or query_text in address.casefold()]
                offset = max(0, int(query.get("offset", [0])[0]))
                limit = max(1, min(200, int(query.get("limit", [100])[0])))
                updated_at = datetime.fromtimestamp(SNORT_BLACKLIST_FILE.stat().st_mtime, timezone.utc).isoformat() if SNORT_BLACKLIST_FILE.exists() else None
                return self.send_json({
                    "configured": bool(addresses), "total": len(addresses), "matched": len(matched),
                    "updatedAt": updated_at, "offset": offset, "limit": limit,
                    "records": [{"id": offset + index, "address": address} for index, address in enumerate(matched[offset:offset + limit])],
                })
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/network/ip-lists":
            try:
                with snort_blacklist_lock:
                    blacklist = load_network_ip_list(SNORT_BLACKLIST_FILE)
                    whitelist = load_network_ip_list(SNORT_WHITELIST_FILE)
                    reasons = read_json_store(SNORT_IP_REASONS_FILE, {"blacklist": {}, "whitelist": {}})
                observed = list(dict.fromkeys(query.get("observed", [])))
                return self.send_json({
                    "blacklist": blacklist,
                    "whitelist": whitelist,
                    "reasons": reasons,
                    "blacklistUpdatedAt": datetime.fromtimestamp(SNORT_BLACKLIST_FILE.stat().st_mtime, timezone.utc).isoformat() if SNORT_BLACKLIST_FILE.exists() else None,
                    "whitelistUpdatedAt": datetime.fromtimestamp(SNORT_WHITELIST_FILE.stat().st_mtime, timezone.utc).isoformat() if SNORT_WHITELIST_FILE.exists() else None,
                    "observed": [classify_observed_ip(address, whitelist, blacklist) for address in observed],
                })
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/network/indicators":
            try:
                query_text = query.get("query", [""])[0].strip().casefold()
                list_name = query.get("list", [""])[0]
                kind = query.get("kind", [""])[0]
                with snort_blacklist_lock:
                    entries = read_json_store(SNORT_INDICATORS_FILE, [])
                matched = [entry for entry in entries if (not list_name or entry.get("list") == list_name) and (not kind or entry.get("kind") == kind) and (not query_text or query_text in (entry.get("value", "") + " " + entry.get("reason", "")).casefold())]
                return self.send_json({"entries": matched, "total": len(entries), "matched": len(matched), "updatedAt": datetime.fromtimestamp(SNORT_INDICATORS_FILE.stat().st_mtime, timezone.utc).isoformat() if SNORT_INDICATORS_FILE.exists() else None})
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/integrations":
            return self.send_json(zero_trust_integrations_payload())

        if parsed.path == "/api/zero-trust/program":
            return self.send_json({"profile": load_zero_trust_program(), "source": "local-program-store"})

        if parsed.path == "/api/zero-trust/analytics":
            try:
                hours = max(1, min(24 * 90, int(query.get("hours", [24])[0])))
                return self.send_json(zero_trust_analytics_payload(hours))
            except (TypeError, ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/detections":
            try:
                minutes = max(1, min(30 * 24 * 60, int(query.get("lookback_minutes", [30])[0])))
                return self.send_json(zero_trust_detections_payload(minutes))
            except (TypeError, ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/playbooks":
            runs = read_zero_trust_playbook_runs(max(1, min(500, int(query.get("limit", [100])[0]))))
            return self.send_json({"playbooks": zero_trust_playbook_catalog(), "runs": runs, "source": "local-dry-run-store"})

        if parsed.path == "/api/integrations/connectors":
            with integration_connectors_lock:
                connectors = [public_integration_connector(item) for item in load_integration_connectors()]
            return self.send_json({"connectors": connectors, "count": len(connectors), "source": "local-connector-registry"})

        if parsed.path == "/api/integrations/feed-state":
            try:
                credentials = public_integration_credential_status().get("tools", {}).get("rubrik", {})
                return self.send_json({
                    **load_integration_feed_state(),
                    "rubrikApiConfigured": bool(credentials.get("configured")),
                    "source": "local-integration-settings",
                    "implementedFeeds": ["rubrik_api", "read_only_provider_api", "inbound_event_connectors"],
                })
            except ValueError as error:
                return self.send_json({"error": str(error)}, 500)

        if parsed.path == "/api/threat-intel/feeds":
            try:
                return self.send_json(get_threat_feed_status())
            except (OSError, sqlite3.Error, ValueError) as error:
                return self.send_json({"error": f"Threat feed status unavailable: {error}"}, 500)

        if parsed.path == "/api/threat-intel/lookup":
            try:
                value = query.get("value", [""])[0]
                indicator_type = query.get("type", [""])[0]
                return self.send_json(lookup_threat_indicators(value, indicator_type))
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
            except (OSError, sqlite3.Error) as error:
                return self.send_json({"error": f"Threat feed lookup failed: {error}"}, 500)

        if parsed.path == "/api/integrations/rubrik/events":
            try:
                if not load_integration_feed_state()["rubrikApiEnabled"]:
                    return self.send_json({"error": "Rubrik API feed is disabled in Settings"}, 409)
                lookback = query.get("lookback_minutes", ["1440"])[0]
                activity_done = query.get("activity_done", ["false"])[0].casefold() == "true"
                audit_done = query.get("audit_done", ["false"])[0].casefold() == "true"
                return self.send_json(rubrik_recent_activity_payload(
                    lookback,
                    query.get("activity_after", [None])[0],
                    query.get("audit_after", [None])[0],
                    activity_done,
                    audit_done,
                ))
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
            except OSError as error:
                return self.send_json({"error": f"Could not persist Rubrik activity: {error}"}, 500)
            except RuntimeError as error:
                return self.send_json({"error": str(error)}, 502)

        if parsed.path == "/api/zero-trust/events":
            try:
                limit = max(1, min(1000, int(query.get("limit", [100])[0])))
                event_type = query.get("event_type", [""])[0].strip()
                records = read_zero_trust_events(limit, event_type)
                return self.send_json({"records": records, "count": len(records), "limit": limit, "source": "local-audit-store"})
            except (ValueError, OverflowError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/claroty/credentials":
            try:
                return self.send_json(claroty_credentials_status())
            except Exception as error:
                return self.send_json({"configured": False, "error": str(error)}, 500)
        
        if parsed.path == "/api/proxy":
            return self.handle_proxy(parsed)
        
        if parsed.path in ("/api/incidents", "/api/dashboard"):
            range_days = max(1, min(365, int(query.get("range", [30])[0])))
            incidents = load_incidents(range_days)
            if parsed.path == "/api/dashboard":
                return self.send_json(dashboard_summary(incidents))
            severity = query.get("severity", [""])[0]
            status = query.get("status", [""])[0]
            if severity:
                incidents = [item for item in incidents if item["severity"].lower() == severity.lower()]
            if status:
                incidents = [item for item in incidents if item["status"].lower() == status.lower()]
            limit = max(1, min(3000, int(query.get("limit", [1000])[0])))
            return self.send_json({"records": incidents[:limit], "total": len(incidents), "source": "report"})
        if parsed.path == "/api/alerts":
            return self.send_json({"alerts": current_alerts(), "source": "sample"})
        if parsed.path == "/api/public-feeds":
            try:
                return self.send_json(public_feed_payload())
            except Exception as error:
                return self.send_json({"error": "Public feed aggregation failed", "detail": str(error)}, 502)
        return self.send_json({"error": "Not found"}, 404)

    def ingest_git_provider_webhook(self, provider):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > GIT_PROVIDER_MAX_WEBHOOK_BYTES:
                return self.send_json({"error": "Webhook body exceeds the allowed size"}, 413)
            raw_body = self.rfile.read(length)
            authenticate_git_webhook(provider, self.headers, raw_body)
        except PermissionError as error:
            return self.send_json({"error": str(error)}, 401)
        except (ValueError, OSError) as error:
            return self.send_json({"error": str(error)}, 400)
        try:
            payload = json.loads(raw_body)
            event_name = self.headers.get("X-GitHub-Event") if provider == "github" else self.headers.get("X-Gitlab-Event")
            delivery_id = self.headers.get("X-GitHub-Delivery") if provider == "github" else self.headers.get("X-Gitlab-Event-UUID")
            event = normalize_git_webhook(provider, event_name, payload, delivery_id)
            routing = save_integration_event(event)
            return self.send_json({"accepted": True, "provider": provider, "eventId": event["event_id"], "routing": routing}, 202)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            return self.send_json({"error": str(error)}, 400)
        except (OSError, sqlite3.Error) as error:
            return self.send_json({"error": f"Webhook event could not be stored: {error}"}, 500)

    def ingest_integration_connector(self, connector_id):
        try:
            connector = authenticate_integration_connector(connector_id, self.headers.get("Authorization"))
        except PermissionError as error:
            return self.send_json({"error": str(error)}, 409)
        if not connector:
            return self.send_json({"error": "Connector token is missing or invalid"}, 401)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1024 * 1024:
                return self.send_json({"error": "Ingestion request must be between 1 byte and 1 MB"}, 400)
            raw_body = self.rfile.read(length)
            if connector["transport"] == "syslog":
                raw_text = raw_body.decode("utf-8")
                events = [validate_zero_trust_event(event) for event in parse_syslog_events(raw_text, connector["name"])]
            else:
                events = connector_json_events(json.loads(raw_body), connector)
            for event in events:
                routing = save_integration_event(event)
                event["routing"] = routing
                append_zero_trust_event(event)
            record_connector_receive(connector_id, len(events))
            return self.send_json({"accepted": True, "connector": connector["name"], "transport": connector["transport"], "acceptedCount": len(events), "receivedAt": datetime.now(timezone.utc).isoformat()}, 202)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            return self.send_json({"error": str(error)}, 400)

    def do_POST(self):
        parsed = urlparse(self.path)
        git_webhook_match = re.fullmatch(r"/api/integrations/webhooks/(github|gitlab)", parsed.path)
        if git_webhook_match:
            return self.ingest_git_provider_webhook(git_webhook_match.group(1))
        if not is_trusted_local_origin(self.headers.get("Origin"), self.headers.get("Host")):
            return self.send_json({"error": "Cross-origin API writes are not allowed"}, 403)
        connector_match = re.fullmatch(r"/api/integrations/connectors/([0-9a-f-]+)/ingest", parsed.path)
        if connector_match:
            return self.ingest_integration_connector(connector_match.group(1))
        if not self.require_local_session():
            return

        if parsed.path == "/api/integrations/feed-state":
            try:
                state = save_integration_feed_state(self.read_json())
                return self.send_json({"saved": True, **state, "source": "local-integration-settings"})
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/threat-intel/feeds/refresh":
            try:
                result = refresh_threat_indicator_feeds()
                return self.send_json(result, 200 if not result.get("failedFeedCount") else 502)
            except (OSError, sqlite3.Error, ValueError) as error:
                return self.send_json({"error": f"Threat feed refresh failed: {error}"}, 502)

        if parsed.path == "/api/integrations/git/refresh":
            try:
                result = refresh_git_provider_feeds()
                return self.send_json(result)
            except (OSError, sqlite3.Error, ValueError, RuntimeError) as error:
                return self.send_json({"error": f"Git provider refresh failed: {error}"}, 502)

        if parsed.path == "/api/integrations/api-feeds/refresh":
            try:
                return self.send_json(refresh_configured_api_feeds())
            except (OSError, sqlite3.Error, ValueError, RuntimeError) as error:
                return self.send_json({"error": f"API feed refresh failed: {error}"}, 502)

        connector_enabled_match = re.fullmatch(r"/api/integrations/connectors/([0-9a-f-]+)/enabled", parsed.path)
        if connector_enabled_match:
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("Connector state body must be a JSON object")
                connector = set_integration_connector_enabled(connector_enabled_match.group(1), payload.get("enabled"))
                if connector is None:
                    return self.send_json({"error": "Integration connector not found"}, 404)
                return self.send_json({"saved": True, "connector": connector})
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        connector_rotate_match = re.fullmatch(r"/api/integrations/connectors/([0-9a-f-]+)/rotate-token", parsed.path)
        if connector_rotate_match:
            try:
                connector = rotate_integration_connector_token(connector_rotate_match.group(1))
                if connector is None:
                    return self.send_json({"error": "Integration connector not found"}, 404)
                return self.send_json(connector, 200)
            except Exception as error:
                return self.send_json({"error": str(error)}, 500)

        testing_match = re.fullmatch(
            r"/api/v1/security-assessment/domains/([a-z0-9-]+)/testing", parsed.path)
        if testing_match:
            if not assessment_domain(testing_match.group(1)):
                return self.send_json({"error": "Unknown assessment domain"}, 404)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 4096:
                    return self.send_json({"error": "Testing request must be between 1 byte and 4 KB"}, 400)
                record = request_assessment_testing(testing_match.group(1), json.loads(self.rfile.read(length)))
                return self.send_json(record, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": f"Testing request could not be saved: {error}"}, 500)

        if parsed.path == "/api/audit/workbooks":
            try:
                editor = "Local session " + hashlib.sha256(get_local_session_token(self.headers.get("Cookie")).encode()).hexdigest()[:8]
                revision = save_audit_workbook_version(self.read_json(), editor)
                return self.send_json({"revision": revision, "source": "local-audit-store"}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/upload/compliance":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_SECUMAT_UPLOAD_BYTES + 128 * 1024:
                    return self.send_json({"error": "SECUMAT upload exceeds the allowed size"}, 413)
                fields, uploaded_file = parse_secumat_multipart(self.headers.get("Content-Type", ""), self.rfile.read(length))
                preview = parse_secumat_workbook(uploaded_file["filename"], uploaded_file["bytes"])
                upload_id = uuid.uuid4().hex
                extension = Path(uploaded_file["filename"]).suffix.lower()
                storage_name = f"{upload_id}{extension}"
                SECUMAT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                final_path = SECUMAT_UPLOAD_DIR / storage_name
                temporary_path = final_path.with_suffix(final_path.suffix + ".tmp")
                temporary_path.write_bytes(uploaded_file["bytes"])
                temporary_path.replace(final_path)
                upload = {
                    "id": upload_id,
                    "upload_name": str(fields.get("upload_name") or uploaded_file["filename"])[:200],
                    "filename": uploaded_file["filename"],
                    "framework": str(fields.get("framework") or "CUSTOM")[:100],
                    "uploaded_by": str(fields.get("uploaded_by") or "local user")[:200],
                    "storage_name": storage_name,
                    "upload_mode": "workbook" if extension != ".csv" else "structured",
                    "preview_available": True,
                    "total_questions": preview["total_questions"],
                    "total_controls": preview["total_controls"],
                    "sheet_count": preview["sheet_count"],
                    "sheet_breakdown": preview["sheet_breakdown"],
                    "sheet_details": preview["sheet_details"],
                    "template_coverage": preview["template_coverage"],
                    "mapping_summary": preview["mapping_summary"],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                save_module_record("secumat_uploads", upload)
                return self.send_json({"message": f"{upload['upload_name']} uploaded and parsed successfully", "upload_id": upload_id, "upload": upload, "stats": {"total_questions": upload["total_questions"], "sheet_count": upload["sheet_count"]}, "source": "local-upload-store"}, 201)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except OSError as error:
                return self.send_json({"error": f"Could not store SECUMAT upload: {error}"}, 500)

        if parsed.path in {"/api/modules", "/api/modules/"}:
            return self.send_json({"error": "Choose a module collection"}, 400)

        module_collection_match = re.fullmatch(r"/api/modules/([a-z_]+)", parsed.path)
        if module_collection_match:
            module_name = module_collection_match.group(1)
            if module_name in AUDIT_WORKFLOW_MODULES:
                return self.send_json({"error": "Use the dedicated audit API"}, 403)
            try:
                record = save_module_record(module_name, self.read_json())
                return self.send_json({"record": record, "source": "local-module-store"}, 201)
            except KeyError:
                return self.send_json({"error": "Unknown module"}, 404)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path in {"/api/automation/run", "/api/v1/automation/run"}:
            try:
                run = run_module_automation(self.read_json(max_bytes=64 * 1024))
                return self.send_json(run, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path in {"/api/custom_questionnaire_templates", "/api/custom_templates"}:
            try:
                payload = self.read_json()
                if not str(payload.get("name") or "").strip():
                    return self.send_json({"error": "Template name is required"}, 400)
                questions = payload.get("questions")
                if not isinstance(questions, list) or not questions or len(questions) > 5000:
                    return self.send_json({"error": "A template must include 1-5,000 questions"}, 400)
                payload["sheets"] = validate_template_sheets(payload.get("sheets"))
                payload["id"] = next_module_numeric_id("custom_templates")
                payload["name"] = str(payload["name"]).strip()[:200]
                payload.setdefault("framework", "CUSTOM")
                payload.setdefault("version", "1.0")
                payload["question_count"] = len(questions)
                template = save_module_record("custom_templates", payload)
                return self.send_json({"status": "created", "template": template}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/secumat_audits":
            try:
                payload = self.read_json()
                if not str(payload.get("audit_name") or "").strip():
                    return self.send_json({"error": "audit_name is required"}, 400)
                payload["id"] = next_module_numeric_id("secumat_audits")
                payload.setdefault("status", "draft")
                payload.setdefault("created_at", datetime.now(timezone.utc).isoformat())
                payload.setdefault("updated_at", payload["created_at"])
                audit = save_module_record("secumat_audits", payload)
                return self.send_json({"status": "created", "audit": audit}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/audit_assignments":
            try:
                payload = self.read_json()
                for field in WORKBOOK_ASSIGNMENT_STATE_FIELDS - {"question_count", "template_file", "template_source"}:
                    payload.pop(field, None)
                if not payload.get("template_file"):
                    payload.pop("template_source", None)
                template_file = str(payload.get("template_file") or "")
                if template_file:
                    available = {item["name"]: item for item in secumat_template_files() if item["extension"] in {"xlsx", "csv"}}
                    if template_file not in available:
                        raise ValueError("Choose a spreadsheet from the audit template library")
                    if not str(payload.get("assigned_to") or "").strip():
                        raise ValueError("An assignee is required")
                    source_path = ROOT / "Audit Templates & Question Bank" / template_file
                    if source_path.stat().st_size > MAX_SECUMAT_UPLOAD_BYTES:
                        raise ValueError("Workbook is too large for assignment preview")
                    preview = parse_secumat_workbook(template_file, source_path.read_bytes())
                    payload["questionnaire_name"] = template_file
                    payload["template_source"] = "workbook"
                    payload["framework"] = available[template_file]["framework"]
                    payload.setdefault("assigned_to_type", "person")
                    payload["question_count"] = preview["total_questions"]
                    payload["pending_items"] = preview["total_questions"]
                questionnaire_name = str(payload.get("questionnaire_name") or payload.get("assessment_name") or "").strip()
                if not questionnaire_name:
                    return self.send_json({"error": "questionnaire_name is required"}, 400)
                payload.setdefault("questionnaire_name", questionnaire_name)
                payload.setdefault("assessment_name", questionnaire_name)
                payload["status"] = "pending"
                payload.setdefault("question_count", 0)
                payload["completed_responses"] = 0
                payload["progress_percent"] = 0.0
                payload["compliance_score"] = None
                payload.setdefault("assignment_date", datetime.now(timezone.utc).isoformat())
                payload["id"] = next_module_numeric_id("audit_assignments")
                assignment = save_module_record("audit_assignments", payload)
                return self.send_json({"status": "created", "assignment": assignment}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/audit_assignment_responses":
            try:
                payload = self.read_json()
                assignment_id = validate_module_id(payload.get("assignment_id"))
                assignment = get_module_record("audit_assignments", assignment_id)
                if not assignment:
                    return self.send_json({"error": "Audit assignment not found"}, 404)
                if assignment.get("template_source") == "workbook" or assignment.get("status") in {"submitted", "completed", "closed"} or assignment.get("reviewed_at"):
                    return self.send_json({"error": "This audit no longer accepts questionnaire responses"}, 409)
                response_items = payload.get("responses")
                if not isinstance(response_items, list) or not response_items or len(response_items) > 2000:
                    return self.send_json({"error": "Provide between 1 and 2,000 responses"}, 400)
                score_map = {"compliant": 100, "partial": 50, "non_compliant": 0, "not_applicable": 100, "needs_review": 25, "deferred": 10, "compensating_control": 75, "pending": 0}
                saved_responses = []
                for response_item in response_items:
                    if not isinstance(response_item, dict):
                        raise ValueError("Each response must be an object")
                    question_id = str(response_item.get("question_id") or "").strip()[:160]
                    if not question_id:
                        raise ValueError("Each response needs a question_id")
                    status = str(response_item.get("response_status") or response_item.get("response") or "pending").strip().lower()
                    if status not in score_map:
                        raise ValueError(f"Unsupported response status: {status}")
                    record = {
                        "assignment_id": assignment_id,
                        "question_id": question_id,
                        "question_text": str(response_item.get("question_text") or "")[:10000],
                        "response_status": status,
                        "response_option": str(response_item.get("response_option") or response_item.get("response") or status)[:1000],
                        "evidence": str(response_item.get("evidence") or "")[:20000],
                        "comments": str(response_item.get("comments") or "")[:20000],
                        "mapping_score": score_map[status],
                    }
                    response_key = uuid.uuid5(uuid.NAMESPACE_URL, f"{assignment_id}:{question_id}").hex
                    record["id"] = response_key
                    saved_responses.append(save_module_record("audit_responses", record))
                result = secumat_assignment_result(assignment_id)
                assignment.update(result["assignment"])
                assignment["status"] = "completed" if payload.get("finalize") and assignment["progress_percent"] >= 100 else "in_progress"
                save_module_record("audit_assignments", assignment, assignment_id)
                result = secumat_assignment_result(assignment_id)
                result["responses"] = saved_responses
                return self.send_json(result, 200)
            except KeyError:
                return self.send_json({"error": "Audit assignment not found"}, 404)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        duplicate_match = re.fullmatch(r"/api/audit_assignments/([^/]+)/duplicate", parsed.path)
        if duplicate_match:
            assignment = get_module_record("audit_assignments", unquote(duplicate_match.group(1)))
            if not assignment:
                return self.send_json({"error": "Audit assignment not found"}, 404)
            for field in ("id", "created_at", "updated_at", "assignment_date", "completed_responses", "progress_percent", "compliance_score", "workbook_audit_id", "edited_by", "last_edited_at", "reviewer_score", "reviewer_comments", "reviewer_notes", "reviewed_by", "reviewed_at"):
                assignment.pop(field, None)
            assignment.update({"status": "pending", "completed_responses": 0, "pending_items": assignment.get("question_count", 0), "progress_percent": 0.0, "compliance_score": None, "assignment_date": datetime.now(timezone.utc).isoformat()})
            duplicate = save_module_record("audit_assignments", assignment)
            return self.send_json({"status": "duplicated", "assignment": duplicate}, 201)

        review_match = re.fullmatch(r"/api/audit_results/([^/]+)/review", parsed.path)
        if review_match:
            assignment_id = unquote(review_match.group(1))
            assignment = get_module_record("audit_assignments", assignment_id)
            if not assignment:
                return self.send_json({"error": "Audit assignment not found"}, 404)
            if assignment.get("status") not in {"submitted", "completed"} or assignment.get("reviewed_at"):
                return self.send_json({"error": "Only submitted audits awaiting review can be finalized"}, 409)
            try:
                payload = self.read_json()
                reviewer_score = float(payload.get("reviewer_score"))
                reviewer_name = str(payload.get("reviewed_by") or "").strip()
                if not 0 <= reviewer_score <= 100 or not reviewer_name:
                    raise ValueError("Reviewer score must be 0-100 and reviewer name is required")
                assignment["reviewer_score"] = reviewer_score
                assignment["reviewer_comments"] = str(payload.get("reviewer_comments") or "")[:20000]
                assignment["reviewer_notes"] = str(payload.get("reviewer_notes") or "")[:20000]
                assignment["reviewed_by"] = reviewer_name[:200]
                assignment["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                assignment["status"] = "completed"
                updated = save_module_record("audit_assignments", assignment, assignment_id)
                return self.send_json({"status": "reviewed", "assignment": updated}, 200)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        automation_alert_match = re.fullmatch(r"/api/v1/automation/alerts/([^/]+)/action", parsed.path)
        if automation_alert_match:
            alert_id = unquote(automation_alert_match.group(1))
            try:
                payload = self.read_json(max_bytes=16 * 1024)
                action = str(payload.get("action") or "").lower()
                allowed_actions = {"acknowledge": "acknowledged", "own": "owned", "escalate": "escalated", "resolve": "resolved"}
                if action not in allowed_actions:
                    return self.send_json({"error": "Unsupported local alert action"}, 400)
                record = get_module_record("alerts", alert_id) or {"id": alert_id, "source": "local-module-store"}
                record.update({"state": allowed_actions[action], "owner": str(payload.get("owner") or record.get("owner") or "Local SOC"), "updated_at": datetime.now(timezone.utc).isoformat(), "automation_mode": "local-record-update"})
                updated = save_module_record("alerts", record, alert_id) if get_module_record("alerts", alert_id) else save_module_record("alerts", record)
                return self.send_json({"alert": updated, "external_actions_executed": False})
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/proxy":
            return self.handle_proxy(parsed)
        if parsed.path == "/api/integrations/credentials":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 64 * 1024:
                    return self.send_json({"error": "Integration settings must be between 1 byte and 64 KB"}, 400)
                result = save_integration_credentials(json.loads(self.rfile.read(length)))
                return self.send_json({"saved": True, "toolId": result[0], "status": public_integration_credential_status()["tools"][result[0]]}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": str(error)}, 500)
        if parsed.path in ("/api/offsec/attack-paths", "/api/offsec/purple-team"):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 1024 * 1024:
                    return self.send_json({"error": "Request must be between 1 byte and 1 MB"}, 400)
                payload = json.loads(self.rfile.read(length))
                handler = offsec_attack_paths_payload if parsed.path.endswith("attack-paths") else offsec_purple_team_payload
                return self.send_json(handler(payload))
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": f"Offensive security analysis failed: {error}"}, 502)

        if parsed.path == "/api/osint/pivot":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16 * 1024:
                    return self.send_json({"error": "Pivot request must be between 1 byte and 16 KB"}, 400)
                payload = json.loads(self.rfile.read(length))
                return self.send_json(osint_pivot_payload(payload))
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except (OSError, sqlite3.Error, RuntimeError) as error:
                return self.send_json({"error": f"OSINT pivot failed: {error}"}, 502)

        if parsed.path == "/api/intel/correlate":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 512 * 1024:
                    return self.send_json({"error": "Correlation request must be between 1 byte and 512 KB"}, 400)
                payload = json.loads(self.rfile.read(length))
                return self.send_json(intel_correlation_payload(payload))
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": f"Correlation failed: {error}"}, 502)

        if parsed.path == "/api/integrations/test":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 4096:
                    return self.send_json({"error": "Test request must be between 1 byte and 4 KB"}, 400)
                payload = json.loads(self.rfile.read(length))
                tool_id = str(payload.get("toolId") or "")
                return self.send_json(integration_connection_test(tool_id))
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": str(error)}, 500)
        if parsed.path == "/api/soc-studio/analyze":
            try:
                payload = self.read_json(max_bytes=1024 * 1024)
                return self.send_json(analyze_soc_studio_payload(payload))
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
        if parsed.path == "/api/swimlane/request":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_PROXY_REQUEST_BYTES:
                    return self.send_json({"error": "Swimlane request must be between 1 byte and 1 MB"}, 400)
                result = swimlane_request(json.loads(self.rfile.read(length)))
                return self.send_json({"source": "live", "data": result})
            except PermissionError as error:
                return self.send_json({"error": str(error)}, 401)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": str(error)}, 502)
        if parsed.path == "/api/zero-trust/events":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > ZERO_TRUST_MAX_EVENT_BYTES:
                    return self.send_json({"error": "Event body must be between 1 byte and 64 KB"}, 400)
                event = validate_zero_trust_event(json.loads(self.rfile.read(length)))
                routing = save_integration_event(event)
                event["routing"] = routing
                append_zero_trust_event(event)
                return self.send_json({"accepted": True, "event": event, "routing": routing}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/program":
            try:
                payload = self.read_json(max_bytes=ZERO_TRUST_PROGRAM_MAX_BYTES)
                profile = save_zero_trust_program(payload)
                return self.send_json({"saved": True, "profile": profile, "source": "local-program-store"}, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/policy/decision":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16 * 1024:
                    return self.send_json({"error": "Policy decision request must be between 1 byte and 16 KB"}, 400)
                decision = evaluate_zero_trust_policy(json.loads(self.rfile.read(length)))
                audit_event = validate_zero_trust_event(decision.pop("audit_event"))
                append_zero_trust_event(audit_event)
                return self.send_json(decision)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/risk/score":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16 * 1024:
                    return self.send_json({"error": "Risk request must be between 1 byte and 16 KB"}, 400)
                payload = json.loads(self.rfile.read(length))
                result = zero_trust_risk_score(payload)
                append_zero_trust_event(validate_zero_trust_event({
                    "event_type": "access.risk.scored",
                    "event_time": result["evaluated_at"],
                    "source": {"system": "zero-trust-risk-engine", "environment": "local"},
                    "subject": {"identity_id": str(payload.get("subject_id") or "unknown")},
                    "outcome": result["decision"],
                    "risk_score": result["score"],
                    "risk_components": result["components"],
                    "enforcement": result["enforcement"],
                }))
                return self.send_json(result)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/detections/run":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                lookback = payload.get("lookback_minutes", 30)
                result = zero_trust_detections_payload(lookback)
                return self.send_json(result)
            except (TypeError, ValueError, OverflowError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/playbooks/run":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16 * 1024:
                    return self.send_json({"error": "Playbook request must be between 1 byte and 16 KB"}, 400)
                run = record_zero_trust_playbook_run(json.loads(self.rfile.read(length)))
                return self.send_json(run, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/integrations/connectors":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16 * 1024:
                    return self.send_json({"error": "Connector request must be between 1 byte and 16 KB"}, 400)
                connector = create_integration_connector(json.loads(self.rfile.read(length)))
                return self.send_json(connector, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/zero-trust/playbooks/run-all":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 16 * 1024:
                    return self.send_json({"error": "Playbook request must be at most 16 KB"}, 400)
                payload = json.loads(self.rfile.read(length)) if length else {}
                trigger = str((payload or {}).get("trigger") or "automatic dry run")[:500]
                runs = [
                    record_zero_trust_playbook_run({"playbook_id": book["id"], "trigger": trigger})
                    for book in zero_trust_playbook_catalog()
                ]
                return self.send_json({
                    "runs": runs,
                    "count": len(runs),
                    "mode": "dry_run",
                    "external_actions_executed": False,
                    "source": "local-dry-run-store",
                }, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/snort/rules":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_SNORT_ARCHIVE_BYTES:
                    return self.send_json({"error": "Snort archive must be between 1 byte and 50 MB"}, 400)
                archive_bytes = self.rfile.read(length)
                records, file_count = parse_snort_archive(archive_bytes)
                with snort_lock:
                    global snort_catalog
                    SNORT_ARCHIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
                    temporary = SNORT_ARCHIVE_FILE.with_suffix(".tmp")
                    temporary.write_bytes(archive_bytes)
                    temporary.replace(SNORT_ARCHIVE_FILE)
                    snort_catalog = None
                catalog = current_snort_catalog()
                all_records = catalog["records"] if catalog else records
                return self.send_json({"configured": True, "total": len(all_records), "enabled": sum(row["enabled"] for row in all_records), "files": catalog["files"] if catalog else file_count}, 201)
            except (ValueError, tarfile.TarError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/snort/update":
            status = update_snort_community_rules(force=True)
            return self.send_json(status, 502 if status.get("lastError") else 200)

        if parsed.path == "/api/snort/openappid":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_OPENAPPID_ARCHIVE_BYTES:
                    return self.send_json({"error": "OpenAppID package must be between 1 byte and 60 MB"}, 400)
                archive_bytes = self.rfile.read(length)
                parse_openappid_archive(archive_bytes)
                with openappid_lock:
                    global openappid_catalog
                    OPENAPPID_ARCHIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
                    temporary = OPENAPPID_ARCHIVE_FILE.with_suffix(".tmp")
                    temporary.write_bytes(archive_bytes)
                    temporary.replace(OPENAPPID_ARCHIVE_FILE)
                    openappid_catalog = None
                return self.send_json(openappid_status_payload(), 201)
            except (ValueError, tarfile.TarError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/snort/openappid/update":
            status = update_openappid_package(force=True)
            return self.send_json(status, 502 if status.get("lastError") else 200)

        if parsed.path == "/api/snort/blacklist":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_SNORT_BLACKLIST_BYTES:
                    return self.send_json({"error": "IP list must be between 1 byte and 10 MB"}, 400)
                addresses = parse_snort_ip_filter(self.rfile.read(length))
                SNORT_BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
                temporary = SNORT_BLACKLIST_FILE.with_suffix(".tmp")
                with snort_blacklist_lock:
                    temporary.write_text("\n".join(addresses) + "\n", encoding="utf-8")
                    temporary.replace(SNORT_BLACKLIST_FILE)
                return self.send_json({
                    "configured": True, "total": len(addresses),
                    "updatedAt": datetime.now(timezone.utc).isoformat(),
                }, 201)
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/network/ip-lists":
            try:
                payload = self.read_json()
                list_name = payload.get("list")
                action = payload.get("action")
                if action is None and isinstance(payload.get("observed"), list):
                    if len(payload["observed"]) > 10000:
                        return self.send_json({"error": "At most 10,000 observed addresses may be classified at once"}, 400)
                    with snort_blacklist_lock:
                        blacklist = load_network_ip_list(SNORT_BLACKLIST_FILE)
                        whitelist = load_network_ip_list(SNORT_WHITELIST_FILE)
                        reasons = read_json_store(SNORT_IP_REASONS_FILE, {"blacklist": {}, "whitelist": {}})
                    observed = list(dict.fromkeys(str(address) for address in payload["observed"]))
                    return self.send_json({
                        "blacklist": blacklist, "whitelist": whitelist, "reasons": reasons,
                        "blacklistUpdatedAt": datetime.fromtimestamp(SNORT_BLACKLIST_FILE.stat().st_mtime, timezone.utc).isoformat() if SNORT_BLACKLIST_FILE.exists() else None,
                        "whitelistUpdatedAt": datetime.fromtimestamp(SNORT_WHITELIST_FILE.stat().st_mtime, timezone.utc).isoformat() if SNORT_WHITELIST_FILE.exists() else None,
                        "observed": [classify_observed_ip(address, whitelist, blacklist) for address in observed],
                    })
                if list_name not in ("blacklist", "whitelist") or action not in ("add", "remove"):
                    return self.send_json({"error": "Choose a whitelist or blacklist and an add or remove action"}, 400)
                raw_addresses = payload.get("addresses", [])
                if isinstance(raw_addresses, str):
                    raw_addresses = [raw_addresses]
                if not isinstance(raw_addresses, list) or not raw_addresses:
                    return self.send_json({"error": "Provide one or more IP addresses or CIDR ranges"}, 400)
                encoded_addresses = "\n".join(str(address) for address in raw_addresses).encode("utf-8")
                requested = parse_snort_ip_filter(encoded_addresses)
                path = SNORT_BLACKLIST_FILE if list_name == "blacklist" else SNORT_WHITELIST_FILE
                with snort_blacklist_lock:
                    current = set(load_network_ip_list(path))
                    if action == "add":
                        reason = str(payload.get("reason") or "").strip()
                        if len(reason) < 3 or len(reason) > 500:
                            return self.send_json({"error": "Reason is required and must be between 3 and 500 characters"}, 400)
                        current.update(requested)
                        reason_store = read_json_store(SNORT_IP_REASONS_FILE, {"blacklist": {}, "whitelist": {}})
                        reason_store.setdefault(list_name, {})
                        for address in requested:
                            reason_store[list_name][address] = reason
                        write_json_store(SNORT_IP_REASONS_FILE, reason_store)
                    else:
                        current.difference_update(requested)
                        reason_store = read_json_store(SNORT_IP_REASONS_FILE, {"blacklist": {}, "whitelist": {}})
                        for address in requested:
                            reason_store.setdefault(list_name, {}).pop(address, None)
                        write_json_store(SNORT_IP_REASONS_FILE, reason_store)
                    updated = sorted(current)
                    save_network_ip_list(path, updated)
                return self.send_json({
                    "list": list_name, "action": action, "total": len(updated),
                    "addresses": updated,
                    "updatedAt": datetime.now(timezone.utc).isoformat(),
                }, 201)
            except (ValueError, UnicodeEncodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/network/indicators":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_SNORT_BLACKLIST_BYTES:
                    return self.send_json({"error": "Indicator request must be between 1 byte and 10 MB"}, 400)
                result = update_network_indicators(json.loads(self.rfile.read(length)))
                return self.send_json(result, 201)
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/claroty/credentials":
            try:
                config = save_claroty_credentials(self.read_json())
                return self.send_json(claroty_credentials_status(config))
            except Exception as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/claroty/credentials/confirm":
            try:
                config = confirm_claroty_credentials()
                return self.send_json(claroty_credentials_status(config))
            except Exception as error:
                return self.send_json({"error": str(error)}, 400)

        if parsed.path == "/api/claroty/device-vulnerability-relations":
            try:
                config = load_claroty_credentials()
                if not config or not config.get("apiKey"):
                    return self.send_json({"error": "Claroty credentials are not configured"}, 401)
                payload = self.read_json()
                payload.setdefault("fields", CLAROTY_DVR_FIELDS)
                payload.setdefault("limit", 1000)
                payload.setdefault("offset", 0)
                upstream = claroty_request(config, CLAROTY_DVR_ENDPOINT, payload)
                return self.send_json({"source": "live", "payload": upstream})
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="ignore")
                return self.send_json({"error": f"Claroty API error {error.code}", "detail": detail}, error.code)
            except Exception as error:
                return self.send_json({"error": "Claroty request failed", "detail": str(error)}, 502)

        if parsed.path == "/api/claroty/feed":
            try:
                payload = self.read_json()
                feed = str(payload.get("feed") or "")
                if feed not in CLAROTY_FEEDS:
                    return self.send_json({"error": "Unsupported Claroty feed"}, 400)
                config = load_claroty_credentials()
                if not config or not config.get("apiKey"):
                    return self.send_json({"error": "Claroty credentials are not configured"}, 401)
                endpoint, fields, response_key = CLAROTY_FEEDS[feed]
                limit = max(1, min(5000, int(payload.get("limit", 1000))))
                offset = max(0, int(payload.get("offset", 0)))
                upstream = claroty_request(config, endpoint, {"fields": fields, "limit": limit, "offset": offset})
                records = claroty_feed_records(upstream, response_key)
                if not isinstance(records, list):
                    keys = list(upstream) if isinstance(upstream, dict) else []
                    return self.send_json({"error": "Unexpected Claroty response shape", "feed": feed, "responseKeys": keys}, 502)
                return self.send_json({
                    "feed": feed, "source": "live", "records": records,
                    "offset": offset, "limit": limit, "hasMore": len(records) == limit,
                    "fetchedAt": datetime.now(timezone.utc).isoformat(),
                })
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="ignore")
                return self.send_json({"error": f"Claroty API error {error.code}", "detail": detail}, error.code)
            except (TypeError, ValueError) as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": "Claroty feed request failed", "detail": str(error)}, 502)

        if parsed.path == "/api/claroty/diagnostics":
            try:
                config = load_claroty_credentials()
                if not config or not config.get("apiKey"):
                    return self.send_json({"error": "Claroty credentials are not configured"}, 401)
                def check_feed(item):
                    feed, (endpoint, fields, response_key) = item
                    started = time.monotonic()
                    try:
                        result = claroty_request(config, endpoint, {"fields": fields[:4], "limit": 1, "offset": 0})
                        rows = result.get(response_key, []) if isinstance(result, dict) else result
                        return {"feed": feed, "ok": True, "sampleCount": len(rows) if isinstance(rows, list) else 0, "latencyMs": round((time.monotonic() - started) * 1000)}
                    except urllib.error.HTTPError as error:
                        return {"feed": feed, "ok": False, "status": error.code, "error": error.read().decode("utf-8", errors="ignore")[:300]}
                    except Exception as error:
                        return {"feed": feed, "ok": False, "error": str(error)[:300]}

                with ThreadPoolExecutor(max_workers=len(CLAROTY_FEEDS)) as pool:
                    results = list(pool.map(check_feed, CLAROTY_FEEDS.items()))
                return self.send_json({"source": "live", "checkedAt": datetime.now(timezone.utc).isoformat(), "feeds": results})
            except Exception as error:
                return self.send_json({"error": "Claroty diagnostics failed", "detail": str(error)}, 502)

        if parsed.path == "/api/claroty/test":
            try:
                payload = self.read_json()
                if any(key in payload for key in ("apiKey", "api_key", "token", "password")):
                    return self.send_json({"ok": False, "msg": "Send Claroty credentials to encrypted Settings storage before testing"}, 400)
                config = load_claroty_credentials()
                if not config or not config.get("apiKey"):
                    return self.send_json({"ok": False, "msg": "Claroty credentials are not configured"}, 401)
                claroty_request(config, CLAROTY_DVR_ENDPOINT, {"fields": ["device_uid", "vulnerability_id"], "limit": 1, "offset": 0})
                return self.send_json({"ok": True, "msg": "Connected successfully - encrypted backend Claroty credential validated"})
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="ignore")
                return self.send_json({"ok": False, "msg": f"Claroty API error {error.code}", "detail": detail}, error.code)
            except Exception as error:
                return self.send_json({"ok": False, "msg": str(error)}, 502)

        match = re.fullmatch(r"/api/alerts/([^/]+)/actions", parsed.path)
        if not match:
            return self.send_json({"error": "Not found"}, 404)
        payload = self.read_json()
        with alert_lock:
            alert = next((item for item in alerts if item["id"] == match.group(1)), None)
            if not alert:
                return self.send_json({"error": "Alert not found"}, 404)
            action = payload.get("action")
            if action == "acknowledge":
                alert["state"] = "Acknowledged"
            elif action == "own":
                alert["state"] = "Investigating"
                alert["owner"] = payload.get("owner") or "SOC Analyst"
            elif action == "escalate":
                alert["state"] = "Escalated"
                alert["owner"] = alert["owner"] or "SOC Analyst"
                alert["ticket"] = alert["ticket"] or f"INC-{random.randint(100000, 999999)}"
            else:
                return self.send_json({"error": "Unsupported action"}, 400)
        return self.send_json(alert)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if not is_trusted_local_origin(self.headers.get("Origin"), self.headers.get("Host")):
            return self.send_json({"error": "Cross-origin API writes are not allowed"}, 403)
        if not self.require_local_session():
            return
        match = re.fullmatch(r"/api/modules/([a-z_]+)/([^/]+)", parsed.path)
        if match:
            module_name, record_id = match.groups()
            if module_name in AUDIT_WORKFLOW_MODULES:
                return self.send_json({"error": "Use the dedicated audit API"}, 403)
            if module_name not in MODULE_NAMES:
                return self.send_json({"error": "Unknown module"}, 404)
            try:
                record_id = unquote(record_id)
                existing = get_module_record(module_name, record_id)
                if not existing:
                    return self.send_json({"error": "Record not found"}, 404)
                payload = self.read_json()
                if module_name == "audit_assignments" and WORKBOOK_ASSIGNMENT_STATE_FIELDS.intersection(payload):
                    return self.send_json({"error": "Audit state is managed by response and review APIs"}, 403)
                updated = save_module_record(module_name, {**existing, **payload}, record_id)
                return self.send_json({"record": updated, "source": "local-module-store"})
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        template_match = re.fullmatch(r"/api/(?:custom_questionnaire_templates|custom_templates)/([^/]+)", parsed.path)
        if template_match:
            try:
                template_id = unquote(template_match.group(1))
                existing = get_module_record("custom_templates", template_id)
                if not existing:
                    return self.send_json({"error": "Template not found"}, 404)
                payload = self.read_json()
                if "sheets" in payload:
                    payload["sheets"] = validate_template_sheets(payload["sheets"])
                if "questions" in payload:
                    if not isinstance(payload["questions"], list) or not 1 <= len(payload["questions"]) <= 5000:
                        return self.send_json({"error": "A template must include 1-5,000 questions"}, 400)
                    payload["question_count"] = len(payload["questions"])
                updated = save_module_record("custom_templates", {**existing, **payload}, template_id)
                return self.send_json({"status": "updated", "template": updated})
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)

        match = re.fullmatch(r"/api/(secumat_audits|audit_assignments)/([^/]+)", parsed.path)
        if match:
            collection, record_id = match.groups()
            module_name = "secumat_audits" if collection == "secumat_audits" else "audit_assignments"
            try:
                record_id = unquote(record_id)
                existing = get_module_record(module_name, record_id)
                if not existing:
                    return self.send_json({"error": "Record not found"}, 404)
                payload = self.read_json()
                if module_name == "audit_assignments" and WORKBOOK_ASSIGNMENT_STATE_FIELDS.intersection(payload):
                    return self.send_json({"error": "Audit state is managed by response and review APIs"}, 403)
                updated = save_module_record(module_name, {**existing, **payload}, record_id)
                return self.send_json({"status": "updated", "audit" if module_name == "secumat_audits" else "assignment": updated})
            except (ValueError, json.JSONDecodeError) as error:
                return self.send_json({"error": str(error)}, 400)
        return self.send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if not is_trusted_local_origin(self.headers.get("Origin"), self.headers.get("Host")):
            return self.send_json({"error": "Cross-origin API writes are not allowed"}, 403)
        if not self.require_local_session():
            return
        integration_match = re.fullmatch(r"/api/integrations/credentials/([a-z0-9-]{1,40})", parsed.path)
        if integration_match:
            try:
                deleted = delete_integration_credentials(integration_match.group(1))
                return self.send_json({"deleted": deleted, "toolId": integration_match.group(1)})
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
            except Exception as error:
                return self.send_json({"error": str(error)}, 500)
        if parsed.path == "/api/claroty/credentials":
            delete_claroty_credentials()
            return self.send_json({"configured": False, "encrypted": False, "needsDailyConfirm": False})
        connector_match = re.fullmatch(r"/api/integrations/connectors/([0-9a-f-]+)", parsed.path)
        if connector_match:
            if not delete_integration_connector(connector_match.group(1)):
                return self.send_json({"error": "Integration connector not found"}, 404)
            return self.send_json({"deleted": True, "id": connector_match.group(1)})
        match = re.fullmatch(r"/api/modules/([a-z_]+)/([^/]+)", parsed.path)
        if match:
            module_name, record_id = match.groups()
            if module_name in AUDIT_WORKFLOW_MODULES:
                return self.send_json({"error": "Use the dedicated audit API"}, 403)
            if module_name not in MODULE_NAMES:
                return self.send_json({"error": "Unknown module"}, 404)
            try:
                deleted = delete_module_record(module_name, unquote(record_id))
                return self.send_json({"deleted": deleted, "id": unquote(record_id), "module": module_name}, 200 if deleted else 404)
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
        template_match = re.fullmatch(r"/api/(?:custom_questionnaire_templates|custom_templates)/([^/]+)", parsed.path)
        if template_match:
            try:
                template_id = unquote(template_match.group(1))
                deleted = delete_module_record("custom_templates", template_id)
                return self.send_json({"deleted": deleted, "id": template_id}, 200 if deleted else 404)
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
        match = re.fullmatch(r"/api/(secumat_audits|audit_assignments)/([^/]+)", parsed.path)
        if match:
            collection, record_id = match.groups()
            module_name = "secumat_audits" if collection == "secumat_audits" else "audit_assignments"
            try:
                record_id = unquote(record_id)
                deleted = delete_module_record(module_name, record_id)
                if not deleted:
                    return self.send_json({"error": "Record not found"}, 404)
                if module_name == "audit_assignments":
                    with MODULE_DATA_LOCK:
                        store = module_store_payload()
                        store["modules"]["audit_responses"] = [item for item in store["modules"]["audit_responses"] if str(item.get("assignment_id")) != record_id]
                        write_json_store(MODULE_DATA_FILE, store)
                return self.send_json({"deleted": True, "id": record_id})
            except ValueError as error:
                return self.send_json({"error": str(error)}, 400)
        return self.send_json({"error": "Not found"}, 404)

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        if not is_trusted_local_origin(self.headers.get("Origin")):
            return self.send_json({"error": "Origin is not allowed"}, 403)
        self.send_response(200)
        self.add_local_cors_headers()
        self.send_header("Access-Control-Max-Age", "3600")
        self.end_headers()


if __name__ == "__main__":
    print(f"SOC dashboard: http://{HOST}:{PORT}")
    print("API health:   http://127.0.0.1:8080/api/health")
    threading.Thread(target=snort_update_worker, name="snort-community-updater", daemon=True).start()
    threading.Thread(target=threat_feed_update_worker, name="threat-feed-updater", daemon=True).start()
    ThreadingHTTPServer((HOST, PORT), DashboardHandler).serve_forever()