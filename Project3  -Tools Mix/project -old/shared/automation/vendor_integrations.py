import copy
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = REPO_ROOT / "data" / "security_tool_integrations.json"
MANUAL_SETTINGS_PATH = REPO_ROOT / "data" / "manual_api_integrations.json"
_CACHE: Dict[str, Dict[str, Any]] = {}


DEFAULT_SETTINGS: Dict[str, Any] = {
    "platforms": {
        "claroty_xdome": {
            "enabled": False,
            "display_name": "Claroty xDome",
            "portal_url": "https://zf.eu.dashboard.claroty.com/dashboard",
            "category": "OT / Exposure Management",
            "modules": ["threat_detection", "compliance_check", "alert_priority"],
            "api_base_url": "https://eu.api.claroty.com",
            "credential_env": ["CLAROTY_BASE_URL", "CLAROTY_API_TOKEN"],
            "health_mode": "live_read_only",
            "timeout_seconds": 15,
            "cache_ttl_seconds": 180,
        },
        "swimlane_secops": {
            "enabled": True,
            "display_name": "Swimlane SECOPS",
            "portal_url": "https://frd-ngxswl01.secops.zf-world.com/",
            "category": "SOAR / Case Management",
            "modules": ["threat_detection", "alert_priority", "compliance_check"],
            "credential_env": ["SWIMLANE_BASE_URL", "SWIMLANE_API_TOKEN"],
            "health_mode": "config_only",
        },
        "crowdstrike_falcon": {
            "enabled": True,
            "display_name": "CrowdStrike Falcon",
            "portal_url": "https://falcon.eu-1.crowdstrike.com/",
            "category": "EDR / Threat Detection",
            "modules": ["threat_detection", "edr_monitor", "alert_priority"],
            "api_base_url": "https://api.eu-1.crowdstrike.com",
            "credential_env": ["CROWDSTRIKE_BASE_URL", "CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"],
            "health_mode": "live_read_only",
            "timeout_seconds": 12,
            "cache_ttl_seconds": 180,
        },
        "microsoft_defender": {
            "enabled": True,
            "display_name": "Microsoft Defender",
            "portal_url": "https://security.microsoft.com/",
            "category": "XDR / Endpoint / Email",
            "modules": ["edr_monitor", "alert_priority", "threat_detection"],
            "credential_env": ["DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"],
            "health_mode": "config_only",
        },
        "microsoft_sentinel": {
            "enabled": True,
            "display_name": "Microsoft Sentinel",
            "portal_url": "https://login.microsoftonline.com/",
            "category": "SIEM / Analytics",
            "modules": ["threat_detection", "alert_priority", "ueba"],
            "credential_env": ["SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET", "SENTINEL_SUBSCRIPTION_ID", "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME"],
            "health_mode": "config_only",
        },
        "microsoft_azure": {
            "enabled": True,
            "display_name": "Microsoft Azure",
            "portal_url": "https://portal.azure.com/#home",
            "category": "Cloud Platform / Management",
            "modules": ["compliance_check", "alert_priority", "ueba"],
            "credential_env": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"],
            "health_mode": "config_only",
        },
        "wiz_portal": {
            "enabled": True,
            "display_name": "Wiz Portal",
            "portal_url": "https://app.wiz.io/",
            "category": "CNAPP / Cloud Security",
            "modules": ["threat_detection", "compliance_check", "alert_priority"],
            "credential_env": ["WIZ_API_URL", "WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET"],
            "health_mode": "config_only",
        },
        "tenable_nessus": {
            "enabled": True,
            "display_name": "Tenable / Nessus",
            "portal_url": "https://cloud.tenable.com/",
            "category": "Vulnerability Management",
            "modules": ["threat_detection", "alert_priority", "vuln_patch"],
            "credential_env": ["NESSUS_BASE_URL", "NESSUS_USERNAME", "NESSUS_PASSWORD"],
            "health_mode": "config_only",
        },
        "trellix_epo": {
            "enabled": True,
            "display_name": "Trellix ePO",
            "portal_url": "",
            "category": "Endpoint Protection",
            "modules": ["edr_monitor", "alert_priority", "compliance_check"],
            "credential_env": ["TRELLIX_BASE_URL", "TRELLIX_API_TOKEN"],
            "health_mode": "config_only",
        },
        "bmc_helix": {
            "enabled": True,
            "display_name": "BMC Helix / Discovery",
            "portal_url": "",
            "category": "ITSM / CMDB",
            "modules": ["alert_priority", "vuln_patch", "compliance_check"],
            "credential_env": ["BMC_BASE_URL", "BMC_USERNAME", "BMC_PASSWORD"],
            "health_mode": "config_only",
        },
        "pits_database": {
            "enabled": True,
            "display_name": "PITS Database",
            "portal_url": "",
            "category": "OT Asset Database",
            "modules": ["threat_detection", "alert_priority", "compliance_check"],
            "credential_env": ["PITS_FEED_CSV"],
            "health_mode": "config_only",
        },
        "mimecast": {
            "enabled": True,
            "display_name": "Mimecast",
            "portal_url": "https://login-de.mimecast.com/",
            "category": "Email Security",
            "modules": ["threat_detection", "ueba"],
            "credential_env": ["MIMECAST_BASE_URL", "MIMECAST_ACCESS_KEY", "MIMECAST_SECRET_KEY", "MIMECAST_APP_ID", "MIMECAST_APP_KEY"],
            "health_mode": "config_only",
        },
    }
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_integration_settings() -> Dict[str, Any]:
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    if SETTINGS_PATH.exists():
        try:
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            settings = _merge_dicts(settings, raw)
        except Exception:
            pass

    # The dashboard administration form stores connection metadata separately
    # from credentials. Merge it here so an enabled integration affects pulls.
    if MANUAL_SETTINGS_PATH.exists():
        try:
            manual_entries = json.loads(MANUAL_SETTINGS_PATH.read_text(encoding="utf-8"))
            for entry in manual_entries if isinstance(manual_entries, list) else []:
                slug = str(entry.get("slug") or "").strip()
                if not slug:
                    continue
                settings.setdefault("platforms", {})[slug] = _merge_dicts(
                    settings["platforms"].get(slug, {}), entry
                )
        except Exception:
            pass
    return settings


def _cache_get(cache_key: str) -> Optional[Dict[str, Any]]:
    entry = _CACHE.get(cache_key)
    if not entry:
        return None
    if time.time() >= entry.get("expires_at", 0):
        _CACHE.pop(cache_key, None)
        return None
    return entry.get("payload")


def _cache_set(cache_key: str, payload: Dict[str, Any], ttl_seconds: int) -> Dict[str, Any]:
    _CACHE[cache_key] = {
        "payload": payload,
        "expires_at": time.time() + max(ttl_seconds, 1),
    }
    return payload


def _required_env_present(env_names: List[str]) -> bool:
    return all(str(os.environ.get(name, "")).strip() for name in env_names)


def _base_health(slug: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    env_names = list(cfg.get("credential_env") or [])
    configured = _required_env_present(env_names)
    enabled = bool(cfg.get("enabled", True))
    if not enabled:
        status = "disabled"
        message = "Integration is disabled in the platform settings file."
    elif configured:
        status = "configured"
        message = "Credentials detected."
    else:
        status = "unconfigured"
        message = "Missing one or more required credential environment variables."

    return {
        "slug": slug,
        "enabled": enabled,
        "configured": configured,
        "status": status,
        "checked_at": _utc_now_iso(),
        "message": message,
        "required_env": env_names,
    }


def _crowdstrike_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "base_url": str(os.environ.get("CROWDSTRIKE_BASE_URL") or cfg.get("api_base_url") or "https://api.eu-1.crowdstrike.com").rstrip("/"),
        "client_id": str(os.environ.get("CROWDSTRIKE_CLIENT_ID") or "").strip(),
        "client_secret": str(os.environ.get("CROWDSTRIKE_CLIENT_SECRET") or "").strip(),
        "member_cid": str(os.environ.get("CROWDSTRIKE_MEMBER_CID") or "").strip(),
        "timeout": int(cfg.get("timeout_seconds") or 12),
        "cache_ttl": int(cfg.get("cache_ttl_seconds") or 180),
    }


def _claroty_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Read Claroty settings from environment without exposing secret values."""
    return {
        "base_url": str(os.environ.get("CLAROTY_BASE_URL") or cfg.get("api_base_url") or "").rstrip("/"),
        "token": str(os.environ.get("CLAROTY_API_TOKEN") or "").strip(),
        "assets_path": str(os.environ.get("CLAROTY_ASSETS_PATH") or "").strip(),
        "vulnerabilities_path": str(os.environ.get("CLAROTY_VULNERABILITIES_PATH") or "/api/v1/device_vulnerability_relations/").strip(),
        "tickets_path": str(os.environ.get("CLAROTY_TICKETS_PATH") or "").strip(),
        "token_header": str(os.environ.get("CLAROTY_TOKEN_HEADER") or "X-API-Key").strip(),
        "token_prefix": str(os.environ.get("CLAROTY_TOKEN_PREFIX") or "").strip(),
        "proxy_url": str(os.environ.get("CLAROTY_PROXY_URL") or "").strip(),
        "verify_tls": str(os.environ.get("CLAROTY_VERIFY_TLS") or "true").strip().lower() not in {"0", "false", "no", "off"},
        "timeout": int(cfg.get("timeout_seconds") or 15),
        "cache_ttl": int(cfg.get("cache_ttl_seconds") or 180),
    }


def _claroty_items(payload: Any) -> List[Dict[str, Any]]:
    """Extract a list of records from common Claroty API response envelopes."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "items", "results", "assets", "vulnerabilities", "incidents", "tickets"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _claroty_items(value)
            if nested:
                return nested
    return []


def _claroty_get(claroty_cfg: Dict[str, Any], path: str, limit: int) -> List[Dict[str, Any]]:
    """Retrieve one Claroty collection with a configurable authentication header."""
    if not path:
        return []
    base_url = str(claroty_cfg["base_url"] or "").rstrip("/")
    path_part = str(path or "").strip("/")
    if path.startswith("http"):
        endpoint = path
    elif path_part and base_url.lower().endswith(path_part.lower()):
        endpoint = base_url + "/"
    else:
        endpoint = f"{base_url}/{path_part}/"
    token_value = claroty_cfg["token"]
    prefix = claroty_cfg["token_prefix"]
    headers = {claroty_cfg["token_header"]: f"{prefix} {token_value}".strip()}
    proxies = {"http": claroty_cfg["proxy_url"], "https": claroty_cfg["proxy_url"]} if claroty_cfg["proxy_url"] else None
    response = requests.get(
        endpoint,
        headers=headers,
        params={"limit": max(1, min(limit, 500))},
        timeout=claroty_cfg["timeout"],
        proxies=proxies,
        verify=bool(claroty_cfg.get("verify_tls", True)),
    )
    response.raise_for_status()
    return _claroty_items(response.json())


def _normalize_claroty_vulnerability(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Claroty vulnerability records for SOC enrichment and ticketing."""
    asset = item.get("asset") if isinstance(item.get("asset"), dict) else {}
    severity = item.get("severity") or item.get("risk_level") or item.get("risk") or item.get("priority") or "medium"
    asset_name = item.get("asset_name") or item.get("device_name") or asset.get("name") or asset.get("hostname") or item.get("asset_id") or "unknown-asset"
    return {
        "source": "claroty_xdome",
        "vulnerability_id": str(item.get("id") or item.get("vulnerability_id") or item.get("uid") or "unknown-vulnerability"),
        "cve": str(item.get("cve") or item.get("cve_id") or item.get("cveId") or ""),
        "severity": _normalize_severity(severity),
        "status": str(item.get("status") or "open").lower(),
        "asset_name": str(asset_name),
        "asset_id": str(item.get("asset_id") or asset.get("id") or asset_name),
        "title": str(item.get("title") or item.get("name") or item.get("description") or "Claroty vulnerability"),
        "description": str(item.get("description") or item.get("details") or ""),
        "cvss_score": item.get("cvss") or item.get("cvss_score") or item.get("score"),
        "first_seen": item.get("first_seen") or item.get("first_detected") or item.get("created_at"),
        "last_seen": item.get("last_seen") or item.get("updated_at") or item.get("modified_at"),
        "raw": item,
    }


def _normalize_claroty_ticket(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Claroty incident or ticket records for SOC queue correlation."""
    severity = item.get("severity") or item.get("priority") or item.get("risk_level") or "medium"
    asset = item.get("asset") if isinstance(item.get("asset"), dict) else {}
    asset_name = item.get("asset_name") or item.get("device_name") or asset.get("name") or item.get("asset_id") or "unknown-asset"
    return {
        "source": "claroty_xdome",
        "ticket_id": str(item.get("id") or item.get("ticket_id") or item.get("incident_id") or "unknown-ticket"),
        "severity": _normalize_severity(severity),
        "status": str(item.get("status") or "open").lower(),
        "asset_name": str(asset_name),
        "title": str(item.get("title") or item.get("name") or "Claroty incident"),
        "description": str(item.get("description") or item.get("details") or ""),
        "created_at": item.get("created_at") or item.get("opened_at") or item.get("first_seen"),
        "updated_at": item.get("updated_at") or item.get("modified_at") or item.get("last_seen"),
        "raw": item,
    }


def fetch_claroty_soc_feed(
    limit: int = 100,
    api_token: Optional[str] = None,
    token_header: Optional[str] = None,
    token_prefix: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_tls: Optional[bool] = None,
) -> Dict[str, Any]:
    """Pull Claroty OT assets, vulnerabilities, and tickets for SOC analytics."""
    settings = load_integration_settings()
    cfg = settings["platforms"]["claroty_xdome"]
    health = _base_health("claroty_xdome", cfg)
    api_token = str(api_token or "").strip()
    if not api_token:
        try:
            from .credential_store import load_integration_token
            api_token = load_integration_token("claroty_xdome") or ""
        except (ImportError, RuntimeError) as exc:
            logger.warning("Saved Claroty credential unavailable: %s", exc)
    if api_token:
        # A dashboard token authorizes this one read-only request only.
        # It is neither persisted nor used to enable the integration.
        health["enabled"] = True
        health["configured"] = True
        health["status"] = "configured"
    if health["status"] == "disabled":
        health["message"] = "Claroty ingestion is disabled until tenant endpoints and credentials are configured."
        return {"health": health, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0}}
    if not health["configured"]:
        health["message"] = "Set CLAROTY_BASE_URL and CLAROTY_API_TOKEN before enabling Claroty read-only ingestion."
        return {"health": health, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0}}

    claroty_cfg = _claroty_config(cfg)
    if api_token:
        claroty_cfg["token"] = api_token
    if token_header in {"Authorization", "X-API-Key"}:
        claroty_cfg["token_header"] = token_header
    if token_prefix in {"Bearer", ""}:
        claroty_cfg["token_prefix"] = token_prefix
    if proxy_url is not None:
        claroty_cfg["proxy_url"] = str(proxy_url or "").strip()
    if verify_tls is not None:
        claroty_cfg["verify_tls"] = bool(verify_tls)
    if not claroty_cfg["base_url"]:
        health["status"] = "unconfigured"
        health["message"] = "CLAROTY_BASE_URL is required for live ingestion."
        return {"health": health, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0}}
    # A browser-supplied token is intentionally never used as a cache key.
    # Skip caching it so a response cannot cross session or token boundaries.
    cache_key = f"claroty:{limit}:{claroty_cfg['base_url']}"
    if not api_token:
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached
    try:
        assets = _claroty_get(claroty_cfg, claroty_cfg["assets_path"], limit)
        vulnerabilities = [_normalize_claroty_vulnerability(item) for item in _claroty_get(claroty_cfg, claroty_cfg["vulnerabilities_path"], limit)]
        tickets = [_normalize_claroty_ticket(item) for item in _claroty_get(claroty_cfg, claroty_cfg["tickets_path"], limit)]
        payload = {
            "health": {**health, "status": "healthy", "message": f"Pulled {len(assets)} assets, {len(vulnerabilities)} vulnerabilities, and {len(tickets)} tickets from Claroty.", "checked_at": _utc_now_iso()},
            "assets": assets,
            "vulnerabilities": vulnerabilities,
            "tickets": tickets,
            "metrics": {"assets": len(assets), "vulnerabilities": len(vulnerabilities), "tickets": len(tickets), "critical": sum(1 for item in vulnerabilities if item["severity"] == "critical"), "high": sum(1 for item in vulnerabilities if item["severity"] == "high"), "base_url": claroty_cfg["base_url"], "proxy_configured": bool(claroty_cfg["proxy_url"]), "tls_verify": bool(claroty_cfg.get("verify_tls", True))},
        }
        return payload if api_token else _cache_set(cache_key, payload, claroty_cfg["cache_ttl"])
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        detail = f"Claroty API returned HTTP {status_code}" if status_code else "Claroty API returned an HTTP error"
        payload = {"health": {**health, "status": "error", "message": detail, "checked_at": _utc_now_iso()}, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0, "http_status": status_code}}
        return payload if api_token else _cache_set(cache_key, payload, 30)
    except requests.exceptions.SSLError:
        payload = {"health": {**health, "status": "error", "message": "Claroty SSL verification failed. Try the ZF proxy setting, confirm the corporate CA trust chain, or temporarily test with TLS verification disabled.", "checked_at": _utc_now_iso()}, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0, "error": "ssl_error", "proxy_configured": bool(claroty_cfg["proxy_url"]), "tls_verify": bool(claroty_cfg.get("verify_tls", True))}}
        return payload if api_token else _cache_set(cache_key, payload, 30)
    except requests.exceptions.ProxyError:
        payload = {"health": {**health, "status": "error", "message": "Claroty proxy connection failed. Check CLAROTY_PROXY_URL or test without the proxy if direct egress is allowed.", "checked_at": _utc_now_iso()}, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0, "error": "proxy_error", "proxy_configured": bool(claroty_cfg["proxy_url"]), "tls_verify": bool(claroty_cfg.get("verify_tls", True))}}
        return payload if api_token else _cache_set(cache_key, payload, 30)
    except requests.exceptions.Timeout:
        payload = {"health": {**health, "status": "error", "message": "Claroty read request timed out. Check proxy connectivity and endpoint reachability.", "checked_at": _utc_now_iso()}, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0, "error": "timeout", "proxy_configured": bool(claroty_cfg["proxy_url"]), "tls_verify": bool(claroty_cfg.get("verify_tls", True))}}
        return payload if api_token else _cache_set(cache_key, payload, 30)
    except Exception as exc:
        payload = {"health": {**health, "status": "error", "message": f"Claroty API check failed: {type(exc).__name__}", "checked_at": _utc_now_iso()}, "assets": [], "vulnerabilities": [], "tickets": [], "metrics": {"assets": 0, "vulnerabilities": 0, "tickets": 0, "error": type(exc).__name__}}
        return payload if api_token else _cache_set(cache_key, payload, 30)


def _normalize_severity(value: Any) -> str:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"critical", "high", "medium", "low", "informational", "info"}:
            return "info" if lowered == "informational" else lowered
    try:
        numeric = int(value)
    except Exception:
        return "medium"
    if numeric >= 90:
        return "critical"
    if numeric >= 70:
        return "high"
    if numeric >= 40:
        return "medium"
    return "low"


def _crowdstrike_token(cs_cfg: Dict[str, Any]) -> str:
    data = {
        "client_id": cs_cfg["client_id"],
        "client_secret": cs_cfg["client_secret"],
    }
    if cs_cfg.get("member_cid"):
        data["member_cid"] = cs_cfg["member_cid"]
    response = requests.post(
        f"{cs_cfg['base_url']}/oauth2/token",
        data=data,
        timeout=cs_cfg["timeout"],
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("CrowdStrike token response did not include access_token")
    return str(token)


def _crowdstrike_get(cs_cfg: Dict[str, Any], token: str, path: str, params: Optional[List[tuple]] = None) -> Dict[str, Any]:
    response = requests.get(
        f"{cs_cfg['base_url']}{path}",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        timeout=cs_cfg["timeout"],
    )
    response.raise_for_status()
    return response.json()


def _normalize_crowdstrike_detection(item: Dict[str, Any]) -> Dict[str, Any]:
    behaviors = item.get("behaviors") or []
    primary_behavior = behaviors[0] if behaviors else {}
    severity_value = (
        item.get("max_severity_displayname")
        or item.get("severity_name")
        or primary_behavior.get("severity")
        or primary_behavior.get("severity_name")
        or item.get("max_severity")
        or 50
    )
    device = item.get("device") if isinstance(item.get("device"), dict) else {}
    hostname = (
        primary_behavior.get("device_name")
        or item.get("device_name")
        or device.get("hostname")
        or device.get("device_id")
        or item.get("device_id")
        or "unknown-endpoint"
    )
    detection_id = item.get("detection_id") or item.get("id") or primary_behavior.get("detection_id") or "unknown-detection"
    title = (
        primary_behavior.get("display_name")
        or primary_behavior.get("tactic")
        or item.get("status")
        or "CrowdStrike detection"
    )
    description = item.get("description") or primary_behavior.get("description") or title
    return {
        "source": "crowdstrike_falcon",
        "detection_id": str(detection_id),
        "severity": _normalize_severity(severity_value),
        "status": str(item.get("status") or "unknown").lower(),
        "hostname": str(hostname),
        "device_id": str(item.get("device_id") or device.get("device_id") or hostname),
        "title": str(title),
        "description": str(description),
        "first_behavior": item.get("first_behavior") or primary_behavior.get("timestamp"),
        "last_behavior": item.get("last_behavior") or item.get("updated_timestamp") or primary_behavior.get("timestamp"),
        "raw": item,
    }


def fetch_crowdstrike_detection_feed(limit: int = 10) -> Dict[str, Any]:
    settings = load_integration_settings()
    cfg = settings["platforms"]["crowdstrike_falcon"]
    health = _base_health("crowdstrike_falcon", cfg)
    if health["status"] == "disabled":
        return {"health": health, "detections": [], "metrics": {"detections": 0}}
    if not health["configured"]:
        health["message"] = "Set CROWDSTRIKE_BASE_URL, CROWDSTRIKE_CLIENT_ID, and CROWDSTRIKE_CLIENT_SECRET to enable live read-only ingestion."
        return {"health": health, "detections": [], "metrics": {"detections": 0}}

    cs_cfg = _crowdstrike_config(cfg)
    cache_key = f"crowdstrike:{limit}:{cs_cfg['base_url']}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        token = _crowdstrike_token(cs_cfg)
        detection_ids_payload = _crowdstrike_get(
            cs_cfg,
            token,
            "/detects/queries/detects/v1",
            params=[("limit", str(max(1, min(limit, 50))))],
        )
        detection_ids = list(detection_ids_payload.get("resources") or [])
        summaries: List[Dict[str, Any]] = []
        if detection_ids:
            summary_params = [("ids", str(det_id)) for det_id in detection_ids[: max(1, min(limit, 50))]]
            summaries_payload = _crowdstrike_get(
                cs_cfg,
                token,
                "/detects/entities/summaries/GET/v1",
                params=summary_params,
            )
            summaries = list(summaries_payload.get("resources") or [])

        detections = [_normalize_crowdstrike_detection(item) for item in summaries]
        critical = sum(1 for item in detections if item["severity"] == "critical")
        high = sum(1 for item in detections if item["severity"] == "high")
        healthy = {
            "health": {
                **health,
                "status": "healthy",
                "message": f"Live read-only CrowdStrike API reachable. Pulled {len(detections)} detections.",
                "checked_at": _utc_now_iso(),
            },
            "detections": detections,
            "metrics": {
                "detections": len(detections),
                "critical": critical,
                "high": high,
                "base_url": cs_cfg["base_url"],
            },
        }
        return _cache_set(cache_key, healthy, cs_cfg["cache_ttl"])
    except Exception as exc:
        error_payload = {
            "health": {
                **health,
                "status": "error",
                "message": f"CrowdStrike API check failed: {exc}",
                "checked_at": _utc_now_iso(),
            },
            "detections": [],
            "metrics": {"detections": 0, "error": str(exc)},
        }
        return _cache_set(cache_key, error_payload, 30)


def build_integration_catalog() -> List[Dict[str, Any]]:
    settings = load_integration_settings()
    platforms = settings.get("platforms") or {}
    crowdstrike_live = fetch_crowdstrike_detection_feed(limit=10)
    claroty_live = fetch_claroty_soc_feed(limit=100)

    catalog: List[Dict[str, Any]] = []
    for slug, cfg in platforms.items():
        health = _base_health(slug, cfg)
        live_metrics: Dict[str, Any] = {}
        if slug == "crowdstrike_falcon":
            health = crowdstrike_live.get("health") or health
            live_metrics = crowdstrike_live.get("metrics") or {}
        elif slug == "claroty_xdome":
            health = claroty_live.get("health") or health
            live_metrics = claroty_live.get("metrics") or {}
        elif health["configured"]:
            health["message"] = "Credentials detected. Live connector is not implemented yet for this platform."
            health["status"] = "configured"
        elif health["status"] == "unconfigured":
            health["message"] = "Configuration file is present, but credential environment variables are missing."

        catalog.append(
            {
                "slug": slug,
                "name": cfg.get("display_name") or slug,
                "vendor": (cfg.get("display_name") or slug).split(" ")[0],
                "category": cfg.get("category") or "Security Platform",
                "portal_url": cfg.get("portal_url") or "",
                "enabled": bool(cfg.get("enabled", True)),
                "modules": list(cfg.get("modules") or []),
                "health_mode": cfg.get("health_mode") or "config_only",
                "credential_env": list(cfg.get("credential_env") or []),
                "health": health,
                "live_metrics": live_metrics,
            }
        )
    return catalog
