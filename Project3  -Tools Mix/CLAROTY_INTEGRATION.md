# Claroty xDome API Integration Guide

## Overview
This document describes how to integrate and test the Claroty xDome API with the SOC Dashboard. The integration uses the **v1 device_vulnerability_relations endpoint** with an API token through the ZF proxy.

---

## Quick Setup

### 1. Add Claroty Configuration
In the dashboard UI, navigate to **Settings › Integrations** and add Claroty xDome:

| Field | Value | Notes |
|-------|-------|-------|
| **Claroty Base URL** | `https://eu.api.claroty.com` | EU endpoint; adjust for your region |
| **API Token** | `<your-api-token>` | Required for the v1 endpoint |
| **ZF Proxy** | `http://cloudproxy.zf-world.com:8080` | Required for ZF network routing |

### 2. Verify Credentials
Click **Test Connection** to validate:
- ✅ Base URL is reachable
- ✅ API token is valid
- ✅ ZF proxy works

---

## API Endpoints

### V1 Endpoint (API Token Authentication)
The dashboard uses this endpoint for Claroty ingestion:

```bash
POST /api/v1/device_vulnerability_relations/
```

**Example Request:**
```bash
curl -X POST \
  -H "Authorization: Bearer your-api-token" \
  -H "X-API-KEY: your-api-token" \
  -H "Content-Type: application/json" \
  -d '{"fields":["device_uid","vulnerability_id"],"limit":1}' \
  https://eu.api.claroty.com/api/v1/device_vulnerability_relations/
```

---

## Troubleshooting

### Issue: `{"detail":"Method Not Allowed"}`
**Cause:** Incorrect HTTP method or missing authentication header

**Solution:**
- ✅ Verify you're using **POST** with a JSON `fields` list for `/api/v1/device_vulnerability_relations/`
- ✅ Check the API token header is present
- ✅ Ensure the API token has **read** permissions in Claroty

### Issue: Proxy Connection Failed
**Cause:** Proxy URL not reachable or incorrect

**Solution:**
- Test proxy manually:
  ```bash
  curl -x http://cloudproxy.zf-world.com:8080 \
    https://eu.api.claroty.com/api/v1/device_vulnerability_relations/
  ```
- Update proxy URL in Settings if needed
- Ensure proxy supports HTTP and HTTPS tunneling

### Issue: CORS Errors in Browser Console
**Cause:** Browser blocking cross-origin requests

**Solution:**
- ✅ Backend proxy automatically enabled (`/api/proxy`)
- ✅ CORS headers added to all responses
- Dashboard uses `/api/proxy?target=<url>` to route through backend

### Issue: 401 Unauthorized
**Cause:** Invalid or expired API key

**Solution:**
- Verify API token in Claroty admin panel (Settings › API › Tokens)
- Check API token has **read** permissions
- Regenerate API token if necessary

### Issue: 403 Forbidden
**Cause:** API key permissions insufficient for write operations

**Solution:**
- Current implementation reads data only through `POST /api/v1/device_vulnerability_relations/`
- Check the API token has permission to read device vulnerability relations

---

## Architecture

### Data Flow
```
Browser
  ↓
JavaScript (claroty.js)
  ↓ [with API token]
Backend Proxy (/api/proxy)
  ↓ [routes through proxy if configured]
ZF Proxy (cloudproxy.zf-world.com:8080)
  ↓
Claroty API (eu.api.claroty.com)
  ↓ [returns JSON]
Browser [with mock fallback on failure]
```

### Authentication Strategy

**API Token Flow (v1):**
```javascript
Authorization: Bearer <token>
X-API-KEY: <token>
```

---

## Testing

### 1. Connection Test
```javascript
// In browser console:
ClarotyAPI.validateConnection()
  .then(r => console.log(r))
```

Expected output:
```json
{ 
  "ok": true, 
  "msg": "Connected successfully · Auth validated" 
}
```

### 2. Fetch Device Vulnerabilities (v1)
```javascript
ClarotyAPI.fetchDeviceVulnerabilityRelations()
  .then(result => console.log(result))
```

Expected output:
```json
{
  "data": [
    {
      "id": "CLA-DVR-8000",
      "deviceId": "DEV-1000",
      "deviceName": "PLC Controller-1000",
      "vulnerabilityId": "VUL-5000",
      "cveId": "CVE-2024-3400",
      "severity": "Critical",
      "cvssScore": 9.8,
      "status": "open"
    },
    ...
  ],
  "source": "live"  // or "mock" if live fetch failed
}
```

### 3. Test with curl
```bash
# Direct call (may fail with CORS in browsers)
curl -X POST -H "Authorization: Bearer your-token" -H "X-API-KEY: your-token" -H "Content-Type: application/json" \
  -d '{"fields":["device_uid","vulnerability_id"],"limit":1}' \
  https://eu.api.claroty.com/api/v1/device_vulnerability_relations/

# Via backend proxy (CORS-safe)
curl -X POST "http://localhost:8080/api/proxy?target=https%3A%2F%2Feu.api.claroty.com%2Fapi%2Fv1%2Fdevice_vulnerability_relations%2F" \
  -H "Authorization: Bearer your-token" -H "X-API-KEY: your-token" -H "Content-Type: application/json" \
  -d '{"fields":["device_uid","vulnerability_id"],"limit":1}'
```

---

## Configuration Files Modified

### 1. `claroty.js`
- ✅ Added v1 endpoint support (`/api/v1/device_vulnerability_relations/`)
- ✅ Added X-API-KEY header for API key authentication
- ✅ Added proxy URL configuration support
- ✅ Added `fetchDeviceVulnerabilityRelations()` method
- ✅ Added `testConnection(endpoint)` for debugging

### 2. `integrations.js`
- ✅ Added `proxyUrl` field to Claroty configuration
- ✅ Reordered fields to prioritize API key
- ✅ Updated placeholder text with v1 endpoint example

### 3. `server.py`
- ✅ Added `/api/proxy` endpoint for CORS-safe proxying
- ✅ Added CORS headers to all responses
- ✅ Added `do_OPTIONS()` for preflight requests
- ✅ Support for forwarding headers and auth tokens

---

## Security Considerations

⚠️ **Important:** This implementation is for **internal/demo use only**.

For **production**, implement:
1. **Backend-only credentials** — Never expose API keys in browser
2. **Secure token storage** — Use httpOnly cookies, not localStorage
3. **Input validation** — Sanitize proxy URLs
4. **Rate limiting** — Protect proxy endpoint from abuse
5. **Audit logging** — Log all proxy requests with user/timestamp

---

## Next Steps

1. **Test Connection** in Settings to verify everything works
2. **Monitor browser console** (F12) for any errors
3. **Check proxy logs** if behind corporate proxy
4. **Enable widgets** that use Claroty data (Production Risk Intelligence, etc.)
5. **Contact Claroty support** if API issues persist

---

## References

- [Claroty API Documentation](https://claroty.com/docs/)
- [Claroty REST API Reference](https://eu.api.claroty.com/docs/)

