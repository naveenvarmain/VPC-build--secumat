# Claroty API Integration — Quick Test Reference

## Browser Console Commands

### 1. Test Connection
```javascript
ClarotyAPI.validateConnection().then(r => console.log(JSON.stringify(r, null, 2)))
```

### 2. Fetch Device Vulnerability Relations (v1)
```javascript
ClarotyAPI.fetchDeviceVulnerabilityRelations().then(r => console.log(JSON.stringify(r, null, 2)))
```

### 3. Fetch Assets (v2)
```javascript
ClarotyAPI.fetchAssets().then(r => console.log(JSON.stringify(r, null, 2)))
```

### 4. Check Current Config
```javascript
// Get saved config from localStorage
JSON.parse(localStorage.getItem("soc-integrations"))?.claroty
```

### 5. Test Specific Endpoint
```javascript
ClarotyAPI.testConnection("/api/v1/device_vulnerability_relations/")
  .then(r => console.log(JSON.stringify(r, null, 2)))
```

---

## Curl Commands (Backend Proxy)

### Start Server
```bash
cd "c:\Users\Z667109\Downloads\tool build\Prj-2 Automation SOAR"
python server.py
```

### Test via Backend Proxy
```bash
curl -X GET "http://localhost:8080/api/proxy?target=https://eu.api.claroty.com/api/v1/device_vulnerability_relations/" \
  -H "X-API-KEY: your-api-key-here" \
  -H "Content-Type: application/json" \
  -v
```

### Test Proxy Connection
```bash
curl -x http://cloudproxy.zf-world.com:8080 \
  -H "X-API-KEY: your-api-key" \
  https://eu.api.claroty.com/api/v1/device_vulnerability_relations/ \
  -v
```

---

## Setup Checklist

- [ ] Base URL set to `https://eu.api.claroty.com`
- [ ] API Key entered in Settings (if using v1)
- [ ] Proxy URL set to `http://cloudproxy.zf-world.com:8080` (if needed)
- [ ] Connection test passes (Test Connection button)
- [ ] Browser console shows no CORS errors
- [ ] `fetchDeviceVulnerabilityRelations()` returns data (not error)
- [ ] Server proxy running on `http://localhost:8080`

---

## Expected Response Format

### Success (v1 device_vulnerability_relations)
```json
{
  "data": [
    {
      "id": "DVR-001",
      "deviceId": "DEV-1001",
      "deviceName": "PLC-01",
      "cveId": "CVE-2024-1234",
      "severity": "Critical",
      "cvssScore": 9.5,
      "status": "open"
    }
  ],
  "source": "live"
}
```

### Error (Method Not Allowed)
```json
{
  "detail": "Method Not Allowed"
}
```

**Fix:**
- ✓ Check HTTP method (should be GET)
- ✓ Verify X-API-KEY header is present
- ✓ Ensure API key has read permissions

---

## Common Issues & Quick Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `Method Not Allowed` | Wrong HTTP method or missing auth | Use GET with X-API-KEY header |
| `401 Unauthorized` | Invalid/expired API key | Regenerate API key in Claroty |
| `403 Forbidden` | Insufficient permissions | Check API key has read access |
| `CORS error` in browser | Cross-origin blocked | Use `/api/proxy` endpoint |
| `Connection timeout` | Proxy unreachable | Verify proxy URL & connectivity |
| `Empty results` | No data available | Check Claroty tenant has devices/vulns |

---

## Files Modified

- ✅ `claroty.js` — Added v1 endpoint & X-API-KEY support
- ✅ `integrations.js` — Added proxy URL field  
- ✅ `server.py` — Added proxy handler & CORS
- ✅ `CLAROTY_INTEGRATION.md` — Full documentation (this folder)

