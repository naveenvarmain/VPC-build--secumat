# Claroty API 405 Error - Troubleshooting Guide

## ⚠️ The Error
```
✗ 405 Method Not Allowed
HTTP 405 error from Claroty API
```

---

## 🔍 What's Happening?

The server is rejecting your request because:
1. ❌ The endpoint doesn't support **GET** requests (expects a different HTTP method)
2. ❌ Authentication headers are missing or incorrect
3. ❌ The API endpoint path is wrong
4. ❌ CORS blocking (browser security policy)

---

## ✅ Solutions to Try

### Solution 1: Try Alternative Endpoints

The `/api/v1/device_vulnerability_relations/` endpoint might not exist or might use a different HTTP method.

Try these endpoints instead:

**Option A: v1 Networks Endpoint**
```
GET /api/v1/networks/
Header: X-API-KEY: <your-api-key>
```

**Option B: v2 Assets Endpoint**
```
GET /api/v2/assets?pageSize=500
Header: Authorization: Bearer <your-api-key>
```

**Option C: v2 Vulnerabilities**
```
GET /api/v2/vulnerabilities?pageSize=500
Header: Authorization: Bearer <your-api-key>
```

### Solution 2: Check Your API Key Format

The API key might need to be formatted differently:

**Current format (X-API-KEY header):**
```
X-API-KEY: abc123def456...
```

**Alternative format (Bearer token in Authorization header):**
```
Authorization: Bearer abc123def456...
```

**Alternative format (Query parameter):**
```
https://eu.api.claroty.com/api/v1/device_vulnerability_relations/?api_key=abc123...
```

### Solution 3: Verify Claroty Tenant & Endpoints

The Claroty API structure varies by:
- **Region**: EU vs US vs APAC endpoint
- **Tenant**: Different base URLs for different instances
- **Version**: v1 vs v2 API differences

**Check your Claroty admin panel:**
1. Log in to Claroty
2. Settings › API › Tokens
3. Note the exact endpoint URL shown there
4. Verify the API key permissions

---

## 🛠️ How to Diagnose in Browser

**Step 1:** Open the demo page and enter your credentials

**Step 2:** Open **Developer Tools** (F12 → Network tab)

**Step 3:** Click **"🔗 Test Connection"**

**Step 4:** Look for the network request:
- **URL:** Should show the exact endpoint being called
- **Method:** Should be GET
- **Headers:** Should show X-API-KEY or Authorization
- **Response Status:** Should show 405 or other error code
- **Response Body:** Shows the error message from Claroty

**Step 5:** Check the **Console tab** (F12 → Console):
- Look for detailed error messages
- Copy-paste them below for troubleshooting

---

## 📋 Request/Response Checklist

When contacting Claroty support, provide:

- [ ] Base URL being used: `https://eu.api.claroty.com` or different?
- [ ] API Key format: Is it a token string? Does it have a prefix?
- [ ] HTTP Method: GET, POST, or other?
- [ ] Current error: 405, 401, 403, etc.?
- [ ] Browser Console errors (F12)
- [ ] Network request headers (F12 → Network tab)
- [ ] Response body from Claroty API

---

## 🔐 API Key Verification

1. **Is the API key valid?**
   ```
   Use the Test Connection button to verify
   ```

2. **Does the API key have read permissions?**
   - Check Claroty: Settings › API › Tokens › Permissions
   - Ensure "Read" or "View" permissions are enabled
   - NOT just "Write" permissions

3. **Is the API key active?**
   - Check if it's been revoked or expired
   - Regenerate if needed in Claroty Settings

---

## 🌐 Common Claroty Endpoints

These are standard endpoints (may vary by version):

### v1 Endpoints
```
GET  /api/v1/networks/
GET  /api/v1/devices/
GET  /api/v1/vulnerabilities/
GET  /api/v1/risks/
POST /api/v1/device_vulnerability_relations/  (dashboard integration endpoint)
```

---

## 🚀 Next Steps

1. **Try each endpoint above** using the demo tool
2. **Check browser console** (F12) for detailed errors
3. **Verify API key permissions** in Claroty admin
4. **Contact Claroty support** with the error details
5. **Use curl for testing** (see below)

---

## 💻 Testing with Curl

### Test Connection (Basic)
```bash
curl -X GET "https://eu.api.claroty.com/api/v1/device_vulnerability_relations/" \
  -H "X-API-KEY: your-api-key-here" \
  -H "Content-Type: application/json" \
  -v
```

### Test with Bearer Token
```bash
curl -X GET "https://eu.api.claroty.com/api/v2/assets" \
  -H "Authorization: Bearer your-api-key-here" \
  -H "Content-Type: application/json" \
  -v
```

### Test via HTTP Proxy
```bash
curl -x "http://cloudproxy.zf-world.com:8080" \
  -X GET "https://eu.api.claroty.com/api/v1/device_vulnerability_relations/" \
  -H "X-API-KEY: your-api-key-here" \
  -v
```

### Expected Successful Response
```json
{
  "items": [
    {
      "id": "123",
      "deviceId": "DEV-001",
      "deviceName": "PLC-Controller",
      "cveId": "CVE-2024-1234",
      "severity": "Critical",
      "cvssScore": 9.8,
      "status": "open"
    }
  ],
  "total": 42,
  "pageSize": 20
}
```

---

## ❌ Common Error Responses & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| **405 Method Not Allowed** | Wrong HTTP method or endpoint doesn't exist | Try different endpoints/methods |
| **401 Unauthorized** | Invalid API key | Regenerate API key in Claroty |
| **403 Forbidden** | API key lacks read permissions | Grant "Read" permissions in Claroty |
| **404 Not Found** | Endpoint path is wrong | Verify exact endpoint URL |
| **CORS Error** | Browser blocking cross-origin request | Use backend proxy or curl |
| **503 Service Unavailable** | Claroty API is down | Wait and retry later |

---

## 📞 Support Resources

- **Claroty Documentation:** https://claroty.com/docs/
- **Claroty API Reference:** https://api.claroty.com/docs/
- **Claroty Support:** https://support.claroty.com/

---

## ✨ Quick Fix Checklist

- [ ] Base URL is correct (https://eu.api.claroty.com)
- [ ] API key is entered (not empty)
- [ ] Using X-API-KEY header (not Authorization)
- [ ] Endpoint path is correct (/api/v1/device_vulnerability_relations/)
- [ ] API key has read permissions
- [ ] API key is not expired
- [ ] No CORS errors (check F12 console)
- [ ] Network is connected (try curl command)

---

## 🎯 Demo Tool Usage

**In the Claroty Data Loader page:**

1. **Paste your Claroty Base URL** (e.g., https://eu.api.claroty.com)
2. **Paste your API Key** (exactly as shown in Claroty)
3. **Optionally paste proxy URL** if needed
4. **Click "Test Connection"** to verify
5. **Check error message** for specific guidance
6. **Try alternative endpoints** if first one fails
7. **Open F12 Console** to see full error details

The enhanced demo now shows:
✅ Exact URL being called
✅ Headers being sent
✅ Response status and headers
✅ Error message details
✅ Suggestions for fixing the error

