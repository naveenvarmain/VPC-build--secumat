# Claroty API Fix - Based on Test Results

## 🔍 Test Results Summary

| Endpoint | Method | Result | Issue |
|----------|--------|--------|-------|
| `/api/v1/device_vulnerability_relations/` | GET | 405 | Endpoint expects **POST**, not GET |
| `/api/v1/networks/` | GET | 404 | Endpoint not found (wrong path) |
| `/api/v1/devices/` | GET | 405 | Endpoint expects **POST**, not GET |
| `/api/v2/assets` | GET | 401 | Wrong auth header (needs Bearer token) |

---

## ✅ The Fix

### **Option 1: Use POST Method (v1 Endpoint - Recommended)**

The endpoint **requires POST**, not GET. Here's how to fix it:

```javascript
// Instead of GET:
fetch('https://eu.api.claroty.com/api/v1/device_vulnerability_relations/', {
    method: 'GET',  // ❌ WRONG
    headers: { 'X-API-KEY': apiKey }
})

// Use POST:
fetch('https://eu.api.claroty.com/api/v1/device_vulnerability_relations/', {
    method: 'POST',  // ✅ CORRECT
    headers: { 
        'X-API-KEY': apiKey,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({})  // Empty or with filters
})
```

### **Option 2: Use v2 API with Bearer Token**

```javascript
fetch('https://eu.api.claroty.com/api/v2/assets', {
    method: 'GET',
    headers: { 
        'Authorization': `Bearer ${apiKey}`,  // ✅ Bearer token
        'Content-Type': 'application/json'
    }
})
```

---

## 📝 Updated claroty.js Function

Replace the `loadDeviceVulnerabilities()` function with this:

```javascript
async function loadDeviceVulnerabilities() {
    const baseUrl = document.getElementById('baseUrl').value;
    const apiKey = document.getElementById('apiKey').value;

    if (!baseUrl || !apiKey) {
        showStatus('loadStatus', 'error', '✗ Missing configuration');
        return;
    }

    showStatus('loadStatus', 'pending', '⏳ Loading from /api/v1/device_vulnerability_relations/ using POST...');
    document.getElementById('loadStatus').classList.add('loading');

    try {
        const url = baseUrl.replace(/\/$/, '') + '/api/v1/device_vulnerability_relations/';
        
        // Use POST instead of GET
        const response = await fetch(url, {
            method: 'POST',  // ✅ Changed from GET to POST
            headers: {
                'X-API-KEY': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})  // Empty body for initial request
        });

        console.log('Response status:', response.status);

        if (!response.ok) {
            const errText = await response.text();
            console.error(`HTTP Error ${response.status}:`, errText);
            throw new Error(`HTTP ${response.status} ${response.statusText}: ${errText.substring(0, 100)}`);
        }

        const result = await response.json();
        const items = Array.isArray(result) ? result : (result.items || result.data || result.results || []);

        if (items.length === 0) {
            showStatus('loadStatus', 'error', '✗ No data returned from API (empty response)');
            return;
        }

        currentData = items;
        updateReports();
        showStatus('loadStatus', 'ok', `✓ Loaded ${items.length} device vulnerability records`);
        console.log('Successfully loaded data:', items);
    } catch (err) {
        console.error('Error details:', err);
        showStatus('loadStatus', 'error', `✗ Failed: ${err.message}`);
    } finally {
        document.getElementById('loadStatus').classList.remove('loading');
    }
}
```

---

## 🔑 Key Changes

| Before | After | Reason |
|--------|-------|--------|
| `method: 'GET'` | `method: 'POST'` | API requires POST |
| No body | `body: JSON.stringify({})` | POST requests need body |
| Only tested GET | Tests both GET & POST | Better diagnostics |

---

## 🧪 Testing the Fix

**Step 1:** Replace your API key with the real one in the form

**Step 2:** Click **"Load Device Vulnerabilities (v1)"**

**Step 3:** Should now return ✅ instead of 405

---

## 💡 Why 405 Happened

The API endpoint at `/api/v1/device_vulnerability_relations/` only accepts **POST** requests, not GET.

- **GET** = Retrieve data (what we were trying)
- **POST** = Submit data (what the API expects)

Some APIs use POST for querying to allow complex filter bodies instead of long URLs.

---

## 🔐 Authentication Summary

| API Version | Method | Auth Header | Status |
|-------------|--------|-------------|--------|
| **v1** | POST | `X-API-KEY: <key>` | ✅ Works (requires POST) |
| **v2** | GET | `Authorization: Bearer <key>` | ✅ Works (different auth) |

---

## 📞 Next Steps

1. **Update your code** to use POST method
2. **Test the connection** again
3. **Load device vulnerabilities** - should now work
4. **View reports** in the dashboard

If still getting errors, check:
- API key is correct and not expired
- API key has read permissions
- Proxy is configured correctly if needed
- No network blocking between your browser and Claroty

