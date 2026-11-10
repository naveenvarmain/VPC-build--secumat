# 🧪 Quick Test Guide - Copy & Paste Ready

## 1️⃣ Test in Browser Console (F12)

### Test 1: Simple POST Test
```javascript
// Replace 'your-api-key' with your actual Claroty API key
const result = await fetch('https://eu.api.claroty.com/api/v1/device_vulnerability_relations/', {
    method: 'POST',
    headers: {
        'X-API-KEY': 'your-api-key',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
})
.then(r => r.json())
.then(d => (console.log('✅ SUCCESS:', d), d))
.catch(e => console.error('❌ ERROR:', e));

console.log(result);
```

### Test 2: With Error Handling & Diagnostics
```javascript
async function testClaroty() {
    const apiKey = 'your-api-key';  // EDIT THIS
    const baseUrl = 'https://eu.api.claroty.com';
    
    try {
        console.log('🔄 Testing Claroty API...');
        const response = await fetch(baseUrl + '/api/v1/device_vulnerability_relations/', {
            method: 'POST',
            headers: {
                'X-API-KEY': apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });
        
        console.log(`📊 Status: ${response.status} ${response.statusText}`);
        console.log(`📋 Headers:`, {
            contentType: response.headers.get('content-type'),
            allow: response.headers.get('allow')
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log(`✅ SUCCESS! Records: ${(data.items || data).length}`);
            return data;
        } else {
            const error = await response.text();
            console.error(`❌ ERROR: ${error}`);
        }
    } catch (e) {
        console.error('❌ EXCEPTION:', e.message);
    }
}

testClaroty();
```

### Test 3: Detailed Response Inspector
```javascript
async function inspectResponse() {
    const response = await fetch('https://eu.api.claroty.com/api/v1/device_vulnerability_relations/', {
        method: 'POST',
        headers: {
            'X-API-KEY': 'your-api-key',
            'Content-Type': 'application/json'
        },
        body: '{}'
    });
    
    console.log('Response Details:');
    console.log('  Status:', response.status);
    console.log('  Type:', response.type);
    console.log('  URL:', response.url);
    console.log('  Headers:');
    for (const [key, value] of response.headers) {
        console.log(`    ${key}: ${value}`);
    }
    
    const data = await response.json();
    console.log('  Body:', data);
    
    // Count records
    const records = data.items || data.data || data.results || data;
    console.log(`  Total Records: ${Array.isArray(records) ? records.length : 'N/A'}`);
}

inspectResponse();
```

---

## 2️⃣ Test with Curl (Command Line)

### Basic Test
```bash
curl -X POST "https://eu.api.claroty.com/api/v1/device_vulnerability_relations/" \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\n%{http_code}\n"
```

### With Proxy
```bash
curl -X POST "https://eu.api.claroty.com/api/v1/device_vulnerability_relations/" \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -x "http://cloudproxy.zf-world.com:8080" \
  -v
```

### With Verbose Output & Save Response
```bash
curl -X POST "https://eu.api.claroty.com/api/v1/device_vulnerability_relations/" \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -v \
  -o response.json \
  -w "Status: %{http_code}\n"

cat response.json | python -m json.tool
```

---

## 3️⃣ Test with Python

### Simple Test
```python
import requests
import json

api_key = 'your-api-key'
base_url = 'https://eu.api.claroty.com'
url = f'{base_url}/api/v1/device_vulnerability_relations/'

headers = {
    'X-API-KEY': api_key,
    'Content-Type': 'application/json'
}

# ✅ Uses POST method
response = requests.post(url, headers=headers, json={})

print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")
```

### With Proxy & Error Handling
```python
import requests
import json

api_key = 'your-api-key'
base_url = 'https://eu.api.claroty.com'
url = f'{base_url}/api/v1/device_vulnerability_relations/'

headers = {
    'X-API-KEY': api_key,
    'Content-Type': 'application/json'
}

proxies = {
    'http': 'http://cloudproxy.zf-world.com:8080',
    'https': 'http://cloudproxy.zf-world.com:8080',
}

try:
    # ✅ POST request with proxy
    response = requests.post(
        url, 
        headers=headers, 
        json={},
        proxies=proxies,
        timeout=10,
        verify=False  # Only if you trust the proxy
    )
    
    print(f"✅ Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        records = data.get('items', data.get('data', data))
        print(f"✅ SUCCESS! Loaded {len(records)} records")
        print(json.dumps(data, indent=2)[:500])  # First 500 chars
    else:
        print(f"❌ Error: {response.text}")
        
except requests.exceptions.ProxyError:
    print("❌ Proxy Error - check proxy settings")
except requests.exceptions.Timeout:
    print("❌ Timeout - server not responding")
except Exception as e:
    print(f"❌ Error: {e}")
```

---

## 4️⃣ Test in Web Dashboard

### Step-by-Step
1. Open: `file:///c:/Users/Z667109/Downloads/tool%20build/Prj-2%20Automation%20SOAR/claroty-demo.html`
2. Enter Base URL: `https://eu.api.claroty.com`
3. Enter API Key: `your-api-key` (from Claroty Settings › API › Tokens)
4. Enter Proxy (optional): `http://cloudproxy.zf-world.com:8080`
5. Click "🔗 Test Connection"
   - ✅ Shows "Connected successfully!"
6. Click "📊 Load Device Vulnerabilities (v1)"
   - ✅ Shows "Loaded X records"
7. View reports in tabs: Summary, Vulnerabilities, Devices, Severity Breakdown

### Troubleshooting in Dashboard
- Open browser console: **F12 or Ctrl+Shift+K**
- Click buttons and check console for:
  - Request details (URL, method, headers)
  - Response status
  - Error messages or data returned

---

## 5️⃣ Expected Responses

### ✅ Success (200 OK)
```json
{
  "items": [
    {
      "id": "DVR-12345",
      "deviceId": "DEV-001",
      "deviceName": "PLC-HVAC-01",
      "cveId": "CVE-2024-1234",
      "severity": "Critical",
      "cvssScore": 9.8,
      "status": "open",
      "firstSeen": "2024-01-15",
      "lastSeen": "2024-01-20"
    }
  ],
  "total": 42,
  "limit": 1000
}
```

### ❌ 405 Error (Wrong Method - OLD)
```
405 Method Not Allowed
Allow: POST
```
**Fix:** Use POST instead of GET ✅

### ❌ 401 Error (Auth Failed)
```json
{"error": "Unauthorized", "message": "Invalid or missing API key"}
```
**Fix:** Check API key in Claroty Settings › API › Tokens

### ❌ 403 Error (No Permission)
```json
{"error": "Forbidden", "message": "API key does not have read permission"}
```
**Fix:** Grant read permission to API key in Claroty

### ❌ CORS Error (Browser)
```
Access to fetch at 'https://eu.api.claroty.com/...' from origin 'file://...' 
has been blocked by CORS policy
```
**Fix:** Use proxy or configure CORS headers

---

## 📋 Checklist Before Testing

- [ ] API key obtained from Claroty Settings
- [ ] API key NOT expired
- [ ] API key has read permission enabled
- [ ] Base URL matches your region (eu/us/etc)
- [ ] Proxy configured if behind firewall
- [ ] Browser cache cleared (Ctrl+Shift+Delete)
- [ ] Demo page reloaded (Ctrl+Shift+R)
- [ ] Using **POST** method, not GET ✅

---

## 🎯 Next Steps

1. **Copy a test command** from above based on your preference
2. **Replace `your-api-key`** with actual key
3. **Run the test**
4. **Check results** against "Expected Responses" section
5. **If successful** ✅ - Your integration is working!
6. **If failed** ❌ - Check checklist above

**Questions?** Check CLAROTY_INTEGRATION.md for full documentation.

