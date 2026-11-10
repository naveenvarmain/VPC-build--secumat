/* =====================================================================
   Claroty xDome REST API client
   ---------------------------------------------------------------------
    Claroty xDome client. Live requests are sent only through allowlisted
    same-origin backend routes using encrypted server-side credentials.

   Endpoint: https://eu.api.claroty.com/api/v1/device_vulnerability_relations/
   Proxy:    http://cloudproxy.zf-world.com:8080
   ===================================================================== */

const ClarotyAPI = (() => {
    const DEFAULT_BASE_URL = "https://eu.api.claroty.com";
    const DEFAULT_PROXY_URL = "http://cloudproxy.zf-world.com:8080";
    const DVR_ENDPOINT = "/api/v1/device_vulnerability_relations/";

    function legacyConfig() {
        try { return JSON.parse(localStorage.getItem("soc-integrations") || "{}").claroty || {}; }
        catch { return {}; }
    }

    let backendStatusCache = null;
    let backendUseApproved = false;

    function extractItems(payload) {
        if (Array.isArray(payload)) return payload;
        return payload?.devices_vulnerabilities || payload?.items || payload?.data || payload?.results || payload?.objects || [];
    }

    async function backendCredentialStatus(force = false) {
        if (backendStatusCache && !force) return backendStatusCache;
        try {
            const response = await fetch("/api/claroty/credentials", { cache: "no-store" });
            backendStatusCache = await response.json();
        } catch (error) {
            backendStatusCache = { configured: false, error: error.message };
        }
        return backendStatusCache;
    }

    async function saveBackendCredentials(credentials) {
        const response = await fetch("/api/claroty/credentials", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(credentials)
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Failed to save Claroty credentials");
        backendStatusCache = payload;
        return payload;
    }

    async function clearBackendCredentials() {
        const response = await fetch("/api/claroty/credentials", { method: "DELETE" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Failed to clear Claroty credentials");
        backendStatusCache = payload;
        return payload;
    }

    async function confirmBackendCredentials() {
        const response = await fetch("/api/claroty/credentials/confirm", { method: "POST" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Failed to confirm Claroty credentials");
        backendStatusCache = payload;
        return payload;
    }

    async function migrateLocalCredentialsToBackend() {
        const saved = legacyConfig();
        if (!saved.apiKey) return backendCredentialStatus();
        const status = await backendCredentialStatus(true);
        if (!status.configured) await saveBackendCredentials(saved);
        try {
            const all = JSON.parse(localStorage.getItem("soc-integrations") || "{}");
            delete all.claroty;
            localStorage.setItem("soc-integrations", JSON.stringify(all));
            sessionStorage.removeItem("claroty-token");
        } catch { /* ignore */ }
        return backendCredentialStatus(true);
    }

    async function enableBackendUse() {
        const status = await migrateLocalCredentialsToBackend();
        backendUseApproved = !!status.configured;
        return status;
    }

    function config() {
        const status = backendStatusCache || {};
        return {
            BASE_URL: status.baseUrl || DEFAULT_BASE_URL,
            PROXY_URL: status.proxyUrl || DEFAULT_PROXY_URL,
            TIMEOUT_MS: 30000,
            API_VERSION: "v1"
        };
    }

    function canGoLive() {
        return !!(backendStatusCache?.configured && backendUseApproved);
    }

    async function backendRequest(path, options = {}) {
        if (path !== DVR_ENDPOINT) throw new Error(`Unsupported backend Claroty endpoint: ${path}`);
        const status = await backendCredentialStatus();
        if (!status.configured || !backendUseApproved) throw new Error("Claroty credentials are not approved in encrypted backend storage");
        const response = await fetch("/api/claroty/device-vulnerability-relations", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: options.body || JSON.stringify({ fields: DVR_FIELDS, limit: 1000, offset: 0 })
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || payload.detail || "Claroty backend request failed");
        return payload.payload;
    }

    async function guarded(liveFn, mockFn, label) {
        if (!canGoLive()) return { data: mockFn(), source: "mock" };
        try {
            const data = await liveFn();
            return { data, source: "live" };
        } catch (error) {
            console.error(`[Claroty] ${label} live fetch failed:`, error.message);
            return { data: [], source: "error", error: error.message };
        }
    }

    const ASSET_TYPES = ["PLC Controller", "HMI Panel", "SCADA Server", "Historian", "Engineering Workstation", "Network Switch", "RTU", "Safety Controller"];
    const ZONES = ["Level 0 - Field", "Level 1 - Control", "Level 2 - Supervisory", "Level 3 - Operations"];
    const CVES = ["CVE-2024-3400", "CVE-2024-21762", "CVE-2023-46604", "CVE-2024-27198", "CVE-2023-34362", "CVE-2024-6387", "CVE-2023-38831", "CVE-2024-4577", "CVE-2022-36804", "CVE-2024-1709"];
    const rand = (min, max) => Math.round(min + Math.random() * (max - min));

    function mockAssets() {
        return Array.from({ length: 12 }, (_, index) => ({
            id: `CLA-AST-${1000 + index}`,
            name: `${ASSET_TYPES[index % ASSET_TYPES.length]}-${1000 + index}`,
            type: ASSET_TYPES[index % ASSET_TYPES.length],
            zone: ZONES[index % ZONES.length],
            criticality: rand(30, 100),
            ip: `10.${rand(1, 30)}.${rand(1, 254)}.${rand(1, 254)}`,
            insecureProtocols: Math.random() > 0.5 ? ["Modbus", "S7"][rand(0, 1)] : null
        }));
    }

    function mockVulnerabilities() {
        return Array.from({ length: 10 }, (_, index) => ({
            id: `CLA-VUL-${5000 + index}`,
            cve: CVES[index % CVES.length],
            asset: `${ASSET_TYPES[index % ASSET_TYPES.length]}-${1000 + index}`,
            severity: ["Critical", "High", "Medium", "Low"][rand(0, 3)],
            cvss: rand(45, 98) / 10,
            status: Math.random() > 0.3 ? "Open" : "Remediated",
            detected: new Date(Date.now() - rand(1, 90) * 86400000).toISOString().slice(0, 10)
        }));
    }

    function mockDeviceVulnerabilityRelations() {
        return Array.from({ length: 15 }, (_, index) => ({
            id: `CLA-DVR-${8000 + index}`,
            deviceId: `DEV-${1000 + index}`,
            deviceName: `${ASSET_TYPES[index % ASSET_TYPES.length]}-${1000 + index}`,
            deviceIp: `10.${rand(1, 30)}.${rand(1, 254)}.${rand(1, 254)}`,
            vulnerabilityId: `VUL-${5000 + index}`,
            cveId: CVES[index % CVES.length],
            severity: ["Critical", "High", "Medium", "Low"][rand(0, 3)],
            cvssScore: rand(45, 98) / 10,
            discoveredDate: new Date(Date.now() - rand(1, 90) * 86400000).toISOString(),
            status: Math.random() > 0.3 ? "open" : "resolved",
            remediationStatus: Math.random() > 0.6 ? "patched" : "unpatched"
        }));
    }

    function mockRiskFindings() {
        return mockVulnerabilities().map((vulnerability, index) => ({
            id: `CLA-TKT-${9000 + index}`,
            asset: vulnerability.asset,
            cve: vulnerability.cve,
            severity: vulnerability.severity,
            opened: vulnerability.detected,
            source: "Claroty xDome",
            status: vulnerability.status === "Remediated" ? "Closed" : "Open"
        }));
    }

    const DVR_FIELDS = [
        "device_uid", "device_name", "device_ip_list", "device_category", "device_subcategory",
        "device_type", "device_model", "device_site_name", "device_combined_os", "device_retired",
        "vulnerability_id", "vulnerability_name", "vulnerability_type", "vulnerability_cve_ids",
        "vulnerability_cvss_v3_score", "vulnerability_epss_score",
        "vulnerability_adjusted_vulnerability_score", "vulnerability_adjusted_vulnerability_score_level",
        "vulnerability_is_known_exploited", "vulnerability_exploits_count",
        "vulnerability_description", "vulnerability_recommendations",
        "vulnerability_published_date", "vulnerability_last_updated",
        "vulnerability_relevance", "patch_install_date"
    ];

    async function fetchDeviceVulnerabilityRelations(limit = 1000, offset = 0) {
        const status = await backendCredentialStatus();
        if (!status.configured || !backendUseApproved) return { data: [], source: "unconfigured", error: "Configure and approve encrypted Claroty credentials." };
        try {
            const response = await backendRequest(DVR_ENDPOINT, { body: JSON.stringify({ fields: DVR_FIELDS, limit, offset }) });
            return { data: extractItems(response), source: "live" };
        } catch (error) {
            return { data: [], source: "error", error: error.message };
        }
    }

    let allRelationsCache = null;
    let allRelationsPromise = null;
    async function fetchAllDeviceVulnerabilityRelations(pageSize = 1000, maxRecords = 50000) {
        if (allRelationsCache) return allRelationsCache;
        if (allRelationsPromise) return allRelationsPromise;
        allRelationsPromise = (async () => {
            const allRows = [];
            let source = "live";
            let error;
            for (let offset = 0; offset < maxRecords; offset += pageSize) {
                const page = await fetchDeviceVulnerabilityRelations(pageSize, offset);
                source = page.source;
                error = page.error;
                allRows.push(...(page.data || []));
                if (page.source !== "live" || !page.data || page.data.length < pageSize) break;
            }
            allRelationsCache = { data: allRows, source, error };
            return allRelationsCache;
        })();
        try {
            return await allRelationsPromise;
        } finally {
            allRelationsPromise = null;
        }
    }

    async function getSeverityBreakdown() {
        const result = await fetchAllDeviceVulnerabilityRelations();
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
        (result.data || []).forEach(row => {
            const value = String(row.vulnerability_adjusted_vulnerability_score_level || row.severity || "Unknown").toLowerCase();
            const severity = Object.keys(counts).find(label => label.toLowerCase() === value) || "Unknown";
            counts[severity] += 1;
        });
        const labels = Object.keys(counts).filter(label => counts[label] || label !== "Unknown");
        return { labels, data: labels.map(label => counts[label]), source: result.source };
    }

    const feedStates = new Map();

    function feedState(feed) {
        if (!feedStates.has(feed)) feedStates.set(feed, { data: [], offset: 0, complete: false, partial: false, source: "pending", error: null, loading: null });
        return feedStates.get(feed);
    }

    async function fetchFeedPage(feed, limit = 5000, offset = 0) {
        if (!canGoLive()) return { data: [], source: "unconfigured", error: "Configure encrypted Claroty credentials before loading live data" };
        try {
            const response = await fetch("/api/claroty/feed", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                cache: "no-store",
                body: JSON.stringify({ feed, limit, offset })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.detail || payload.error || `Claroty feed request failed (${response.status})`);
            return { data: payload.records || [], source: payload.source || "live", hasMore: !!payload.hasMore, fetchedAt: payload.fetchedAt };
        } catch (error) {
            console.error(`[Claroty] ${feed} feed failed:`, error.message);
            return { data: [], source: "error", error: error.message };
        }
    }

    async function loadFeedPage(feed, limit = 5000) {
        const state = feedState(feed);
        if (state.complete || state.loading) return state.loading || state;
        state.loading = (async () => {
            const page = await fetchFeedPage(feed, limit, state.offset);
            state.error = page.error || null;
            if (page.source === "live") {
                state.source = "live";
                state.data.push(...page.data);
                state.offset += page.data.length;
                state.complete = !page.hasMore;
                state.partial = false;
            } else {
                if (state.source === "live" && state.data.length) {
                    state.complete = false;
                    state.partial = true;
                } else {
                    state.source = page.source;
                    state.complete = true;
                    state.partial = false;
                }
            }
            state.fetchedAt = page.fetchedAt || new Date().toISOString();
            document.dispatchEvent(new CustomEvent("xdome:feed-ready", {
                detail: { feed, source: state.source, loaded: state.data.length, complete: state.complete, partial: state.partial, error: state.error }
            }));
            return state;
        })();
        try {
            return await state.loading;
        } finally {
            state.loading = null;
        }
    }

    async function loadAllFeed(feed, limit = 5000, maxRecords = 100000, onProgress) {
        let state = feedState(feed);
        while (!state.complete && state.data.length < maxRecords) {
            const previousOffset = state.offset;
            state = await loadFeedPage(feed, Math.min(limit, maxRecords - state.data.length));
            if (onProgress) onProgress({ feed, loaded: state.data.length, complete: state.complete, source: state.source, error: state.error });
            if (state.source !== "live" || state.error || state.offset === previousOffset) break;
        }
        return { data: state.data.slice(), source: state.source, complete: state.complete, partial: state.partial, error: state.error, fetchedAt: state.fetchedAt };
    }

    async function feedDiagnostics() {
        if (!canGoLive()) return { source: "unconfigured", feeds: [], error: "Claroty credentials are not approved for this load" };
        try {
            const response = await fetch("/api/claroty/diagnostics", { method: "POST", cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || `Diagnostics failed (${response.status})`);
            return payload;
        } catch (error) {
            return { source: "error", feeds: [], error: error.message };
        }
    }

    async function refreshData() {
        allRelationsCache = null;
        allRelationsPromise = null;
        feedStates.clear();
        await backendCredentialStatus(true);
    }

    async function fetchAssets() {
        const result = await loadAllFeed("devices");
        if (result.source !== "live") return result.source === "unconfigured" ? { data: mockAssets(), source: "mock" } : result;
        return {
            data: result.data.map(row => ({
                id: row.uid,
                name: row.device_name || row.uid,
                type: row.device_type || "Unknown",
                zone: row.site_name || "",
                ip: Array.isArray(row.ip_list) ? row.ip_list.join(", ") : row.ip_list || "",
                manufacturer: row.manufacturer || "",
                model: row.model || "",
                online: row.is_online,
                risk: row.risk_score
            })),
            source: "live",
            complete: result.complete,
            fetchedAt: result.fetchedAt
        };
    }

    async function fetchVulnerabilities() {
        const result = await fetchAllDeviceVulnerabilityRelations();
        if (result.source !== "live") return result;
        return {
            data: result.data.map((row, index) => ({
                id: row.vulnerability_id || `CLA-VUL-${index}`,
                cve: Array.isArray(row.vulnerability_cve_ids) ? row.vulnerability_cve_ids[0] : row.vulnerability_cve_ids || row.cveId || "Unknown CVE",
                asset: row.device_name || row.deviceName || "Unknown asset",
                severity: row.vulnerability_adjusted_vulnerability_score_level || row.severity || "Unknown",
                cvss: Number(row.vulnerability_cvss_v3_score || row.cvssScore) || 0,
                status: row.patch_install_date ? "Remediated" : "Open",
                detected: row.vulnerability_last_updated || row.vulnerability_published_date || new Date().toISOString().slice(0, 10)
            })),
            source: "live"
        };
    }

    async function fetchSocTickets() {
        return { data: [], source: "requires_source", error: "Claroty provides vulnerability findings, not SOC tickets; connect an ITSM/SOAR source." };
    }

    async function fetchAlerts(onProgress) {
        const result = await loadAllFeed("alerts", 1000, 50000, onProgress);
        return { ...result, data: result.data.map(row => ({
            id: row.id,
            title: row.alert_name || row.alert_type_name || row.description || "xDome alert",
            type: row.alert_type_name || "",
            category: row.category || "",
            class: row.alert_class || "",
            status: row.status || "Unknown",
            detected: row.detected_time || "",
            updated: row.updated_time || "",
            devices: Number(row.devices_count) || 0,
            unresolvedDevices: Number(row.unresolved_devices_count) || 0,
            otDevices: Number(row.ot_devices_count) || 0,
            itDevices: Number(row.it_devices_count) || 0,
            iotDevices: Number(row.iot_devices_count) || 0,
            mitreIcs: row.mitre_technique_ics_names || [],
            mitreEnterprise: row.mitre_technique_enterprise_names || [],
            description: row.description || "",
            maliciousIpTags: row.malicious_ip_tags_list || []
        })) };
    }

    async function fetchVulnerabilityCatalog(onProgress) {
        return loadAllFeed("vulnerabilities", 1000, 50000, onProgress);
    }

    async function fetchEvents(onProgress) {
        const result = await loadAllFeed("events", 1000, 50000, onProgress);
        return { ...result, data: result.data.map(row => ({
            ...row,
            device: row.side_a_name || row.side_b_name || "",
            site: row.side_a_site_name || row.side_b_site_name || "",
            risk: row.side_a_risk_score ?? row.side_b_risk_score,
            severity: row.malicious_ip_severity || "",
            timestamp: row.timestamp || ""
        })) };
    }

    async function validateConnection() {
        try {
            const status = await backendCredentialStatus(true);
            if (!status.configured) return { ok: false, msg: "Claroty encrypted backend credentials are not configured" };
            backendUseApproved = true;
            const response = await fetch("/api/claroty/test", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: "{}"
            });
            const payload = await response.json();
            return payload.ok ? payload : { ok: false, msg: payload.msg || payload.error || "Connection failed" };
        } catch (error) {
            return { ok: false, msg: `Connection failed - ${error.message}` };
        }
    }

    async function testConnection(endpoint = DVR_ENDPOINT, options) {
        if (endpoint !== DVR_ENDPOINT) return { ok: false, msg: "Only the supported Claroty v1 relations endpoint can be tested" };
        const status = await validateConnection();
        if (!status.ok) return status;
        const result = await fetchDeviceVulnerabilityRelations(1, 0);
        return result.source === "live" ? { ok: true, msg: `Connected successfully · 1-row relations test through encrypted backend` } : { ok: false, msg: result.error || "Claroty connection failed" };
    }

    return {
        canGoLive, guarded,
        fetchAssets, fetchVulnerabilities, fetchDeviceVulnerabilityRelations, fetchAllDeviceVulnerabilityRelations, fetchSocTickets, getSeverityBreakdown, refreshData,
        fetchFeedPage, loadFeedPage, loadAllFeed, feedState, fetchAlerts, fetchVulnerabilityCatalog, fetchEvents, feedDiagnostics,
        backendCredentialStatus, saveBackendCredentials, clearBackendCredentials, confirmBackendCredentials,
        migrateLocalCredentialsToBackend, enableBackendUse,
        validateConnection, testConnection,
        connectionStatus: () => canGoLive() ? "pending-live" : "demo"
    };
})();

window.ClarotyAPI = ClarotyAPI;
