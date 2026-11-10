/* =====================================================================
   Swimlane REST API client
   ---------------------------------------------------------------------
   Thin wrapper around the Swimlane REST API with automatic fallback to
   mock data when USE_LIVE is false, the token is missing, or a request
   fails/times out. Every method resolves with { data, source } where
   source is "live" or "mock" so the UI can badge the data origin.

   Reference endpoints (Swimlane Turbine / 10.x):
     GET  /api/app                          -> list applications
     POST /api/app/{appId}/record/search    -> search records (filters)
     GET  /api/reports/{reportId}/execute   -> run a saved report
     GET  /api/user/authorize               -> validate token
   ===================================================================== */

const SwimlaneAPI = (() => {
    const baseConfig = window.SWIMLANE_CONFIG || {};
            let serverCredentialTools = {};
            let serverCredentialLoad = null;

            async function loadServerCredentials(force = false) {
                if (serverCredentialLoad && !force) return serverCredentialLoad;
                serverCredentialLoad = (async () => {
                    try {
                        const response = await fetch("/api/integrations/credentials", { cache: "no-store" });
                        const payload = await response.json();
                        serverCredentialTools = response.ok ? payload.tools || {} : {};
                    } catch {
                        serverCredentialTools = {};
                    }
                    return serverCredentialTools;
                })();
                try { return await serverCredentialLoad; }
                finally { serverCredentialLoad = null; }
            }

            function config() {
                const backend = serverCredentialTools.swimlane || {};
                const safe = backend.safeConfig || {};
                const configured = !!(backend.configured && safe.baseUrl && safe.appId);
                return {
                    ...baseConfig,
                    USE_LIVE: configured,
                    BASE_URL: safe.baseUrl || baseConfig.BASE_URL,
                    PAT: "",
                    APPS: { ...(baseConfig.APPS || {}), incidents: safe.appId || "" }
                };
            }

            function canGoLive() {
                return !!config().USE_LIVE;
            }

            async function request(path, options = {}) {
                await loadServerCredentials();
                if (!canGoLive()) throw new Error("Swimlane credentials are not configured in encrypted backend storage");
                let requestBody;
                if (options.body) {
                    try { requestBody = JSON.parse(options.body); }
                    catch { throw new Error("Swimlane proxy body must be valid JSON"); }
                }
                const response = await fetch("/api/swimlane/request", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ path, method: options.method || "GET", body: requestBody })
                });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.error || `Swimlane ${response.status}`);
                return payload.data;
            }

            async function searchRecords(appId, filters = [], pageSize = 1000) {
                if (!appId) throw new Error("Missing appId");
                const body = { filters, pageSize, aggregates: [], columns: [] };
                return request(`/api/app/${appId}/record/search`, { method: "POST", body: JSON.stringify(body) });
            }

            async function runReport(reportId) {
                if (!reportId) throw new Error("Missing reportId");
                return request(`/api/reports/${reportId}/execute`, { method: "GET" });
            }

            async function guarded(liveFn, mockFn, label) {
                await loadServerCredentials();
                if (!canGoLive()) return { data: mockFn(), source: "mock" };
                try {
                    return { data: await liveFn(), source: "live" };
                } catch (error) {
                    console.warn(`[Swimlane] ${label} live fetch failed; using sample data:`, error.message);
                    return { data: mockFn(), source: "mock" };
                }
            }
    /* =================================================================
       Concrete incident feed — end-to-end example
       Pulls records from the Incident app and derives MTTD/MTTR trend,
       severity breakdown, and closure rate. Falls back to a single
       shared mock pool via guarded() so charts AND drill-downs stay
       consistent when live is off or a request fails.
       ================================================================= */

    // Normalize a raw Swimlane record's "values" object into flat fields.
    function values(rec) { return rec && (rec.values || rec) || {}; }
    function minutesBetween(a, b) {
        const t1 = Date.parse(a), t2 = Date.parse(b);
        if (isNaN(t1) || isNaN(t2)) return null;
        return Math.max(0, (t2 - t1) / 60000);
    }
    function dayKey(d) {
        const t = Date.parse(d);
        return isNaN(t) ? null : new Date(t).toISOString().slice(0, 10);
    }
    function localDayKey(d) {
        const t = Date.parse(d);
        if (isNaN(t)) return null;
        const date = new Date(t);
        return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
    }
    function lastNDays(n) {
        return Array.from({ length: n }, (_, i) => {
            const d = new Date(); d.setDate(d.getDate() - (n - 1 - i));
            return d.toISOString().slice(0, 10);
        });
    }

    /* ---------- Shared mock incident pool ---------- */
    const SEVS = ["Critical", "High", "Medium", "Low"];
    const SEV_WEIGHT = [0.08, 0.18, 0.34, 0.40];
    const TITLES = [
        "Phishing email reported", "Malware detected on endpoint", "Suspicious PowerShell execution",
        "Impossible-travel sign-in", "Privilege escalation attempt", "Data exfiltration alert",
        "Brute-force login attempts", "C2 beacon detected", "Ransomware behavior blocked",
        "Unauthorized cloud upload", "DLP policy violation", "Vulnerability actively exploited",
        "Anomalous service account use", "Off-hours admin access", "USB mass-storage alert"
    ];
    const SOURCES = ["Microsoft Sentinel", "Splunk ES", "CrowdStrike", "Defender XDR", "QRadar", "Elastic Security", "M365"];
    const MITRE = ["T1566 Phishing", "T1078 Valid Accounts", "T1059 PowerShell", "T1003 Cred Dumping", "T1021 Lateral Move", "T1041 Exfiltration"];
    const ANALYSTS = ["Aisha K.", "Marco R.", "Lena W.", "Raj P.", "Yuki T.", "Unassigned"];

    function weightedSev() {
        const roll = Math.random();
        let cumulative = 0;
        for (let index = 0; index < SEVS.length; index++) {
            cumulative += SEV_WEIGHT[index];
            if (roll <= cumulative) return SEVS[index];
        }
        return "Low";
    }
    function seededRand(min, max) { return min + Math.random() * (max - min); }

    function buildMockPool(days) {
        const pool = [];
        let sequence = 4200;
        for (let dayOffset = days - 1; dayOffset >= 0; dayOffset--) {
            const perDay = Math.round(seededRand(6, 16));
            for (let index = 0; index < perDay; index++) {
                const created = new Date();
                created.setDate(created.getDate() - dayOffset);
                created.setHours(Math.floor(seededRand(0, 24)), Math.floor(seededRand(0, 60)));
                const severity = weightedSev();
                const detectDelay = seededRand(2, 18);
                const responseDelay = seededRand(6, 70);
                const closeDelay = seededRand(20, 260);
                const detected = new Date(created.getTime());
                const responded = new Date(created.getTime() + responseDelay * 60000);
                const closed = Math.random() < 0.9 ? new Date(created.getTime() + closeDelay * 60000) : null;
                pool.push({
                    id: `INC-${sequence++}`,
                    title: TITLES[Math.floor(Math.random() * TITLES.length)],
                    severity,
                    status: closed ? "Closed" : "Open",
                    created: created.toISOString(),
                    detected: detected.toISOString(),
                    responded: responded.toISOString(),
                    closed: closed ? closed.toISOString() : null,
                    mttd: Math.round(detectDelay),
                    mttr: closed ? Math.round((closed - detected) / 60000) : null,
                    assignee: ANALYSTS[Math.floor(Math.random() * ANALYSTS.length)],
                    source: SOURCES[Math.floor(Math.random() * SOURCES.length)],
                    mitre: MITRE[Math.floor(Math.random() * MITRE.length)],
                    automated: Math.random() < 0.72
                });
            }
        }
        return pool;
    }

    const _pool = buildMockPool(90);
    function poolInRange(range) {
        const cutoff = Date.now() - range * 86400000;
        return _pool.filter(record => Date.parse(record.created) >= cutoff);
    }

    function mockTrend(range) {
        const labels = lastNDays(range);
        const byDay = {};
        poolInRange(range).forEach(record => {
            const key = dayKey(record.created);
            if (!key) return;
            (byDay[key] || (byDay[key] = { detected: [], resolved: [] }));
            byDay[key].detected.push(record.mttd);
            if (record.mttr != null) byDay[key].resolved.push(record.mttr);
        });
        const average = values => values.length ? values.reduce((total, value) => total + value, 0) / values.length : null;
        return {
            labels,
            mttd: labels.map(key => average((byDay[key] || {}).detected || [])),
            mttr: labels.map(key => average((byDay[key] || {}).resolved || []))
        };
    }
    function mockSeverity(range) {
        const b = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        poolInRange(range).forEach(r => b[r.severity]++);
        return { labels: Object.keys(b), data: Object.values(b) };
    }
    function mockClosure(range) {
        const recs = poolInRange(range);
        const closed = recs.filter(r => r.status === "Closed").length;
        const pct = recs.length ? Math.round((closed / recs.length) * 100) : 0;
        return { closed: pct, open: 100 - pct };
    }
    function mockRecords(filter = {}) {
        let recs = poolInRange(filter.range || 30);
        if (filter.severity) recs = recs.filter(r => r.severity === filter.severity);
        if (filter.status) recs = recs.filter(r => r.status.toLowerCase() === filter.status.toLowerCase());
        if (filter.day) recs = recs.filter(r => dayKey(r.created) === filter.day);
        if (filter.dateFrom) recs = recs.filter(r => localDayKey(r.created) && localDayKey(r.created) >= filter.dateFrom);
        if (filter.dateTo) recs = recs.filter(r => localDayKey(r.created) && localDayKey(r.created) <= filter.dateTo);
        if (filter.assignee) recs = recs.filter(r => r.assignee === filter.assignee);
        if (filter.automated != null) recs = recs.filter(r => r.automated === filter.automated);
        return recs.sort((a, b) => Date.parse(b.created) - Date.parse(a.created));
    }

    /* ---------- Live fetch + normalize ---------- */
    async function fetchIncidents() {
        const cfg = config();
        const appId = (cfg.APPS || {}).incidents;
        const res = await searchRecords(appId);
        return res.records || res.results || res || [];
    }
    function normalizeLive(rec) {
        const cfg = config();
        const F = cfg.FIELDS || {};
        const v = values(rec);
        const created = v[F.createdAt], detected = v[F.detectedAt] || created, closed = v[F.closedAt] || null;
        return {
            id: rec.id || rec.trackingId || v.trackingId || "—",
            title: v.name || v.title || v.summary || "Incident",
            severity: v[F.severity] || "—",
            status: v[F.status] || (closed ? "Closed" : "Open"),
            created, detected, responded: v[F.respondedAt] || null, closed,
            mttd: minutesBetween(detected, v[F.respondedAt]),
            mttr: minutesBetween(detected, closed),
            assignee: v.assignee || v.owner || "—",
            source: v.source || "—",
            mitre: v.mitre || v.technique || "—",
            automated: !!v.automated
        };
    }

    // --- MTTD / MTTR trend over the last N days ---
    async function getIncidentTrend(range) {
        return guarded(async () => {
            const recs = (await fetchIncidents()).map(normalizeLive);
            const byDay = {};
            recs.forEach(r => {
                const key = dayKey(r.created || r.detected); if (!key) return;
                (byDay[key] || (byDay[key] = { d: [], r: [] }));
                if (r.mttd != null) byDay[key].d.push(r.mttd);
                if (r.mttr != null) byDay[key].r.push(r.mttr);
            });
            const labels = lastNDays(range);
            const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
            return { labels, mttd: labels.map(k => avg((byDay[k] || {}).d || [])), mttr: labels.map(k => avg((byDay[k] || {}).r || [])) };
        }, () => mockTrend(range), "getIncidentTrend");
    }

    // --- Volume by severity ---
    async function getSeverityBreakdown(range) {
        return guarded(async () => {
            const recs = (await fetchIncidents()).map(normalizeLive);
            const b = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            recs.forEach(r => { const k = Object.keys(b).find(x => x.toLowerCase() === (r.severity || "").toLowerCase()); if (k) b[k]++; });
            return { labels: Object.keys(b), data: Object.values(b) };
        }, () => mockSeverity(range), "getSeverityBreakdown");
    }

    // --- Closure rate ---
    async function getClosureRate(range) {
        return guarded(async () => {
            const recs = (await fetchIncidents()).map(normalizeLive);
            const closed = recs.filter(r => (r.status || "").toLowerCase().includes("close") || r.closed).length;
            const pct = recs.length ? Math.round((closed / recs.length) * 100) : 0;
            return { closed: pct, open: 100 - pct };
        }, () => mockClosure(range), "getClosureRate");
    }

    // --- Records for drill-down (filtered) ---
    async function getRecords(filter = {}) {
        return guarded(async () => {
            const cfg = config();
            const F = cfg.FIELDS || {};
            // Map dashboard filter -> Swimlane search filters.
            const filters = [];
            if (filter.severity) filters.push({ fieldId: F.severity, filterType: "equals", value: filter.severity });
            if (filter.status) filters.push({ fieldId: F.status, filterType: "equals", value: filter.status });
            const res = await searchRecords((cfg.APPS || {}).incidents, filters);
            let recs = (res.records || res.results || res || []).map(normalizeLive);
            if (filter.day) recs = recs.filter(r => dayKey(r.created) === filter.day);
            if (filter.dateFrom) recs = recs.filter(r => localDayKey(r.created) && localDayKey(r.created) >= filter.dateFrom);
            if (filter.dateTo) recs = recs.filter(r => localDayKey(r.created) && localDayKey(r.created) <= filter.dateTo);
            return recs;
        }, () => mockRecords(filter), "getRecords");
    }

    // Build a deep link to open a record in Swimlane.
    function recordUrl(id) {
        const cfg = config();
        const appId = (cfg.APPS || {}).incidents;
        if (!cfg.BASE_URL || !appId || !id) return null;
        return `${cfg.BASE_URL.replace(/\/$/, "")}/record/${appId}/${id}`;
    }

    return {
        canGoLive,
        guarded,
        searchRecords,
        runReport,
        validateConnection: () => request("/api/user/authorize", { method: "GET" }),
        getIncidentTrend,
        getSeverityBreakdown,
        getClosureRate,
        getRecords,
        recordUrl,
        loadServerCredentials,
        connectionStatus: () => {
            const cfg = config();
            return canGoLive() ? "live" : (cfg.USE_LIVE ? "misconfigured" : "demo");
        }
    };
})();

window.SwimlaneAPI = SwimlaneAPI;
