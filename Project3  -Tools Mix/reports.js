/* =====================================================================
   Report ingestion & classification engine
   ---------------------------------------------------------------------
   Parses a SOC incident report CSV (columns: Tracking Id, Case Status,
   BMC Incident Title), classifies each incident into a category +
   severity, and produces aggregates that feed the dashboard analytics.

   Works with the provided ZF SOC export and any CSV with those columns.
   ===================================================================== */

const Reports = (() => {

    /* ---------- CSV parser (handles quoted fields with commas) ---------- */
    function parseCSV(text) {
        const rows = [];
        let field = "", row = [], inQuotes = false;
        for (let i = 0; i < text.length; i++) {
            const c = text[i], next = text[i + 1];
            if (inQuotes) {
                if (c === '"' && next === '"') { field += '"'; i++; }
                else if (c === '"') { inQuotes = false; }
                else field += c;
            } else {
                if (c === '"') inQuotes = true;
                else if (c === ",") { row.push(field); field = ""; }
                else if (c === "\r") { /* skip */ }
                else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
                else field += c;
            }
        }
        if (field.length || row.length) { row.push(field); rows.push(row); }
        return rows.filter(r => r.length && r.some(c => c.trim() !== ""));
    }

    /* ---------- Classification rules (first match wins) ---------- */
    // category = chart bucket, severity = RAG, automated = detection pipeline
    const RULES = [
        { re: /break glass|bga|max prio/i,                     category: "Privileged Access", severity: "Critical", automated: true },
        { re: /domain admin|critical ad group|built-in-groups|ad named location/i, category: "AD Security", severity: "High", automated: true },
        { re: /ransomware|wannacry|encrypted/i,                category: "Ransomware", severity: "Critical", automated: false },
        { re: /laptop stolen|verlustmeldung|loss report/i,     category: "Lost / Stolen Device", severity: "High", automated: false },
        { re: /compromised partner|exposed credential|entra id risk/i, category: "Identity Risk", severity: "High", automated: true },
        { re: /av - relevant malware|high amount of av|malware detected|mobile device management - malware/i, category: "Malware / AV", severity: "High", automated: true },
        { re: /crowdstrike/i,                                  category: "EDR (CrowdStrike)", severity: "High", automated: true },
        { re: /defender experts/i,                             category: "Defender Experts", severity: "High", automated: true },
        { re: /sentinel|graphapi/i,                            category: "SIEM (Sentinel)", severity: "High", automated: true },
        { re: /dns tunneling|dns match/i,                      category: "DNS Threats", severity: "Medium", automated: true },
        { re: /claroty|xdome/i,                                category: "OT/ICS (Claroty)", severity: "Medium", automated: true },
        { re: /threat hunting/i,                               category: "Threat Hunting", severity: "Low", automated: true },
        { re: /phishing|suspicious (link|file|files|popup)|harmful files|reported phishing|fishing/i, category: "Phishing", severity: "Medium", automated: false },
        { re: /swap request/i,                                 category: "Software Approval", severity: "Low", automated: false },
        { re: /named location/i,                               category: "Config Change", severity: "Low", automated: false },
        { re: /mfa|authentication|reauthentication|sign in|sign-in|login|password|aadsts/i, category: "Auth / Access", severity: "Medium", automated: false },
        { re: /on hold|on-hold|blocked|blockage|block(ed)? (e-?mail|mail)|release|attachment|held|safe sender|unblock|delivery/i, category: "Email Security", severity: "Low", automated: false },
        { re: /host down|service critical|connection time|vdi|firewall|fire wall/i, category: "Infrastructure", severity: "Low", automated: true }
    ];
    const DEFAULT = { category: "Other", severity: "Low", automated: false };

    function classify(title) {
        const t = title || "";
        for (const r of RULES) if (r.re.test(t)) return { category: r.category, severity: r.severity, automated: r.automated };
        return { ...DEFAULT };
    }

    // Infer a source system from the title so drill-downs feel real.
    function inferSource(title, category) {
        const map = {
            "Malware / AV": "Microsoft Defender", "Defender Experts": "Defender Experts",
            "EDR (CrowdStrike)": "CrowdStrike", "OT/ICS (Claroty)": "Claroty xDome",
            "SIEM (Sentinel)": "Microsoft Sentinel", "Identity Risk": "Entra ID",
            "DNS Threats": "DNS Security", "Privileged Access": "Entra ID / AD",
            "AD Security": "Active Directory", "Threat Hunting": "Threat Intel",
            "Email Security": "Mimecast / M365", "Phishing": "M365 Defender"
        };
        return map[category] || "SOC Portal";
    }

    /* ---------- Build dataset + aggregates from parsed rows ---------- */
    function build(rows, range) {
        const header = rows[0].map(h => h.trim().toLowerCase());
        const idIdx = header.findIndex(h => h.includes("tracking"));
        const stIdx = header.findIndex(h => h.includes("status"));
        const tiIdx = header.findIndex(h => h.includes("title"));
        const body = rows.slice(1);

        const rangeDays = range || 30;
        const now = Date.now();
        const span = rangeDays * 86400000;

        const records = body.map((r, i) => {
            const title = (r[tiIdx] || "").trim();
            const status = (r[stIdx] || "").trim() || "CLOSED";
            const c = classify(title);
            // Distribute across the reporting window by sequence (newest first).
            const created = new Date(now - (i / Math.max(1, body.length - 1)) * span);
            return {
                id: (r[idIdx] || ("REC-" + i)).trim(),
                title,
                status: /close/i.test(status) ? "Closed" : (status || "Open"),
                severity: c.severity,
                category: c.category,
                automated: c.automated,
                source: inferSource(title, c.category),
                mitre: c.category,
                created: created.toISOString(),
                detected: created.toISOString(),
                responded: null,
                closed: /close/i.test(status) ? created.toISOString() : null,
                mttd: null,
                mttr: null,
                assignee: "SOC Analyst"
            };
        });

        // Severity breakdown
        const sev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        records.forEach(r => { if (sev[r.severity] != null) sev[r.severity]++; });

        // Category breakdown (sorted desc)
        const catMap = {};
        records.forEach(r => catMap[r.category] = (catMap[r.category] || 0) + 1);
        const categories = Object.entries(catMap).sort((a, b) => b[1] - a[1]);

        // Closure
        const closed = records.filter(r => r.status === "Closed").length;
        const closurePct = records.length ? Math.round((closed / records.length) * 100) : 0;

        // Daily volume
        const dayMap = {};
        records.forEach(r => { const k = r.created.slice(0, 10); dayMap[k] = (dayMap[k] || 0) + 1; });
        const labels = Array.from({ length: rangeDays }, (_, i) => {
            const d = new Date(); d.setDate(d.getDate() - (rangeDays - 1 - i));
            return d.toISOString().slice(0, 10);
        });
        const volume = labels.map(k => dayMap[k] || 0);

        // KPIs
        const automated = records.filter(r => r.automated).length;
        const automationRate = records.length ? Math.round((automated / records.length) * 100) : 0;
        const open = records.filter(r => r.status !== "Closed").length;
        const hoursSaved = Math.round((automated * 20) / 60); // 20 min manual effort each

        return {
            records, severity: sev, categories, closurePct,
            labels, volume,
            sourceRows: rows,
            kpis: {
                total: records.length, open, closed, automationRate, automated,
                hoursSaved, topCategory: categories[0] ? categories[0][0] : "—"
            }
        };
    }

    async function loadSample(range) {
        const res = await fetch("data/sample-soc-report.csv");
        const text = await res.text();
        return build(parseCSV(text), range);
    }

    return { parseCSV, classify, build, loadSample };
})();

window.Reports = Reports;
