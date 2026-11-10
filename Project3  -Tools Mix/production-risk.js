/* =====================================================================
   production-risk.js — Production Risk Intelligence
   Single-tab module (inside API Integration Settings) that correlates
   findings across 11 security tools into an executive risk view,
   a CVE detection correlation matrix, MTTR/SLA analytics and a
   plant/line production risk heatmap. Mock data only — wire each
   metric to your real connectors when backend integrations go live.
   ===================================================================== */

const PRI = (() => {
    const C = { accent: "#464feb", accent2: "#6a72f0", green: "#22c55e", amber: "#f59e0b", red: "#ef4444", purple: "#8b5cf6", blue: "#3b82f6", muted: "#8b90a3", grid: "#2a2f3d" };

    function gradient(ctx, hex) {
        const g = ctx.createLinearGradient(0, 0, 0, 220);
        g.addColorStop(0, hex + "55"); g.addColorStop(1, hex + "00");
        return g;
    }
    const rand = (min, max) => Math.round(min + Math.random() * (max - min));
    const baseOpts = {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { boxWidth: 12, padding: 12, font: { size: 11 } } } },
        scales: { x: { grid: { display: false } }, y: { grid: { color: C.grid }, beginAtZero: true } }
    };

    /* ---- Reference data ---- */
    const TOOLS = [
        { id: "claroty", name: "Claroty xDome", logo: "CL", color: "#5c2d91", auth: "API Key", interval: "One-time/manual" },
        { id: "swimlane", name: "Swimlane SecOps", logo: "SL", color: "#464feb", auth: "API Key", interval: "5 min" },
        { id: "crowdstrike", name: "CrowdStrike Falcon", logo: "CS", color: "#e10600", auth: "OAuth2", interval: "10 min" },
        { id: "defender", name: "Microsoft Defender", logo: "DE", color: "#00b4d8", auth: "OAuth2", interval: "15 min" },
        { id: "azure", name: "Microsoft Azure", logo: "AZ", color: "#0078d4", auth: "OAuth2", interval: "30 min" },
        { id: "wiz", name: "Wiz Portal", logo: "WZ", color: "#7c3aed", auth: "OAuth2", interval: "30 min" },
        { id: "sentinel", name: "Microsoft Sentinel", logo: "SE", color: "#0078d4", auth: "OAuth2", interval: "10 min" },
        { id: "nessus", name: "Tenable / Nessus", logo: "TE", color: "#00c176", auth: "API Key", interval: "60 min" },
        { id: "trellix", name: "Trellix (McAfee ePO)", logo: "TX", color: "#d9272e", auth: "OAuth2", interval: "15 min" },
        { id: "bmc", name: "BMC Helix / Discovery", logo: "BM", color: "#f59e0b", auth: "Basic Auth", interval: "60 min" },
        { id: "pits", name: "PITS Database", logo: "PI", color: "#22c55e", auth: "Database", interval: "60 min" }
    ];

    const PLANTS = [
        { name: "Plant A — Stuttgart", revenue: 420000 },
        { name: "Plant B — Shanghai", revenue: 365000 },
        { name: "Plant C — Detroit", revenue: 298000 },
        { name: "Plant D — Pune", revenue: 210000 }
    ];
    const LINES = ["Line 1", "Line 2", "Line 3", "Line 4"];

    /* Risk Score Formula: CVSS*.25 + Criticality*.25 + Impact*.20 + Exploitability*.10 + Aging*.10 + Exposure*.10 */
    function computeRisk({ cvss, criticality, impact, exploitability, aging, exposure }) {
        return Math.round(cvss * .25 + criticality * .25 + impact * .20 + exploitability * .10 + aging * .10 + exposure * .10);
    }

    let cache = null;
    function data() {
        if (cache) return cache;
        const assetTypes = ["PLC Controller", "HMI Panel", "SCADA Server", "Historian", "Engineering Workstation", "Network Switch", "RTU", "Safety Controller"];
        const cves = ["CVE-2024-3400", "CVE-2024-21762", "CVE-2023-46604", "CVE-2024-27198", "CVE-2023-34362", "CVE-2024-6387", "CVE-2023-38831", "CVE-2024-4577", "CVE-2022-36804", "CVE-2024-1709"];
        const corrTools = ["claroty", "nessus", "bmc", "trellix", "crowdstrike", "pits"];

        const assets = Array.from({ length: 8 }, (_, i) => {
            const cvss = rand(55, 98) / 10;
            const criticality = rand(40, 100);
            const impact = rand(40, 100);
            const exploitability = rand(20, 100);
            const aging = rand(10, 100);
            const exposure = rand(10, 100);
            const risk = computeRisk({ cvss: cvss * 10, criticality, impact, exploitability, aging, exposure });
            return {
                asset: `${assetTypes[i % assetTypes.length]}-${1000 + i}`,
                plant: PLANTS[i % PLANTS.length].name,
                type: assetTypes[i % assetTypes.length],
                cve: cves[i % cves.length],
                risk, cvss,
                status: risk >= 80 ? "Critical" : risk >= 60 ? "High" : risk >= 40 ? "Medium" : "Low"
            };
        }).sort((a, b) => b.risk - a.risk);

        const correlation = cves.map(cve => {
            const detected = {};
            let count = 0;
            corrTools.forEach(t => {
                const hit = Math.random() > 0.32;
                detected[t] = hit; if (hit) count++;
            });
            return { cve, detected, confidence: Math.round((count / corrTools.length) * 100) };
        });

        const tickets = Array.from({ length: 10 }, (_, i) => {
            const sev = ["Critical", "High", "Medium", "Low"][rand(0, 3)];
            const slaTarget = { Critical: 3, High: 7, Medium: 15, Low: 30 }[sev];
            const resolution = Math.max(1, slaTarget + rand(-4, 8));
            const opened = new Date(); opened.setDate(opened.getDate() - rand(5, 90));
            return {
                id: `RT-${8000 + i}`, asset: assets[i % assets.length].asset, severity: sev,
                opened: opened.toISOString().slice(0, 10), slaTarget, resolution,
                breached: resolution > slaTarget
            };
        });

        const heat = PLANTS.map(p => ({ plant: p.name, revenue: p.revenue, lines: LINES.map(() => rand(20, 95)) }));

        cache = { assets, correlation, corrTools, tickets, heat, cves };
        return cache;
    }

    /* ---- KPI + badge helpers ---- */
    function kpiCard(label, value, sub, pillClass, pillText) {
        return `<div class="kpi-card sm">
            <div class="kpi-top"><span class="kpi-label">${label}</span>${pillText ? `<span class="pill ${pillClass}">${pillText}</span>` : ""}</div>
            <div class="kpi-value">${value}</div>
            <div class="kpi-sub">${sub}</div>
        </div>`;
    }
    function riskBadge(score) {
        const cls = score >= 80 ? "hi" : score >= 60 ? "hi" : score >= 40 ? "md" : "lo";
        return `<span class="risk-score ${cls}">${score}</span>`;
    }
    function confBadge(v) {
        const cls = v >= 70 ? "green" : v >= 40 ? "amber" : "red";
        return `<span class="pill ${cls}">${v}%</span>`;
    }

    let charts = {};
    function destroy(id) { if (charts[id]) { charts[id].destroy(); delete charts[id]; } }

    /* ---- Executive Risk ---- */
    function renderExec() {
        const d = data();
        document.getElementById("priExecKpis").innerHTML = [
            kpiCard("Risk Score", "51<small>/100</small>", "Down from 82 baseline", "green", "▼ Improving"),
            kpiCard("Critical Assets", "14", "Across 4 plants", "red", "● Critical"),
            kpiCard("Coverage %", "92<small>%</small>", "Assets under monitoring", "green", "▲ Good"),
            kpiCard("MTTR Days", "6.2<small>d</small>", "All production assets", "amber", "● Watch"),
            kpiCard("SLA Breaches", "9", "Last 30 days", "amber", "● Watch"),
            kpiCard("Compliance Score", "88<small>%</small>", "IEC 62443 / NIST CSF", "green", "▲ Good")
        ].join("");

        destroy("riskTrend");
        const tctx = document.getElementById("priRiskTrendChart").getContext("2d");
        charts.riskTrend = new Chart(tctx, {
            type: "line",
            data: {
                labels: ["Q1", "Q2", "Q3", "Q4"],
                datasets: [{ label: "Risk Score", data: [82, 71, 63, 51], borderColor: C.red, backgroundColor: gradient(tctx, C.red), fill: true, tension: .4, borderWidth: 2 }]
            },
            options: baseOpts
        });

        destroy("severity");
        const sevCtx = document.getElementById("priSeverityChart").getContext("2d");
        charts.severity = new Chart(sevCtx, {
            type: "doughnut",
            data: { labels: ["Critical", "High", "Medium", "Low"], datasets: [{ data: [14, 38, 62, 90], backgroundColor: [C.red, C.amber, C.accent2, C.green] }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } } }
        });

        destroy("toolStack");
        const toolCtx = document.getElementById("priToolStackChart").getContext("2d");
        const labels = TOOLS.map(t => t.name);
        charts.toolStack = new Chart(toolCtx, {
            type: "bar",
            data: {
                labels,
                datasets: [
                    { label: "Critical", data: labels.map(() => rand(0, 8)), backgroundColor: C.red, stack: "s" },
                    { label: "High", data: labels.map(() => rand(2, 14)), backgroundColor: C.amber, stack: "s" },
                    { label: "Medium", data: labels.map(() => rand(4, 20)), backgroundColor: C.accent2, stack: "s" }
                ]
            },
            options: { ...baseOpts, scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, grid: { color: C.grid } } } }
        });

        destroy("revenue");
        const revCtx = document.getElementById("priRevenueChart").getContext("2d");
        charts.revenue = new Chart(revCtx, {
            type: "bar",
            data: { labels: PLANTS.map(p => p.name), datasets: [{ label: "€ / day at risk", data: PLANTS.map(p => Math.round(p.revenue * (rand(15, 45) / 100))), backgroundColor: C.purple }] },
            options: baseOpts
        });

        const tbody = document.querySelector("#priAssetsTable tbody");
        tbody.innerHTML = d.assets.map(a => `<tr>
            <td>${a.asset}</td><td>${a.plant}</td><td>${a.type}</td><td>${a.cve}</td>
            <td>${riskBadge(a.risk)}</td>
            <td><span class="pill ${a.status === "Critical" ? "red" : a.status === "High" ? "amber" : "green"}">${a.status}</span></td>
        </tr>`).join("");
    }

    /* ---- Claroty xDome live data ---- */
    let _clarotyCache = null;
    async function pullClaroty() {
        if (_clarotyCache) return _clarotyCache;
        if (!window.ClarotyAPI) return (_clarotyCache = { assets: { data: [], source: "error" }, vulns: { data: [], source: "error" }, tickets: { data: [], source: "error" } });
        const [assets, vulns, tickets] = await Promise.all([
            ClarotyAPI.fetchAssets(), ClarotyAPI.fetchVulnerabilities(), ClarotyAPI.fetchSocTickets()
        ]);
        return (_clarotyCache = { assets, vulns, tickets });
    }

    /* ---- Correlation Matrix ---- */
    async function renderCorr() {
        const d = data();
        const claroty = await pullClaroty();
        const clarotyCves = new Set((claroty.vulns.data || []).map(v => v.cve));
        const clarotyLive = claroty.vulns.source === "live";
        d.correlation.forEach(row => {
            if (clarotyLive) row.detected.claroty = clarotyCves.has(row.cve);
            row.confidence = Math.round((d.corrTools.filter(tool => row.detected[tool]).length / d.corrTools.length) * 100);
        });

        const toolLabel = id => TOOLS.find(t => t.id === id)?.name || id;
        document.getElementById("priCorrHead").innerHTML =
            `<th>CVE</th>${d.corrTools.map(t => `<th>${toolLabel(t)}</th>`).join("")}<th>Sample confidence</th>`;
        document.getElementById("priCorrBody").innerHTML = d.correlation.map(row => `<tr>
            <td><strong>${row.cve}</strong></td>
            ${d.corrTools.map(t => `<td style="text-align:center;color:${row.detected[t] ? C.green : C.red}">${row.detected[t] ? "✓" : "✗"}</td>`).join("")}
            <td>${confBadge(row.confidence)}</td>
        </tr>`).join("");

        const corrCard = document.querySelector("#priView-corr .card .muted");
        if (corrCard) corrCard.innerHTML = `Sample estimate; other vendor columns are simulated until connected · Claroty column: <strong style="color:${clarotyLive ? C.green : C.amber}">${clarotyLive ? "live pull" : claroty.vulns.source === "error" ? "live request failed" : "no live feed"}</strong>`;

        destroy("coverage");
        const covCtx = document.getElementById("priCoverageChart").getContext("2d");
        const counts = d.corrTools.map(t => d.correlation.filter(r => r.detected[t]).length);
        charts.coverage = new Chart(covCtx, {
            type: "bar",
            data: { labels: d.corrTools.map(toolLabel), datasets: [{ label: "CVEs detected", data: counts, backgroundColor: C.blue }] },
            options: baseOpts
        });
    }

    /* ---- MTTR & SLA ---- */
    async function renderMttr() {
        const d = data();
        const claroty = await pullClaroty();
        // Claroty does not provide SOC tickets; this view uses the shared sample ticket pool.
        const clarotyTickets = (claroty.tickets.data || []).map(t => {
            const slaTarget = { Critical: 3, High: 7, Medium: 15, Low: 30 }[t.severity] || 15;
            const opened = new Date(t.opened);
            const resolution = t.status === "Closed" ? Math.max(1, Math.round((Date.now() - opened.getTime()) / 86400000)) : null;
            return { id: t.id, asset: t.asset, severity: t.severity, opened: t.opened, slaTarget, resolution: resolution ?? (slaTarget + rand(-2, 6)), breached: resolution != null && resolution > slaTarget, source: t.source };
        });
        const allTickets = [...d.tickets, ...clarotyTickets];
        const breachPct = Math.round((allTickets.filter(t => t.breached).length / allTickets.length) * 100);
        document.getElementById("priMttrKpis").innerHTML = [
            kpiCard("MTTR — All Assets", "8.4<small>d</small>", "SUM(Resolution) ÷ Closed Tickets", "green", "▲ Good"),
            kpiCard("MTTR — Critical OT", "3.1<small>d</small>", "OT/ICS production assets only", "green", "▲ Good"),
            kpiCard("SLA Breach %", `${breachPct}<small>%</small>`, "Breached ÷ Total incidents", breachPct > 25 ? "red" : "amber", breachPct > 25 ? "● High" : "● Watch"),
            kpiCard("Open Backlog", `${allTickets.filter(t => !t.breached).length}`, "Tickets within SLA window", "green", "▲ Good")
        ].join("");

        destroy("mttrTrend");
        const mctx = document.getElementById("priMttrTrendChart").getContext("2d");
        const months = ["Mar", "Apr", "May", "Jun", "Jul", "Aug"];
        charts.mttrTrend = new Chart(mctx, {
            type: "line",
            data: {
                labels: months,
                datasets: [
                    { label: "MTTR — All Assets", data: [14, 12.5, 11, 9.6, 8.9, 8.4], borderColor: C.accent2, backgroundColor: gradient(mctx, C.accent2), fill: true, tension: .4, borderWidth: 2 },
                    { label: "MTTR — Critical OT", data: [6.2, 5.4, 4.8, 3.9, 3.4, 3.1], borderColor: C.red, backgroundColor: gradient(mctx, C.red), fill: true, tension: .4, borderWidth: 2 }
                ]
            },
            options: baseOpts
        });

        destroy("mttrSla");
        const sctx = document.getElementById("priMttrSlaChart").getContext("2d");
        charts.mttrSla = new Chart(sctx, {
            type: "bar",
            data: {
                labels: ["Critical", "High", "Medium", "Low"],
                datasets: [
                    { label: "Actual MTTR (d)", data: [2.8, 6.5, 12.1, 22], backgroundColor: C.accent },
                    { label: "SLA Target (d)", data: [3, 7, 15, 30], backgroundColor: C.muted }
                ]
            },
            options: baseOpts
        });

        document.querySelector("#priTicketsTable tbody").innerHTML = allTickets.map(t => `<tr>
            <td>${t.id}${t.source ? ` <span class="muted">(${t.source})</span>` : ""}</td><td>${t.asset}</td>
            <td><span class="pill ${t.severity === "Critical" ? "red" : t.severity === "High" ? "amber" : "green"}">${t.severity}</span></td>
            <td>${t.opened}</td><td>${t.slaTarget}d</td><td>${t.resolution}d</td>
            <td><span class="pill ${t.breached ? "red" : "green"}">${t.breached ? "⚠ Breached" : "✓ On Time"}</span></td>
        </tr>`).join("");
    }

    /* ---- Heatmap ---- */
    function heatClass(v) { return v >= 80 ? "crit" : v >= 60 ? "high" : v >= 40 ? "med" : "low"; }

    const HEAT_RISKS = ["Critical", "High", "Medium", "Low", "Very Low"];
    const RISK_CLASS = { Critical: "crit", High: "high", Medium: "med", Low: "low", "Very Low": "low", Unknown: "low" };
    const HEAT_TOP_SITES = 25;
    const HEAT_PAGE_SIZE = 50;
    const DEVICE_FIELDS = [
        ["device_name", "Device"], ["uid", "UID"], ["ip_list", "IP address"],
        ["site_name", "Site"], ["site_group_name", "Site group"], ["device_category", "Category"],
        ["device_subcategory", "Sub-category"], ["device_type", "Type"], ["manufacturer", "Manufacturer"],
        ["model", "Model"], ["risk_score", "Risk"], ["is_online", "Online"],
        ["suspicious", "Suspicious"], ["retired", "Retired"]
    ];
    const heatState = { showAll: false, drill: null, page: 0 };
    const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
    const num = value => Number(value || 0).toLocaleString();
    const cellText = value => Array.isArray(value) ? value.join(", ") : (value === true ? "Yes" : value === false ? "No" : value ?? "");
    const riskLevel = row => HEAT_RISKS.find(l => l.toLowerCase() === String(row.risk_score ?? "").trim().toLowerCase()) || "Unknown";
    const siteName = row => String(row.site_name || "").trim() || "Unassigned";

    function heatSiteRows() {
        const bySite = new Map();
        ClarotyAPI.feedState("devices").data.forEach(row => {
            const site = siteName(row);
            if (!bySite.has(site)) bySite.set(site, { site, total: 0, counts: {} });
            const entry = bySite.get(site);
            entry.total += 1;
            const level = riskLevel(row);
            entry.counts[level] = (entry.counts[level] || 0) + 1;
        });
        return [...bySite.values()].sort((a, b) =>
            (b.counts.Critical || 0) - (a.counts.Critical || 0) ||
            (b.counts.High || 0) - (a.counts.High || 0) ||
            b.total - a.total);
    }

    function heatDrillDevices(site, level) {
        return ClarotyAPI.feedState("devices").data
            .filter(row => siteName(row) === site && (level === "All" || riskLevel(row) === level));
    }

    function renderHeatDrill() {
        const drill = heatState.drill;
        if (!drill) return;
        const rows = drill.rows;
        const pages = Math.max(1, Math.ceil(rows.length / HEAT_PAGE_SIZE));
        heatState.page = Math.min(heatState.page, pages - 1);
        const start = heatState.page * HEAT_PAGE_SIZE;
        const shown = rows.slice(start, start + HEAT_PAGE_SIZE);
        const state = ClarotyAPI.feedState("devices");
        const partial = state.complete ? "" : " Device feed is partially loaded, so counts may be incomplete.";
        document.getElementById("drawerBody").innerHTML = `
            <p class="rec-summary">${num(rows.length)} device${rows.length === 1 ? "" : "s"} · showing ${rows.length ? num(start + 1) : 0}–${num(Math.min(start + HEAT_PAGE_SIZE, rows.length))}.${partial}</p>
            <button type="button" class="ifc-btn save" data-pri-heat-export="1">Download this cell as CSV</button>
            <div class="table-wrap"><table><thead><tr>${DEVICE_FIELDS.map(([, label]) => `<th>${esc(label)}</th>`).join("")}</tr></thead><tbody>
            ${shown.map(row => `<tr>${DEVICE_FIELDS.map(([key]) => `<td>${esc(cellText(row[key])) || "—"}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${DEVICE_FIELDS.length}">No loaded device matched this cell.</td></tr>`}
            </tbody></table></div>
            <div class="xd-risk-pages"><button type="button" data-pri-heat-page="prev" ${heatState.page === 0 ? "disabled" : ""}>Previous</button><span>Page ${heatState.page + 1} of ${pages}</span><button type="button" data-pri-heat-page="next" ${start + HEAT_PAGE_SIZE >= rows.length ? "disabled" : ""}>Next</button></div>`;
    }

    function openHeatDrill(site, level) {
        heatState.drill = { site, level, rows: heatDrillDevices(site, level) };
        heatState.page = 0;
        const drawer = document.getElementById("drawer");
        drawer.dataset.operationsDrill = "false";
        document.getElementById("drawerTitle").textContent = `${site} · ${level === "All" ? "All devices" : `${level} risk`}`;
        document.getElementById("drawerSub").textContent = "Claroty xDome live device records";
        renderHeatDrill();
        drawer.classList.add("open");
        document.getElementById("drawerOverlay").classList.add("open");
        drawer.setAttribute("aria-hidden", "false");
    }

    function exportHeatDrill() {
        const drill = heatState.drill;
        if (!drill) return;
        const cell = value => `"${String(cellText(value)).replace(/"/g, '""')}"`;
        const csv = [DEVICE_FIELDS.map(([, label]) => cell(label)).join(",")]
            .concat(drill.rows.map(row => DEVICE_FIELDS.map(([key]) => cell(row[key])).join(",")))
            .join("\r\n");
        const url = URL.createObjectURL(new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" }));
        const link = document.createElement("a");
        link.href = url;
        link.download = `xdome-${drill.site}-${drill.level}`.replace(/[^a-z0-9-]+/gi, "-").toLowerCase() + ".csv";
        link.click();
        URL.revokeObjectURL(url);
    }

    function renderHeat() {
        const grid = document.getElementById("priHeatmapGrid");
        const state = ClarotyAPI.feedState("devices");
        const allRows = heatSiteRows();
        const note = document.getElementById("priHeatNote");

        if (!allRows.length) {
            grid.innerHTML = `<p class="rec-empty">${state.source === "live" ? "No device records are loaded yet." : "Claroty device feed is not loaded. Configure credentials and refresh to populate this heatmap."}</p>`;
            if (note) note.textContent = "";
            destroy("plantRevenue"); destroy("plantRisk");
            return;
        }

        const rows = heatState.showAll ? allRows : allRows.slice(0, HEAT_TOP_SITES);
        const columns = HEAT_RISKS.concat(allRows.some(r => r.counts.Unknown) ? ["Unknown"] : []);
        if (note) {
            note.innerHTML = `${num(allRows.length)} sites · ${num(state.data.length)} devices loaded${state.complete ? "" : " (partial feed)"} · showing ${rows.length === allRows.length ? "all" : `top ${num(rows.length)}`} by critical count. `
                + `<button type="button" class="pri-heat-toggle" data-pri-heat-toggle="1">${heatState.showAll ? `Show top ${HEAT_TOP_SITES}` : `Show all ${num(allRows.length)} sites`}</button>`;
        }

        grid.innerHTML = `
            <div class="pri-heat-row pri-heat-head">
                <div class="pri-heat-cell pri-heat-corner">Site</div>
                ${columns.map(l => `<div class="pri-heat-cell pri-heat-colhead">${esc(l)}</div>`).join("")}
                <div class="pri-heat-cell pri-heat-colhead">Total</div>
            </div>
            ${rows.map(row => `
            <div class="pri-heat-row">
                <div class="pri-heat-cell pri-heat-rowhead" title="${esc(row.site)}">${esc(row.site)}</div>
                ${columns.map(level => {
                    const value = row.counts[level] || 0;
                    return `<button type="button" class="pri-heat-cell pri-heat-val ${RISK_CLASS[level]}${value ? "" : " pri-heat-zero"}" data-pri-heat-cell="${esc(row.site)}|${esc(level)}" ${value ? "" : "disabled"} title="${esc(row.site)} · ${esc(level)} risk · ${num(value)} devices — click to list them">${num(value)}</button>`;
                }).join("")}
                <button type="button" class="pri-heat-cell pri-heat-val pri-heat-total" data-pri-heat-cell="${esc(row.site)}|All" title="${esc(row.site)} · all ${num(row.total)} devices">${num(row.total)}</button>
            </div>`).join("")}
        `;

        const chartRows = allRows.slice(0, 12);
        destroy("plantRevenue");
        const prCtx = document.getElementById("priPlantRevenueChart").getContext("2d");
        charts.plantRevenue = new Chart(prCtx, {
            type: "bar",
            data: { labels: chartRows.map(r => r.site), datasets: [{ label: "Devices", data: chartRows.map(r => r.total), backgroundColor: C.purple }] },
            options: baseOpts
        });

        destroy("plantRisk");
        const pkCtx = document.getElementById("priPlantRiskChart").getContext("2d");
        charts.plantRisk = new Chart(pkCtx, {
            type: "bar",
            data: {
                labels: chartRows.map(r => r.site),
                datasets: [
                    { label: "Critical", data: chartRows.map(r => r.counts.Critical || 0), backgroundColor: C.red },
                    { label: "High", data: chartRows.map(r => r.counts.High || 0), backgroundColor: C.amber }
                ]
            },
            options: { ...baseOpts, scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, grid: { color: C.grid }, beginAtZero: true } } }
        });
    }

    /* ---- Tool Integration Status ---- */
    async function renderInteg() {
        const devices = ClarotyAPI.feedState("devices");
        const vulnerabilities = ClarotyAPI.feedState("vulnerabilities");
        const grid = document.getElementById("priIntegGrid");
        const liveCount = result => result?.source === "live" ? (result.data || []).length : null;
        const assets = liveCount(devices);
        const findings = liveCount(vulnerabilities);
        const lastSync = devices.fetchedAt || vulnerabilities.fetchedAt;
        const readOnlyApiFeeds = ["github", "gitlab", "misp", "keycloak", "opensearch", "wazuh", "sentinelone", "defender-cloud-apps", "prismacloud", "netapp", "cato"];
        grid.innerHTML = TOOLS.map(t => {
            const isClaroty = t.id === "claroty";
            const live = isClaroty && (devices.source === "live" || vulnerabilities.source === "live");
            const configured = typeof INTEGRATIONS !== "undefined" && INTEGRATIONS.isConfigured(t.id);
            const manualApiFeed = readOnlyApiFeeds.includes(t.id);
            const failed = isClaroty && (devices.source === "error" || vulnerabilities.source === "error");
            const status = live ? "live data" : failed ? "request failed" : isClaroty ? (ClarotyAPI.canGoLive() ? "awaiting initial feed" : "awaiting credentials") : configured && manualApiFeed ? "settings saved · manual sync" : configured ? "settings saved · test required" : manualApiFeed ? "read-only sync available" : t.id === "swimlane" ? "pending credentials" : "connector pending";
            const statusColor = live ? C.green : failed ? C.red : C.amber;
            const statusIcon = live ? "●" : failed ? "✕" : "◔";
            const assetCount = live && isClaroty ? assets : null;
            const findingCount = live && isClaroty ? findings : null;
            const lastSyncText = live && isClaroty && lastSync ? `Last response: ${new Date(lastSync).toLocaleString()}` : configured && manualApiFeed ? "Manual API sync is available in SIEM Workbench" : configured ? "No successful sync recorded" : isClaroty ? "Configure Claroty credentials to load live data" : manualApiFeed ? "Configure encrypted credentials, then sync from SIEM Workbench" : t.id === "swimlane" ? "Live feed requires complete credentials and a successful test" : "A live server-side connector is not implemented";
            return `<div class="integ-card">
                <div class="integ-head">
                    <div class="integ-logo" style="background:${t.color}">${t.logo}</div>
                    <div>
                        <div class="integ-title">${t.name}</div>
                        <div class="integ-status" style="color:${statusColor}">${statusIcon} ${status[0].toUpperCase() + status.slice(1)}</div>
                    </div>
                </div>
                <div class="integ-sub">Connection</div>
                <ul class="integ-list">
                    <li>Auth: ${t.auth}</li>
                    <li>Planned interval: ${t.interval}</li>
                    <li>${lastSyncText}</li>
                </ul>
                <div class="integ-metrics">
                    <div class="integ-metric"><b>${assetCount == null ? "—" : assetCount.toLocaleString()}</b><span>Assets loaded</span></div>
                    <div class="integ-metric"><b>${findingCount == null ? "—" : findingCount.toLocaleString()}</b><span>Findings loaded</span></div>
                    <div class="integ-metric"><b>${live && isClaroty ? "Live" : "—"}</b><span>Verified status</span></div>
                    <div class="integ-metric"><b>${t.id === "pits" ? "DB" : "REST"}</b><span>Interface</span></div>
                </div>
            </div>`;
        }).join("");

        destroy("ingest");
        const iCtx = document.getElementById("priIngestChart").getContext("2d");
        charts.ingest = new Chart(iCtx, {
            type: "bar",
            data: { labels: TOOLS.map(t => t.name), datasets: [{ label: "Verified records loaded", data: TOOLS.map(t => t.id === "claroty" && assets != null ? assets + (findings || 0) : null), backgroundColor: C.blue }] },
            options: baseOpts
        });
    }

    const RENDERERS = { exec: renderExec, corr: renderCorr, mttr: renderMttr, heat: renderHeat, integ: renderInteg };

    function activateTab(tab) {
        document.querySelectorAll("#priSubtabs .pri-subtab-btn").forEach(b => b.classList.toggle("active", b.dataset.pritab === tab));
        document.querySelectorAll(".pri-view").forEach(v => v.hidden = v.id !== `priView-${tab}`);
        return Promise.resolve((RENDERERS[tab] || renderExec)()).catch(err => console.error("[ProductionRisk] render failed:", err));
    }

    function initNav() {
        document.querySelectorAll("#integTopTabs .pri-toplevel-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                document.querySelectorAll("#integTopTabs .pri-toplevel-btn").forEach(b => b.classList.toggle("active", b === btn));
                const isRisk = btn.dataset.itab === "risk";
                document.getElementById("integCredsView").hidden = isRisk;
                document.getElementById("integRiskView").hidden = !isRisk;
                if (isRisk) activateTab("exec");
            });
        });
        document.querySelectorAll("#priSubtabs .pri-subtab-btn").forEach(btn => {
            btn.addEventListener("click", () => activateTab(btn.dataset.pritab));
        });

        const heatView = document.getElementById("priView-heat");
        if (heatView) {
            heatView.addEventListener("click", event => {
                const cell = event.target.closest("[data-pri-heat-cell]");
                if (cell) {
                    const [site, level] = cell.dataset.priHeatCell.split("|");
                    return openHeatDrill(site, level);
                }
                if (event.target.closest("[data-pri-heat-toggle]")) {
                    heatState.showAll = !heatState.showAll;
                    return renderHeat();
                }
            });
        }

        const drawerBody = document.getElementById("drawerBody");
        if (drawerBody) {
            drawerBody.addEventListener("click", event => {
                if (event.target.closest("[data-pri-heat-export]")) return exportHeatDrill();
                const page = event.target.closest("[data-pri-heat-page]")?.dataset.priHeatPage;
                if (!page || !heatState.drill) return;
                const pages = Math.max(1, Math.ceil(heatState.drill.rows.length / HEAT_PAGE_SIZE));
                heatState.page = Math.min(pages - 1, Math.max(0, heatState.page + (page === "next" ? 1 : -1)));
                renderHeatDrill();
            });
        }
    }

    document.addEventListener("DOMContentLoaded", initNav);
    return {
        activateTab,
        async refreshData(refreshClient = true) {
            _clarotyCache = null;
            if (refreshClient) await ClarotyAPI.refreshData();
            const tab = document.querySelector("#priSubtabs .pri-subtab-btn.active")?.dataset.pritab || "exec";
            return activateTab(tab);
        }
    };
})();

window.PRI = PRI;
