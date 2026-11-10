const XDPortal = (() => {
    const FEEDS = ["devices", "alerts", "vulnerabilities", "events"];
    const LOAD_FEEDS = [...FEEDS, "relations"];
    const LABELS = { devices: "Devices", alerts: "Alerts", vulnerabilities: "CVEs", events: "Network events" };
    const FEED_ICONS = { devices: "cpu", alerts: "shield-alert", vulnerabilities: "bug", events: "activity" };
    const MONITORS = [
        ["Git / repository security", "Configure GitHub or GitLab in Settings; sync in SIEM Workbench"],
        ["SaaS SDLC / Kiro", "CI/CD and Kiro audit connector required"],
        ["AI tools / API security", "AI gateway and API audit connector required"],
        ["EKS production security", "AWS EKS and runtime telemetry connector required"],
        ["OpenShift production security", "OpenShift audit and runtime telemetry connector required"]
    ];
    const cache = { devices: [], alerts: [], vulnerabilities: [], events: [] };
    let lastRefresh = null;
    let refreshing = null;
    let feedLoadGeneration = 0;
    let overviewCveRange = "all";
    let riskPage = 0;
    const riskPageSize = 80;
    let alertPage = 0;
    let eventPage = 0;
    const feedTablePageSize = 100;
    const homeFilters = { site: "", risk: "" };
    let overviewRange = "30";
    let operationsRange = "30";
    let operationsRenderTimer = null;
    let operationsDrillState = null;
    const operationsDrillPageSize = 50;
    const overviewFilters = { site_group_name: "", site_name: "", network: "", device_category: "", device_subcategory: "", manufacturer: "", device_type: "", risk_score: "" };
    const overviewFilterFields = [
        ["site_group_name", "Site Group"], ["site_name", "Site Name"], ["network", "Network · IPv4 /24"],
        ["device_category", "Category"], ["device_subcategory", "Sub-Category"], ["manufacturer", "Manufacturer"],
        ["device_type", "Device Type"], ["risk_score", "Risk Score"]
    ];
    let networkView = "activity";
    let ipListData = null;
    let indicatorData = null;
    let overviewIntegrationData = null;
    let overviewIntegrationRequest = null;
    const text = value => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
    const number = value => Number(value || 0).toLocaleString();
    const time = value => value ? new Date(value).toLocaleString() : "Unknown";
    const count = (items, test) => items.filter(test).length;
    const RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Very Low"];
    const deviceRisk = row => RISK_LEVELS.find(level => level.toLowerCase() === String(row.risk_score ?? "").trim().toLowerCase()) || "Unknown";
    const isKnownExploited = row => row.is_known_exploited === true || String(row.is_known_exploited).trim().toLowerCase() === "true";
    const onlineStatus = row => {
        if (row.is_online === true || String(row.is_online).trim().toLowerCase() === "true") return "Online";
        if (row.is_online === false || String(row.is_online).trim().toLowerCase() === "false") return "Offline";
        return "Unknown";
    };
    const online = row => onlineStatus(row) === "Online";
    const riskColor = { Critical: "var(--red)", High: "var(--orange)", Medium: "var(--yellow)", Low: "var(--green)", "Very Low": "var(--green)", Unknown: "var(--muted)" };
    const impactLabels = ["Very Low", "Low", "Medium", "High", "Critical"];
    const heatLevels = [[0, 0, 1, 2, 3], [1, 1, 2, 2, 4], [2, 2, 2, 2, 4], [2, 3, 3, 4, 4], [2, 3, 4, 4, 4]];
    let normalizedCvesSource = null;
    let normalizedCves = [];
    function exposureCell(row) {
        const epss = Number(row.epss_score);
        const cvss = Number(row.cvss_v3_score);
        if (row.epss_score == null || row.epss_score === "" || row.cvss_v3_score == null || row.cvss_v3_score === "" || !Number.isFinite(epss) || !Number.isFinite(cvss) || epss < 0 || epss > 1 || cvss < 0 || cvss > 10) return null;
        return [Math.min(4, Math.floor(epss * 5)), Math.min(4, Math.floor(cvss / 2))];
    }
    function riskVulnerabilities(range = "all") {
        if (normalizedCvesSource !== cache.vulnerabilities) {
            const byCve = new Map();
            cache.vulnerabilities.forEach((row, index) => {
                const name = String(row.name || "").trim();
                const ids = Array.isArray(row.cve_ids) ? row.cve_ids : [];
                const candidates = [...ids, ...(name ? [name] : [])]
                    .map(value => String(value).trim())
                    .filter(value => /^CVE-\d{4}-\d+$/i.test(value));
                candidates.forEach(cve => {
                    const key = cve.toUpperCase();
                    const direct = name.toUpperCase() === key;
                    const existing = byCve.get(key);
                    if (existing && (!direct || existing.direct)) return;
                    byCve.set(key, { row: { ...row, name: key, cve_ids: [key] }, index, direct });
                });
            });
            normalizedCvesSource = cache.vulnerabilities;
            normalizedCves = [...byCve.values()];
        }
        const uniqueCves = normalizedCves;
        if (range === "all") return uniqueCves;
        const cutoff = Date.now() - Number(range) * 86400000;
        return uniqueCves.filter(({ row }) => {
            const published = Date.parse(row.published_date);
            return Number.isFinite(published) && published >= cutoff && published <= Date.now();
        });
    }
    function exposureMatrix(vulns = riskVulnerabilities().map(({ row }) => row)) {
        const matrix = Array.from({ length: 5 }, () => Array(5).fill(0));
        vulns.forEach(row => {
            const cell = exposureCell(row);
            if (cell) matrix[cell[0]][cell[1]] += 1;
        });
        return matrix;
    }
    function heatMap(matrix) {
        return `<div class="xd-matrix"><span class="xd-matrix-impact">Impact</span><span></span>${impactLabels.map(item => `<b>${item}</b>`).join("")}${matrix.map((row, index) => `<b>${impactLabels[index]}</b>${row.map((value, impact) => `<button type="button" class="xd-heat" data-xd-cell="${index}:${impact}" data-risk="${value ? heatLevels[index][impact] : -1}" aria-label="Show ${number(value)} CVEs and affected devices for ${impactLabels[index]} likelihood, ${impactLabels[impact]} impact" title="${impactLabels[index]} likelihood / ${impactLabels[impact]} impact: ${number(value)} CVEs and related devices">${number(value)}</button>`).join("")}`).join("")}</div>`;
    }
    function renderOverviewCharts(devices, alerts, range) {
        if (!window.Chart) return;
        const riskLabels = [...RISK_LEVELS, "Unknown"];
        const riskCounts = riskLabels.map(label => count(devices, row => deviceRisk(row) === label));
        const onlineCount = count(devices, online);
        const offlineCount = count(devices, row => onlineStatus(row) === "Offline");
        const unknownCount = devices.length - onlineCount - offlineCount;
        const categories = new Map();
        devices.forEach(row => {
            const category = String(row.device_category || "Unknown").trim() || "Unknown";
            categories.set(category, (categories.get(category) || 0) + 1);
        });
        const sortedCategories = [...categories.entries()].sort((a, b) => b[1] - a[1]);
        const buckets = new Map();
        alerts.forEach(alert => {
            const time = Date.parse(alert.detected_time);
            if (!Number.isFinite(time)) return;
            const date = new Date(time);
            const key = range === "all"
                ? `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`
                : date.toISOString().slice(0, 10);
            buckets.set(key, (buckets.get(key) || 0) + 1);
        });
        const alertLabels = [...buckets.keys()].sort();
        const colors = ["#ef4444", "#f59e0b", "#facc15", "#22c55e", "#64748b", "#cbd5e1"];
        const options = { responsive: true, maintainAspectRatio: false, animation: { duration: 450 }, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 10, font: { size: 10 } } } } };
        const create = (id, config) => {
            const canvas = document.getElementById(id);
            if (!canvas) return;
            Chart.getChart(canvas)?.destroy();
            new Chart(canvas, config);
        };
        create("xdOverviewRiskChart", { type: "doughnut", data: { labels: riskLabels.filter((_, index) => riskCounts[index]), datasets: [{ data: riskCounts.filter(value => value > 0), backgroundColor: colors, borderWidth: 0 }] }, options });
        create("xdOverviewConnectivityChart", { type: "doughnut", data: { labels: ["Online", "Offline", "Unknown"], datasets: [{ data: [onlineCount, offlineCount, unknownCount], backgroundColor: ["#22c55e", "#ef4444", "#64748b"], borderWidth: 0 }] }, options });
        create("xdOverviewCategoryChart", { type: "bar", data: { labels: sortedCategories.slice(0, 10).map(([label]) => label), datasets: [{ label: "Active assets", data: sortedCategories.slice(0, 10).map(([, value]) => value), backgroundColor: "#5b68ef", borderRadius: 3 }] }, options: { ...options, indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: "rgba(127,127,127,.15)" } }, y: { grid: { display: false } } } } });
        create("xdOverviewAlertTrendChart", { type: "line", data: { labels: alertLabels, datasets: [{ label: "Claroty alerts", data: alertLabels.map(label => buckets.get(label)), borderColor: "#f59e0b", backgroundColor: "rgba(245,158,11,.14)", fill: true, tension: .25, pointRadius: 2, borderWidth: 2 }] }, options: { ...options, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } }, y: { beginAtZero: true, grid: { color: "rgba(127,127,127,.15)" } } } } });
    }

    function renderOverviewToolSummary() {
        const host = document.getElementById("xdOverviewTools");
        if (!host || !overviewIntegrationData) return;
        const tools = typeof INTEGRATIONS !== "undefined" ? INTEGRATIONS.TOOLS : [];
        const eventConnectors = overviewIntegrationData.eventConnectors || [];
        const savedConfigs = tools.filter(tool => tool.id !== "claroty" && INTEGRATIONS.isConfigured(tool.id)).length;
        const clarotyLive = ClarotyAPI.feedState("devices").source === "live";
        host.innerHTML = `<div class="xd-surface-head"><div><h3>Security Tool &amp; Connector Overview</h3><p>${number(savedConfigs)} of ${number(Math.max(0, tools.length - 1))} non-Claroty tool settings saved · ${number(eventConnectors.length)} event receivers registered · Claroty is live when its feed succeeds.</p></div><button type="button" class="xd-link" data-xd-navigate="integrations">Manage integrations</button></div><div class="xd-overview-tools-grid"><div><strong>${number(savedConfigs)}</strong><span>Saved tool configurations</span></div><div><strong>${number(eventConnectors.length)}</strong><span>Registered event receivers</span></div><div><strong>${clarotyLive ? "Live" : "Pending"}</strong><span>Claroty xDome feed</span></div></div>`;
    }

    async function loadOverviewToolSummary() {
        const host = document.getElementById("xdOverviewTools");
        if (!host) return;
        if (overviewIntegrationData) { renderOverviewToolSummary(); return; }
        if (overviewIntegrationRequest) return overviewIntegrationRequest;
        overviewIntegrationRequest = (async () => {
            try {
                const response = await fetch("/api/zero-trust/integrations", { cache: "no-store" });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.error || "Tool inventory unavailable");
                overviewIntegrationData = payload;
                renderOverviewToolSummary();
            } catch (error) {
                if (host.isConnected) host.innerHTML = `<div class="xd-surface-head"><h3>Security Tool &amp; Connector Overview</h3></div><p role="alert">${text(error.message)}</p>`;
            } finally {
                overviewIntegrationRequest = null;
            }
        })();
        return overviewIntegrationRequest;
    }
    const badge = (label, value) => `<div class="xd-stat"><span>${label}</span><strong>${number(value)}</strong></div>`;
    const metricButton = (label, value, metric) => `<button type="button" class="xd-stat xd-stat-button" data-xd-home-metric="${metric}" aria-label="Show ${number(value)} ${label.toLowerCase()} in live device inventory" title="Open matching live devices"><span>${label}</span><strong>${number(value)}</strong></button>`;
    const source = feed => {
        const state = ClarotyAPI.feedState(feed);
        if (state.source === "live" && state.error) return `${number(state.data.length)} live records · partial · last page failed: ${text(state.error)}`;
        if (state.source === "error") return `Failed: ${text(state.error)}`;
        if (state.loading) return `${number(state.data.length)} loaded · Loading from Claroty xDome…`;
        if (state.source !== "live") return "Awaiting Claroty API";
        return `${number(state.data.length)} loaded${state.complete ? "" : " (partial, more pages available)"}`;
    };

    function filters() {
        const devices = cache.devices;
        const sites = [...new Set(devices.map(row => row.site_name).filter(Boolean))].sort();
        const field = document.getElementById("xdPortalSite");
        if (field) {
            field.innerHTML = `<option value="">All sites</option>${sites.map(site => `<option value="${text(site)}">${text(site)}</option>`).join("")}`;
            field.value = sites.includes(homeFilters.site) ? homeFilters.site : "";
        }
        const risk = document.getElementById("xdPortalRisk");
        if (risk) risk.value = homeFilters.risk;
    }

    function filteredDevices() {
        return uniqueDeviceRows(cache.devices).filter(row => (!homeFilters.site || row.site_name === homeFilters.site) && (!homeFilters.risk || deviceRisk(row) === homeFilters.risk));
    }

    function uniqueDeviceRows(rows) {
        const byUid = new Map();
        rows.forEach(row => {
            const uid = String(row.uid || "").trim();
            if (uid && !byUid.has(uid)) byUid.set(uid, row);
        });
        return [...byUid.values()];
    }

    function deviceIpv4Networks(row) {
        const source = Array.isArray(row.ip_list) ? row.ip_list : String(row.ip_list || "").split(/[,;\s]+/);
        const networks = new Set();
        source.forEach(value => {
            const match = String(value || "").trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d{1,2})?$/);
            if (!match) return;
            const octets = match.slice(1).map(Number);
            if (octets.some(octet => octet < 0 || octet > 255)) return;
            networks.add(`${octets[0]}.${octets[1]}.${octets[2]}.0/24`);
        });
        return [...networks];
    }

    function renderOverviewLive() {
        const host = document.getElementById("xdOverviewLive");
        if (!host) return;
        const deviceState = ClarotyAPI.feedState("devices");
        const alertState = ClarotyAPI.feedState("alerts");
        if (deviceState.source !== "live") {
            host.innerHTML = `<div class="xd-surface" role="status"><h3>Claroty xDome Inventory</h3><p>${text(source("devices"))}</p><p>Risk visualizations require live Claroty inventory and CVE data. No sample asset risk is substituted.</p><button type="button" class="xd-command" data-xd-refresh>Refresh live data</button></div><section id="xdOverviewTools" class="xd-surface xd-overview-tools"><div class="xd-surface-head"><div><h3>Security Tool &amp; Connector Overview</h3><p>Saved credentials and registered receivers are not proof of successful vendor connectivity.</p></div><button type="button" class="xd-link" data-xd-navigate="integrations">Manage integrations</button></div><p role="status">Loading tool readiness…</p></section>`;
            loadOverviewToolSummary();
            return;
        }

        const rows = deviceState.data;
        const allDevices = uniqueDeviceRows(rows);
        const retired = row => row.retired === true || String(row.retired).toLowerCase() === "true";
        const retiredCount = count(allDevices, retired);
        const retirementUnknown = count(allDevices, row => row.retired == null || row.retired === "");
        const matchesFilters = row => Object.entries(overviewFilters).every(([field, selected]) => {
            if (!selected) return true;
            if (field === "network") return deviceIpv4Networks(row).includes(selected);
            return String(row[field] ?? "").trim() === selected;
        });
        const activeDevices = allDevices.filter(row => !retired(row));
        const devices = activeDevices.filter(matchesFilters);
        const retiredDevices = allDevices.filter(row => retired(row) && matchesFilters(row));
        const filterControls = overviewFilterFields.map(([field, label]) => {
            const values = field === "network"
                ? activeDevices.flatMap(deviceIpv4Networks)
                : activeDevices.map(row => String(row[field] ?? "").trim());
            const options = [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
            return `<label data-filter-field="${field}" class="${overviewFilters[field] ? "is-filtered" : ""}" title="${field === "network" ? "Derived from each device's IPv4 address as a /24; not a native xDome network object." : "Filtered from the corresponding live xDome device field."}">${text(label)}<select data-xd-overview-filter="${field}" aria-label="${text(label)} filter"><option value="">All ${text(label.replace(" · IPv4 /24", "s"))}</option>${options.map(value => `<option value="${text(value)}" ${overviewFilters[field] === value ? "selected" : ""}>${text(value)}</option>`).join("")}</select></label>`;
        }).join("");
        const onlineCount = count(devices, online);
        const offlineCount = count(devices, row => onlineStatus(row) === "Offline");
        const unknownStatus = devices.length - onlineCount - offlineCount;
        const highRisk = count(devices, row => ["Critical", "High"].includes(deviceRisk(row)));
        const missingManufacturer = count(devices, row => !String(row.manufacturer || "").trim());
        const missingType = count(devices, row => !String(row.device_type || "").trim());
        const categoryCount = category => count(devices, row => String(row.device_category || "").trim().toUpperCase() === category.toUpperCase());
        const suspiciousCount = count(devices, row => Array.isArray(row.suspicious) ? row.suspicious.length > 0 : Boolean(row.suspicious) && String(row.suspicious).toLowerCase() !== "false");
        const manufacturerCounts = new Map();
        const typeCounts = new Map();
        devices.forEach(row => {
            const manufacturer = String(row.manufacturer || "").trim();
            const type = String(row.device_type || "").trim();
            if (manufacturer) manufacturerCounts.set(manufacturer, (manufacturerCounts.get(manufacturer) || 0) + 1);
            if (type) typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
        });
        const sorted = values => [...values.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
        const renderBars = (entries, max) => entries.slice(0, 10).map(([label, value]) => `<div class="xd-overview-bar"><span title="${text(label)}">${text(label)}</span><div><i style="width:${max ? Math.round(value / max * 100) : 0}%"></i></div><b>${number(value)}</b><small>${devices.length ? `${(value / devices.length * 100).toFixed(1)}%` : "0%"}</small></div>`).join("");

        const allAlerts = alertState.source === "live" ? cache.alerts : [];
        const cutoff = overviewRange === "all" ? null : Date.now() - Number(overviewRange) * 86400000;
        const filteredAlerts = allAlerts.filter(alert => {
            if (cutoff == null) return true;
            const detected = Date.parse(alert.detected_time);
            return Number.isFinite(detected) && detected >= cutoff && detected <= Date.now();
        });
        const missingAlertDates = cutoff == null ? 0 : allAlerts.filter(alert => !Number.isFinite(Date.parse(alert.detected_time))).length;
        const alertTypes = new Map();
        filteredAlerts.forEach(alert => {
            const label = String(alert.alert_type_name || alert.alert_name || "Unknown alert type");
            const summary = alertTypes.get(label) || { devices: 0, alerts: 0 };
            summary.devices += Number(alert.devices_count) || 0;
            summary.alerts += 1;
            alertTypes.set(label, summary);
        });
        const sortedAlertTypes = [...alertTypes.entries()].sort((a, b) => b[1].devices - a[1].devices || a[0].localeCompare(b[0]));
        const maxAlertDevices = Math.max(1, ...sortedAlertTypes.map(([, value]) => value.devices));
        const connected = onlineCount + offlineCount + unknownStatus === devices.length;
        const totalAlertsAffected = filteredAlerts.reduce((total, alert) => total + (Number(alert.devices_count) || 0), 0);
        const alertStatus = alertState.source === "live" ? `${number(allAlerts.length)} alerts ${alertState.complete ? "loaded" : "loaded so far"}` : text(source("alerts"));
        const vulnerabilityState = ClarotyAPI.feedState("vulnerabilities");
        const matchingCves = riskVulnerabilities(overviewCveRange);
        const cveMatrix = exposureMatrix(matchingCves.map(({ row }) => row));
        const mappedCves = cveMatrix.flat().reduce((sum, value) => sum + value, 0);
        const excludedCves = matchingCves.length - mappedCves;
        const cveRangeLabel = overviewCveRange === "all" ? "all published dates" : `published in the last ${overviewCveRange} days`;
        const renderInventoryMetric = ([label, value]) => {
            const percent = value == null || !devices.length ? null : Math.min(100, Math.max(0, value / devices.length * 100));
            const tone = label === "Online" || label === "Corporate" || label === "Industrial" ? "green"
                : label === "High Risk" ? "red"
                    : label === "Status unknown" || label === "New this week" ? "slate"
                        : label === "Suspicious" ? "amber" : label === "OT" || label === "IoT" ? "cyan" : "blue";
            return `<div class="xd-overview-stat tone-${tone}" title="${label === "New this week" ? "Not available: xDome does not expose a created/first-seen date." : "Count from the currently filtered Claroty asset set."}"><span>${text(label)}</span><b>${value == null ? "N/A" : number(value)}</b>${percent == null ? `<small>Not reported</small>` : `<div class="xd-overview-stat-track" role="meter" aria-valuenow="${percent.toFixed(1)}" aria-valuemin="0" aria-valuemax="100"><i style="width:${percent.toFixed(1)}%"></i></div>`}</div>`;
        };

        host.innerHTML = `<div class="xd-overview-head"><div><h2>Claroty xDome Live Overview</h2><p>${number(rows.length)} API rows · ${number(allDevices.length)} unique UIDs · ${number(activeDevices.length)} active · ${number(retiredCount)} retired · ${number(rows.length - allDevices.length)} duplicate rows removed · ${deviceState.complete ? "all device pages loaded" : "device feed is partial"} · Updated ${text(time(deviceState.fetchedAt))}</p></div><div class="xd-overview-controls"><div class="xd-risk-ranges" role="group" aria-label="Alert time range">${[["7", "7D"], ["30", "30D"], ["90", "90D"], ["all", "Full data"]].map(([value, label]) => `<button type="button" class="xd-risk-range" data-xd-overview-range="${value}" aria-pressed="${overviewRange === value}">${label}</button>`).join("")}</div><button type="button" class="xd-command" data-xd-refresh>Refresh live data</button></div></div>
            <div class="xd-overview-filterbar">${filterControls}<button type="button" class="xd-command" data-xd-overview-reset>Clear filters</button></div>
            <p class="xd-overview-note">Inventory stats use ${number(devices.length)} active assets of ${number(activeDevices.length)} currently loaded; ${number(retirementUnknown)} records lack retirement status. Retired assets are excluded from active counts. Alert range is independent. Network is derived from IPv4 /24 prefixes; xDome has no native network field. New-this-week is unavailable because no created/first-seen date is exposed.</p>
            <div class="xd-overview-grid">
                <section class="xd-surface"><div class="xd-surface-head"><h3>Inventory High Level Stats</h3><span>${connected ? "Connectivity reconciled" : "Connectivity mismatch"}</span></div><div class="xd-overview-total"><strong>${number(devices.length)}</strong><span>Active devices</span></div><div class="xd-overview-metrics">${[["Corporate", categoryCount("Corporate")], ["Guest", categoryCount("Guest")], ["Industrial", categoryCount("Industrial")], ["OT", categoryCount("OT")], ["IoT", categoryCount("IoT")], ["IT", categoryCount("IT")], ["Online", onlineCount], ["High Risk", highRisk], ["Suspicious", suspiciousCount], ["Retired", retiredDevices.length], ["New this week", null], ["Status unknown", unknownStatus]].map(renderInventoryMetric).join("")}</div><p>${number(missingManufacturer)} active assets have no manufacturer · ${number(missingType)} active assets have no device type. ${number(retirementUnknown)} records have unknown retirement status; category totals use xDome's reported device_category field.</p></section>
                <section class="xd-surface"><div class="xd-surface-head"><h3>Manufacturer Distribution (${number(manufacturerCounts.size)})</h3><button type="button" class="xd-link" data-xd-navigate="devices">View all assets</button></div><div class="xd-overview-bars">${renderBars(sorted(manufacturerCounts), sorted(manufacturerCounts)[0]?.[1] || 0) || `<p>No manufacturer values returned.</p>`}</div><p>Top 10 of ${number(manufacturerCounts.size)} named manufacturers · percentages use ${number(devices.length)} unique assets.</p></section>
                <section class="xd-surface"><div class="xd-surface-head"><h3>Affected Devices by Alert Type</h3><span>${text(alertStatus)}</span></div><div class="xd-overview-alert-total"><strong>${number(totalAlertsAffected)}</strong><span>Device-alert associations · ${number(filteredAlerts.length)} alerts · ${overviewRange === "all" ? "full loaded history" : `last ${overviewRange} days`}</span></div><div class="xd-overview-bars">${sortedAlertTypes.slice(0, 10).map(([label, value]) => `<div class="xd-overview-bar"><span title="${text(label)}">${text(label)}</span><div><i style="width:${Math.round(value.devices / maxAlertDevices * 100)}%"></i></div><b>${number(value.devices)}</b><small>${number(value.alerts)} alerts</small></div>`).join("") || `<p>${text(source("alerts"))}</p>`}</div><p>Counts sum xDome alert device totals; the same asset can occur in multiple alerts.${missingAlertDates ? ` ${number(missingAlertDates)} alerts excluded because detection time is missing.` : ""} ${alertState.source === "live" && !alertState.complete ? "Alert feed is partial." : ""}</p></section>
                <section class="xd-surface"><div class="xd-surface-head"><h3>Device Type Family Distribution (${number(typeCounts.size)})</h3><button type="button" class="xd-link" data-xd-navigate="devices">All assets</button></div><div class="xd-overview-bars">${renderBars(sorted(typeCounts), sorted(typeCounts)[0]?.[1] || 0) || `<p>No device types returned.</p>`}</div><p>Top 10 of ${number(typeCounts.size)} reported device types · ${number(missingType)} assets have no reported type.</p></section>
            </div>
            <section class="xd-surface xd-overview-heatmap"><div class="xd-surface-head"><div><h3>Effective Likelihood vs. Impact Heat Map</h3><p>Unique Claroty CVEs · likelihood = EPSS · impact = CVSS</p></div><div class="xd-risk-ranges" role="group" aria-label="CVE publication period">${[["7", "7D"], ["30", "30D"], ["90", "90D"], ["all", "Full data"]].map(([value, label]) => `<button type="button" class="xd-risk-range" data-xd-overview-cve-range="${value}" aria-pressed="${overviewCveRange === value}">${label}</button>`).join("")}</div></div><p>${number(matchingCves.length)} unique CVEs ${cveRangeLabel} from ${number(vulnerabilityState.data.length)} Claroty vulnerability records · ${vulnerabilityState.complete ? "feed complete" : "feed partial; counts cover loaded records only"} · ${number(excludedCves)} CVEs excluded (missing or invalid EPSS/CVSS scores). Advisory CVE lists are deduplicated; direct CVE records take precedence. This is derived from Claroty data, not the native xDome device-risk score.</p>${heatMap(cveMatrix)}</section>
            <div class="xd-overview-chart-grid"><section class="xd-surface"><div class="xd-surface-head"><h3>Active Asset Risk Distribution</h3><span>${number(devices.length)} filtered</span></div><div class="chart-box"><canvas id="xdOverviewRiskChart"></canvas></div></section><section class="xd-surface"><div class="xd-surface-head"><h3>Device Connectivity</h3><span>${number(unknownStatus)} unknown</span></div><div class="chart-box"><canvas id="xdOverviewConnectivityChart"></canvas></div></section><section class="xd-surface"><div class="xd-surface-head"><h3>Assets by Category</h3><span>Top 10 · live xDome categories</span></div><div class="chart-box"><canvas id="xdOverviewCategoryChart"></canvas></div></section><section class="xd-surface"><div class="xd-surface-head"><h3>Alert Activity</h3><span>${overviewRange === "all" ? "All loaded dates" : `Last ${overviewRange} days`}</span></div><div class="chart-box"><canvas id="xdOverviewAlertTrendChart"></canvas></div></section></div>
            <section id="xdOverviewTools" class="xd-surface xd-overview-tools"><div class="xd-surface-head"><div><h3>Security Tool &amp; Connector Overview</h3><p>Saved credentials and registered receivers are not proof of successful vendor connectivity.</p></div><button type="button" class="xd-link" data-xd-navigate="integrations">Manage integrations</button></div><p role="status">Loading tool readiness…</p></section>`;
        renderOverviewCharts(devices, filteredAlerts, overviewRange);
        loadOverviewToolSummary();
    }

    function renderHome() {
        const host = document.getElementById("xdHomeDashboard");
        if (!host) return;
        const devices = filteredDevices();
        const breakdown = [...RISK_LEVELS, "Unknown"];
        const loading = source("devices");
        const homeFeedCards = FEEDS.map(feed => {
            const state = ClarotyAPI.feedState(feed);
            const status = state.source === "live" ? state.complete ? "Complete" : "Partial · more pages"
                : state.source === "error" ? "Error · refresh to retry" : state.loading ? "Loading…" : state.source === "mock" ? "Simulated" : "Not loaded";
            const stateClass = state.source === "live" ? state.complete ? "complete" : "partial" : state.source === "error" ? "error" : state.loading ? "loading" : "pending";
            const route = { devices: "devices", alerts: "alertfeed", vulnerabilities: "threats", events: "network" }[feed];
            return `<button type="button" class="xd-feed-card ${stateClass}" data-xd-navigate="${route}" aria-label="Open ${text(LABELS[feed])}: ${number(state.data?.length)} loaded, ${text(status)}"><span class="xd-feed-card-heading"><span class="xd-feed-card-icon"><i data-lucide="${FEED_ICONS[feed]}" aria-hidden="true"></i></span><span class="xd-feed-card-status"><i></i>${text(status)}</span></span><strong>${number(state.data?.length)}</strong><span class="xd-feed-card-label">${text(LABELS[feed])}</span><small>${text(state.fetchedAt ? `Updated ${time(state.fetchedAt)}` : state.error || "Awaiting live data")}</small></button>`;
        }).join("");
        const alerts = cache.alerts;
        const cves = cache.vulnerabilities;
        const events = cache.events;
        const groupCounts = (rows, getLabel) => {
            const groups = new Map();
            rows.forEach(row => {
                const label = getLabel(row);
                groups.set(label, (groups.get(label) || 0) + 1);
            });
            return [...groups.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])).slice(0, 4);
        };
        const alertGroups = groupCounts(alerts, row => String(row.alert_type_name || row.alert_name || row.category || "Unknown alert type"));
        const cveGroups = groupCounts(cves, row => {
            const severity = String(row.adjusted_vulnerability_score_level || "").trim();
            if (severity) return severity;
            const cvss = Number(row.cvss_v3_score);
            return !Number.isFinite(cvss) ? "Unknown" : cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : "Low";
        });
        const eventGroups = groupCounts(events, row => String(row.event_type || "Unknown event type"));
        const alertUnresolved = count(alerts, row => /open|unresolved|active|investigating/i.test(String(row.status || "")));
        const cveRiskColor = label => ({ Critical: "var(--red)", High: "var(--orange)", Medium: "var(--amber)", Low: "var(--green)", Unknown: "var(--muted)" }[label] || "var(--accent)");
        const visualBars = (groups, destination, colorFor) => {
            const maximum = Math.max(1, ...groups.map(([, value]) => value));
            return groups.map(([label, value], index) => `<button type="button" class="xd-home-visual-row" data-xd-navigate="${destination}" title="Open ${destination === "alertfeed" ? "live alerts" : destination === "threats" ? "the CVE backlog" : "live Network Activity"}"><span title="${text(label)}">${text(label)}</span><span class="xd-home-visual-track"><i style="width:${Math.max(2, Math.round(value / maximum * 100))}%;--home-bar-color:${colorFor(label, index)}"></i></span><strong>${number(value)}</strong></button>`).join("") || `<p>No loaded records in this feed.</p>`;
        };
        host.innerHTML = `<div class="xd-head"><div><h2>xDome Home</h2><span>${loading} · ${lastRefresh ? `Updated ${time(lastRefresh)}` : "Not yet refreshed"}</span></div><button type="button" class="xd-command" data-xd-refresh>Refresh live feeds</button></div>
            <div class="xd-filters"><select id="xdPortalSite" aria-label="Site filter"><option value="">All sites</option></select><select id="xdPortalRisk" aria-label="Risk filter"><option value="">All risks</option>${breakdown.map(item => `<option>${item}</option>`).join("")}</select><button type="button" class="xd-command" data-xd-navigate="devices">View devices</button><button type="button" class="xd-command" data-xd-navigate="riskmanagement">Risk &amp; Exposures</button></div>
            <div class="xd-stats">${metricButton("Devices loaded", devices.length, "all")}${metricButton("Online", count(devices, online), "online")}${metricButton("Offline", count(devices, row => onlineStatus(row) === "Offline"), "offline")}${metricButton("Status unknown", count(devices, row => onlineStatus(row) === "Unknown"), "unknown")}${metricButton("Critical risk", count(devices, row => deviceRisk(row) === "Critical"), "critical")}${metricButton("High risk", count(devices, row => deviceRisk(row) === "High"), "high")}</div>
            <div class="xd-columns"><div class="xd-surface"><div class="xd-surface-head"><h3>Risk distribution · loaded devices</h3><button type="button" class="xd-link" data-xd-navigate="riskmanagement">Risk overview</button></div><div class="xd-bars">${breakdown.map(item => `<div style="--risk-color:${riskColor[item]}"><span>${item}</span><meter min="0" max="${Math.max(1, devices.length)}" value="${count(devices, row => deviceRisk(row) === item)}"></meter><b>${number(count(devices, row => deviceRisk(row) === item))}</b></div>`).join("")}</div></div>
            <section class="xd-surface xd-home-feed-surface"><div class="xd-surface-head"><h3>Live xDome feeds</h3><button type="button" class="xd-link" data-xd-refresh>Refresh feeds</button></div><div class="xd-feed-card-grid">${homeFeedCards}</div></section></div>
            <div class="xd-surface"><div class="xd-surface-head"><h3>Highest-risk devices · loaded inventory</h3><button type="button" class="xd-link" data-xd-navigate="devices">All devices</button></div><div class="table-wrap"><table><thead><tr><th>Device</th><th>Site</th><th>Type</th><th>Risk</th><th>State</th></tr></thead><tbody>${devices.filter(row => ["Critical", "High"].includes(deviceRisk(row))).sort((a, b) => (deviceRisk(a) === "Critical" ? 0 : 1) - (deviceRisk(b) === "Critical" ? 0 : 1)).slice(0, 8).map(row => `<tr><td>${text(row.device_name || row.uid)}</td><td>${text(row.site_name)}</td><td>${text(row.device_type)}</td><td><span class="xd-risk-label" style="--risk-color:${riskColor[deviceRisk(row)]}">${text(deviceRisk(row))}</span></td><td>${onlineStatus(row)}</td></tr>`).join("") || `<tr><td colspan="5">No high-risk devices on the loaded page.</td></tr>`}</tbody></table></div></div>
            <div class="xd-surface"><div class="xd-surface-head"><h3>Risk &amp; Exposures</h3><button type="button" class="xd-link" data-xd-navigate="riskmanagement">Risk overview</button></div><div class="xd-stats xd-preview-stats">${badge("Critical / high devices", count(devices, row => ["Critical", "High"].includes(deviceRisk(row))))}${badge("Known-exploited CVEs", count(cache.vulnerabilities, isKnownExploited))}</div><p>Device-risk and exploited-CVE totals are from the loaded Claroty feed. The detailed CVE heat map is below.</p></div>
            <div class="xd-surface"><div class="xd-surface-head"><h3>Alerts &amp; Threats</h3><button type="button" class="xd-link" data-xd-navigate="alertfeed">All alerts</button></div><div class="xd-home-visual-total"><strong>${number(alerts.length)}</strong><span>${text(source("alerts"))} · ${number(alertUnresolved)} unresolved</span></div><div class="xd-home-visual-bars">${visualBars(alertGroups, "alertfeed", () => "var(--red)")}</div></div>
            <div class="xd-surface"><div class="xd-surface-head"><h3>Vulnerabilities &amp; CVEs</h3><button type="button" class="xd-link" data-xd-navigate="threats">CVE backlog</button></div><div class="xd-home-visual-total"><strong>${number(cves.length)}</strong><span>${text(source("vulnerabilities"))} · ${number(count(cves, isKnownExploited))} known exploited</span></div><div class="xd-home-visual-bars">${visualBars(cveGroups, "threats", cveRiskColor)}</div></div>
            <div class="xd-surface"><div class="xd-surface-head"><h3>Network &amp; OT Activity</h3><button type="button" class="xd-link" data-xd-navigate="network">All events</button></div><div class="xd-home-visual-total"><strong>${number(events.length)}</strong><span>${text(source("events"))} · loaded event types</span></div><div class="xd-home-visual-bars">${visualBars(eventGroups, "network", (_label, index) => ["var(--cyan)", "var(--accent)", "var(--green)", "var(--amber)"][index % 4])}</div></div>
            <div class="xd-surface xd-home-actions"><div class="xd-surface-head"><h3>Workspace &amp; integrations</h3></div><button type="button" class="xd-command" data-xd-navigate="integrations">Claroty API settings</button><button type="button" class="xd-command" data-xd-navigate="profile">Monitoring &amp; exports</button><button type="button" class="xd-command" data-xd-navigate="intel">Threat intelligence</button></div>`;
        filters();
        renderOverviewLive();
        renderOverviewAiWidget();
        renderOverviewCoverageWidget();
        renderOperationsLive();
        window.renderCustomOverviewWidgets?.();
        if (document.getElementById("zerotrust")?.classList.contains("active")) window.ZeroTrustView?.render();
        window.lucide?.createIcons({ root: host });
    }

    function analyzeLoadedData() {
        const states = Object.fromEntries(FEEDS.map(feed => [feed, ClarotyAPI.feedState(feed)]));
        const devices = states.devices.data || [];
        const alerts = states.alerts.data || [];
        const vulnerabilities = states.vulnerabilities.data || [];
        const live = FEEDS.some(feed => states[feed].source === "live");
        const liveDevices = states.devices.source === "live" ? uniqueDeviceRows(devices) : null;
        const metrics = {
            devices: liveDevices?.length ?? null,
            criticalDevices: liveDevices ? count(liveDevices, row => deviceRisk(row) === "Critical") : null,
            highDevices: liveDevices ? count(liveDevices, row => deviceRisk(row) === "High") : null,
            highRiskDevices: liveDevices ? count(liveDevices, row => ["Critical", "High"].includes(deviceRisk(row))) : null,
            onlineDevices: liveDevices ? count(liveDevices, online) : null,
            offlineDevices: liveDevices ? count(liveDevices, row => onlineStatus(row) === "Offline") : null,
            unknownDeviceStatus: liveDevices ? count(liveDevices, row => onlineStatus(row) === "Unknown") : null,
            alerts: states.alerts.source === "live" ? alerts.length : null,
            unresolvedAlerts: states.alerts.source === "live" ? count(alerts, row => /open|unresolved|active|investigating/i.test(String(row.status || ""))) : null,
            vulnerabilityRecords: states.vulnerabilities.source === "live" ? vulnerabilities.length : null,
            knownExploited: states.vulnerabilities.source === "live" ? count(vulnerabilities, isKnownExploited) : null,
            networkEvents: (states.events.data || []).length
        };
        const feedCount = (feed, value) => states[feed].source === "live" ? number(value) : states[feed].source === "error" ? "unavailable" : "not loaded";
        const coverage = FEEDS.map(feed => {
            const state = states[feed];
            const label = LABELS[feed];
            if (state.source === "live") return `${label}: ${number(state.data.length)} loaded · ${state.complete ? "complete" : "partial"}`;
            if (state.source === "error") return `${label}: unavailable · ${state.error || "feed error"}`;
            if (state.source === "mock") return `${label}: simulated · not live`;
            return `${label}: not loaded`;
        });
        const summary = live
            ? [
                `Loaded xDome evidence: ${feedCount("devices", metrics.devices)} unique device records, ${feedCount("alerts", metrics.alerts)} alerts, ${feedCount("vulnerabilities", metrics.vulnerabilityRecords)} vulnerability records, and ${feedCount("events", states.events.data?.length || 0)} network events.`,
                metrics.criticalDevices == null ? "Device risk is not available until the device feed loads." : `${number(metrics.criticalDevices)} critical-risk devices (${number(metrics.highRiskDevices)} high or critical) in the unique loaded inventory.`,
                metrics.unresolvedAlerts == null ? "Unresolved alert count is not available until the alert feed loads." : `${number(metrics.unresolvedAlerts)} unresolved alerts in the loaded records.`,
                metrics.knownExploited == null ? "Known-exploited vulnerability count is not available until the vulnerability feed loads." : `${number(metrics.knownExploited)} known-exploited vulnerability records.`,
                `Coverage: ${coverage.join("; ")}.`,
                "Rule-based analysis of loaded xDome data only; this is not generative AI."
            ].join("\n")
            : "No live xDome feed is loaded. Configure Claroty and refresh live feeds before generating a data-backed draft.";
        return { hasLiveData: live, metrics, coverage, summary };
    }

    function renderOverviewAiWidget() {
        const host = document.getElementById("xdOverviewAiWidget");
        if (!host) return;
        const analysis = analyzeLoadedData();
        const metrics = analysis.metrics;
        const metricTile = (label, value, note, tone, ratio, total) => {
            const available = value != null;
            const percent = available && total > 0 ? Math.min(100, Math.max(0, value / total * 100)) : 0;
            return `<div class="xd-live-metric tone-${tone}"><span>${text(label)}</span><strong>${available ? number(value) : "Not loaded"}</strong><small>${text(note)}</small><div class="xd-live-meter" aria-hidden="true"><i style="width:${percent.toFixed(1)}%"></i></div></div>`;
        };
        const tiles = [
            metricTile("Devices loaded", metrics.devices, "Unique live assets", "blue", metrics.devices, metrics.devices),
            metricTile("Online", metrics.onlineDevices, "Connected assets", "green", metrics.onlineDevices, metrics.devices),
            metricTile("Offline", metrics.offlineDevices, "Offline assets", "orange", metrics.offlineDevices, metrics.devices),
            metricTile("Status unknown", metrics.unknownDeviceStatus, "Connectivity not reported", "slate", metrics.unknownDeviceStatus, metrics.devices),
            metricTile("Critical risk", metrics.criticalDevices, "Critical assets", "red", metrics.criticalDevices, metrics.devices),
            metricTile("High risk", metrics.highDevices, "High-risk assets", "amber", metrics.highDevices, metrics.devices),
            metricTile("Unresolved alerts", metrics.unresolvedAlerts, `${metrics.alerts == null ? "Alerts not loaded" : `${number(metrics.alerts)} total loaded`}`, "cyan", metrics.unresolvedAlerts, metrics.alerts),
            metricTile("Known exploited CVEs", metrics.knownExploited, `${metrics.vulnerabilityRecords == null ? "CVEs not loaded" : `${number(metrics.vulnerabilityRecords)} records loaded`}`, "magenta", metrics.knownExploited, metrics.vulnerabilityRecords)
        ].join("");
        const feedStatuses = FEEDS.map(feed => {
            const state = ClarotyAPI.feedState(feed);
            const status = state.source === "live" ? state.complete ? "Live · complete" : "Live · partial"
                : state.source === "error" ? "Error" : state.source === "mock" ? "Simulated" : "Not loaded";
            const stateClass = state.source === "live" ? state.complete ? "complete" : "partial" : state.source === "error" ? "error" : "pending";
            return `<div class="xd-live-feed-status ${stateClass}"><span></span><strong>${text(LABELS[feed])}</strong><small>${number(state.data?.length)} · ${status}</small></div>`;
        }).join("");
        host.innerHTML = `<section class="xd-surface xd-live-analysis"><div class="xd-surface-head"><div><h3>Live xDome analysis</h3><p>Counts reflect currently loaded xDome data; partial feeds are labeled. Rule-based analysis, not generative AI.</p></div><button type="button" class="xd-command" data-xd-open-ai-draft>Create xDome draft</button></div><div class="xd-live-metric-grid">${tiles}</div><div class="xd-live-feed-strip" aria-label="Live xDome feed coverage">${feedStatuses}</div></section>`;
    }

    function renderOverviewCoverageWidget() {
        const host = document.getElementById("xdOverviewCoverageWidget");
        if (!host) return;
        const routes = { devices: "devices", alerts: "alertfeed", vulnerabilities: "threats", events: "network" };
        const cards = FEEDS.map(feed => {
            const state = ClarotyAPI.feedState(feed);
            const status = state.source === "live"
                ? state.complete ? "Live · complete" : state.error ? `Live · partial · ${state.error}` : "Live · partial"
                : state.source === "error" ? `Error · ${state.error || "refresh to retry"}`
                    : state.source === "mock" ? "Simulated · not live" : "Not loaded";
            const stateClass = state.source === "live" ? state.complete ? "complete" : "partial" : state.source === "error" ? "error" : "pending";
            return `<button type="button" class="xd-feed-card ${stateClass}" data-xd-navigate="${routes[feed]}" aria-label="Open ${text(LABELS[feed])}: ${number(state.data?.length)} loaded, ${text(status)}"><span class="xd-feed-card-heading"><span class="xd-feed-card-icon"><i data-lucide="${FEED_ICONS[feed]}" aria-hidden="true"></i></span><span class="xd-feed-card-status"><i></i>${text(status.replace("Live · ", ""))}</span></span><strong>${number(state.data?.length)}</strong><span class="xd-feed-card-label">${text(LABELS[feed])}</span><small>${text(state.fetchedAt ? `Updated ${time(state.fetchedAt)}` : state.error || "Awaiting live data")}</small></button>`;
        }).join("");
        host.innerHTML = `<section class="xd-surface xd-feed-coverage"><div class="xd-surface-head"><div><h3>Live xDome feeds</h3><p>Loaded records and provider coverage</p></div><button type="button" class="xd-command" data-xd-refresh>Refresh live feeds</button></div><div class="xd-feed-card-grid">${cards}</div></section>`;
        window.lucide?.createIcons({ root: host });
    }

    function renderOperationsLive() {
        const host = document.getElementById("xdOperationsDashboard");
        if (!host) return;
        const states = ["devices", "alerts", "vulnerabilities", "events"].map(feed => [feed, ClarotyAPI.feedState(feed)]);
        if (!states.some(([, state]) => state.source === "live")) {
            host.innerHTML = `<div class="xd-surface" role="status"><h2>OT Operations · Claroty xDome</h2><p>${text(source("devices"))}</p><button type="button" class="xd-command" data-xd-refresh>Refresh live data</button></div>`;
            return;
        }
        const devices = uniqueDeviceRows(cache.devices);
        const cutoff = operationsRange === "all" ? null : Date.now() - Number(operationsRange) * 86400000;
        const inRange = value => {
            if (cutoff == null) return true;
            const timestamp = Date.parse(value);
            return Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= Date.now();
        };
        const alerts = [...new Map(cache.alerts.map(row => [String(row.id ?? `${row.alert_name}-${row.detected_time}`), row])).values()].filter(row => inRange(row.detected_time));
        const events = cache.events.filter(row => inRange(row.timestamp));
        const unresolvedAlert = row => /open|unresolved|active|investigating/i.test(String(row.status || ""));
        const unresolved = count(alerts, unresolvedAlert);
        const resolved = count(alerts, row => /resolved|closed|mitigated/i.test(String(row.status || "")));
        const onlineCount = count(devices, online);
        const offlineCount = count(devices, row => onlineStatus(row) === "Offline");
        const highRisk = count(devices, row => ["Critical", "High"].includes(deviceRisk(row)));
        const criticalRisk = count(devices, row => deviceRisk(row) === "Critical");
        const associations = alerts.reduce((sum, row) => sum + (Number(row.devices_count) || 0), 0);
        const typeCounts = new Map();
        alerts.forEach(row => {
            const type = String(row.alert_type_name || row.alert_name || "Unknown alert type");
            const item = typeCounts.get(type) || { total: 0, unresolved: 0 };
            item.total += 1;
            item.unresolved += unresolvedAlert(row) ? 1 : 0;
            typeCounts.set(type, item);
        });
        const topTypes = [...typeCounts.entries()].sort((a, b) => b[1].unresolved - a[1].unresolved || b[1].total - a[1].total).slice(0, 10);
        const maxUnresolved = Math.max(1, ...topTypes.map(([, value]) => value.unresolved));
        const latestTime = states.map(([, state]) => state.fetchedAt).filter(Boolean).sort().at(-1);
        const status = state => state.source === "live" ? `${number(state.data.length)} ${state.complete ? "loaded" : "loaded · partial"}${state.error ? ` · last page failed: ${text(state.error)}` : ""}` : state.source === "error" ? `Failed · ${text(state.error || "request failed")}` : state.loading ? "Loading first page…" : "Awaiting live data";
        const latestAlerts = alerts.slice().sort((a, b) => Date.parse(b.detected_time || 0) - Date.parse(a.detected_time || 0)).slice(0, 20);
        const latestEvents = events.slice().sort((a, b) => Date.parse(b.timestamp || 0) - Date.parse(a.timestamp || 0)).slice(0, 12);
        const operationMetric = (id, label, value) => `<button type="button" class="xd-stat xd-stat-button" data-xd-operations-metric="${id}" aria-label="Show ${number(value)} ${text(label.toLowerCase())} from live xDome data"><span>${text(label)}</span><strong>${number(value)}</strong></button>`;
        host.innerHTML = `<div class="xd-operations-head"><div><h2>OT Operations · Claroty xDome</h2><p>Live xDome feeds · Last response ${text(time(latestTime))}</p></div><div class="xd-overview-controls"><div class="xd-risk-ranges" role="group" aria-label="Operations time range">${[["7", "7D"], ["30", "30D"], ["90", "90D"], ["all", "Full data"]].map(([value, label]) => `<button type="button" class="xd-risk-range" data-xd-operations-range="${value}" aria-pressed="${operationsRange === value}">${label}</button>`).join("")}</div><button type="button" class="xd-command" data-xd-refresh>Refresh live data</button></div></div>
            <p class="xd-overview-note">The time range filters Claroty alerts and events. Device counts use all assets currently loaded. Alert device counts are associations and may overlap. Analyst assignments, false-positive dispositions, and incident resolution durations are not provided by these feeds.</p>
            <div class="xd-stats xd-operations-stats">${operationMetric("assets", "Unique assets", devices.length)}${operationMetric("online", "Online", onlineCount)}${operationMetric("offline", "Offline", offlineCount)}${operationMetric("high-risk", "Critical / high-risk devices", highRisk)}${operationMetric("alerts", "Alerts in range", alerts.length)}${operationMetric("unresolved", "Unresolved alerts", unresolved)}${operationMetric("associations", "Affected-device associations", associations)}${operationMetric("events", "Events in range", events.length)}</div>
            <div class="xd-operations-grid"><section class="xd-surface"><div class="xd-surface-head"><h3>Live feed status</h3><button type="button" class="xd-link" data-xd-navigate="devices">Open inventory</button></div>${states.map(([feed, state]) => `<div class="xd-feed-state"><b>${LABELS[feed]}</b><span>${status(state)}</span></div>`).join("")}<p>${number(criticalRisk)} critical-risk assets · ${number(resolved)} alerts report resolved/closed. This is not incident MTTR.</p></section>
            <section class="xd-surface"><div class="xd-surface-head"><h3>Unresolved alerts by type</h3><button type="button" class="xd-link" data-xd-navigate="alertfeed">Open live alerts</button></div><div class="xd-overview-bars">${topTypes.map(([type, value]) => `<button type="button" class="xd-overview-bar xd-ops-alert-type" data-xd-operations-alert-type="${text(type)}" aria-label="Show ${number(value.unresolved)} unresolved ${text(type)} alerts"><span title="${text(type)}">${text(type)}</span><div><i style="width:${Math.round(value.unresolved / maxUnresolved * 100)}%"></i></div><b>${number(value.unresolved)} open</b><small>${number(value.total)} total</small></button>`).join("") || `<p>${text(status(ClarotyAPI.feedState("alerts")))}</p>`}</div><p>Open/unresolved counts use xDome alert status; no SOC incident status is inferred.</p></section></div>
            <section class="xd-surface"><div class="xd-surface-head"><h3>Latest Claroty alerts</h3><span>${number(alerts.length)} in range</span></div><div class="table-wrap"><table><thead><tr><th>Detected</th><th>Alert type</th><th>Status</th><th>Device / host</th><th>Devices</th><th>Updated</th></tr></thead><tbody>${latestAlerts.map(row => `<tr><td>${text(time(row.detected_time))}</td><td><button type="button" class="xd-link" data-xd-ops-alert="${text(row.id)}">${text(row.alert_type_name || row.alert_name || "Unknown alert")}</button></td><td>${text(row.status || "Unknown")}</td><td>${text(alertDeviceLabel(row))}</td><td>${number(row.devices_count)}</td><td>${text(time(row.updated_time))}</td></tr>`).join("") || `<tr><td colspan="6">${text(status(ClarotyAPI.feedState("alerts")))}</td></tr>`}</tbody></table></div></section>
                        <section class="xd-surface"><div class="xd-surface-head"><h3>Latest Claroty alerts</h3><span>${number(alerts.length)} in range</span><button type="button" class="xd-link" data-xd-operations-metric="alerts">View all alerts</button></div><div class="table-wrap"><table><thead><tr><th>Detected</th><th>Alert type</th><th>Status</th><th>Device / host</th><th>Devices</th><th>Updated</th></tr></thead><tbody>${latestAlerts.map(row => `<tr><td>${text(time(row.detected_time))}</td><td><button type="button" class="xd-link" data-xd-ops-alert="${text(row.id)}">${text(row.alert_type_name || row.alert_name || "Unknown alert")}</button></td><td>${text(row.status || "Unknown")}</td><td>${text(alertDeviceLabel(row))}</td><td>${number(row.devices_count)}</td><td>${text(time(row.updated_time))}</td></tr>`).join("") || `<tr><td colspan="6">${text(status(ClarotyAPI.feedState("alerts")))}</td></tr>`}</tbody></table></div></section>
            <section class="xd-surface"><div class="xd-surface-head"><h3>Recent OT/network events</h3><button type="button" class="xd-link" data-xd-navigate="network">Open Network Activity</button></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Source</th><th>Destination</th><th>Protocol</th></tr></thead><tbody>${latestEvents.map(row => `<tr><td>${text(time(row.timestamp))}</td><td><button type="button" class="xd-link" data-xd-ops-event="${cache.events.indexOf(row)}">${text(row.event_type || "Network event")}</button></td><td>${text(row.side_a_name || row.side_a_ip || "—")}</td><td>${text(row.side_b_name || row.side_b_ip || "—")}</td><td>${text(row.protocol || "—")}</td></tr>`).join("") || `<tr><td colspan="5">${text(status(ClarotyAPI.feedState("events")))}</td></tr>`}</tbody></table></div><p>Showing currently loaded events${ClarotyAPI.feedState("events").complete ? "." : "; more pages are available in Network Activity."}</p></section>`;
    }

    function scheduleOperationsRender() {
        if (!document.getElementById("operations")?.classList.contains("active") || operationsRenderTimer != null) return;
        operationsRenderTimer = setTimeout(() => {
            operationsRenderTimer = null;
            renderOperationsLive();
            if (document.getElementById("drawer")?.dataset.operationsDrill === "true" && operationsDrillState) {
                const currentPage = operationsDrillState.page;
                const metric = operationsDrillState.metric;
                openOperationsMetric(metric);
                operationsDrillState.page = Math.min(currentPage, Math.max(0, Math.ceil(operationsDrillState.rows.length / operationsDrillPageSize) - 1));
                renderOperationsDrillPage();
            }
        }, 250);
    }

    function renderRisk() {
        const host = document.getElementById("xdRiskDashboard");
        if (!host) return;
        const devices = filteredDevices();
        const breakdown = [...RISK_LEVELS, "Unknown"];
        const matches = riskVulnerabilities();
        const vulns = matches.map(({ row }) => row);
        riskPage = Math.min(riskPage, Math.max(0, Math.ceil(matches.length / riskPageSize) - 1));
        const pageMatches = matches.slice(riskPage * riskPageSize, (riskPage + 1) * riskPageSize);
        host.innerHTML = `<div class="xd-head"><div><h2>Risk &amp; Exposures</h2><span>${source("devices")} · CVEs: ${source("vulnerabilities")}</span></div><button type="button" class="xd-command" data-xd-refresh>Refresh</button></div>
            <div class="xd-stats">${badge("Devices loaded", devices.length)}${badge("Critical & high risk", count(devices, row => ["Critical", "High"].includes(deviceRisk(row))))}${badge("Known exploited CVEs", count(vulns, isKnownExploited))}${badge("Affected devices (CVE sum)", vulns.reduce((total, row) => total + (Number(row.affected_devices_count) || 0), 0))}</div>
            <div class="xd-surface"><h3>xDome device risk categories</h3><div class="xd-bars">${breakdown.map(item => `<div><span>${item}</span><meter min="0" max="${Math.max(1, devices.length)}" value="${count(devices, row => deviceRisk(row) === item)}"></meter><b>${number(count(devices, row => deviceRisk(row) === item))}</b></div>`).join("")}</div><p>The Effective Likelihood vs. Impact CVE heat map and publication-date filters are on Overview.</p></div>
            <div class="xd-surface"><h3>Vulnerability catalog · ${number(vulns.length)} matching CVEs</h3><div class="table-wrap"><table><thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Exploited</th><th>Affected devices</th><th>Priority</th></tr></thead><tbody>${pageMatches.map(({ row, index }) => `<tr><td><button type="button" class="xd-link" data-xd-vuln="${index}">${text(Array.isArray(row.cve_ids) ? row.cve_ids.join(", ") : row.cve_ids || row.name)}</button></td><td>${text(row.cvss_v3_score)}</td><td>${text(row.epss_score)}</td><td>${row.is_known_exploited ? "Yes" : "No"}</td><td>${number(row.affected_devices_count)}</td><td>${text(row.adjusted_vulnerability_score_level)}</td></tr>`).join("") || `<tr><td colspan="6">${source("vulnerabilities")}</td></tr>`}</tbody></table></div><div class="xd-risk-pages"><button type="button" data-xd-risk-page="prev" aria-label="Previous CVE page" ${riskPage === 0 ? "disabled" : ""}>Previous</button><span>${matches.length ? number(riskPage * riskPageSize + 1) : 0}–${number(Math.min((riskPage + 1) * riskPageSize, matches.length))} of ${number(matches.length)}${ClarotyAPI.feedState("vulnerabilities").complete ? "" : " loaded (partial)"}</span><button type="button" data-xd-risk-page="next" aria-label="Next CVE page" ${riskPage * riskPageSize + riskPageSize >= matches.length ? "disabled" : ""}>Next</button></div></div>`;
    }

    function renderAlerts() {
        const host = document.getElementById("xdAlertsDashboard");
        if (!host) return;
        const alerts = cache.alerts;
        host.innerHTML = `<div class="xd-head"><div><h2>Alerts &amp; Threats</h2><span>${source("alerts")}</span></div><button type="button" class="xd-command" data-xd-refresh>Refresh alerts</button></div>
            <div class="xd-stats">${badge("Alerts loaded", alerts.length)}${badge("Affected devices", alerts.reduce((sum, row) => sum + (Number(row.devices_count) || 0), 0))}${badge("Unresolved devices", alerts.reduce((sum, row) => sum + (Number(row.unresolved_devices_count) || 0), 0))}</div>
            <div class="xd-filters"><input id="xdAlertSearch" type="search" placeholder="Search alerts, categories or MITRE" aria-label="Search live alerts"><select id="xdAlertStatus" aria-label="Alert status"><option value="">All statuses</option>${[...new Set(alerts.map(row => row.status).filter(Boolean))].sort().map(value => `<option>${text(value)}</option>`).join("")}</select></div>
            <div class="xd-surface"><div class="table-wrap"><table><thead><tr><th>Alert</th><th>Type</th><th>Category</th><th>Status</th><th>Device / host</th><th>Devices</th><th>Detected</th></tr></thead><tbody id="xdAlertRows"></tbody></table></div><div class="xd-risk-pages"><button type="button" data-xd-feed-page="alerts:prev" aria-label="Previous alerts">Previous</button><span id="xdAlertPageStatus"></span><button type="button" data-xd-feed-page="alerts:next" aria-label="Next alerts">Next</button></div></div>`;
        filterAlerts();
    }

    function alertRelatedDevices(alert) {
        const alertId = String(alert?.id ?? "");
        const relatedEvents = ClarotyAPI.feedState("events").data.filter(event => String(event.alert_id ?? "") === alertId);
        const hostnamePattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
        const embeddedHostnames = `${alert?.alert_name || ""} ${alert?.description || ""}`.match(hostnamePattern) || [];
        const directNames = [alert?.device_name, alert?.deviceName, alert?.host_name, alert?.hostname, ...embeddedHostnames];
        const eventNames = relatedEvents.flatMap(event => [event.side_a_name || event.side_a_ip, event.side_b_name || event.side_b_ip]);
        return [...new Set([...directNames, ...eventNames].map(value => String(value || "").trim()).filter(value => value && value !== "—"))];
    }

    function alertDeviceLabel(alert) {
        const devices = alertRelatedDevices(alert);
        if (devices.length) return devices.slice(0, 4).join(", ");
        const state = ClarotyAPI.feedState("events");
        if (state.source !== "live" && state.data.length === 0) return state.error ? `Network events failed: ${state.error}` : "Network events unavailable";
        return state.complete ? "No linked device in loaded events" : `Not found in ${number(state.data.length)} loaded events yet`;
    }

    function renderAlertEvidence(alert) {
        const alertId = String(alert.id ?? "");
        const eventState = ClarotyAPI.feedState("events");
        const linkedEvents = cache.events.filter(event => String(event.alert_id ?? "") === alertId);
        const hosts = alertRelatedDevices(alert);
        const hostKeys = new Set(hosts.map(value => value.toLowerCase()));
        const devices = cache.devices.filter(device => {
            const values = [device.device_name, device.uid, ...(Array.isArray(device.ip_list) ? device.ip_list : String(device.ip_list || "").split(/[,;\s]+/))];
            return values.some(value => hostKeys.has(String(value || "").trim().toLowerCase()));
        });
        const addresses = [...new Set([
            ...linkedEvents.flatMap(event => [event.side_a_ip, event.side_b_ip]),
            ...devices.flatMap(device => Array.isArray(device.ip_list) ? device.ip_list : String(device.ip_list || "").split(/[,;\s]+/))
        ].map(value => String(value || "").trim()).filter(Boolean))];
        const evidenceText = [alert.alert_name, alert.description, JSON.stringify(alert.malicious_ip_tags_list || ""), ...linkedEvents.flatMap(event => [event.description, event.malicious_ip_type, JSON.stringify(event.malicious_ip_tags_list || "")])].join(" ");
        const iocs = new Map();
        const collect = (type, expression) => {
            for (const match of evidenceText.matchAll(expression)) iocs.set(`${type}:${match[0].toLowerCase()}`, { type, value: match[0] });
        };
        collect("CVE", /\bCVE-\d{4}-\d{4,}\b/gi);
        collect("URL", /\bhttps?:\/\/[^\s<>"']+/gi);
        collect("IP", /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g);
        collect("Hash", /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi);
        const hostnamePattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
        for (const host of evidenceText.match(hostnamePattern) || []) iocs.set(`Domain:${host.toLowerCase()}`, { type: "Domain", value: host });
        const eventStatus = eventState.source === "live"
            ? eventState.complete ? "Event feed complete" : `${number(eventState.data.length)} events loaded; more pages may contain matches${eventState.error ? ` · last page failed: ${text(eventState.error)}` : ""}`
            : eventState.loading ? "Event feed is still loading" : eventState.source === "error" ? `Event feed failed: ${eventState.error || "request error"}` : "Event feed not loaded";
        const rawFields = Object.entries(alert).filter(([, value]) => value != null && value !== "").map(([key, value]) => `<div><b>${text(key.replaceAll("_", " "))}</b><span>${text(Array.isArray(value) ? value.map(item => typeof item === "object" ? JSON.stringify(item) : item).join(", ") : typeof value === "object" ? JSON.stringify(value) : value)}</span></div>`).join("");
        const eventRows = linkedEvents.slice(0, 100).map(event => {
            const vector = [event.direction ? `direction ${event.direction}` : "", event.comm_type ? `communication ${event.comm_type}` : "", event.selected_port ? `port ${event.selected_port}` : "", event.login_username ? `user ${event.login_username}` : "", event.side_a_purdue_level || event.side_b_purdue_level ? `Purdue ${event.side_a_purdue_level || "?"} → ${event.side_b_purdue_level || "?"}` : ""].filter(Boolean).join(" · ");
            const iocDetails = [event.malicious_ip_type, event.malicious_ip_severity, event.malicious_ip_confidence == null ? "" : `confidence ${event.malicious_ip_confidence}`, event.malicious_ip_source, Array.isArray(event.malicious_ip_tags_list) ? event.malicious_ip_tags_list.join(", ") : event.malicious_ip_tags_list, vector].filter(Boolean).join(" · ");
            return `<tr><td>${text(time(event.timestamp))}</td><td>${text(event.event_type || "Network event")}</td><td>${text(event.side_a_name || event.side_a_ip || "—")}</td><td>${text(event.side_a_ip || "—")}</td><td>${text(event.side_b_name || event.side_b_ip || "—")}</td><td>${text(event.side_b_ip || "—")}</td><td>${text(event.protocol || event.ip_protocol || "—")}</td><td>${text(iocDetails || "No IOC or vector details reported")}</td><td><button type="button" class="xd-link" data-xd-alert-event="${cache.events.indexOf(event)}">Full log</button></td></tr>`;
        }).join("");

        const incident = window.XDIncidents?.build?.().find(item => String(item.alertId) === alertId);
        const story = incident && window.XDIncidents?.attackStory?.(incident);
        const pathSurface = story?.steps?.length
            ? `<div class="xd-surface"><h4>ATT&amp;CK path · ${story.steps.length} reported stage(s)</h4>${story.steps.map(step => `<div class="ig-story-step"><div class="ig-story-icon" style="background:${step.color}22;border-color:${step.color}">${text(step.icon)}</div><div class="ig-story-body"><div class="ig-story-title">${text(step.title)}</div><div class="ig-story-desc">${text(step.desc)}</div></div></div>`).join("")}<p class="muted">Stages are grouped by ATT&amp;CK tactic order; sequence is not independently verified.</p></div>`
            : `<div class="xd-surface"><h4>ATT&amp;CK path</h4><p class="rec-empty">No MITRE technique was reported for this alert.</p></div>`;
        drawerTitle.textContent = alert.alert_name || alert.alert_type_name || "Claroty alert";
        drawerSub.textContent = `${alertId || "No alert ID"} · ${eventStatus}`;
        drawerBody.innerHTML = `<div class="xd-surface"><h4>Alert summary</h4><div class="xd-detail"><div><b>Type / category</b><span>${text(alert.alert_type_name || "Unknown type")} · ${text(alert.category || "Unknown category")}</span></div><div><b>Status / class</b><span>${text(alert.status || "Unknown status")} · ${text(alert.alert_class || "Unknown class")}</span></div><div><b>Detected / updated</b><span>${text(time(alert.detected_time))} · ${text(time(alert.updated_time))}</span></div><div><b>Device associations</b><span>${number(alert.devices_count)} total · ${number(alert.unresolved_devices_count)} unresolved</span></div><div><b>Device / host</b><span>${text(hosts.join(", ") || "No host identity in loaded alert/event data")}</span></div><div><b>IP addresses</b><span>${text(addresses.join(", ") || "No IP address in loaded alert/event data")}</span></div><div><b>Matched inventory records</b><span>${number(devices.length)} · matching loaded device name, UID, or IP</span></div></div></div><div class="xd-surface"><h4>IOC and malicious-IP evidence</h4>${iocs.size ? `<div class="xd-detail">${[...iocs.values()].map(item => `<div><b>${text(item.type)}</b><span>${text(item.value)}</span></div>`).join("")}</div>` : `<p class="rec-empty">No CVE, URL, IP, hash, or domain was found in the loaded alert/event fields.</p>`}<p>Malicious-IP tags: ${text(Array.isArray(alert.malicious_ip_tags_list) ? alert.malicious_ip_tags_list.map(value => typeof value === "object" ? JSON.stringify(value) : value).join(", ") : alert.malicious_ip_tags_list || "None reported")}</p></div><div class="xd-surface"><h4>Linked event logs · ${number(linkedEvents.length)}</h4><p>${text(eventStatus)}. Event links use matching alert IDs.</p><div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Source device</th><th>Source IP</th><th>Destination device</th><th>Destination IP</th><th>Protocol</th><th>IOC details</th><th>Details</th></tr></thead><tbody>${eventRows || `<tr><td colspan="9">${text(eventStatus)}. No linked event logs are currently loaded.</td></tr>`}</tbody></table></div>${linkedEvents.length > 100 ? `<p>Showing the first 100 of ${number(linkedEvents.length)} linked events.</p>` : ""}</div><div class="xd-surface"><h4>Matched device records · ${number(devices.length)}</h4>${devices.length ? `<div class="table-wrap"><table><thead><tr><th>Device / host</th><th>IP address</th><th>Site</th><th>Type</th><th>Risk</th><th>Online</th></tr></thead><tbody>${devices.slice(0, 100).map(device => `<tr><td>${text(device.device_name || device.uid || "Unknown")}</td><td>${text(Array.isArray(device.ip_list) ? device.ip_list.join(", ") : device.ip_list || "—")}</td><td>${text(device.site_name || "—")}</td><td>${text(device.device_type || device.device_category || "—")}</td><td>${text(deviceRisk(device))}</td><td>${text(onlineStatus(device))}</td></tr>`).join("")}</tbody></table></div>` : `<p class="rec-empty">No loaded inventory record matched the alert host/IP names.</p>`}</div><details class="xd-surface"><summary>Complete Claroty alert fields</summary><div class="xd-detail">${rawFields || `<p>No raw alert fields were returned.</p>`}</div></details>`;
        drawerBody.insertAdjacentHTML("afterbegin", pathSurface);
        if (eventState.source === "live" && !eventState.complete) {
            const loadMore = document.createElement("button");
            loadMore.type = "button";
            loadMore.className = "xd-command xd-alert-load-events";
            loadMore.textContent = eventState.error ? "Retry event feed" : `Load next event page · ${number(eventState.data.length)} loaded`;
            loadMore.addEventListener("click", async () => {
                loadMore.disabled = true;
                loadMore.textContent = "Loading event page…";
                const previousCount = eventState.data.length;
                const next = await ClarotyAPI.loadFeedPage("events", 1000);
                cache.events = next.data.slice();
                renderAlertEvidence(alert);
                const newButton = drawerBody.querySelector(".xd-alert-load-events");
                if (newButton && next.data.length === previousCount && !next.error) newButton.textContent = "No additional event records returned · retry";
            });
            drawerBody.append(loadMore);
        }
        document.getElementById("drawer").classList.add("open");
        document.getElementById("drawerOverlay").classList.add("open");
        document.getElementById("drawer").setAttribute("aria-hidden", "false");
    }

    async function openAlertDetails(alert) {
        if (!alert) return;
        renderAlertEvidence(alert);
        let state = ClarotyAPI.feedState("events");
        if (state.loading) {
            await state.loading;
            state = ClarotyAPI.feedState("events");
            cache.events = state.data.slice();
            renderAlertEvidence(alert);
        }
        if (state.source === "pending" && !state.loading && ClarotyAPI.canGoLive()) {
            state = await ClarotyAPI.loadFeedPage("events", 1000);
            cache.events = state.data.slice();
            renderAlertEvidence(alert);
        }
        for (let page = 0; page < 2 && state.source === "live" && !state.complete && !cache.events.some(event => String(event.alert_id ?? "") === String(alert.id ?? "")); page += 1) {
            const previousCount = state.data.length;
            state = await ClarotyAPI.loadFeedPage("events", 1000);
            cache.events = state.data.slice();
            renderAlertEvidence(alert);
            if (state.data.length === previousCount) break;
        }
    }

    function deviceEvidence(device) {
        const identities = new Set([
            device.device_name, device.uid,
            ...(Array.isArray(device.ip_list) ? device.ip_list : String(device.ip_list || "").split(/[,;\s]+/))
        ].map(value => String(value || "").trim().toLowerCase()).filter(Boolean));
        const matchingEvents = cache.events.filter(event => [event.side_a_name, event.side_b_name, event.side_a_ip, event.side_b_ip]
            .some(value => identities.has(String(value || "").trim().toLowerCase())));
        const eventAlertIds = new Set(matchingEvents.map(event => String(event.alert_id ?? "")).filter(Boolean));
        const matchingAlerts = cache.alerts.filter(alert => eventAlertIds.has(String(alert.id ?? "")));
        const deviceIds = new Set([String(device.uid || ""), String(device.device_name || "")].filter(Boolean).map(value => value.toLowerCase()));
        const matchingRelations = ClarotyAPI.feedState("relations").data.filter(row => deviceIds.has(String(row.device_uid || "").toLowerCase()) || deviceIds.has(String(row.device_name || "").toLowerCase()));
        const cves = [...new Set(matchingRelations.flatMap(relationCveIds))];
        return {
            events: matchingEvents,
            alerts: matchingAlerts,
            alertTypes: [...new Set(matchingAlerts.map(alert => alert.alert_type_name || alert.alert_name).filter(Boolean))],
            cves
        };
    }

    function renderOperationsDrillPage() {
        const drill = operationsDrillState;
        if (!drill) return;
        const drawer = document.getElementById("drawer");
        const drawerBody = document.getElementById("drawerBody");
        const drawerSub = document.getElementById("drawerSub");
        drawer.dataset.operationsDrill = "true";
        const feedState = ClarotyAPI.feedState(drill.feed);
        const start = drill.page * operationsDrillPageSize;
        const shown = drill.rows.slice(start, start + operationsDrillPageSize);
        const sourceStatus = feedState.source === "live"
            ? feedState.complete ? "feed complete" : `${number(feedState.data.length)} loaded · more pages available`
            : feedState.loading ? "feed still loading" : feedState.source === "error" ? `request failed: ${feedState.error || "unknown error"}` : "not loaded";
        drawerTitle.textContent = drill.title;
        drawerSub.textContent = `${number(drill.rows.length)} matching records · ${sourceStatus}`;

        let headers;
        let body;
        if (drill.kind === "devices") {
            headers = ["Device / host", "Site", "Type", "Risk", "State", "Related alert types", "CVEs"];
            body = shown.map((row, index) => {
                const evidence = deviceEvidence(row);
                const allIndex = start + index;
                return `<tr><td><button type="button" class="xd-link" data-xd-operations-drill-row="${allIndex}">${text(row.device_name || row.uid || "Unknown device")}</button></td><td>${text(row.site_name || "—")}</td><td>${text(row.device_type || row.device_category || "—")}</td><td>${text(deviceRisk(row))}</td><td>${text(onlineStatus(row))}</td><td>${text(evidence.alertTypes.join(", ") || (evidence.events.length ? "Linked event; alert record not loaded" : "No matching loaded event"))}</td><td>${text(evidence.cves.join(", ") || "No loaded relation")}</td></tr>`;
            }).join("");
        } else if (drill.kind === "alerts") {
            headers = ["Detected", "Alert type", "Status", "Device / host", "Devices"];
            body = shown.map((row, index) => `<tr><td>${text(time(row.detected_time))}</td><td><button type="button" class="xd-link" data-xd-operations-drill-row="${start + index}">${text(row.alert_type_name || row.alert_name || "Unknown alert")}</button></td><td>${text(row.status || "Unknown")}</td><td>${text(alertDeviceLabel(row))}</td><td>${number(row.devices_count)}</td></tr>`).join("");
        } else {
            headers = ["Time", "Event", "Source device / host", "Destination device / host", "Alert type", "Protocol"];
            body = shown.map((row, index) => {
                const alert = cache.alerts.find(item => String(item.id ?? "") === String(row.alert_id ?? ""));
                return `<tr><td>${text(time(row.timestamp))}</td><td><button type="button" class="xd-link" data-xd-operations-drill-row="${start + index}">${text(row.event_type || row.description || "Network event")}</button></td><td>${text(row.side_a_name || row.side_a_ip || "—")}</td><td>${text(row.side_b_name || row.side_b_ip || "—")}</td><td>${text(alert?.alert_type_name || alert?.alert_name || "No linked alert in loaded feed")}</td><td>${text(row.protocol || "—")}</td></tr>`;
            }).join("");
        }
        const empty = `<tr><td colspan="${headers.length}">${text(sourceStatus)}. No matching records are loaded.</td></tr>`;
        drawerBody.innerHTML = `<p class="rec-summary">Showing ${shown.length ? number(start + 1) : 0}–${number(Math.min(start + operationsDrillPageSize, drill.rows.length))} of ${number(drill.rows.length)} loaded matches. Device alert/CVE associations use currently loaded event and relation feeds.</p><div class="table-wrap"><table><thead><tr>${headers.map(header => `<th>${text(header)}</th>`).join("")}</tr></thead><tbody>${body || empty}</tbody></table></div><div class="xd-risk-pages"><button type="button" data-xd-operations-drill-page="prev" ${drill.page === 0 ? "disabled" : ""}>Previous</button><span>Page ${drill.page + 1} of ${Math.max(1, Math.ceil(drill.rows.length / operationsDrillPageSize))}</span><button type="button" data-xd-operations-drill-page="next" ${start + operationsDrillPageSize >= drill.rows.length ? "disabled" : ""}>Next</button></div>`;
        drawer.classList.add("open");
        document.getElementById("drawerOverlay").classList.add("open");
        drawer.setAttribute("aria-hidden", "false");
    }

    function openOperationsMetric(metric) {
        const cutoff = operationsRange === "all" ? null : Date.now() - Number(operationsRange) * 86400000;
        const inRange = value => cutoff == null || Number.isFinite(Date.parse(value)) && Date.parse(value) >= cutoff && Date.parse(value) <= Date.now();
        const alerts = [...new Map(cache.alerts.map(row => [String(row.id ?? `${row.alert_name}-${row.detected_time}`), row])).values()].filter(row => inRange(row.detected_time));
        const events = cache.events.filter(row => inRange(row.timestamp));
        const devices = uniqueDeviceRows(cache.devices);
        const unresolved = row => /open|unresolved|active|investigating/i.test(String(row.status || ""));
        let drill;
        if (["assets", "online", "offline", "high-risk"].includes(metric)) {
            const predicates = {
                assets: () => true,
                online,
                offline: row => onlineStatus(row) === "Offline",
                "high-risk": row => ["Critical", "High"].includes(deviceRisk(row))
            };
            const rank = { Critical: 0, High: 1, Medium: 2, Low: 3, "Very Low": 4, Unknown: 5 };
            const rows = devices.filter(predicates[metric]).sort((left, right) => rank[deviceRisk(left)] - rank[deviceRisk(right)]);
            const titles = { assets: "Unique live devices", online: "Online devices", offline: "Offline devices", "high-risk": "Critical / high-risk devices" };
            drill = { title: titles[metric], feed: "devices", kind: "devices", rows };
        } else if (metric.startsWith("alert-type:")) {
            const alertType = metric.slice("alert-type:".length);
            const rows = alerts.filter(row => unresolved(row) && String(row.alert_type_name || row.alert_name || "Unknown alert type") === alertType);
            drill = { title: `Unresolved alerts · ${alertType}`, feed: "alerts", kind: "alerts", rows };
        } else if (["alerts", "unresolved", "associations"].includes(metric)) {
            const rows = metric === "unresolved" ? alerts.filter(unresolved) : metric === "associations" ? alerts.filter(row => Number(row.devices_count) > 0) : alerts;
            const titles = { alerts: "Live xDome alerts", unresolved: "Unresolved xDome alerts", associations: "Alerts with affected-device associations" };
            drill = { title: titles[metric], feed: "alerts", kind: "alerts", rows };
        } else {
            drill = { title: "Live network events", feed: "events", kind: "events", rows: events };
        }
        operationsDrillState = { ...drill, metric, page: 0 };
        renderOperationsDrillPage();
    }

    function openOperationsDrillRow(index) {
        const drill = operationsDrillState;
        const row = drill?.rows[index];
        if (!row) return;
        if (drill.kind === "alerts") return openAlertDetails(row);
        if (drill.kind === "events") {
            const alert = cache.alerts.find(item => String(item.id ?? "") === String(row.alert_id ?? ""));
            return details({ ...row, linked_alert_type: alert?.alert_type_name || alert?.alert_name || "No linked alert in loaded feed", linked_alert_status: alert?.status || "—" }, "Claroty network event");
        }
        const evidence = deviceEvidence(row);
        details({
            ...row,
            linked_alert_types: evidence.alertTypes,
            linked_alert_ids: evidence.alerts.map(alert => alert.id),
            related_network_event_count: evidence.events.length,
            related_cves: evidence.cves,
            evidence_scope: "Correlations use currently loaded xDome event and device-vulnerability relation pages"
        }, "Critical / high-risk device");
    }

    function openSearchResult(kind, index) {
        const feedByKind = { Alert: "alerts", Device: "devices", CVE: "vulnerabilities", "CVE / Device": "relations", "Event / IOC": "events" };
        const feed = feedByKind[kind];
        const row = feed && ClarotyAPI.feedState(feed).data[index];
        if (!row) return;
        if (kind === "Alert") return openAlertDetails(row);
        details(row, kind === "Device" ? "Claroty device" : kind === "Event / IOC" ? "Claroty network event" : kind === "CVE / Device" ? "Claroty device vulnerability" : "Claroty CVE");
    }

    function filterAlerts() {
        const body = document.getElementById("xdAlertRows");
        if (!body) return;
        const query = document.getElementById("xdAlertSearch")?.value.toLowerCase() || "";
        const status = document.getElementById("xdAlertStatus")?.value || "";
        const rows = cache.alerts.map((row, index) => ({ row, index })).filter(({ row }) => (!status || row.status === status) && (!query || [row.alert_name, row.alert_type_name, row.category, row.description, row.mitre_technique_ics_names, alertDeviceLabel(row)].join(" ").toLowerCase().includes(query)));
        alertPage = Math.min(alertPage, Math.max(0, Math.ceil(rows.length / feedTablePageSize) - 1));
        const start = alertPage * feedTablePageSize;
        body.innerHTML = rows.slice(start, start + feedTablePageSize).map(({ row, index }) => `<tr><td><button type="button" class="xd-link" data-xd-alert="${index}">${text(row.alert_name || row.alert_type_name || row.id)}</button></td><td>${text(row.alert_type_name)}</td><td>${text(row.category)}</td><td>${text(row.status)}</td><td>${text(alertDeviceLabel(row))}</td><td>${number(row.devices_count)}</td><td>${text(time(row.detected_time))}</td></tr>`).join("") || `<tr><td colspan="7">${source("alerts")}</td></tr>`;
        document.getElementById("xdAlertPageStatus").textContent = `${rows.length ? number(start + 1) : 0}-${number(Math.min(start + feedTablePageSize, rows.length))} of ${number(rows.length)}`;
        document.querySelector('[data-xd-feed-page="alerts:prev"]').disabled = start === 0;
        document.querySelector('[data-xd-feed-page="alerts:next"]').disabled = start + feedTablePageSize >= rows.length;
    }

    function renderNetwork() {
        const host = document.getElementById("xdNetworkDashboard");
        if (!host) return;
        const rows = cache.events;
        host.innerHTML = `<div class="xd-head"><div><h2>Network &amp; OT Activity</h2><span>${source("events")}</span></div><div class="xd-network-head-actions"><nav class="xd-network-tabs" role="tablist" aria-label="Network views">${[["activity", "Network Activity"], ["ip-lists", "IP Allow/Block"], ["indicators", "IOC &amp; Paths"]].map(([view, label]) => `<button type="button" role="tab" data-xd-network-view="${view}" aria-selected="${networkView === view}" class="${networkView === view ? "active" : ""}">${label}</button>`).join("")}</nav><button type="button" class="xd-command" data-xd-refresh>Refresh events</button></div></div>
            <div class="xd-ip-manager" id="xdIpListManager" ${networkView === "ip-lists" ? "" : "hidden"}></div>
            <div class="xd-ip-manager" id="xdIndicatorManager" ${networkView === "indicators" ? "" : "hidden"}></div>
            <div id="xdNetworkActivity" ${networkView === "activity" ? "" : "hidden"}><div class="xd-stats">${badge("Events loaded", rows.length)}${badge("Malicious IP matches", count(rows, row => !!row.malicious_ip_type))}${badge("OT activity", count(rows, row => !!row.ot_activity_event_type))}</div>
            <div class="xd-filters"><input id="xdEventSearch" type="search" placeholder="Search IP, device, event or protocol" aria-label="Search network events"></div>
            <div class="xd-surface"><div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Malicious IP</th></tr></thead><tbody id="xdEventRows"></tbody></table></div><div class="xd-risk-pages"><button type="button" data-xd-feed-page="events:prev" aria-label="Previous events">Previous</button><span id="xdEventPageStatus"></span><button type="button" data-xd-feed-page="events:next" aria-label="Next events">Next</button><button type="button" data-xd-load-events ${ClarotyAPI.feedState("events").complete || ClarotyAPI.feedState("events").loading ? "disabled" : ""}>Load more events</button></div></div></div>`;
        filterEvents();
        if (networkView === "ip-lists") refreshIpLists();
        if (networkView === "indicators") refreshIndicators();
    }

    function visibleNetworkIps() {
        const addresses = new Set();
        const add = value => {
            const values = Array.isArray(value) ? value : String(value || "").split(/[,;\s]+/);
            values.map(item => String(item).trim()).filter(Boolean).forEach(address => addresses.add(address));
        };
        cache.events.forEach(row => { add(row.side_a_ip); add(row.side_b_ip); });
        return [...addresses].sort();
    }

    function renderIpLists() {
        const host = document.getElementById("xdIpListManager");
        if (!host) return;
        const lists = ipListData || { blacklist: [], whitelist: [], observed: [], reasons: {} };
        const renderList = (name, label) => `<div class="xd-ip-list"><h4>${label} <span>${number(lists[name].length)}</span></h4>${lists[name].map(address => `<div class="xd-ip-row"><div><code>${text(address)}</code><small>${text(lists.reasons?.[name]?.[address] || "Imported entry · no reason recorded")}</small></div><button type="button" class="xd-link" data-xd-ip-remove="${name}" data-address="${text(address)}">Remove</button></div>`).join("") || `<p>No ${label.toLowerCase()} entries.</p>`}</div>`;
        host.innerHTML = `<div class="xd-surface xd-ip-manager-surface"><div class="xd-surface-head"><div><h3>IP Whitelist &amp; Blacklist</h3><p>Saved on this workstation. Reasons document intent; these lists do not enforce firewall policy.</p></div><button type="button" class="xd-link" data-xd-ip-reload>Reload lists</button></div>
            <div class="xd-ip-actions"><label>List<select id="xdIpListTarget"><option value="blacklist">Blacklist</option><option value="whitelist">Whitelist</option></select></label><label>Single IP or CIDR<input id="xdIpSingle" type="text" placeholder="192.0.2.10 or 192.0.2.0/24" autocomplete="off"></label></div>
            <label class="xd-ip-bulk-label" for="xdIpReason">Reason (required)</label><input id="xdIpReason" type="text" maxlength="500" placeholder="Why should this address be allowlisted or blocked?" />
            <div class="xd-ip-actions"><button type="button" class="xd-command" data-xd-ip-add-single>Add address</button><span id="xdIpStatus" role="status" aria-live="polite"></span></div>
            <label class="xd-ip-bulk-label" for="xdIpBulk">Bulk IPs or CIDRs</label><textarea id="xdIpBulk" rows="4" placeholder="One IP or CIDR per line; commas and spaces are also accepted"></textarea><div class="xd-ip-actions"><button type="button" class="xd-command" data-xd-ip-add-bulk>Add bulk entries with reason</button></div>
            <div class="xd-ip-columns">${renderList("blacklist", "Blacklist")}${renderList("whitelist", "Whitelist")}</div>
            <div class="xd-ip-observed"><h4>Observed network IPs <span>${number(lists.observed.length)} loaded</span></h4><p>Unique source and destination IPs found in the currently loaded event feed. Feed status: ${source("events")}.</p><div class="table-wrap"><table><thead><tr><th>IP</th><th>List status</th><th>Matched entry</th></tr></thead><tbody>${lists.observed.map(item => `<tr><td><code>${text(item.address)}</code></td><td>${text(item.status)}</td><td>${text(item.matchedBy.join(", ") || "—")}</td></tr>`).join("") || `<tr><td colspan="3">No network IPs are loaded yet.</td></tr>`}</tbody></table></div></div></div>`;
    }

    async function refreshIpLists() {
        const host = document.getElementById("xdIpListManager");
        if (host) host.innerHTML = `<p role="status">Loading saved IP lists and observed network addresses…</p>`;
        try {
            const response = await fetch("/api/network/ip-lists", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ observed: visibleNetworkIps() })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not load IP lists");
            ipListData = payload;
            renderIpLists();
        } catch (error) {
            if (host) host.innerHTML = `<p role="alert">IP lists unavailable: ${text(error.message)}</p><button type="button" class="xd-link" data-xd-ip-reload>Retry</button>`;
        }
    }

    async function updateIpList(action, list, values, reason = "") {
        const status = document.getElementById("xdIpStatus");
        if (status) status.textContent = "Saving…";
        try {
            const response = await fetch("/api/network/ip-lists", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action, list, addresses: values, reason })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not update IP list");
            await refreshIpLists();
            const updatedStatus = document.getElementById("xdIpStatus");
            if (updatedStatus) updatedStatus.textContent = `${payload.total} ${list} entries saved.`;
            return true;
        } catch (error) {
            if (status) status.textContent = error.message;
            return false;
        }
    }

    function renderIndicators() {
        const host = document.getElementById("xdIndicatorManager");
        if (!host) return;
        const entries = indicatorData?.entries || [];
        host.innerHTML = `<div class="xd-surface xd-ip-manager-surface"><div class="xd-surface-head"><div><h3>IOC &amp; Path Allow/Block Lists</h3><p>Domains, URLs, file paths, and SHA-256 values are stored locally with a reason. These lists do not enforce DNS, web, or endpoint controls.</p></div><button type="button" class="xd-link" data-xd-indicator-reload>Reload entries</button></div>
            <div class="xd-ip-actions"><label>List<select id="xdIndicatorList"><option value="blacklist">Blacklist</option><option value="whitelist">Whitelist</option></select></label><label>Indicator type<select id="xdIndicatorKind"><option value="domain">Domain</option><option value="url">URL</option><option value="sha256">SHA-256</option><option value="file_path">File path</option></select></label><label>Single indicator<input id="xdIndicatorSingle" type="text" placeholder="domain, URL, hash, or absolute path" autocomplete="off"></label></div>
            <label class="xd-ip-bulk-label" for="xdIndicatorReason">Reason (required)</label><input id="xdIndicatorReason" type="text" maxlength="500" placeholder="Why should this indicator be allowlisted or blocked?" />
            <div class="xd-ip-actions"><button type="button" class="xd-command" data-xd-indicator-add-single>Add indicator</button><span id="xdIndicatorStatus" role="status" aria-live="polite"></span></div>
            <label class="xd-ip-bulk-label" for="xdIndicatorBulk">Bulk indicators (one per line, same type and reason)</label><textarea id="xdIndicatorBulk" rows="4" placeholder="Paste one indicator per line"></textarea><div class="xd-ip-actions"><button type="button" class="xd-command" data-xd-indicator-add-bulk>Add bulk indicators</button></div>
            <div class="xd-ip-observed"><h4>Saved indicators <span>${number(entries.length)} loaded</span></h4><div class="table-wrap"><table><thead><tr><th>List</th><th>Type</th><th>Indicator</th><th>Reason</th><th></th></tr></thead><tbody>${entries.map(entry => `<tr><td>${text(entry.list)}</td><td>${text(entry.kind)}</td><td><code>${text(entry.value)}</code></td><td>${text(entry.reason)}</td><td><button type="button" class="xd-link" data-xd-indicator-remove="${text(entry.list)}" data-kind="${text(entry.kind)}" data-value="${text(entry.value)}">Remove</button></td></tr>`).join("") || `<tr><td colspan="5">No IOC or path indicators saved.</td></tr>`}</tbody></table></div></div></div>`;
    }

    async function refreshIndicators() {
        const host = document.getElementById("xdIndicatorManager");
        if (host) host.innerHTML = `<p role="status">Loading saved IOC and path entries…</p>`;
        try {
            const response = await fetch("/api/network/indicators", { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not load indicators");
            indicatorData = payload;
            renderIndicators();
        } catch (error) {
            if (host) host.innerHTML = `<p role="alert">Indicator lists unavailable: ${text(error.message)}</p><button type="button" class="xd-link" data-xd-indicator-reload>Retry</button>`;
        }
    }

    async function updateIndicator(action, list, kind, values, reason = "") {
        const status = document.getElementById("xdIndicatorStatus");
        if (status) status.textContent = "Saving…";
        try {
            const response = await fetch("/api/network/indicators", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action, list, kind, values, reason })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not update indicators");
            await refreshIndicators();
            const updatedStatus = document.getElementById("xdIndicatorStatus");
            if (updatedStatus) updatedStatus.textContent = `${payload.entries.length} indicators saved.`;
            return true;
        } catch (error) {
            if (status) status.textContent = error.message;
            return false;
        }
    }

    function filterEvents() {
        const body = document.getElementById("xdEventRows");
        if (!body) return;
        const query = document.getElementById("xdEventSearch")?.value.toLowerCase() || "";
        const rows = cache.events.map((row, index) => ({ row, index })).filter(({ row }) => !query || [row.side_a_ip, row.side_b_ip, row.side_a_name, row.side_b_name, row.event_type, row.protocol].join(" ").toLowerCase().includes(query));
        eventPage = Math.min(eventPage, Math.max(0, Math.ceil(rows.length / feedTablePageSize) - 1));
        const start = eventPage * feedTablePageSize;
        body.innerHTML = rows.slice(start, start + feedTablePageSize).map(({ row, index }) => `<tr><td>${text(time(row.timestamp))}</td><td><button type="button" class="xd-link" data-xd-event="${index}">${text(row.event_type)}</button></td><td>${text(row.side_a_name || row.side_a_ip)}</td><td>${text(row.side_b_name || row.side_b_ip)}</td><td>${text(row.protocol)}</td><td>${text(row.malicious_ip_type || "—")}</td></tr>`).join("") || `<tr><td colspan="6">${source("events")}</td></tr>`;
        document.getElementById("xdEventPageStatus").textContent = `${rows.length ? number(start + 1) : 0}-${number(Math.min(start + feedTablePageSize, rows.length))} of ${number(rows.length)} loaded${ClarotyAPI.feedState("events").complete ? "" : " (partial)"}`;
        document.querySelector('[data-xd-feed-page="events:prev"]').disabled = start === 0;
        document.querySelector('[data-xd-feed-page="events:next"]').disabled = start + feedTablePageSize >= rows.length;
    }

    function renderProfile() {
        const host = document.getElementById("xdProfileDashboard");
        if (!host) return;
        host.innerHTML = `<div class="xd-head"><div><h2>Monitoring &amp; Exports</h2><span>Claroty feed status and external connector readiness</span></div><button type="button" class="xd-command" data-xd-check>Test Claroty APIs</button></div>
            <div class="xd-surface"><h3>Claroty feeds</h3>${FEEDS.concat("relations").map(feed => `<div class="xd-feed-state"><b>${text(LABELS[feed] || "Device-vulnerability relations")}</b><span>${source(feed)}</span></div>`).join("")}</div>
            <div class="xd-surface"><h3>Additional security monitoring</h3>${MONITORS.map(([name, requirement]) => `<div class="xd-feed-state"><b>${text(name)}</b><span>Not connected · ${text(requirement)}</span></div>`).join("")}</div>
            <div class="xd-surface"><h3>Export loaded Claroty records</h3><div class="xd-filters"><select id="xdExportFeed" aria-label="Select feed to export">${FEEDS.map(feed => `<option value="${feed}">${LABELS[feed]}</option>`).join("")}</select><button type="button" class="xd-command" data-xd-export>Download CSV</button></div><p>Exports only currently loaded records. Sensitive asset and alert data stays on this workstation.</p></div>
            <div class="xd-surface"><h3>Analysis</h3><p>Automated summarization uses the loaded Claroty data. Generative AI requires a separately configured provider; no AI decisions or actions are sent to xDome.</p><button type="button" class="xd-command" data-xd-analyze>Analyze loaded data</button><div id="xdAnalysisResult" role="status"></div></div><div id="xdDiagnosticsResult" role="status"></div>`;
    }

    function render() { renderHome(); renderRisk(); renderAlerts(); renderNetwork(); renderProfile(); }

    async function refresh(force = false) {
        if (refreshing) return refreshing;
        refreshing = (async () => {
            const generation = ++feedLoadGeneration;
            if (force) await ClarotyAPI.refreshData();
            if (!ClarotyAPI.canGoLive()) { render(); return; }
            const feedRequests = LOAD_FEEDS.map(async feed => {
                const updateView = () => {
                    if (generation !== feedLoadGeneration) return;
                    const state = ClarotyAPI.feedState(feed);
                    if (feed === "relations") {
                        renderProfile();
                        return;
                    }
                    cache[feed] = state.data.slice();
                    renderHome();
                    if (feed === "devices" || feed === "vulnerabilities") renderRisk();
                    if (feed === "vulnerabilities") window.refreshOverviewSeverity?.();
                    if (feed === "alerts") renderAlerts();
                    if (feed === "events") renderNetwork();
                    if (feed === "devices" || feed === "alerts" || feed === "events") scheduleOperationsRender();
                    renderProfile();
                };
                await ClarotyAPI.loadAllFeed(feed, 1000, 100000, updateView);
                updateView();
            });
            render();
            await Promise.all(feedRequests);
            lastRefresh = new Date().toISOString();
            renderHome();
        })();
        try { return await refreshing; } finally { refreshing = null; }
    }

    function details(row, label) {
        const drawer = document.getElementById("drawer");
        drawer.dataset.operationsDrill = "false";
        document.getElementById("drawerTitle").textContent = label;
        document.getElementById("drawerSub").textContent = "Claroty xDome live record";
        document.getElementById("drawerBody").innerHTML = `<div class="xd-detail">${Object.entries(row).filter(([, value]) => value != null && value !== "").map(([key, value]) => `<div><b>${text(key.replaceAll("_", " "))}</b><span>${text(Array.isArray(value) ? value.join(", ") : value)}</span></div>`).join("")}</div>`;
        drawer.classList.add("open");
        document.getElementById("drawerOverlay").classList.add("open");
        drawer.setAttribute("aria-hidden", "false");
    }

    function relationCveIds(row) {
        const values = [
            ...(Array.isArray(row.vulnerability_cve_ids) ? row.vulnerability_cve_ids : String(row.vulnerability_cve_ids || "").split(/[,;\s]+/)),
            row.vulnerability_name,
            ...(Array.isArray(row.cve_ids) ? row.cve_ids : String(row.cve_ids || "").split(/[,;\s]+/)),
            row.name
        ];
        return values.map(value => String(value || "").trim().toUpperCase()).filter(value => /^CVE-\d{4}-\d+$/.test(value));
    }

    async function showCveExposureDevices(likelihood, impact, range) {
            const matchingCves = riskVulnerabilities(range).map(({ row }) => row).filter(row => {
                const cell = exposureCell(row);
                return cell && cell[0] === likelihood && cell[1] === impact;
            });
            const cveIds = new Set(matchingCves.flatMap(relationCveIds));
            details({ matching_cves: matchingCves.length, cve_ids: [...cveIds].slice(0, 100), scoring: "EPSS likelihood / CVSS impact (derived)" }, "CVE exposure cell");
            const drawerBody = document.getElementById("drawerBody");
            const drawerSub = document.getElementById("drawerSub");
            if (!cveIds.size) {
                drawerBody.innerHTML += `<p class="rec-empty">No CVE IDs are available for device correlation in this cell.</p>`;
                return;
            }
            drawerSub.textContent = "Loading live Claroty device-vulnerability relations…";
            drawerBody.innerHTML = `<div class="drawer-loading">Loading affected devices for ${number(cveIds.size)} CVEs…</div>`;
            try {
                let state = ClarotyAPI.feedState("relations");
                if (state.source !== "live" && !ClarotyAPI.canGoLive()) throw new Error("Configure Claroty credentials to load affected devices.");
                for (let page = 0; page < 5 && !state.complete && state.data.length < 50000 && state.source !== "error"; page += 1) {
                    const previousCount = state.data.length;
                    state = await ClarotyAPI.loadFeedPage("relations", 1000);
                    drawerSub.textContent = `Searching live relations: ${number(state.data.length)} loaded${state.complete ? " · complete" : " · partial"}`;
                    if (state.data.length === previousCount) break;
                }
                if (state.source !== "live") throw new Error(state.error || "Claroty relation feed is unavailable.");
                const related = state.data.filter(row => relationCveIds(row).some(cve => cveIds.has(cve)));
                const shown = related.slice(0, 100);
                const canLoadMore = !state.complete && state.data.length < 50000;
                drawerSub.textContent = `${number(related.length)} related device-CVE records · ${state.complete ? "relation feed complete" : `first ${number(state.data.length)} relations loaded`}`;
                drawerBody.innerHTML = `<p class="rec-summary">${number(matchingCves.length)} CVEs in this heat-map cell · ${number(related.length)} matching live device-CVE records${related.length > shown.length ? ` · showing first ${number(shown.length)}` : ""}</p>${shown.length ? `<div class="table-wrap"><table><thead><tr><th>Device</th><th>IP</th><th>Site</th><th>CVE</th><th>CVSS</th><th>EPSS</th></tr></thead><tbody>${shown.map(row => `<tr><td>${text(row.device_name || row.device_uid || "Unknown")}</td><td>${text(Array.isArray(row.device_ip_list) ? row.device_ip_list.join(", ") : row.device_ip_list || "—")}</td><td>${text(row.device_site_name || "—")}</td><td>${text(relationCveIds(row).filter(cve => cveIds.has(cve)).join(", ") || row.vulnerability_id || "—")}</td><td>${text(row.vulnerability_cvss_v3_score ?? "—")}</td><td>${text(row.vulnerability_epss_score ?? "—")}</td></tr>`).join("")}</tbody></table></div>` : `<div class="rec-empty">No affected device relations were found in the loaded pages.${canLoadMore ? " Load more relations to continue searching." : ""}</div>`}${canLoadMore ? `<button type="button" class="xd-command" data-xd-cve-load-more="${likelihood}:${impact}:${text(range)}">Load next 5,000 relations</button>` : ""}`;
            } catch (error) {
                drawerSub.textContent = "Claroty live relation lookup";
                drawerBody.innerHTML = `<div class="rec-empty">${text(error.message)}</div>`;
            }
        }

    function exportFeed() {
        const feed = document.getElementById("xdExportFeed")?.value || "devices";
        const rows = cache[feed];
        if (!rows.length) { document.getElementById("xdDiagnosticsResult").textContent = `No ${feed} records loaded to export.`; return; }
        const keys = [...new Set(rows.flatMap(row => Object.keys(row)))];
        const csv = [keys, ...rows.map(row => keys.map(key => Array.isArray(row[key]) ? row[key].join("; ") : row[key] ?? ""))]
            .map(row => row.map(value => `"${String(value).replaceAll('"', '""')}"`).join(",")).join("\r\n");
        const url = URL.createObjectURL(new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }));
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = `claroty-${feed}-${new Date().toISOString().slice(0, 10)}.csv`;
        anchor.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    document.addEventListener("click", async event => {
        if (event.target.closest("[data-xd-refresh]")) await refresh(true);
        const homeMetric = event.target.closest("[data-xd-home-metric]")?.dataset.xdHomeMetric;
        if (homeMetric) {
            window.showSection("devices");
            await window.XDOME?.renderDevices();
            const severity = document.getElementById("xdDeviceSeverityFilter");
            const status = document.getElementById("xdDeviceStatusFilter");
            const search = document.getElementById("xdDeviceSearch");
            if (!severity || !status || !search) return;
            severity.value = homeMetric === "critical" ? "Critical" : homeMetric === "high" ? "High" : "";
            status.value = homeMetric === "online" ? "true" : homeMetric === "offline" ? "false" : homeMetric === "unknown" ? "unknown" : "";
            search.value = "";
            severity.dispatchEvent(new Event("change", { bubbles: true }));
            status.dispatchEvent(new Event("change", { bubbles: true }));
            document.getElementById("xdDevicesTable")?.scrollIntoView({ behavior: "smooth", block: "center" });
            return;
        }
        const operationMetric = event.target.closest("[data-xd-operations-metric]")?.dataset.xdOperationsMetric;
        if (operationMetric) {
            openOperationsMetric(operationMetric);
            return;
        }
        const alertType = event.target.closest("[data-xd-operations-alert-type]")?.dataset.xdOperationsAlertType;
        if (alertType) {
            openOperationsMetric(`alert-type:${alertType}`);
            return;
        }
        const drillPage = event.target.closest("[data-xd-operations-drill-page]")?.dataset.xdOperationsDrillPage;
        if (drillPage && operationsDrillState) {
            operationsDrillState.page = Math.max(0, operationsDrillState.page + (drillPage === "next" ? 1 : -1));
            renderOperationsDrillPage();
            return;
        }
        const drillRow = event.target.closest("[data-xd-operations-drill-row]")?.dataset.xdOperationsDrillRow;
        if (drillRow != null) {
            openOperationsDrillRow(Number(drillRow));
            return;
        }
        const opsEventIndex = event.target.closest("[data-xd-ops-event]")?.dataset.xdOpsEvent;
        if (opsEventIndex != null) {
            const row = cache.events[Number(opsEventIndex)];
            if (row) {
                const alert = cache.alerts.find(item => String(item.id ?? "") === String(row.alert_id ?? ""));
                details({ ...row, linked_alert_type: alert?.alert_type_name || alert?.alert_name || "No linked alert in loaded feed", linked_alert_status: alert?.status || "—" }, "Claroty network event");
            }
            return;
        }
        const networkTab = event.target.closest("[data-xd-network-view]");
        if (networkTab) {
            networkView = networkTab.dataset.xdNetworkView;
            renderNetwork();
            return;
        }
        if (event.target.closest("[data-xd-overview-reset]")) {
            Object.keys(overviewFilters).forEach(field => { overviewFilters[field] = ""; });
            renderOverviewLive();
        }
        if (event.target.closest("[data-xd-ip-reload]")) await refreshIpLists();
        const removeIp = event.target.closest("[data-xd-ip-remove]");
        if (removeIp) await updateIpList("remove", removeIp.dataset.xdIpRemove, [removeIp.dataset.address]);
        if (event.target.closest("[data-xd-ip-add-single]")) {
            const address = document.getElementById("xdIpSingle").value.trim();
            const list = document.getElementById("xdIpListTarget").value;
            const reason = document.getElementById("xdIpReason").value.trim();
            if (address && await updateIpList("add", list, [address], reason)) {
                document.getElementById("xdIpSingle").value = "";
                document.getElementById("xdIpReason").value = "";
            }
        }
        if (event.target.closest("[data-xd-ip-add-bulk]")) {
            const addresses = document.getElementById("xdIpBulk").value.trim();
            const list = document.getElementById("xdIpListTarget").value;
            const reason = document.getElementById("xdIpReason").value.trim();
            if (addresses && await updateIpList("add", list, [addresses], reason)) {
                document.getElementById("xdIpBulk").value = "";
                document.getElementById("xdIpReason").value = "";
            }
        }
        if (event.target.closest("[data-xd-indicator-reload]")) await refreshIndicators();
        if (event.target.closest("[data-xd-indicator-remove]")) {
            const button = event.target.closest("[data-xd-indicator-remove]");
            await updateIndicator("remove", button.dataset.xdIndicatorRemove, button.dataset.kind, [button.dataset.value]);
        }
        if (event.target.closest("[data-xd-indicator-add-single]")) {
            const value = document.getElementById("xdIndicatorSingle").value.trim();
            const list = document.getElementById("xdIndicatorList").value;
            const kind = document.getElementById("xdIndicatorKind").value;
            const reason = document.getElementById("xdIndicatorReason").value.trim();
            if (value && await updateIndicator("add", list, kind, [value], reason)) {
                document.getElementById("xdIndicatorSingle").value = "";
                document.getElementById("xdIndicatorReason").value = "";
            }
        }
        if (event.target.closest("[data-xd-indicator-add-bulk]")) {
            const values = document.getElementById("xdIndicatorBulk").value.split(/[\r\n,]+/).map(value => value.trim()).filter(Boolean);
            const list = document.getElementById("xdIndicatorList").value;
            const kind = document.getElementById("xdIndicatorKind").value;
            const reason = document.getElementById("xdIndicatorReason").value.trim();
            if (values.length && await updateIndicator("add", list, kind, values, reason)) {
                document.getElementById("xdIndicatorBulk").value = "";
                document.getElementById("xdIndicatorReason").value = "";
            }
        }
        const route = event.target.closest("[data-xd-navigate]")?.dataset.xdNavigate;
        if (route === "profile") {
            window.showSection("integrations");
            document.querySelector('#settingsTabs [data-settings-tab="profile"]')?.click();
        } else if (route) window.showSection(route);
        const operationsAlertId = event.target.closest("[data-xd-ops-alert]")?.dataset.xdOpsAlert;
        if (operationsAlertId) {
            const row = cache.alerts.find(alert => String(alert.id) === operationsAlertId);
            if (row) await openAlertDetails(row);
        }
        const alertEventIndex = event.target.closest("[data-xd-alert-event]")?.dataset.xdAlertEvent;
        if (alertEventIndex != null) {
            const row = cache.events[Number(alertEventIndex)];
            if (row) {
                const parentAlert = cache.alerts.find(alert => String(alert.id ?? "") === String(row.alert_id ?? ""));
                details({ ...row, linked_alert_type: parentAlert?.alert_type_name || parentAlert?.alert_name || "No linked alert in loaded feed", linked_alert_status: parentAlert?.status || "—" }, "Claroty event log");
            }
            return;
        }
        const alert = event.target.closest("[data-xd-alert]")?.dataset.xdAlert;
        if (alert != null) await openAlertDetails(cache.alerts[Number(alert)]);
        const vuln = event.target.closest("[data-xd-vuln]")?.dataset.xdVuln;
        if (vuln != null) details(cache.vulnerabilities[Number(vuln)], "Claroty CVE");
        const network = event.target.closest("[data-xd-event]")?.dataset.xdEvent;
        if (network != null) details(cache.events[Number(network)], "Claroty network event");
        const cell = event.target.closest("[data-xd-cell]")?.dataset.xdCell;
        if (cell) {
            const [likelihood, impact] = cell.split(":").map(Number);
            const range = document.getElementById("overview")?.classList.contains("active") ? overviewCveRange : "all";
            await showCveExposureDevices(likelihood, impact, range);
        }
        const moreRelations = event.target.closest("[data-xd-cve-load-more]")?.dataset.xdCveLoadMore;
        if (moreRelations) {
            const [likelihood, impact, range] = moreRelations.split(":");
            await showCveExposureDevices(Number(likelihood), Number(impact), range);
        }
        const overviewPeriod = event.target.closest("[data-xd-overview-range]")?.dataset.xdOverviewRange;
        if (overviewPeriod != null) { overviewRange = overviewPeriod; renderOverviewLive(); }
        const cvePeriod = event.target.closest("[data-xd-overview-cve-range]")?.dataset.xdOverviewCveRange;
        if (cvePeriod != null) { overviewCveRange = cvePeriod; renderOverviewLive(); }
        const operationsPeriod = event.target.closest("[data-xd-operations-range]")?.dataset.xdOperationsRange;
        if (operationsPeriod != null) { operationsRange = operationsPeriod; renderOperationsLive(); }
        const page = event.target.closest("[data-xd-risk-page]")?.dataset.xdRiskPage;
        if (page) { riskPage += page === "next" ? 1 : -1; renderRisk(); }
        const feedPage = event.target.closest("[data-xd-feed-page]")?.dataset.xdFeedPage;
        if (feedPage) {
            const [feed, direction] = feedPage.split(":");
            if (feed === "alerts") { alertPage += direction === "next" ? 1 : -1; filterAlerts(); }
            if (feed === "events") { eventPage += direction === "next" ? 1 : -1; filterEvents(); }
        }
        if (event.target.closest("[data-xd-load-events]")) {
            const button = event.target.closest("[data-xd-load-events]");
            button.disabled = true;
            const query = document.getElementById("xdEventSearch")?.value || "";
            const result = await ClarotyAPI.loadFeedPage("events", 5000);
            cache.events = result.data.slice();
            renderHome();
            renderProfile();
            renderNetwork();
            document.getElementById("xdEventSearch").value = query;
            filterEvents();
        }
        if (event.target.closest("[data-xd-export]")) exportFeed();
        if (event.target.closest("[data-xd-check]")) {
            const status = await ClarotyAPI.feedDiagnostics();
            document.getElementById("xdDiagnosticsResult").textContent = status.error || status.feeds.map(item => `${item.feed}: ${item.ok ? "connected" : item.error || `HTTP ${item.status}`}`).join(" · ");
        }
        if (event.target.closest("[data-xd-analyze]")) {
            const result = document.getElementById("xdAnalysisResult");
            if (result) result.textContent = analyzeLoadedData().summary;
        }
        if (event.target.closest("[data-xd-open-ai-draft]")) {
            document.getElementById("createAiBtn")?.click();
            const chatInput = document.getElementById("aiChatInput");
            if (chatInput?.form) {
                chatInput.value = "Draft an xDome summary";
                chatInput.form.requestSubmit();
            }
        }
    });
    document.addEventListener("input", event => {
        if (event.target.id === "xdAlertSearch") { alertPage = 0; filterAlerts(); }
        if (event.target.id === "xdEventSearch") { eventPage = 0; filterEvents(); }
    });
    document.addEventListener("change", event => {
        const overviewFilter = event.target.closest("[data-xd-overview-filter]");
        if (overviewFilter) {
            overviewFilters[overviewFilter.dataset.xdOverviewFilter] = overviewFilter.value;
            renderOverviewLive();
        }
        if (event.target.id === "xdPortalSite" || event.target.id === "xdPortalRisk") {
            homeFilters.site = document.getElementById("xdPortalSite").value;
            homeFilters.risk = document.getElementById("xdPortalRisk").value;
            renderHome();
            renderRisk();
        }
        if (event.target.id === "xdAlertStatus") { alertPage = 0; filterAlerts(); }
    });
    render();
    return { refresh, render, renderOperations: renderOperationsLive, analyzeLoadedData, openSearchResult };
})();

window.XDPortal = XDPortal;