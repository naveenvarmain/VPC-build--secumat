/* =====================================================================
   xDome dashboard modules
   Claroty device coverage, vulnerability backlog, and risk tab mounting.
   ===================================================================== */

const XDOME = (() => {
    const COLORS = { green: "#22c55e", amber: "#f59e0b", red: "#ef4444", accent: "#464feb", accent2: "#6a72f0", grid: "#2a2f3d", muted: "#8b90a3" };
    const severityRank = { Critical: 5, High: 4, Medium: 3, Low: 2, "Very Low": 1, Unknown: 0 };
    const charts = {};

    function destroy(id) {
        if (!charts[id]) return;
        charts[id].destroy();
        delete charts[id];
    }

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

    function normalizeSeverity(value) {
        const text = String(value || "Unknown").toLowerCase();
        if (text.includes("very low")) return "Very Low";
        if (text.includes("critical")) return "Critical";
        if (text.includes("high")) return "High";
        if (text.includes("medium")) return "Medium";
        if (text.includes("very low")) return "Very Low";
        if (text.includes("low")) return "Low";
        return "Unknown";
    }

    function pillClass(severity) {
        if (severity === "Critical") return "red";
        if (severity === "High" || severity === "Medium") return "amber";
        return "green";
    }

    function countBy(items, getter) {
        return items.reduce((counts, item) => {
            const key = getter(item) || "Unknown";
            counts[key] = (counts[key] || 0) + 1;
            return counts;
        }, {});
    }

    function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>\"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character]);
    }

    function displayValue(value) {
        if (Array.isArray(value)) return value.join(", ") || "—";
        return value == null || value === "" ? "—" : String(value);
    }

    function isTrue(value) {
        return value === true || value === 1 || ["true", "yes", "1"].includes(String(value).toLowerCase());
    }

    function sourceLabel(source) {
        if (source === "live") return "Claroty live API";
        if (source === "error") return "Claroty live request failed - use Refresh to retry";
        if (source === "pending") return "Loading live Claroty devices…";
        if (source === "unconfigured") return "Configure Claroty credentials to load live devices";
        return "Claroty is not connected for this session";
    }

    function chartBase() {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { boxWidth: 12, padding: 12, font: { size: 11 } } } },
            scales: { x: { grid: { display: false } }, y: { grid: { color: COLORS.grid }, beginAtZero: true } }
        };
    }

    function summarizeDevices(rows) {
        const byUid = new Map();
        rows.forEach(row => {
            const uid = String(row.uid || "").trim();
            if (uid && !byUid.has(uid)) byUid.set(uid, row);
        });
        return [...byUid.values()].map(row => ({
            id: row.uid,
            name: row.device_name || row.uid || "Unknown device",
            ip: Array.isArray(row.ip_list) ? row.ip_list.join(", ") : row.ip_list || "",
            site: row.site_name || "",
            manufacturer: row.manufacturer || "",
            type: row.device_type || "Unknown",
            model: row.model || "",
            risk: normalizeSeverity(row.risk_score),
            online: row.is_online == null ? null : isTrue(row.is_online)
        })).filter(device => device.id).sort((a, b) => severityRank[b.risk] - severityRank[a.risk] || a.name.localeCompare(b.name));
    }

    function deviceIllustration(type) {
        const kind = /plc|controller|rtu|dcs/i.test(type) ? "controller"
            : /hmi|workstation|panel|scada/i.test(type) ? "display"
            : /switch|router|firewall|gateway/i.test(type) ? "network"
            : /sensor|meter|instrument|transmitter/i.test(type) ? "sensor" : "device";
        const shapes = {
            controller: '<rect x="9" y="12" width="46" height="40" rx="3"/><path d="M9 23h46M9 34h46M22 23v29M42 23v29"/><circle cx="16" cy="17" r="1"/><circle cx="23" cy="17" r="1"/>',
            display: '<rect x="7" y="10" width="50" height="36" rx="3"/><path d="M19 55h26M32 46v9M14 17h36v22H14z"/>',
            network: '<rect x="8" y="18" width="48" height="30" rx="3"/><path d="M8 29h48M14 37h5M24 37h5M34 37h5M44 37h5M16 48v5M48 48v5"/>',
            sensor: '<circle cx="32" cy="29" r="14"/><circle cx="32" cy="29" r="5"/><path d="M32 43v11M22 54h20M12 14l5 5M52 14l-5 5"/>',
            device: '<rect x="13" y="8" width="38" height="48" rx="3"/><path d="M21 17h22M21 25h22M21 33h22M21 43h8M36 43h7"/>'
        };
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none" stroke="#17635c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${shapes[kind]}</svg>`;
        return `<img class="device-visual" src="data:image/svg+xml,${encodeURIComponent(svg)}" alt="${escapeHtml(kind)} illustration" width="52" height="52">`;
    }

    let currentDevices = [];
    let devicePageSource = "pending";
    let deviceHasMore = true;
    let devicePage = 0;
    const DEVICE_PAGE_SIZE = 5000;
    const DEVICE_TABLE_PAGE_SIZE = 100;
    const deviceTableBody = document.querySelector("#xdDevicesTable tbody");

    let deviceRiskBand = "";

    function renderDeviceRows() {
        if (!deviceTableBody) return;
        const query = String(document.getElementById("xdDeviceSearch")?.value || "").trim().toLowerCase();
        const risk = document.getElementById("xdDeviceSeverityFilter")?.value || "";
        const status = document.getElementById("xdDeviceStatusFilter")?.value || "";
        const visible = currentDevices.filter(device => {
            const text = [device.id, device.name, device.ip, device.site, device.type, device.model, device.manufacturer].join(" ").toLowerCase();
            return (!query || text.includes(query))
                && (!risk || device.risk === risk)
                && (deviceRiskBand !== "criticalhigh" || device.risk === "Critical" || device.risk === "High")
                && (!status || (status === "unknown" ? device.online == null : String(device.online) === status));
        });
        const loadState = deviceHasMore ? "more Claroty devices available" : "all returned devices loaded";
        const pageCount = Math.max(1, Math.ceil(visible.length / DEVICE_TABLE_PAGE_SIZE));
        devicePage = Math.min(devicePage, pageCount - 1);
        const start = devicePage * DEVICE_TABLE_PAGE_SIZE;
        const pageRows = visible.slice(start, start + DEVICE_TABLE_PAGE_SIZE);
        setText("xdDeviceResultCount", `${visible.length ? start + 1 : 0}-${Math.min(start + DEVICE_TABLE_PAGE_SIZE, visible.length)} of ${visible.length.toLocaleString()} shown · ${currentDevices.length.toLocaleString()} loaded · ${loadState}`);
        deviceTableBody.innerHTML = pageRows.length ? pageRows.map(device => {
            const name = escapeHtml(device.name);
            const type = escapeHtml(device.type);
            const status = device.online == null ? "Unknown" : device.online ? "Online" : "Offline";
            return `<tr>
                <td>${deviceIllustration(device.type)}<span class="device-name-cell"><strong>${name}</strong><small>${escapeHtml(device.id)}</small></span></td>
                <td>${escapeHtml(device.ip || "—")}</td>
                <td>${escapeHtml(device.site || "—")}</td>
                <td>${escapeHtml(device.manufacturer || "—")}</td>
                <td>${type}${device.model ? `<small class="device-cell-sub">${escapeHtml(device.model)}</small>` : ""}</td>
                <td><span class="pill ${pillClass(device.risk)}">${escapeHtml(device.risk)}</span></td>
                <td><span class="pill ${device.online == null ? "" : device.online ? "green" : "amber"}">${status}</span></td>
                <td><button type="button" class="device-details-btn" data-device-id="${escapeHtml(device.id)}">Details</button></td>
            </tr>`;
        }).join("") : `<tr><td colspan="8" class="device-empty">${currentDevices.length ? "No devices match these filters." : devicePageSource === "error" ? "Claroty device request failed — use Refresh to retry." : devicePageSource === "pending" ? "Loading devices from Claroty…" : "No devices returned by Claroty."}</td></tr>`;
        const previous = document.getElementById("xdDevicePrevPage");
        const next = document.getElementById("xdDeviceNextPage");
        if (previous) previous.disabled = start === 0;
        if (next) next.disabled = start + DEVICE_TABLE_PAGE_SIZE >= visible.length;
    }

    function showDeviceDetails(device) {
        const dialog = document.getElementById("xdDeviceDialog");
        if (!dialog) return;
        setText("xdDeviceDialogTitle", device.name);
        const fields = [
            ["Device UID", device.id], ["Device name", device.name], ["IP addresses", device.ip],
            ["Site", device.site], ["Manufacturer", device.manufacturer], ["Device type", device.type],
            ["Model", device.model], ["Online", device.online == null ? "Unknown" : device.online ? "Yes" : "No"], ["Risk score", device.risk]
        ];
        const body = document.getElementById("xdDeviceDialogBody");
        body.innerHTML = `<dl class="device-detail-grid">${fields.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(displayValue(value))}</dd></div>`).join("")}</dl>
            <p class="muted device-api-note">Device illustrations represent the reported type; xDome does not provide photos in this feed. MAC, network, VLAN, category, and operating-system fields are also unavailable.</p>`;
        if (!dialog.open) dialog.showModal();
    }

    if (deviceTableBody) deviceTableBody.addEventListener("click", event => {
        const button = event.target.closest("[data-device-id]");
        if (!button) return;
        const device = currentDevices.find(item => String(item.id) === button.dataset.deviceId);
        if (device) showDeviceDetails(device);
    });
    document.getElementById("xdDeviceSeverityFilter")?.addEventListener("change", () => { deviceRiskBand = ""; devicePage = 0; renderDeviceRows(); });
    document.getElementById("xdDeviceStatusFilter")?.addEventListener("change", () => { devicePage = 0; renderDeviceRows(); });
    document.getElementById("xdDeviceSearch")?.addEventListener("input", () => { devicePage = 0; renderDeviceRows(); });
    document.getElementById("xdDevicePrevPage")?.addEventListener("click", () => { devicePage = Math.max(0, devicePage - 1); renderDeviceRows(); });
    document.getElementById("xdDeviceNextPage")?.addEventListener("click", () => { devicePage += 1; renderDeviceRows(); });
    document.getElementById("xdDeviceDialogClose")?.addEventListener("click", () => document.getElementById("xdDeviceDialog")?.close());
    document.getElementById("xdDeviceDialog")?.addEventListener("click", event => {
        if (event.target === event.currentTarget) event.currentTarget.close();
    });

    function renderDeviceSummary() {
        const devices = currentDevices;
        const offlineCount = devices.filter(device => device.online === false).length;
        const onlineCount = devices.filter(device => device.online === true).length;
        const criticalHigh = devices.filter(device => ["Critical", "High"].includes(device.risk)).length;
        const stillLoading = !devices.length && devicePageSource !== "error";
        const kpi = value => stillLoading ? "…" : value.toLocaleString();

        setText("xdDevicesSource", sourceLabel(devicePageSource));
        setText("xdDevicesTotal", kpi(devices.length));
        setText("xdDevicesCoverage", kpi(onlineCount));
        setText("xdDevicesOpenFindings", kpi(offlineCount));
        setText("xdDevicesUnknown", kpi(devices.filter(device => device.online == null).length));
        setText("xdDevicesCritical", kpi(criticalHigh));
        const loadMore = document.getElementById("xdDeviceLoadMore");
        if (loadMore) {
            loadMore.hidden = !deviceHasMore || devicePageSource !== "live";
            loadMore.disabled = false;
            loadMore.textContent = "Load More Devices";
        }

        const typeCounts = countBy(devices, device => device.type);
        destroy("deviceType");
        charts.deviceType = new Chart(document.getElementById("xdDeviceTypeChart"), {
            type: "bar",
            data: { labels: Object.keys(typeCounts), datasets: [{ label: "Devices", data: Object.values(typeCounts), backgroundColor: COLORS.accent }] },
            options: chartBase()
        });

        const severityCounts = countBy(devices, device => device.risk);
        const severityLabels = ["Critical", "High", "Medium", "Low", "Very Low", "Unknown"].filter(label => severityCounts[label]);
        destroy("deviceSeverity");
        charts.deviceSeverity = new Chart(document.getElementById("xdDeviceSeverityChart"), {
            type: "doughnut",
            data: { labels: severityLabels, datasets: [{ data: severityLabels.map(label => severityCounts[label]), backgroundColor: [COLORS.red, COLORS.amber, COLORS.accent2, COLORS.green, COLORS.muted] }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } } }
        });

        renderDeviceRows();
    }

    async function loadDevicePage(reset = false) {
        if (!window.ClarotyAPI) return;
        const loadMore = document.getElementById("xdDeviceLoadMore");
        if (loadMore) {
            loadMore.disabled = true;
            loadMore.textContent = reset ? "Loading…" : "Loading…";
        }
        const existing = ClarotyAPI.feedState("devices");
        currentDevices = summarizeDevices(existing.data);
        devicePageSource = existing.source === "pending" ? "pending" : existing.source;
        deviceHasMore = !existing.complete;
        renderDeviceSummary();
        if (existing.complete || existing.source === "error") return;
        setText("xdDevicesSource", `Loading Claroty devices (${existing.data.length.toLocaleString()} loaded)…`);
        try {
            const result = await ClarotyAPI.loadFeedPage("devices", DEVICE_PAGE_SIZE);
            devicePageSource = result.source;
            deviceHasMore = !result.complete;
            currentDevices = summarizeDevices(result.data);
            if (result.source === "error") setText("xdDevicesSource", `Claroty request failed: ${result.error || "Use Refresh to retry"}`);
            renderDeviceSummary();
        } catch (error) {
            devicePageSource = "error";
            deviceHasMore = false;
            setText("xdDevicesSource", `Claroty request failed: ${error.message}`);
            renderDeviceSummary();
        }
    }

    async function renderDevices() {
        if (ClarotyAPI.feedState("devices").data.length) {
            currentDevices = summarizeDevices(ClarotyAPI.feedState("devices").data);
            devicePageSource = ClarotyAPI.feedState("devices").source;
            deviceHasMore = !ClarotyAPI.feedState("devices").complete;
            renderDeviceSummary();
            return;
        }
        await loadDevicePage(true);
    }

    document.getElementById("xdDeviceLoadMore")?.addEventListener("click", () => loadDevicePage());

    document.querySelectorAll("[data-device-filter]").forEach(card => card.addEventListener("click", () => {
        const choice = card.dataset.deviceFilter;
        const statusSelect = document.getElementById("xdDeviceStatusFilter");
        const severitySelect = document.getElementById("xdDeviceSeverityFilter");
        deviceRiskBand = choice === "criticalhigh" ? "criticalhigh" : "";
        if (severitySelect) severitySelect.value = "";
        if (statusSelect) statusSelect.value = choice === "online" ? "true" : choice === "offline" ? "false" : choice === "unknown" ? "unknown" : "";
        document.querySelectorAll("[data-device-filter]").forEach(other => other.classList.toggle("active", other === card && choice !== "all"));
        devicePage = 0;
        renderDeviceRows();
        document.getElementById("xdDevicesTable")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }));

    let vulnerabilityRows = [];
    let vulnerabilityPage = 0;
    const VULNERABILITY_PAGE_SIZE = 100;

    function renderVulnerabilityRows() {
        const tbody = document.querySelector("#xdVulnTable tbody");
        if (!tbody) return;
        const query = (document.getElementById("xdVulnSearch")?.value || "").trim().toLowerCase();
        const visible = vulnerabilityRows.filter(item => !query || `${item.cve} ${item.asset}`.toLowerCase().includes(query));
        vulnerabilityPage = Math.min(vulnerabilityPage, Math.max(0, Math.ceil(visible.length / VULNERABILITY_PAGE_SIZE) - 1));
        const start = vulnerabilityPage * VULNERABILITY_PAGE_SIZE;
        const rows = visible.slice(start, start + VULNERABILITY_PAGE_SIZE);
        setText("xdVulnResultCount", `${visible.length ? start + 1 : 0}-${Math.min(start + VULNERABILITY_PAGE_SIZE, visible.length)} of ${visible.length.toLocaleString()} loaded findings${ClarotyAPI.feedState("relations").complete ? "" : " · more Claroty pages available"}`);
        tbody.innerHTML = rows.map(item => `<tr>
            <td><strong>${escapeHtml(item.cve)}</strong></td>
            <td>${escapeHtml(item.asset)}</td>
            <td><span class="pill ${pillClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
            <td>${Number(item.cvss || 0).toFixed(1)}</td>
            <td>${escapeHtml(item.status)}</td>
            <td>${escapeHtml(String(item.detected || "").slice(0, 10))}</td>
        </tr>`).join("") || `<tr><td colspan="6" class="device-empty">${vulnerabilityRows.length ? "No findings match this search." : "No Claroty findings loaded."}</td></tr>`;
        document.getElementById("xdVulnPrevPage").disabled = start === 0;
        document.getElementById("xdVulnNextPage").disabled = start + VULNERABILITY_PAGE_SIZE >= visible.length;
    }

    async function renderVulnerabilities(loadMore = false) {
        if (!window.ClarotyAPI) return;
        const button = document.getElementById("xdVulnLoadMore");
        if (button) button.disabled = true;
        const state = ClarotyAPI.feedState("relations");
        const result = loadMore || !state.data.length ? await ClarotyAPI.loadFeedPage("relations", 1000) : state;
        const vulnerabilities = (result.data || []).map((row, index) => ({
            cve: Array.isArray(row.vulnerability_cve_ids) ? row.vulnerability_cve_ids.join(", ") : row.vulnerability_cve_ids || row.vulnerability_name || row.vulnerability_id || `Finding ${index + 1}`,
            asset: row.device_name || row.device_uid || "Unknown device",
            severity: normalizeSeverity(row.vulnerability_adjusted_vulnerability_score_level),
            cvss: row.vulnerability_cvss_v3_score,
            status: row.patch_install_date ? "Remediated" : "Open",
            detected: row.vulnerability_last_updated || row.vulnerability_published_date || ""
        }));
        vulnerabilityRows = vulnerabilities;
        const open = vulnerabilities.filter(item => !String(item.status || "").toLowerCase().includes("remediated") && !String(item.status || "").toLowerCase().includes("closed"));
        const criticalHigh = vulnerabilities.filter(item => ["Critical", "High"].includes(item.severity)).length;

        setText("xdVulnSource", result.source === "live"
            ? `${sourceLabel(result.source)} · ${vulnerabilities.length.toLocaleString()} relations loaded${result.complete ? "" : " (partial)"}`
            : result.error || sourceLabel(result.source));
        setText("xdVulnTotal", vulnerabilities.length.toLocaleString());
        setText("xdVulnCriticalHigh", criticalHigh.toLocaleString());
        setText("xdVulnOpen", open.length.toLocaleString());
        setText("xdVulnClosed", (vulnerabilities.length - open.length).toLocaleString());
        if (button) {
            button.hidden = result.source !== "live" || result.complete;
            button.disabled = false;
        }

        const severityCounts = countBy(vulnerabilities, item => item.severity);
        const severityLabels = ["Critical", "High", "Medium", "Low", "Unknown"].filter(label => severityCounts[label]);
        destroy("vulnSeverity");
        charts.vulnSeverity = new Chart(document.getElementById("xdVulnSeverityChart"), {
            type: "doughnut",
            data: { labels: severityLabels, datasets: [{ data: severityLabels.map(label => severityCounts[label]), backgroundColor: [COLORS.red, COLORS.amber, COLORS.accent2, COLORS.green, COLORS.muted] }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } } }
        });

        renderVulnerabilityRows();
    }

    document.getElementById("xdVulnLoadMore")?.addEventListener("click", () => renderVulnerabilities(true));
    document.getElementById("xdVulnSearch")?.addEventListener("input", () => { vulnerabilityPage = 0; renderVulnerabilityRows(); });
    document.getElementById("xdVulnPrevPage")?.addEventListener("click", () => { vulnerabilityPage = Math.max(0, vulnerabilityPage - 1); renderVulnerabilityRows(); });
    document.getElementById("xdVulnNextPage")?.addEventListener("click", () => { vulnerabilityPage++; renderVulnerabilityRows(); });

    function mountRiskManagement() {
        const host = document.getElementById("riskManagementHost");
        const view = document.getElementById("integRiskView");
        if (host && view && view.parentElement !== host) host.appendChild(view);
        if (view) view.hidden = false;
    }

    function renderRiskManagement() {
        mountRiskManagement();
        if (window.PRI) window.PRI.activateTab("exec");
    }

    mountRiskManagement();
    return { renderDevices, renderVulnerabilities, renderRiskManagement, mountRiskManagement };
})();

window.XDOME = XDOME;