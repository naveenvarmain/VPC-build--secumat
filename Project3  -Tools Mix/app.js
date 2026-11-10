/* =====================================================================
    OT Platform — Security Operations Dashboard
    Claroty xDome is the primary live OT data source for device,
    vulnerability and risk modules.
   ===================================================================== */

const ACCENT = "#464feb";
const COLORS = { accent: "#464feb", accent2: "#6a72f0", green: "#22c55e", amber: "#f59e0b", red: "#ef4444", muted: "#8b90a3", grid: "#2a2f3d" };

Chart.defaults.color = COLORS.muted;
Chart.defaults.font.family = "Segoe UI, system-ui, sans-serif";
Chart.defaults.borderColor = COLORS.grid;

/* ---------- Navigation ---------- */
const navItems = document.querySelectorAll(".nav-item");
const panels = document.querySelectorAll(".panel");
const viewGroups = [
    { label: "Threat Intel menu", views: [["intel", "Threat Intel", "brain-circuit"], ["insider", "Insider Threat", "scan-eye"], ["threatmap", "Threat Map", "map"]] },
    { label: "Automation menu", views: [["automation", "Automation", "workflow"], ["roi", "Automation ROI", "chart-no-axes-column"], ["playbooks", "Playbooks", "book-open"], ["scorecard", "Exec Scorecard", "layout-dashboard"], ["alertfeed", "Live Alert Feed", "radio"], ["sla", "SLA Tracker", "timer"]] }
];
viewGroups.forEach(group => {
    const menu = `<nav class="settings-tabs" aria-label="${group.label}">${group.views.map(([id, name, icon]) => `<button type="button" class="settings-tab-btn" data-section-view="${id}" aria-pressed="false"><i data-lucide="${icon}" aria-hidden="true"></i>${name}</button>`).join("")}</nav>`;
    group.views.forEach(([id]) => document.getElementById(id)?.insertAdjacentHTML("afterbegin", menu));
});
if (window.lucide) lucide.createIcons();
function showSection(id) {
    panels.forEach(p => p.classList.toggle("active", p.id === id));
    const parent = viewGroups.find(group => group.views.some(([section]) => section === id))?.views[0][0] || id;
    navItems.forEach(n => n.classList.toggle("active", n.dataset.section === parent));
    document.querySelectorAll("[data-section-view]").forEach(button => {
        button.classList.toggle("active", button.dataset.sectionView === id);
        button.setAttribute("aria-pressed", String(button.dataset.sectionView === id));
    });
    if (id === "automation" || id === "playbooks") loadModuleAutomation();
    setTimeout(() => {
        document.querySelectorAll(`#${id} canvas`).forEach(canvas => {
            const chart = Chart.getChart(canvas);
            if (!chart) return;
            const width = canvas.parentElement.clientWidth;
            const height = canvas.parentElement.clientHeight;
            if (!width || !height) return;
            if (chart.width && chart.height && chart.options.responsive) {
                chart.resize();
                return;
            }
            const ratio = window.devicePixelRatio || 1;
            chart.options.responsive = false;
            canvas.width = width * ratio;
            canvas.height = height * ratio;
            chart.width = width;
            chart.height = height;
            chart.ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
            chart.update("none");
            chart.draw();
        });
    }, 50);
}
navItems.forEach(item => item.addEventListener("click", e => { e.preventDefault(); showSection(item.dataset.section); }));
document.querySelectorAll("[data-section-view]").forEach(button => button.addEventListener("click", () => showSection(button.dataset.sectionView)));
showSection("overview");
INTEGRATIONS.loadServerCredentialStatus();

/* ---------- Topbar widget, profile, and draft actions ---------- */
const widgetToggleButton = document.getElementById("manageWidgetsBtn");
const widgetPanel = document.getElementById("widgetManagerPanel");
const profileButton = document.getElementById("profileMenuBtn");
const profilePanel = document.getElementById("profileMenu");
const widgetPreferenceKey = "soc-overview-widgets-v2";
const legacyWidgetPreferenceKey = "soc-overview-widgets-v1";
const customWidgetStorageKey = "soc-overview-custom-widgets-v1";
const dashboardStorageKey = "soc-overview-dashboards-v1";
const currentDashboardStorageKey = "soc-overview-current-dashboard-v1";
const defaultOverviewWidgets = ["xdHomeDashboard", "xdOverviewLive", "xdOverviewAiWidget", "xdOverviewCoverageWidget", "socKpis", "incidentCharts", "activityHeatmap"];
function escapeOverviewWidgetText(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}
const customMetricCatalog = [
    { id: "devices", label: "Loaded devices", feed: "devices", value: state => state.data.length },
    { id: "highRiskDevices", label: "High-risk devices", feed: "devices", value: state => state.data.filter(row => /critical|high/i.test(String(row.risk_score || ""))).length },
    { id: "alerts", label: "Loaded alerts", feed: "alerts", value: state => state.data.length },
    { id: "unresolvedAlerts", label: "Unresolved alerts", feed: "alerts", value: state => state.data.filter(row => /open|unresolved|active|investigating/i.test(String(row.status || ""))).length },
    { id: "exploitedCves", label: "Known-exploited CVEs", feed: "vulnerabilities", value: state => state.data.filter(row => row.is_known_exploited === true || String(row.is_known_exploited).toLowerCase() === "true").length },
    { id: "events", label: "Loaded network events", feed: "events", value: state => state.data.length }
];

function readCustomOverviewWidgets() {
    try {
        const values = JSON.parse(localStorage.getItem(customWidgetStorageKey) || "[]");
        if (!Array.isArray(values)) return [];
        return values.filter(widget => widget && /^customMetric_[a-zA-Z0-9_-]{1,80}$/.test(widget.id) && customMetricCatalog.some(metric => metric.id === widget.metric) && typeof widget.name === "string").slice(0, 24);
    } catch {
        return [];
    }
}

function readSavedDashboards() {
    try {
        const values = JSON.parse(localStorage.getItem(dashboardStorageKey) || "[]");
        return Array.isArray(values) ? values.filter(item => item && typeof item.id === "string" && typeof item.name === "string" && Array.isArray(item.widgets)).slice(0, 20) : [];
    } catch {
        return [];
    }
}

function readOverviewWidgetPreferences() {
    try {
        const allowed = new Set([...defaultOverviewWidgets, ...readCustomOverviewWidgets().map(widget => widget.id)]);
        const currentDashboardId = localStorage.getItem(currentDashboardStorageKey);
        const currentDashboard = readSavedDashboards().find(item => item.id === currentDashboardId);
        if (currentDashboard) return currentDashboard.widgets.filter(widgetId => allowed.has(widgetId));
        const value = JSON.parse(localStorage.getItem(widgetPreferenceKey) || "null");
        if (Array.isArray(value)) return value.filter(widgetId => allowed.has(widgetId));
        const legacy = JSON.parse(localStorage.getItem(legacyWidgetPreferenceKey) || "null");
        return Array.isArray(legacy)
            ? [...new Set([...legacy, "xdOverviewAiWidget", "xdOverviewCoverageWidget"])].filter(widgetId => allowed.has(widgetId))
            : defaultOverviewWidgets;
    } catch {
        return defaultOverviewWidgets;
    }
}

function applyOverviewWidgetPreferences() {
    const enabled = new Set(readOverviewWidgetPreferences());
    const customOptions = document.getElementById("customWidgetOptions");
    const customWidgets = readCustomOverviewWidgets();
    if (customOptions) customOptions.innerHTML = customWidgets.map(widget => `<label><input type="checkbox" data-overview-widget="${widget.id}" /> ${escapeOverviewWidgetText(widget.name)}</label>`).join("");
    document.querySelectorAll("[data-overview-widget]").forEach(input => {
        const widgetId = input.dataset.overviewWidget;
        const visible = enabled.has(widgetId);
        input.checked = visible;
        const section = document.querySelector(`[data-widget-id="${widgetId}"]`);
        if (section) section.classList.toggle("overview-widget-hidden", !visible);
    });
    renderCustomOverviewWidgets();
    refreshDashboardControls();
}

function renderCustomOverviewWidgets() {
    const host = document.getElementById("customOverviewWidgets");
    if (!host || !window.ClarotyAPI) return;
    const enabled = new Set(readOverviewWidgetPreferences());
    host.innerHTML = readCustomOverviewWidgets().map(widget => {
        const metric = customMetricCatalog.find(item => item.id === widget.metric);
        const state = ClarotyAPI.feedState(metric.feed);
        const available = state.source === "live";
        const value = available ? metric.value(state).toLocaleString() : "—";
        const status = available ? state.complete ? "Live" : "Live · partial" : state.source === "error" ? "Request failed" : "Awaiting live feed";
        return `<article class="custom-metric-widget${enabled.has(widget.id) ? "" : " overview-widget-hidden"}" data-widget-id="${widget.id}"><div><h3>${escapeOverviewWidgetText(widget.name)}</h3><span>${escapeOverviewWidgetText(metric.label)} · ${escapeOverviewWidgetText(status)}</span></div><strong>${value}</strong><button type="button" class="custom-widget-remove" data-remove-custom-widget="${widget.id}" aria-label="Remove ${escapeOverviewWidgetText(widget.name)}">×</button></article>`;
    }).join("");
    host.querySelectorAll("[data-remove-custom-widget]").forEach(button => button.addEventListener("click", () => {
        const removeId = button.dataset.removeCustomWidget;
        const remaining = readCustomOverviewWidgets().filter(widget => widget.id !== removeId);
        try { localStorage.setItem(customWidgetStorageKey, JSON.stringify(remaining)); } catch { /* storage may be unavailable */ }
        const enabledNow = readOverviewWidgetPreferences().filter(widgetId => widgetId !== removeId);
        try { localStorage.setItem(widgetPreferenceKey, JSON.stringify(enabledNow)); } catch { /* storage may be unavailable */ }
        applyOverviewWidgetPreferences();
    }));
}

function refreshDashboardControls() {
    const select = document.getElementById("savedDashboardSelect");
    if (!select) return;
    const current = localStorage.getItem(currentDashboardStorageKey) || "";
    select.innerHTML = `<option value="">Current Overview</option>${readSavedDashboards().map(item => `<option value="${escapeOverviewWidgetText(item.id)}">${escapeOverviewWidgetText(item.name)}</option>`).join("")}`;
    select.value = current;
    const remove = document.getElementById("deleteSavedDashboard");
    if (remove) remove.disabled = !current;
}

async function loadModuleAnalytics() {
    const grid = document.getElementById("moduleAnalyticsGrid");
    const status = document.getElementById("moduleAnalyticsSource");
    const breakdown = document.getElementById("moduleAnalyticsBreakdown");
    if (!grid || !status || !breakdown) return;
    status.textContent = "Loading local module records…";
    try {
        const response = await fetch("/api/analytics/modules", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Analytics API ${response.status}`);
        const totals = payload.totals || {};
        const metrics = [
            ["Assets", totals.assets], ["Vulnerabilities", totals.vulnerabilities],
            ["Alerts", totals.alerts], ["Open items", totals.open_items],
            ["SECUMAT audits", totals.audits], ["Audit assignments", totals.assignments],
            ["Average risk score", totals.average_risk_score == null ? "Not calculated" : `${totals.average_risk_score}/100`]
        ];
        grid.innerHTML = metrics.map(([label, value]) => `<div class="module-analytics-metric"><span>${escapeOverviewWidgetText(label)}</span><strong>${value == null ? "0" : escapeOverviewWidgetText(String(value))}</strong></div>`).join("");
        const moduleRows = Object.entries(payload.modules || {}).map(([name, count]) => `<tr><td>${escapeOverviewWidgetText(name.replaceAll("_", " "))}</td><td>${escapeOverviewWidgetText(String(count))}</td></tr>`).join("");
        breakdown.innerHTML = `<table><thead><tr><th>Local module</th><th>Records</th></tr></thead><tbody>${moduleRows || `<tr><td colspan="2">No records saved yet.</td></tr>`}</tbody></table>`;
        const hasRecords = Object.values(payload.modules || {}).some(value => Number(value) > 0);
        status.textContent = hasRecords
            ? `Local module store · updated ${new Date(payload.generated_at).toLocaleString()}. Live xDome feeds are reported separately above.`
            : "No local module records yet. Live xDome availability is reported separately; no sample counts are included here.";
    } catch (error) {
        status.textContent = `Module analytics unavailable: ${error.message}`;
        grid.replaceChildren();
        breakdown.replaceChildren();
    }
}

async function loadModuleAutomation() {
    const playbooksElement = document.getElementById("moduleAutomationPlaybooks");
    const runsElement = document.getElementById("moduleAutomationRuns");
    const status = document.getElementById("moduleAutomationStatus");
    if (!playbooksElement || !runsElement || !status) return;
    status.textContent = "Loading local dry-run playbooks…";
    try {
        const response = await fetch("/api/automation/playbooks", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Automation API ${response.status}`);
        playbooksElement.innerHTML = (payload.playbooks || []).map(playbook => `<article class="module-automation-item"><div><h3>${escapeOverviewWidgetText(playbook.name)}</h3><p>Modules: ${escapeOverviewWidgetText(playbook.modules.join(", "))}</p><small>Dry-run only · external actions disabled</small></div><button type="button" class="xd-command" data-module-playbook="${escapeOverviewWidgetText(playbook.id)}">Run dry-run</button></article>`).join("") || `<p>No local playbooks are defined.</p>`;
        runsElement.innerHTML = (payload.runs || []).slice(0, 10).map(run => `<div class="module-automation-run"><strong>${escapeOverviewWidgetText(run.requested_module)}</strong><span>${escapeOverviewWidgetText(new Date(run.created_at).toLocaleString())}</span><span>Dry-run · no external actions</span></div>`).join("") || `<p>No automation runs recorded.</p>`;
        status.textContent = "Runs read local records and only create plans. They do not invoke vendor APIs or perform external actions.";
    } catch (error) {
        status.textContent = `Automation API unavailable: ${error.message}`;
        playbooksElement.replaceChildren();
        runsElement.replaceChildren();
    }
}

async function runModuleAutomation(playbookId, button) {
    const status = document.getElementById("moduleAutomationStatus");
    if (button) button.disabled = true;
    if (status) status.textContent = "Recording dry-run…";
    try {
        const response = await fetch("/api/automation/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ module: playbookId })
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Automation API ${response.status}`);
        if (status) status.textContent = `Dry-run ${payload.id} recorded. No vendor calls or external actions were executed.`;
        await loadModuleAutomation();
    } catch (error) {
        if (status) status.textContent = `Dry-run failed: ${error.message}`;
    } finally {
        if (button) button.disabled = false;
    }
}

document.getElementById("refreshModuleAnalytics")?.addEventListener("click", loadModuleAnalytics);
document.getElementById("refreshModuleAutomation")?.addEventListener("click", loadModuleAutomation);
document.getElementById("moduleAutomationPlaybooks")?.addEventListener("click", event => {
    const button = event.target.closest("[data-module-playbook]");
    if (button) runModuleAutomation(button.dataset.modulePlaybook, button);
});

function saveDashboardPreset(name, widgetIds, replaceCurrent = true) {
    const normalized = String(name || "").trim().slice(0, 48);
    if (!normalized) throw new Error("Enter a dashboard name.");
    const allowed = new Set([...defaultOverviewWidgets, ...readCustomOverviewWidgets().map(widget => widget.id)]);
    const widgets = [...new Set(widgetIds.filter(widgetId => allowed.has(widgetId)))];
    if (!widgets.length) throw new Error("Choose at least one widget.");
    const currentId = localStorage.getItem(currentDashboardStorageKey);
    const dashboards = readSavedDashboards();
    const existing = replaceCurrent ? dashboards.find(item => item.id === currentId) : null;
    const id = existing?.id || `dashboard_${Date.now().toString(36)}`;
    const updated = { id, name: normalized, widgets };
    const next = existing ? dashboards.map(item => item.id === id ? updated : item) : [...dashboards, updated].slice(-20);
    localStorage.setItem(dashboardStorageKey, JSON.stringify(next));
    localStorage.setItem(currentDashboardStorageKey, id);
    localStorage.setItem(widgetPreferenceKey, JSON.stringify(widgets));
    refreshDashboardControls();
    applyOverviewWidgetPreferences();
    return updated;
}

function loadDashboardPreset(id) {
    const dashboard = readSavedDashboards().find(item => item.id === id);
    if (!dashboard) return;
    localStorage.setItem(currentDashboardStorageKey, id);
    localStorage.setItem(widgetPreferenceKey, JSON.stringify(dashboard.widgets));
    applyOverviewWidgetPreferences();
}

function closeHeaderPanels() {
    if (widgetPanel) widgetPanel.hidden = true;
    if (profilePanel) profilePanel.hidden = true;
    widgetToggleButton?.setAttribute("aria-expanded", "false");
    profileButton?.setAttribute("aria-expanded", "false");
}

applyOverviewWidgetPreferences();
loadModuleAnalytics();
loadModuleAutomation();
widgetToggleButton?.addEventListener("click", event => {
    event.stopPropagation();
    const opening = widgetPanel.hidden;
    closeHeaderPanels();
    widgetPanel.hidden = !opening;
    widgetToggleButton.setAttribute("aria-expanded", String(opening));
    if (opening) applyOverviewWidgetPreferences();
});
widgetPanel?.addEventListener("change", event => {
    if (!event.target.matches("[data-overview-widget]")) return;
    const enabled = [...widgetPanel.querySelectorAll("[data-overview-widget]:checked")].map(input => input.dataset.overviewWidget);
    try { localStorage.setItem(widgetPreferenceKey, JSON.stringify(enabled)); } catch { /* storage may be unavailable */ }
    try { localStorage.removeItem(currentDashboardStorageKey); } catch { /* storage may be unavailable */ }
    applyOverviewWidgetPreferences();
});
document.getElementById("resetOverviewWidgets")?.addEventListener("click", () => {
    try { localStorage.removeItem(widgetPreferenceKey); } catch { /* storage may be unavailable */ }
    try { localStorage.removeItem(legacyWidgetPreferenceKey); } catch { /* storage may be unavailable */ }
    try { localStorage.removeItem(currentDashboardStorageKey); } catch { /* storage may be unavailable */ }
    applyOverviewWidgetPreferences();
});
document.getElementById("savedDashboardSelect")?.addEventListener("change", event => {
    if (event.target.value) {
        loadDashboardPreset(event.target.value);
        const dashboard = readSavedDashboards().find(item => item.id === event.target.value);
        if (dashboard) document.getElementById("savedDashboardName").value = dashboard.name;
    }
    else {
        try { localStorage.removeItem(currentDashboardStorageKey); } catch { /* storage may be unavailable */ }
        applyOverviewWidgetPreferences();
    }
});
document.getElementById("saveDashboardPreset")?.addEventListener("click", () => {
    const input = document.getElementById("savedDashboardName");
    const status = document.getElementById("dashboardManagerStatus");
    const name = input.value.trim();
    try {
        const dashboard = saveDashboardPreset(name, readOverviewWidgetPreferences());
        input.value = "";
        input.placeholder = `Saved: ${dashboard.name}`;
        if (status) status.textContent = `Saved dashboard: ${dashboard.name}.`;
    } catch (error) {
        if (status) status.textContent = error.message;
        input.setCustomValidity(error.message);
        input.reportValidity();
        input.addEventListener("input", () => input.setCustomValidity(""), { once: true });
    }
});
document.getElementById("deleteSavedDashboard")?.addEventListener("click", () => {
    const select = document.getElementById("savedDashboardSelect");
    const id = select.value;
    if (!id) return;
    try {
        localStorage.setItem(dashboardStorageKey, JSON.stringify(readSavedDashboards().filter(item => item.id !== id)));
        localStorage.removeItem(currentDashboardStorageKey);
    } catch { /* storage may be unavailable */ }
    refreshDashboardControls();
    applyOverviewWidgetPreferences();
    const status = document.getElementById("dashboardManagerStatus");
    if (status) status.textContent = "Dashboard deleted.";
});
document.getElementById("addCustomWidget")?.addEventListener("click", () => {
    const nameInput = document.getElementById("customWidgetName");
    const status = document.getElementById("dashboardManagerStatus");
    const metricId = document.getElementById("customWidgetMetric").value;
    const metric = customMetricCatalog.find(item => item.id === metricId);
    const name = nameInput.value.trim().slice(0, 36) || metric?.label;
    if (!metric) return;
    const widgets = readCustomOverviewWidgets();
    if (widgets.length >= 24) {
        if (status) status.textContent = "Remove a custom widget before adding another.";
        nameInput.setCustomValidity("Remove a custom widget before adding another.");
        nameInput.reportValidity();
        return;
    }
    const id = `customMetric_${crypto.randomUUID?.().replaceAll("-", "") || Date.now().toString(36)}`;
    widgets.push({ id, name, metric: metric.id });
    try {
        localStorage.setItem(customWidgetStorageKey, JSON.stringify(widgets));
        localStorage.removeItem(currentDashboardStorageKey);
        const enabled = readOverviewWidgetPreferences();
        localStorage.setItem(widgetPreferenceKey, JSON.stringify([...new Set([...enabled, id])]));
    } catch {
        if (status) status.textContent = "Could not save this widget in browser storage.";
        nameInput.setCustomValidity("Could not save this widget in browser storage.");
        nameInput.reportValidity();
        return;
    }
    nameInput.value = "";
    nameInput.setCustomValidity("");
    applyOverviewWidgetPreferences();
    if (status) status.textContent = `Added live metric widget: ${name}.`;
});

function openSettingsDestination(tab) {
    closeHeaderPanels();
    window.showSection("integrations");
    document.querySelector(`#settingsTabs [data-settings-tab="${tab}"]`)?.click();
    if (tab === "integrations") setTimeout(() => document.getElementById("ifc-entra")?.scrollIntoView({ behavior: "smooth", block: "center" }), 200);
}

profileButton?.addEventListener("click", event => {
    event.stopPropagation();
    const opening = profilePanel.hidden;
    closeHeaderPanels();
    profilePanel.hidden = !opening;
    profileButton.setAttribute("aria-expanded", String(opening));
    const status = document.getElementById("profileIdentityStatus");
    if (status) {
        const configured = typeof INTEGRATIONS !== "undefined" && INTEGRATIONS.isConfigured("entra");
        status.textContent = configured ? "Entra settings saved; connection not verified. SSO/MFA are not enforced." : "No identity provider is configured; SSO/MFA are not enforced.";
    }
});
profilePanel?.addEventListener("click", event => {
    const action = event.target.closest("[data-profile-action]")?.dataset.profileAction;
    if (!action) return;
    openSettingsDestination(action === "profile" ? "profile" : action === "sso" ? "integrations" : "users");
});
document.querySelectorAll("[data-close-popover]").forEach(button => button.addEventListener("click", closeHeaderPanels));
document.addEventListener("click", event => {
    if (!widgetPanel?.contains(event.target) && !widgetToggleButton?.contains(event.target) && !profilePanel?.contains(event.target) && !profileButton?.contains(event.target)) closeHeaderPanels();
});
document.addEventListener("keydown", event => { if (event.key === "Escape") closeHeaderPanels(); });

/* ---------- Global search across loaded security records ---------- */
const globalSearchInput = document.getElementById("gsInput");
const globalSearchResults = document.getElementById("gsResults");
const globalSearchClear = document.getElementById("gsClear");
const globalSearchButton = document.getElementById("gsSearchBtn");
let globalSearchTimer = null;
let globalSearchGeneration = 0;
let globalTicketCache = { data: [], source: "unavailable", loadedAt: 0 };

function globalSearchText(value) {
    if (value == null) return "";
    if (Array.isArray(value)) return value.map(globalSearchText).join(" ");
    if (typeof value === "object") return Object.values(value).map(globalSearchText).join(" ");
    return String(value);
}

function globalSearchAdd(matches, kind, title, meta, searchable, route, index, source, severity = "") {
    if (!globalSearchText(searchable).toLowerCase().includes(globalSearchInput.value.trim().toLowerCase())) return;
    matches.push({ kind, title, meta, route, index, source, severity });
}

function collectGlobalSearchMatches(query) {
    const matches = [];
    const states = Object.fromEntries(["devices", "alerts", "vulnerabilities", "relations", "events"].map(feed => [feed, ClarotyAPI.feedState(feed)]));
    const eventDevicesByAlert = new Map();
    states.events.data.forEach(event => {
        if (event.alert_id == null) return;
        const names = [event.side_a_name, event.side_b_name, event.side_a_ip, event.side_b_ip].filter(Boolean);
        const current = eventDevicesByAlert.get(String(event.alert_id)) || [];
        eventDevicesByAlert.set(String(event.alert_id), [...new Set([...current, ...names])]);
    });

    states.alerts.data.forEach((row, index) => {
        const title = row.alert_name || row.alert_type_name || row.id || "xDome alert";
        const devices = eventDevicesByAlert.get(String(row.id)) || [];
        const hostnames = `${row.alert_name || ""} ${row.description || ""}`.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || [];
        const deviceText = [...new Set([...devices, ...hostnames])].join(", ") || "Device not linked in loaded network events";
        globalSearchAdd(matches, "Alert", title, `${row.status || "Status unknown"} · ${deviceText}`, { ...row, deviceText }, "alertfeed", index, states.alerts.source, row.severity || row.risk_level || "");
    });
    states.devices.data.forEach((row, index) => {
        const title = row.device_name || row.uid || "Unknown device";
        const ip = Array.isArray(row.ip_list) ? row.ip_list.join(", ") : row.ip_list || "";
        globalSearchAdd(matches, "Device", title, [row.site_name, row.device_type, ip, row.risk_score].filter(Boolean).join(" · "), row, "devices", index, states.devices.source, row.risk_score || "");
    });
    states.vulnerabilities.data.forEach((row, index) => {
        const ids = Array.isArray(row.cve_ids) ? row.cve_ids.join(", ") : row.cve_ids || "";
        const title = ids || row.name || row.id || "Vulnerability";
        globalSearchAdd(matches, "CVE", title, [row.adjusted_vulnerability_score_level, row.affected_devices_count == null ? "" : `${row.affected_devices_count} affected devices`].filter(Boolean).join(" · "), row, "threats", index, states.vulnerabilities.source, row.adjusted_vulnerability_score_level || "CVE");
    });
    states.relations.data.forEach((row, index) => {
        const cves = globalSearchText(row.vulnerability_cve_ids || row.vulnerability_name || row.vulnerability_id);
        const title = row.device_name || row.device_uid || "Device vulnerability";
        globalSearchAdd(matches, "CVE / Device", title, `${cves || "CVE unavailable"} · ${row.vulnerability_adjusted_vulnerability_score_level || "Risk unknown"}`, row, "threats", index, states.relations.source, row.vulnerability_adjusted_vulnerability_score_level || "CVE");
    });
    states.events.data.forEach((row, index) => {
        const sourceDevice = row.side_a_name || row.side_a_ip || "Unknown source";
        const destinationDevice = row.side_b_name || row.side_b_ip || "Unknown destination";
        globalSearchAdd(matches, "Event / IOC", row.event_type || row.description || "Network event", `${sourceDevice} → ${destinationDevice} · ${row.protocol || "Protocol unknown"}`, row, "network", index, states.events.source, row.malicious_ip_severity || "IOC");
    });

    (typeof alertFeedItems === "undefined" ? [] : alertFeedItems).forEach((row, index) => {
        const device = row.deviceName || row.device_name || "Device not provided by sample feed";
        globalSearchAdd(matches, "SOC Alert", row.title, `${row.sev || "Severity unknown"} · ${row.src || "Unknown source"} · ${device}`, row, "alertfeed", index, row.dataSource || "sample", row.sev || "Alert");
    });
    return matches.slice(0, 30);
}

async function loadGlobalTicketRecords() {
    if (Date.now() - globalTicketCache.loadedAt < 20000) return globalTicketCache;
    if (!window.SwimlaneAPI) return globalTicketCache;
    try {
        const response = await SwimlaneAPI.getRecords({ range: 90 });
        globalTicketCache = { data: response.data || [], source: response.source || "unavailable", loadedAt: Date.now() };
    } catch {
        globalTicketCache = { data: [], source: "error", loadedAt: Date.now() };
    }
    return globalTicketCache;
}

function renderGlobalSearchResults(matches, query) {
    if (!globalSearchResults) return;
    const groups = new Map();
    matches.forEach((match, index) => {
        match.resultIndex = index;
        if (!groups.has(match.kind)) groups.set(match.kind, []);
        groups.get(match.kind).push(match);
    });
    const rows = [...groups.entries()].map(([kind, items]) => `<section class="gs-section"><div class="gs-section-title">${kind}<span class="gs-section-count">${items.length}</span></div>${items.map(item => `<button type="button" class="gs-item" role="option" data-global-result="${item.resultIndex}" data-global-kind="${item.kind}" data-global-index="${item.index}" data-global-route="${item.route}" data-global-source="${item.source}"><span class="gs-item-icon">${item.kind.includes("CVE") ? "◈" : item.kind.includes("Device") ? "▣" : item.kind.includes("Alert") ? "⚠" : item.kind.includes("IOC") ? "⌕" : "▤"}</span><span class="gs-item-body"><span class="gs-item-title">${esc(item.title)}</span><span class="gs-item-meta">${esc(item.meta || "No additional details")}</span></span><span class="gs-item-badge ${esc(item.severity || item.kind)}">${esc(item.source === "live" ? "Live" : item.source === "mock" ? "Sample" : item.source === "error" ? "Error" : item.source === "pending" ? "Loading" : item.kind)}</span></button>`).join("")}</section>`).join("");
    const feedStates = ["devices", "alerts", "vulnerabilities", "relations", "events"].map(feed => ClarotyAPI.feedState(feed));
    const partial = feedStates.some(state => state.loading || state.source === "live" && !state.complete);
    const recognizedIoc = typeof classifyIoc === "function" ? classifyIoc(query) : null;
    const iocAction = recognizedIoc ? `<button type="button" class="gs-item" data-global-ioc="${esc(query)}"><span class="gs-item-icon">⌕</span><span class="gs-item-body"><span class="gs-item-title">Enrich ${esc(recognizedIoc.toUpperCase())}: ${esc(query)}</span><span class="gs-item-meta">Open Threat Intel lookups</span></span><span class="gs-item-badge IOC">IOC</span></button>` : "";
    const empty = !matches.length && !iocAction ? `<div class="gs-empty">No matching loaded records. Live search covers records currently loaded by each feed.</div>` : "";
    globalSearchResults.innerHTML = `${rows}${iocAction}${empty}<div class="gs-search-foot">${partial ? "Some feeds are still loading; results may be partial." : "Searches currently loaded feeds and records."}</div>`;
    globalSearchResults.hidden = false;
    globalSearchInput?.setAttribute("aria-expanded", "true");
}

async function runGlobalSearch() {
    const query = globalSearchInput?.value.trim() || "";
    if (!globalSearchResults || !query) {
        if (globalSearchResults) globalSearchResults.hidden = true;
        globalSearchInput?.setAttribute("aria-expanded", "false");
        return;
    }
    globalSearchClear.hidden = false;
    if (query.length < 2) {
        globalSearchResults.innerHTML = `<div class="gs-empty">Enter at least 2 characters.</div>`;
        globalSearchResults.hidden = false;
        return;
    }
    const generation = ++globalSearchGeneration;
    let matches = collectGlobalSearchMatches(query);
    renderGlobalSearchResults(matches.slice(0, 24), query);
    const tickets = await loadGlobalTicketRecords();
    if (generation !== globalSearchGeneration || query !== globalSearchInput.value.trim()) return;
    tickets.data.forEach((row, index) => {
        const title = row.title || row.id || "Incident ticket";
        globalSearchAdd(matches, "Ticket", title, `${row.severity || "Severity unknown"} · ${row.status || "Status unknown"} · ${row.id || "No ID"}`, row, "operations", index, tickets.source, row.severity || "Ticket");
    });
    const ioc = typeof classifyIoc === "function" ? classifyIoc(query) : null;
    renderGlobalSearchResults(matches.slice(0, 24), query);
    if (ioc && !matches.length) globalSearchResults.insertAdjacentHTML("afterbegin", `<div class="gs-empty">No exact local record match for this ${esc(ioc.toUpperCase())}. Use the Threat Intel action below for external lookups.</div>`);
}

globalSearchInput?.addEventListener("input", () => {
    clearTimeout(globalSearchTimer);
    globalSearchTimer = setTimeout(runGlobalSearch, 180);
});
globalSearchInput?.addEventListener("keydown", event => {
    if (event.key === "Escape") { globalSearchResults.hidden = true; globalSearchInput.setAttribute("aria-expanded", "false"); return; }
    if (event.key === "Enter") {
        event.preventDefault();
        globalSearchResults.querySelector(".gs-item")?.click();
    }
});
globalSearchButton?.addEventListener("click", runGlobalSearch);
globalSearchClear?.addEventListener("click", () => {
    globalSearchInput.value = "";
    globalSearchClear.hidden = true;
    globalSearchResults.hidden = true;
    globalSearchInput.setAttribute("aria-expanded", "false");
    globalSearchInput.focus();
});
globalSearchResults?.addEventListener("click", event => {
    const item = event.target.closest("[data-global-result]");
    if (item) {
        const kind = item.dataset.globalKind;
        const route = item.dataset.globalRoute;
        const index = Number(item.dataset.globalIndex);
        showSection(route);
        if (["Alert", "Device", "CVE", "CVE / Device", "Event / IOC"].includes(kind)) {
            setTimeout(() => window.XDPortal?.openSearchResult?.(kind, index), 0);
        } else if (kind === "SOC Alert") {
            const alert = alertFeedItems[index];
            if (alert) openAlert(alert);
        } else if (kind === "Ticket") {
            const ticket = globalTicketCache.data[index];
            if (ticket) {
                drawerTitle.textContent = ticket.title || ticket.id || "Incident ticket";
                drawerSub.textContent = `${ticket.id || "No record ID"} · ${globalTicketCache.source === "live" ? "Live Swimlane" : "Sample data"}`;
                drawerBody.innerHTML = `<div class="xd-detail">${Object.entries(ticket).map(([key, value]) => `<div><b>${esc(key.replaceAll("_", " "))}</b><span>${esc(globalSearchText(value) || "—")}</span></div>`).join("")}</div>`;
                drawer.classList.add("open");
                drawerOverlay.classList.add("open");
                drawer.setAttribute("aria-hidden", "false");
            }
        }
        globalSearchResults.hidden = true;
        globalSearchInput.setAttribute("aria-expanded", "false");
        return;
    }
    const ioc = event.target.closest("[data-global-ioc]")?.dataset.globalIoc;
    if (ioc) {
        showSection("intel");
        const input = document.getElementById("iocInput");
        if (input) { input.value = ioc; input.dispatchEvent(new Event("input", { bubbles: true })); }
        globalSearchResults.hidden = true;
        globalSearchInput.setAttribute("aria-expanded", "false");
    }
});
document.addEventListener("click", event => {
    if (!event.target.closest("#gsWrap")) {
        if (globalSearchResults) globalSearchResults.hidden = true;
        globalSearchInput?.setAttribute("aria-expanded", "false");
    }
});
document.addEventListener("keydown", event => {
    if (event.key === "/" && !event.ctrlKey && !event.metaKey && !["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName)) {
        event.preventDefault();
        globalSearchInput?.focus();
    }
});

function createLocalSecurityDraft(type = "summary", focus = "") {
    const analysis = window.XDPortal?.analyzeLoadedData?.();
    const metrics = analysis?.metrics || {};
    const coverage = analysis?.coverage?.join("\n") || "xDome feed coverage is unavailable.";
    const summary = analysis?.summary || "Live xDome analysis is unavailable. Configure Claroty and refresh live feeds.";
    const displayMetric = value => value == null ? "not available until its feed loads" : Number(value).toLocaleString();
    const focusLine = focus ? `Focus: ${focus}` : "Focus: currently loaded xDome evidence";
    const lines = type === "response"
        ? ["Response draft · local rule-based output", focusLine, `${displayMetric(metrics.unresolvedAlerts)} unresolved alerts and ${displayMetric(metrics.criticalDevices)} critical-risk devices are present in loaded feeds.`, "1. Verify the alert and affected device in Claroty.", "2. Correlate recent network events and vulnerability context.", "3. Coordinate any containment with the connected SOC/EDR owner; no action was executed here.", "4. Record disposition in the source system and verify recovery.", "", "Feed coverage:", coverage]
        : type === "policy"
            ? ["Zero Trust policy draft · local rule-based output", focus ? `Focus: ${focus}` : "Scope: OT asset access", "Verify identity with phishing-resistant authentication; evaluate current managed/compliant device posture, certificate status, and endpoint risk.", "Deny known noncompliant devices, invalid certificates, and critical endpoint risk; step up when evidence is unknown.", "Limit authorization to the requested resource and record each decision.", "Draft only: no identity provider or policy enforcement point is connected.", "", "Live xDome context:", summary]
            : ["xDome security summary · local rule-based output", focusLine, summary, "", "Feed coverage:", coverage, "", "This is not generative AI. Verify details in Claroty before taking action."];
    return lines.join("\n");
}

const overviewWidgetCatalog = [
    { id: "xdHomeDashboard", label: "Live xDome Home", keywords: /\b(asset|device|inventory|ot|ics|network|alert|cve|vulnerability|risk)\b/i },
    { id: "xdOverviewLive", label: "Live inventory overview", keywords: /\b(inventory|device|manufacturer|site|category|cve|vulnerability|exposure|risk|alert)\b/i },
    { id: "xdOverviewAiWidget", label: "Live xDome analysis", keywords: /\b(summary|analysis|insight|critical|priority)\b/i },
    { id: "xdOverviewCoverageWidget", label: "xDome feed coverage", keywords: /\b(coverage|feed|connector|source|completeness|data status)\b/i },
    { id: "socKpis", label: "SOC KPI strip", keywords: /\b(kpi|mttd|mttr|sla|soc|performance|executive|metrics)\b/i },
    { id: "incidentCharts", label: "Incident trend charts", keywords: /\b(trend|chart|incident|alert|timeline|volume|over time)\b/i },
    { id: "activityHeatmap", label: "Incident activity heatmap", keywords: /\b(activity|heat ?map|weekly|calendar)\b/i }
];

function renderDashboardBuilder() {
    const history = document.getElementById("aiChatHistory");
    const article = document.createElement("article");
    article.className = "ai-chat-message ai-dashboard-builder";
    const heading = document.createElement("strong");
    heading.textContent = "Create your custom dashboard";
    const description = document.createElement("p");
    description.textContent = "Describe your dashboard goal in natural language. For a more targeted dashboard, mention specific networks, categories, manufacturers, device types, or risk scores.";
    const form = document.createElement("form");
    form.id = "aiDashboardForm";
    const label = document.createElement("label");
    label.htmlFor = "aiDashboardGoal";
    label.textContent = "Dashboard goal";
    const textarea = document.createElement("textarea");
    textarea.id = "aiDashboardGoal";
    textarea.maxLength = 300;
    textarea.required = true;
    textarea.rows = 3;
    textarea.placeholder = "Show critical OT devices, vulnerable assets, and alert trends…";
    const footer = document.createElement("div");
    footer.className = "ai-dashboard-form-footer";
    const count = document.createElement("output");
    count.id = "aiDashboardGoalCount";
    count.textContent = "0/300 Characters";
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "ai-run-btn";
    submit.textContent = "Create dashboard";
    footer.append(count, submit);
    const status = document.createElement("p");
    status.dataset.aiDashboardStatus = "true";
    status.setAttribute("role", "status");
    status.textContent = copilotTokenEndpoint()
        ? "Copilot Studio can select from the existing Overview widgets."
        : "Generated from predefined widgets. Connect Copilot Studio in Integrations for model-generated layouts.";
    form.append(label, textarea, footer, status);
    article.append(heading, description, form);
    history.append(article);
    textarea.addEventListener("input", () => { count.textContent = `${textarea.value.length}/300 Characters`; });
    textarea.focus();
    history.scrollTop = history.scrollHeight;
}

function localDashboardWidgetSelection(goal) {
    const selected = overviewWidgetCatalog.filter(widget => widget.keywords.test(goal)).map(widget => widget.id);
    return selected.length ? selected : ["xdHomeDashboard", "xdOverviewLive", "xdOverviewAiWidget"];
}

async function generateCustomDashboard(goal) {
    let widgetIds = [];
    let generatedBy = "Local predefined-widget matching";
    if (copilotTokenEndpoint()) {
        try {
            const catalog = overviewWidgetCatalog.map(({ id, label }) => ({ id, label }));
            const answer = await askCopilotStudio(`Select the best existing dashboard widgets for this goal. Do not invent widgets or data. Return JSON only in this exact shape: {"widgets":["widget-id"]}. Allowed widgets: ${JSON.stringify(catalog)}. User goal: ${goal}`);
            const json = answer.match(/\{[\s\S]*\}/)?.[0];
            const parsed = JSON.parse(json || answer);
            const allowed = new Set(overviewWidgetCatalog.map(widget => widget.id));
            widgetIds = [...new Set((Array.isArray(parsed.widgets) ? parsed.widgets : []).filter(id => allowed.has(id)))];
            if (!widgetIds.length) throw new Error("Copilot returned no supported widget IDs.");
            generatedBy = "Copilot Studio";
        } catch {
            widgetIds = localDashboardWidgetSelection(goal);
            generatedBy = "Local fallback (Copilot Studio did not return a supported layout)";
        }
    } else {
        widgetIds = localDashboardWidgetSelection(goal);
    }
    const name = goal.replace(/\s+/g, " ").trim().slice(0, 48) || "AI dashboard";
    const dashboard = saveDashboardPreset(name, widgetIds, false);
    return { widgetIds, generatedBy, dashboardName: dashboard.name };
}

async function handleUnifiedAssistantQuery(query) {
    const normalized = query.trim();
    if (/\b(create|build|customi[sz]e|generate)\b.{0,35}\bdashboard\b/i.test(normalized)) {
        appendLocalChatMessage("user", normalized);
        renderDashboardBuilder();
        return;
    }
    if (/\b(refresh|reload)\b.*\b(xdome|claroty|feed|live data)\b/i.test(normalized)) {
        appendLocalChatMessage("user", normalized);
        appendLocalChatMessage("assistant", "Refreshing the live xDome feeds…", [], "Live data");
        try {
            await window.XDPortal.refresh(true);
            appendLocalChatMessage("assistant", window.XDPortal.analyzeLoadedData().summary, [], "Live data");
        } catch (error) {
            appendLocalChatMessage("assistant", `xDome refresh failed: ${error.message}`, [], "Live data");
        }
        return;
    }
    if (/\b(draft|drafts)\b|\bwrite (?:me )?(?:a |an )?(?:summary|response|policy)/i.test(normalized)) {
        const type = /\b(policy|zero trust)\b/i.test(normalized) ? "policy" : /\b(response|incident|alert)\b/i.test(normalized) ? "response" : "summary";
        appendLocalChatMessage("user", normalized);
        appendLocalChatMessage("assistant", createLocalSecurityDraft(type), [], "Local draft");
        return;
    }
    await answerFromApplicationKnowledge(normalized);
}
const APPLICATION_KB_DOCUMENTS = [
    ["README.md", "Application guide"],
    ["CLAROTY_INTEGRATION.md", "Claroty integration"],
    ["CLAROTY_QUICK_TEST.md", "Claroty quick test"],
    ["CLAROTY_TESTING.md", "Claroty testing"],
    ["CLAROTY_405_TROUBLESHOOTING.md", "Claroty troubleshooting"],
    ["CLAROTY_FIX_POST_METHOD.md", "Claroty POST method fix"],
    ["CLAROTY_SOLUTION_SUMMARY.md", "Claroty solution summary"],
    ["CLAROTY_SOLUTION_COMPLETE.md", "Claroty complete solution"]
];

function appendLocalChatMessage(role, message, results = [], label = role === "user" ? "You" : "Application KB") {
    const history = document.getElementById("aiChatHistory");
    if (!history) return;
    if (role === "user") document.getElementById("aiChatStarters")?.remove();
    const article = document.createElement("article");
    article.className = `ai-chat-message ai-chat-${role}`;
    const name = document.createElement("strong");
    name.textContent = label;
    const body = document.createElement("p");
    body.textContent = message;
    article.append(name, body);
    results.forEach(result => article.append(createKnowledgeCard(result, message)));
    history.append(article);
    history.scrollTop = history.scrollHeight;
    return article;
}

async function answerFromApplicationKnowledge(query) {
    appendLocalChatMessage("user", query);
    const response = appendLocalChatMessage("assistant", "Searching the application knowledge base…");
    await loadApplicationKnowledgeBase();
    const results = searchApplicationKnowledge(query, 3);
    const responseLabel = response.querySelector("strong");
    const responseBody = response.querySelector("p");
    if (copilotTokenEndpoint()) {
        responseLabel.textContent = "Copilot Studio";
        responseBody.textContent = "Connecting…";
        try {
            const answer = await askCopilotStudio(query);
            responseBody.textContent = answer;
            if (results.length) results.forEach(section => response.append(createKnowledgeCard(section, query)));
            else responseBody.textContent += "\n\nNo matching local documentation sections were found.";
        } catch (error) {
            responseBody.textContent = `Copilot Studio is unavailable: ${error.message}${results.length ? " Local documentation results follow." : ""}`;
            results.forEach(section => response.append(createKnowledgeCard(section, query)));
        }
        return;
    }
    responseBody.textContent = results.length
        ? `I found ${results.length} relevant application reference${results.length === 1 ? "" : "s"}. These excerpts come from the local knowledge base, not a generative model.`
        : "I could not find a matching section in the local application knowledge base.";
    results.forEach(section => response.append(createKnowledgeCard(section, query)));
}
const copilotEndpointStorageKey = "soc-copilot-studio-token-endpoint-v1";
let applicationKnowledgeBase = [];
let applicationKnowledgeLoad = null;
let copilotWebChatLoad = null;
let copilotDirectLine = null;
let copilotUserId = null;
let copilotConnectionPromise = null;

function parseKnowledgeSections(source, title, markdown) {
    const sections = [];
    let heading = title;
    let lines = [];
    const save = () => {
        const body = lines.join("\n").trim();
        if (body) sections.push({ source, title, heading, body, searchable: `${heading}\n${body}`.toLowerCase() });
    };
    markdown.split(/\r?\n/).forEach(line => {
        const match = line.match(/^\s{0,3}#{1,4}\s+(.+?)\s*#*\s*$/);
        if (match) {
            save();
            heading = match[1].trim();
            lines = [];
        } else {
            lines.push(line);
        }
    });
    save();
    return sections;
}

async function loadApplicationKnowledgeBase() {
    if (applicationKnowledgeLoad) return applicationKnowledgeLoad;
    applicationKnowledgeLoad = Promise.all(APPLICATION_KB_DOCUMENTS.map(async ([source, title]) => {
        try {
            const response = await fetch(`/${encodeURIComponent(source)}`, { cache: "no-store" });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return parseKnowledgeSections(source, title, await response.text());
        } catch {
            return [];
        }
    })).then(groups => {
        applicationKnowledgeBase = groups.flat();
        return applicationKnowledgeBase;
    }).catch(error => {
        applicationKnowledgeLoad = null;
        throw error;
    });
    return applicationKnowledgeLoad;
}

function searchApplicationKnowledge(query, limit = 6) {
    const normalized = String(query || "").trim().toLowerCase();
    const terms = [...new Set(normalized.match(/[a-z0-9][a-z0-9._/-]{1,}/g) || [])];
    if (!terms.length) return [];
    return applicationKnowledgeBase.map(section => {
        const heading = section.heading.toLowerCase();
        let score = 0;
        terms.forEach(term => {
            if (heading.includes(term)) score += 5;
            let offset = 0;
            while ((offset = section.searchable.indexOf(term, offset)) !== -1) {
                score += 1;
                offset += term.length;
            }
        });
        if (section.searchable.includes(normalized)) score += 8;
        return { ...section, score };
    }).filter(section => section.score > 0).sort((left, right) => right.score - left.score).slice(0, limit);
}

function createKnowledgeCard(section, query = "") {
    const article = document.createElement("article");
    article.className = "ai-kb-result";
    const heading = document.createElement("strong");
    heading.textContent = section.heading;
    const source = document.createElement("small");
    source.textContent = `${section.title} · ${section.source}`;
    const preview = document.createElement("p");
    const content = section.body.replace(/```[\s\S]*?```/g, "Code example omitted from preview.").replace(/\s+/g, " ").trim();
    const firstTerm = (query.toLowerCase().match(/[a-z0-9][a-z0-9._/-]{1,}/) || [""])[0];
    const matchAt = firstTerm ? content.toLowerCase().indexOf(firstTerm) : -1;
    const start = matchAt > 100 ? matchAt - 100 : 0;
    preview.textContent = `${start ? "…" : ""}${content.slice(start, start + 360)}${content.length > start + 360 ? "…" : ""}`;
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Read full section";
    const fullText = document.createElement("pre");
    fullText.textContent = section.body;
    details.append(summary, fullText);
    article.append(heading, source, preview, details);
    return article;
}

function renderKnowledgeResults(container, results, query) {
    container.replaceChildren();
    if (!results.length) {
        const empty = document.createElement("p");
        empty.className = "ai-kb-empty";
        empty.textContent = applicationKnowledgeBase.length ? "No matching application documentation found." : "Application documentation could not be loaded.";
        container.append(empty);
        return;
    }
    results.forEach(section => container.append(createKnowledgeCard(section, query)));
}

function setAiTab(name) {
    document.querySelectorAll("#aiModalBody [data-ai-tab]").forEach(button => {
        const active = button.dataset.aiTab === name;
        button.setAttribute("aria-selected", String(active));
        button.classList.toggle("active", active);
    });
    document.querySelectorAll("#aiModalBody [data-ai-panel]").forEach(panel => {
        panel.hidden = panel.dataset.aiPanel !== name;
    });
}

function appendLocalChatMessage(role, message, results = []) {
    const history = document.getElementById("aiChatHistory");
    if (!history) return;
    const article = document.createElement("article");
    article.className = `ai-chat-message ai-chat-${role}`;
    const label = document.createElement("strong");
    label.textContent = role === "user" ? "You" : "Application KB";
    const body = document.createElement("p");
    body.textContent = message;
    article.append(label, body);
    results.forEach(result => article.append(createKnowledgeCard(result, message)));
    history.append(article);
    history.scrollTop = history.scrollHeight;
}

async function answerFromApplicationKnowledge(query) {
    await loadApplicationKnowledgeBase();
    const results = searchApplicationKnowledge(query, 3);
    appendLocalChatMessage("user", query);
    appendLocalChatMessage("assistant", results.length
        ? `I found ${results.length} relevant application reference${results.length === 1 ? "" : "s"}. These excerpts come from the local knowledge base, not a generative model.`
        : "I could not find a matching section in the local application knowledge base. Try a feature name, page, or error message.", results);
}

function copilotTokenEndpoint() {
    try { return localStorage.getItem(copilotEndpointStorageKey) || ""; }
    catch { return ""; }
}

function validateCopilotTokenEndpoint(value) {
    try {
        const endpoint = new URL(value);
        const microsoftHost = /(^|\.)api\.powerplatform\.(com|us|de|cn)$/i.test(endpoint.hostname);
        const sensitiveQuery = [...endpoint.searchParams.keys()].some(key => /secret|token|password|key|sig/i.test(key));
        return endpoint.protocol === "https:" && microsoftHost && endpoint.pathname.includes("/powervirtualagents/") && !endpoint.username && !endpoint.password && !sensitiveQuery;
    } catch {
        return false;
    }
}

function loadCopilotWebChat() {
    if (window.WebChat) return Promise.resolve(window.WebChat);
    if (copilotWebChatLoad) return copilotWebChatLoad;
    copilotWebChatLoad = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = "https://cdn.botframework.com/botframework-webchat/latest/webchat.js";
        script.async = true;
        script.onload = () => window.WebChat ? resolve(window.WebChat) : reject(new Error("Microsoft Web Chat did not initialize."));
        script.onerror = () => reject(new Error("Microsoft Web Chat could not be loaded. Check network access to cdn.botframework.com."));
        document.head.append(script);
    }).catch(error => {
        copilotWebChatLoad = null;
        throw error;
    });
    return copilotWebChatLoad;
}

function updateCopilotEndpointUi(message = "") {
    const input = document.getElementById("aiCopilotEndpoint");
    const status = document.getElementById("aiCopilotStatus");
    const startButton = document.getElementById("aiCopilotStart");
    if (!input || !status || !startButton) return;
    const endpoint = copilotTokenEndpoint();
    input.value = endpoint;
    const valid = validateCopilotTokenEndpoint(endpoint);
    startButton.hidden = !valid;
    status.textContent = message || (valid
        ? "Copilot Studio token endpoint saved. Start a session to connect."
        : "Copilot Studio is not configured. Local app help and KB chat remain available.");
}

async function connectCopilotStudio() {
    if (copilotDirectLine) return copilotDirectLine;
    if (copilotConnectionPromise) return copilotConnectionPromise;
    const endpoint = copilotTokenEndpoint();
    if (!validateCopilotTokenEndpoint(endpoint)) throw new Error("Copilot Studio token endpoint is not configured in Settings - Integrations.");
    copilotConnectionPromise = (async () => {
        const tokenUrl = new URL(endpoint);
        const marker = "/powervirtualagents";
        const environmentEndpoint = tokenUrl.href.slice(0, tokenUrl.href.indexOf(marker));
        const apiVersion = tokenUrl.searchParams.get("api-version");
        if (!environmentEndpoint || !apiVersion) throw new Error("The token endpoint must include the Copilot Studio api-version parameter.");
        const regionalUrl = `${environmentEndpoint}${marker}/regionalchannelsettings?api-version=${encodeURIComponent(apiVersion)}`;
        const [webChat, regionalResponse, tokenResponse] = await Promise.all([
            loadCopilotWebChat(),
            fetch(regionalUrl, { cache: "no-store" }),
            fetch(endpoint, { cache: "no-store" })
        ]);
        const regional = await regionalResponse.json();
        const tokenPayload = await tokenResponse.json();
        if (!regionalResponse.ok || !tokenResponse.ok) throw new Error("Copilot Studio could not issue chat configuration or a conversation token.");
        if (!tokenPayload.token || !regional.channelUrlsById?.directline) throw new Error("Copilot Studio returned incomplete chat configuration.");
        const directLineBase = regional.channelUrlsById.directline.replace(/\/+$/, "");
        copilotUserId = `dl_${crypto.randomUUID().replaceAll("-", "")}`;
        copilotDirectLine = webChat.createDirectLine({ domain: `${directLineBase}/v3/directline`, token: tokenPayload.token, userID: copilotUserId });
        return copilotDirectLine;
    })().catch(error => {
        copilotConnectionPromise = null;
        copilotDirectLine = null;
        throw error;
    });
    return copilotConnectionPromise;
}

async function askCopilotStudio(query) {
    const directLine = await connectCopilotStudio();
    return new Promise((resolve, reject) => {
        let activitySubscription;
        let postSubscription;
        const timeout = setTimeout(() => {
            activitySubscription?.unsubscribe();
            postSubscription?.unsubscribe();
            reject(new Error("Copilot Studio did not reply before the request timed out."));
        }, 45000);
        const finish = (error, answer) => {
            clearTimeout(timeout);
            activitySubscription?.unsubscribe();
            postSubscription?.unsubscribe();
            if (error) reject(error);
            else resolve(answer);
        };
        activitySubscription = directLine.activity$.subscribe({
            next: activity => {
                if (activity.type !== "message" || activity.from?.id === copilotUserId) return;
                const answer = String(activity.text || activity.attachments?.map(item => item.content?.text || item.name || "").filter(Boolean).join("\n") || "").trim();
                if (answer) finish(null, answer);
            },
            error: error => finish(error)
        });
        postSubscription = directLine.postActivity({
            from: { id: copilotUserId, name: "OT Platform" },
            type: "message",
            text: query
        }).subscribe({ error: error => finish(error) });
    });
}

function renderKnowledgeBaseSources() {
    const host = document.getElementById("aiKbSources");
    if (!host) return;
    host.replaceChildren();
    APPLICATION_KB_DOCUMENTS.forEach(([source, title]) => {
        const count = applicationKnowledgeBase.filter(section => section.source === source).length;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "ai-kb-source";
        button.dataset.aiKbSource = title;
        const name = document.createElement("strong");
        name.textContent = title;
        const details = document.createElement("small");
        details.textContent = `${source} · ${count ? `${count} sections indexed` : "not loaded"}`;
        button.append(name, details);
        host.append(button);
    });
}

function renderAiAssistant() {
    document.getElementById("aiModalBody").innerHTML = `<div class="ai-local-chat"><div id="aiChatHistory" class="ai-chat-history" aria-live="polite"><div id="aiChatStarters" class="ai-chat-starters"><button type="button" data-ai-starter="How do I use the OT Platform?">App help</button><button type="button" data-ai-starter="How do I configure Claroty xDome?">Claroty setup</button><button type="button" data-ai-starter="Draft an xDome summary">xDome summary</button><button type="button" data-ai-starter="Draft a Zero Trust policy">Zero Trust draft</button><button type="button" data-ai-starter="Refresh xDome live feeds">Refresh live data</button><button type="button" data-ai-starter="Create my custom dashboard">Create dashboard</button></div></div><form id="aiChatForm" class="ai-assistant-form"><textarea id="aiChatInput" aria-label="Search application help and knowledge base" rows="2" maxlength="1000" placeholder="" required></textarea><button type="submit" class="ai-run-btn" aria-label="Search">Search</button></form></div>`;
    document.getElementById("aiChatInput").focus();
}

const aiModalBody = document.getElementById("aiModalBody");
aiModalBody?.addEventListener("click", event => {
    if (event.target.closest("[data-ai-dashboard-overview]")) {
        closeLocalDraftModal();
        window.showSection?.("overview");
        return;
    }
    const starter = event.target.closest("[data-ai-starter]");
    if (starter) {
        const input = document.getElementById("aiChatInput");
        input.value = starter.dataset.aiStarter;
        input.form.requestSubmit();
        return;
    }
    if (event.target.closest("[data-ai-save-copilot]")) {
        const endpoint = document.getElementById("aiCopilotEndpoint").value.trim();
        if (!validateCopilotTokenEndpoint(endpoint)) {
            updateCopilotEndpointUi("Enter a valid HTTPS Copilot Studio token endpoint. Direct Line secrets are not accepted.");
            return;
        }
        try { localStorage.setItem(copilotEndpointStorageKey, endpoint); }
        catch { updateCopilotEndpointUi("Could not save the endpoint in this browser."); return; }
        updateCopilotEndpointUi("Token endpoint saved on this device. Endpoint presence does not verify the agent; start a chat to test it.");
    }
    if (event.target.closest("#aiCopilotStart")) startCopilotStudioChat();
});
aiModalBody?.addEventListener("submit", async event => {
    if (event.target.id === "aiDashboardForm") {
        event.preventDefault();
        const form = event.target;
        const goal = form.querySelector("#aiDashboardGoal").value.trim();
        const submit = form.querySelector("button[type='submit']");
        const status = form.querySelector("[data-ai-dashboard-status]");
        if (!goal) return;
        submit.disabled = true;
        status.textContent = "Selecting dashboard widgets…";
        try {
            const result = await generateCustomDashboard(goal);
            const labels = result.widgetIds.map(id => overviewWidgetCatalog.find(widget => widget.id === id)?.label).filter(Boolean);
            status.textContent = `${result.generatedBy} saved "${result.dashboardName}" with ${labels.length} widgets: ${labels.join(", ")}.`;
            const openOverview = document.createElement("button");
            openOverview.type = "button";
            openOverview.className = "xd-link";
            openOverview.dataset.aiDashboardOverview = "true";
            openOverview.textContent = "Open Overview";
            status.after(openOverview);
        } catch (error) {
            status.textContent = error.message;
        } finally {
            submit.disabled = false;
        }
        return;
    }
    if (event.target.id === "aiChatForm") {
        event.preventDefault();
        const input = document.getElementById("aiChatInput");
        const query = input.value.trim();
        if (!query) return;
        input.value = "";
        const button = event.target.querySelector("button[type='submit']");
        button.disabled = true;
        try { await handleUnifiedAssistantQuery(query); }
        catch { appendLocalChatMessage("assistant", "The local application knowledge base could not be loaded. Check that the app server is running and retry."); }
        finally { button.disabled = false; }
    }
});
aiModalBody?.addEventListener("keydown", event => {
    if (event.target.id === "aiChatInput" && event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        event.target.form.requestSubmit();
    }
});

let lastAiTrigger = null;

function closeLocalDraftModal(restoreFocus = false) {
    const modal = document.getElementById("aiModal");
    if (!modal) return;
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    if (lastAiTrigger?.hasAttribute("aria-expanded")) lastAiTrigger.setAttribute("aria-expanded", "false");
    if (restoreFocus && lastAiTrigger?.isConnected) lastAiTrigger.focus();
    lastAiTrigger = null;
}

function openLocalDraftModal(event) {
    closeHeaderPanels();
    const modal = document.getElementById("aiModal");
    if (!modal) return;
    lastAiTrigger = event?.currentTarget || document.activeElement;
    document.getElementById("aiModalTitle").textContent = "Create with AI";
    document.getElementById("aiModalSub").textContent = "Search knowledge, analyze loaded feeds, and create drafts or dashboards.";
    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    if (lastAiTrigger?.hasAttribute("aria-expanded")) lastAiTrigger.setAttribute("aria-expanded", "true");
    renderAiAssistant();
}

document.getElementById("createAiBtn")?.addEventListener("click", openLocalDraftModal);
document.getElementById("slaAIBtn")?.addEventListener("click", openLocalDraftModal);
document.getElementById("aiRunBtn")?.addEventListener("click", openLocalDraftModal);
document.getElementById("aiModalClose")?.addEventListener("click", () => closeLocalDraftModal(true));
document.addEventListener("click", event => {
    const modal = document.getElementById("aiModal");
    if (!modal || modal.hidden || modal.contains(event.target)) return;
    if (lastAiTrigger?.contains(event.target) || event.target.closest("[data-xd-open-ai-draft]")) return;
    closeLocalDraftModal();
});
document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !document.getElementById("aiModal")?.hidden) closeLocalDraftModal(true);
});

/* ---------- Animated counters ---------- */
function animateCounters() {
    document.querySelectorAll(".kpi-value[data-count]").forEach(el => {
        const target = +el.dataset.count;
        const suffix = el.querySelector("small") ? el.querySelector("small").outerHTML : "";
        const animationId = String((+(el.dataset.animationId || 0)) + 1);
        el.dataset.animationId = animationId;
        let cur = 0;
        const step = Math.max(1, target / 40);
        const tick = () => {
            if (el.dataset.animationId !== animationId) return;
            cur = Math.min(target, cur + step);
            el.innerHTML = Math.round(cur).toLocaleString() + suffix;
            if (cur < target) requestAnimationFrame(tick);
        };
        tick();
    });
}
animateCounters();

/* ---------- Helpers ---------- */
const days = n => Array.from({ length: n }, (_, i) => {
    const d = new Date(); d.setDate(d.getDate() - (n - 1 - i));
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
});
const rand = (min, max) => Math.round(min + Math.random() * (max - min));
const series = (n, min, max, trend = 0) => Array.from({ length: n }, (_, i) => rand(min, max) - Math.round(i * trend));

function gradient(ctx, hex) {
    const g = ctx.createLinearGradient(0, 0, 0, 240);
    g.addColorStop(0, hex + "55"); g.addColorStop(1, hex + "00");
    return g;
}

const baseOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { boxWidth: 12, padding: 14, font: { size: 11 } } } },
    scales: { x: { grid: { display: false } }, y: { grid: { color: COLORS.grid }, beginAtZero: true } }
};

/* ---------- Data source badge ---------- */
function markSource(results) {
    const claroty = results.find(r => r && r.source && r.labels);
    const label = document.getElementById("connLabel");
    const dot = document.querySelector("#connFoot .conn-dot");
    if (!label || !dot) return;
    if (!claroty) return;
    if (claroty.source === "live") {
        label.textContent = "Connected · Claroty live";
        dot.className = "conn-dot";
    } else if (claroty.source === "error") {
        label.textContent = "Claroty live request failed";
        dot.className = "conn-dot misconfigured";
    } else {
        label.textContent = "Claroty demo · credentials required";
        dot.className = "conn-dot demo";
    }
}

let charts = {};
let REPORT = null;
let buildGeneration = 0;

/* Shared Claroty CVE severity rollup so the overview doughnut can be rebuilt
   or refreshed incrementally while the xDome catalog is still streaming. */
const CLAROTY_SEVERITY_LABELS = ["Critical", "High", "Medium", "Low", "Unknown"];
function clarotySeverityState() {
    const catalog = ClarotyAPI.feedState("vulnerabilities");
    const counts = Object.fromEntries(CLAROTY_SEVERITY_LABELS.map(label => [label, 0]));
    catalog.data.forEach(row => {
        const value = String(row.adjusted_vulnerability_score_level || "Unknown").toLowerCase();
        const severity = CLAROTY_SEVERITY_LABELS.find(label => label.toLowerCase() === value) || "Unknown";
        counts[severity]++;
    });
    return {
        labels: CLAROTY_SEVERITY_LABELS,
        data: CLAROTY_SEVERITY_LABELS.map(label => counts[label]),
        source: catalog.source,
        error: catalog.error,
        catalog
    };
}

function clarotySeverityHeadline(state) {
    if (state.source === "live") {
        return `${state.catalog.data.length.toLocaleString()} loaded from xDome CVE catalog${state.catalog.complete ? "" : " (partial)"}`;
    }
    if (state.source === "error") return `Live load failed · ${esc(state.error)}`;
    return "Awaiting Claroty CVE catalog";
}

/* Update only the severity doughnut as xDome CVE pages arrive. */
function refreshOverviewSeverity() {
    if (REPORT || !charts.severity) return;
    const state = clarotySeverityState();
    charts.severity.data.labels = state.labels.map((label, index) => `${label} (${Number(state.data[index] || 0).toLocaleString()})`);
    charts.severity.data.datasets[0].data = state.data;
    charts.severity.update("none");
    const head = document.querySelector("#overview .chart-row .card:not(.wide) .card-head");
    if (head) head.innerHTML = `<h3>Claroty CVEs by Severity</h3><span class="muted">${clarotySeverityHeadline(state)}</span>`;
    markSource([state]);
}
window.refreshOverviewSeverity = refreshOverviewSeverity;

/* Push an ingested report's KPIs into the Overview cards */
function applyReportKpis() {
    if (!REPORT) return;
    const k = REPORT.kpis;
    const setKpi = (label, value, sub) => {
        document.querySelectorAll("#overview .kpi-card").forEach(card => {
            const l = (card.querySelector(".kpi-label")?.textContent || "").trim();
            if (l !== label) return;
            const v = card.querySelector(".kpi-value");
            const small = v.querySelector("small")?.outerHTML || "";
            v.dataset.count = value;
            v.innerHTML = Number(value).toLocaleString() + small;
            const s = card.querySelector(".kpi-sub");
            if (sub && s) s.innerHTML = sub;
        });
    };
    const openCritical = REPORT.records.filter(r => r.status === "Open" && r.severity === "Critical").length;
    setKpi("Open Incidents", k.open, `${openCritical} critical open · ${k.total} in report`);
    const openCard = [...document.querySelectorAll("#overview .kpi-card")]
        .find(card => card.querySelector(".kpi-label")?.textContent.trim() === "Open Incidents");
    const openPill = openCard?.querySelector(".pill");
    if (openPill) {
        openPill.className = `pill ${k.open ? "amber" : "green"}`;
        openPill.textContent = k.open ? "● Active" : "✓ None open";
    }
    setKpi("Automation Rate", k.automationRate, `${k.automated} of ${k.total} auto-detected`);
    setKpi("Hours Saved / mo", k.hoursSaved, `Top type: <span class="up">${k.topCategory}</span>`);
    animateCounters();
}

/* Local filter over the ingested report's records (drill-down) */
function filterReportRecords(f = {}) {
    let recs = REPORT.records.slice();
    if (f.severity) recs = recs.filter(r => r.severity === f.severity);
    if (f.status) recs = recs.filter(r => r.status === f.status);
    if (f.category) recs = recs.filter(r => r.category === f.category);
    if (f.source) recs = recs.filter(r => r.source === f.source);
    if (f.automated) recs = recs.filter(r => r.automated);
    if (f.day) recs = recs.filter(r => r.created.slice(0, 10) === f.day);
    if (f.dateFrom) recs = recs.filter(r => r.created && r.created.slice(0, 10) >= f.dateFrom);
    if (f.dateTo) recs = recs.filter(r => r.created && r.created.slice(0, 10) <= f.dateTo);
    return recs.slice(0, 300);
}

async function build(range = 30) {
    const generation = ++buildGeneration;
    Object.values(charts).forEach(c => c.destroy());
    charts = {};
    const L = days(range);

    /* ---- Live feeds (fall back to mock automatically) ---- */
    const iso = n => Array.from({ length: n }, (_, i) => {
        const d = new Date(); d.setDate(d.getDate() - (n - 1 - i));
        return d.toISOString().slice(0, 10);
    });
    const fmtLabel = s => /^\d{4}-\d{2}-\d{2}$/.test(s)
        ? new Date(s).toLocaleDateString("en-US", { month: "short", day: "numeric" })
        : s;

    const mockTrend = () => ({ labels: iso(range), mttd: series(range, 9, 16, 0.02), mttr: series(range, 42, 70, 0.08) });
    const mockClosure = () => ({ closed: 92, open: 8 });

    const [trendR, closeR] = await Promise.all([
        SwimlaneAPI.getIncidentTrend(range, mockTrend),
        SwimlaneAPI.getClosureRate(mockClosure)
    ]);
    if (generation !== buildGeneration) return;
    const clarotySeverity = clarotySeverityState();
    const catalog = clarotySeverity.catalog;
    markSource([trendR, closeR, clarotySeverity]);

    // Keep the raw ISO day labels so trend clicks can filter by date.
    const trendIsoLabels = (REPORT ? REPORT.labels : trendR.data.labels).slice();
    const isoLabels = iso(range);
    // Open the underlying incident records for any chart element.
    const drill = (title, sub, filter) => openRecords(title, sub, filter || {});

    /* ===== Overview: Incident Trends (demo) / Incident Volume (report) ===== */
    const tctx = document.getElementById("trendChart").getContext("2d");
    const tHead = document.querySelector("#overview .card.wide .card-head");
    if (tHead) tHead.innerHTML = REPORT
        ? `<h3>Incident Volume</h3><span class="muted">Daily incidents from report</span>`
        : `<h3>Incident Trends</h3><span class="muted">MTTD vs MTTR over time</span>`;
    const trendDatasets = REPORT
        ? [{ label: "Incidents / day", data: REPORT.volume, borderColor: COLORS.accent, backgroundColor: gradient(tctx, COLORS.accent), fill: true, tension: .4, pointRadius: 0, borderWidth: 2 }]
        : [
            { label: "MTTD (min)", data: trendR.data.mttd, borderColor: COLORS.accent, backgroundColor: gradient(tctx, COLORS.accent), fill: true, tension: .4, pointRadius: 0, borderWidth: 2, spanGaps: true },
            { label: "MTTR (min)", data: trendR.data.mttr, borderColor: COLORS.amber, backgroundColor: gradient(tctx, COLORS.amber), fill: true, tension: .4, pointRadius: 0, borderWidth: 2, spanGaps: true }
          ];
    charts.trend = new Chart(tctx, {
        type: "line",
        data: { labels: trendIsoLabels.map(fmtLabel), datasets: trendDatasets },
        options: {
            ...baseOpts,
            onClick: (e, els) => {
                if (!els.length) return;
                const day = trendIsoLabels[els[0].index];
                openRecords(`Incidents on ${fmtLabel(day)}`, "Click a record to see full detail", { day, range });
            }
        }
    });

    /* ===== Alert Volume by Severity — LIVE feed / report ===== */
    const sevLabels = REPORT ? ["Critical", "High", "Medium", "Low"] : clarotySeverity.labels;
    const sevData = REPORT
        ? [REPORT.severity.Critical, REPORT.severity.High, REPORT.severity.Medium, REPORT.severity.Low]
        : clarotySeverity.data;
    const severityDisplayLabels = sevLabels.map((label, index) => `${label} (${Number(sevData[index] || 0).toLocaleString()})`);
    const severityHead = document.querySelector("#overview .chart-row .card:not(.wide) .card-head");
    if (severityHead) severityHead.innerHTML = REPORT
        ? `<h3>Alert Volume by Severity</h3><span class="muted">Imported report records</span>`
        : `<h3>Claroty CVEs by Severity</h3><span class="muted">${clarotySeverityHeadline(clarotySeverity)}</span>`;
    charts.severity = new Chart(document.getElementById("severityChart"), {
        type: "doughnut",
        data: {
            labels: severityDisplayLabels,
            datasets: [{ data: sevData, backgroundColor: [COLORS.red, COLORS.amber, COLORS.accent, COLORS.accent2], borderWidth: 0 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: "62%",
            plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 12, font: { size: 11 } } } },
            onClick: (e, els) => {
                if (!els.length) return;
                const sev = sevLabels[els[0].index];
                if (REPORT) openRecords(`${sev} severity incidents`, "Filtered by severity", { severity: sev, range });
                else window.showSection("riskmanagement");
            }
        },
        plugins: [{
            id: "severityCountLabels",
            afterDatasetsDraw(chart) {
                const dataset = chart.data.datasets[0];
                const arcs = chart.getDatasetMeta(0).data;
                const context = chart.ctx;
                context.save();
                context.font = "600 10px Segoe UI, sans-serif";
                context.fillStyle = "#fff";
                context.textAlign = "center";
                context.textBaseline = "middle";
                arcs.forEach((arc, index) => {
                    const value = Number(dataset.data[index] || 0);
                    const props = arc.getProps(["x", "y", "startAngle", "endAngle", "innerRadius", "outerRadius"], true);
                    if (!value || props.endAngle - props.startAngle < 0.28) return;
                    const angle = (props.startAngle + props.endAngle) / 2;
                    const radius = (props.innerRadius + props.outerRadius) / 2;
                    context.fillText(value.toLocaleString(), props.x + Math.cos(angle) * radius, props.y + Math.sin(angle) * radius);
                });
                context.restore();
            }
        }]
    });

    /* ===== Analyst Productivity (demo) / Incidents by Source (report) ===== */
    const aHead = document.querySelector("#operations .chart-row .card:first-child .card-head");
    let srcTop = null;
    if (REPORT) {
        const m = {};
        REPORT.records.forEach(r => m[r.source] = (m[r.source] || 0) + 1);
        srcTop = Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8);
    }
    if (aHead) aHead.innerHTML = REPORT
        ? `<h3>Incidents by Source</h3><span class="muted">Detection source systems</span>`
        : `<h3>Analyst Productivity</h3><span class="muted">Cases handled per analyst</span>`;
    charts.analyst = new Chart(document.getElementById("analystChart"), {
        type: "bar",
        data: {
            labels: srcTop ? srcTop.map(s => s[0]) : ["Aisha", "Marco", "Lena", "Raj", "Yuki"],
            datasets: [{ label: srcTop ? "Incidents" : "Cases closed", data: srcTop ? srcTop.map(s => s[1]) : [64, 58, 71, 49, 66], backgroundColor: COLORS.accent, borderRadius: 6 }]
        },
        options: {
            ...baseOpts, plugins: { legend: { display: false } },
            onClick: (e, els) => {
                if (!els.length) return;
                if (srcTop) drill(`${srcTop[els[0].index][0]} incidents`, "Filtered by detection source", { source: srcTop[els[0].index][0] });
                else drill("All incidents", "Underlying records", { range });
            }
        }
    });

    /* ===== False Positive Reduction ===== */
    charts.fp = new Chart(document.getElementById("fpChart"), {
        type: "line",
        data: { labels: ["Q1", "Q2", "Q3", "Q4"], datasets: [{ label: "FP rate %", data: [38, 29, 21, 14], borderColor: COLORS.green, backgroundColor: "transparent", tension: .4, borderWidth: 3, pointRadius: 4, pointBackgroundColor: COLORS.green }] },
        options: {
            ...baseOpts, plugins: { legend: { display: false } },
            onClick: () => drill("All incidents", "Underlying records from report", { range })
        }
    });

    /* ===== Incident Closure Rate — LIVE feed / report ===== */
    const closedPct = REPORT ? REPORT.closurePct : closeR.data.closed;
    const openPct = REPORT ? (100 - REPORT.closurePct) : closeR.data.open;
    charts.closure = new Chart(document.getElementById("closureChart"), {
        type: "doughnut",
        data: { labels: ["Closed", "Open"], datasets: [{ data: [closedPct, openPct], backgroundColor: [COLORS.green, COLORS.grid], borderWidth: 0 }] },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: "72%",
            plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
            onClick: (e, els) => {
                if (!els.length) return;
                const status = els[0].index === 0 ? "Closed" : "Open";
                openRecords(`${status} incidents`, "Filtered by status", { status, range });
            }
        }
    });

    /* ===== Top Attack Techniques (demo) / Top Incident Types (report) ===== */
    const mHead = document.querySelector("#threats .card.wide .card-head");
    const catTop = REPORT ? REPORT.categories.slice(0, 8) : null;
    if (mHead) mHead.innerHTML = REPORT
        ? `<h3>Top Incident Types</h3><span class="muted">Classified from report data</span>`
        : `<h3>Top Attack Techniques</h3><span class="muted">MITRE ATT&CK mapping</span>`;
    charts.mitre = new Chart(document.getElementById("mitreChart"), {
        type: "bar",
        data: {
            labels: catTop ? catTop.map(c => c[0]) : ["Phishing (T1566)", "Valid Accounts (T1078)", "PowerShell (T1059)", "Cred Dumping (T1003)", "Lateral Move (T1021)", "Exfiltration (T1041)"],
            datasets: [{ label: catTop ? "Incidents" : "Detections", data: catTop ? catTop.map(c => c[1]) : [142, 98, 76, 54, 41, 27], backgroundColor: COLORS.accent, borderRadius: 6 }]
        },
        options: {
            ...baseOpts, indexAxis: "y", plugins: { legend: { display: false } },
            onClick: (e, els) => {
                if (!els.length || !catTop) return;
                const cat = catTop[els[0].index][0];
                openRecords(`${cat} incidents`, "Filtered by incident type", { category: cat });
            }
        }
    });

    /* ===== Vulnerability Aging ===== */
    charts.vuln = new Chart(document.getElementById("vulnChart"), {
        type: "bar",
        data: {
            labels: ["0–7 d", "8–30 d", "31–60 d", "61–90 d", "90+ d"],
            datasets: [
                { label: "Critical", data: [12, 9, 5, 3, 2], backgroundColor: COLORS.red, borderRadius: 4, stack: "s" },
                { label: "High", data: [34, 26, 18, 11, 7], backgroundColor: COLORS.amber, borderRadius: 4, stack: "s" },
                { label: "Medium", data: [78, 61, 40, 25, 14], backgroundColor: COLORS.accent, borderRadius: 4, stack: "s" }
            ]
        },
        options: {
            ...baseOpts,
            scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, grid: { color: COLORS.grid } } },
            onClick: (e, els) => {
                if (!els.length) return;
                const sev = charts.vuln.data.datasets[els[0].datasetIndex].label;
                drill(`${sev} severity incidents`, "Filtered by severity", { severity: sev, range });
            }
        }
    });

    /* ===== Automation Success Rate ===== */
    const actx = document.getElementById("autoChart").getContext("2d");
    charts.auto = new Chart(actx, {
        type: "line",
        data: {
            labels: L,
            datasets: [
                { label: "Successful", data: series(range, 180, 260, -0.4), borderColor: COLORS.green, backgroundColor: gradient(actx, COLORS.green), fill: true, tension: .4, pointRadius: 0, borderWidth: 2 },
                { label: "Failed", data: series(range, 4, 16), borderColor: COLORS.red, backgroundColor: "transparent", tension: .4, pointRadius: 0, borderWidth: 2 }
            ]
        },
        options: {
            ...baseOpts,
            onClick: (e, els) => {
                if (!els.length) return;
                const day = isoLabels[els[0].index];
                drill(`Incidents on ${fmtLabel(day)}`, "Automation activity that day", { day, range });
            }
        }
    });

    /* ===== Hours Saved by Use Case ===== */
    const useCaseCat = { "Phishing": "Phishing", "Malware": "Malware / AV", "SIEM Triage": "SIEM (Sentinel)", "Vuln Mgmt": "Infrastructure", "Access": "Auth / Access", "Insider": "Identity Risk" };
    charts.savings = new Chart(document.getElementById("savingsChart"), {
        type: "bar",
        data: {
            labels: ["Phishing", "Malware", "SIEM Triage", "Vuln Mgmt", "Access", "Insider"],
            datasets: [{ label: "Hours / mo", data: [520, 410, 380, 210, 180, 140], backgroundColor: COLORS.accent2, borderRadius: 6 }]
        },
        options: {
            ...baseOpts, indexAxis: "y", plugins: { legend: { display: false } },
            onClick: (e, els) => {
                if (!els.length) return;
                const label = charts.savings.data.labels[els[0].index];
                const cat = useCaseCat[label];
                drill(`${label} incidents`, "Automation savings context", cat ? { category: cat } : { automated: true });
            }
        }
    });

    /* ===== Insider: User Risk Score Trend ===== */
    const ictx = document.getElementById("insiderTrendChart").getContext("2d");
    charts.insiderTrend = new Chart(ictx, {
        type: "line",
        data: {
            labels: L,
            datasets: [
                { label: "Privileged users", data: series(range, 55, 78, -0.05), borderColor: COLORS.red, backgroundColor: gradient(ictx, COLORS.red), fill: true, tension: .4, pointRadius: 0, borderWidth: 2 },
                { label: "Third-party users", data: series(range, 40, 62), borderColor: COLORS.amber, backgroundColor: "transparent", tension: .4, pointRadius: 0, borderWidth: 2 },
                { label: "Standard users", data: series(range, 18, 34), borderColor: COLORS.accent, backgroundColor: "transparent", tension: .4, pointRadius: 0, borderWidth: 2 }
            ]
        },
        options: {
            ...baseOpts,
            onClick: () => drill("Identity risk incidents", "Insider / identity-related records", { category: "Identity Risk" })
        }
    });

    /* ===== Insider: Behavioral Anomalies ===== */
    charts.anomaly = new Chart(document.getElementById("anomalyChart"), {
        type: "bar",
        data: {
            labels: ["Off-hours", "Unusual login", "Excess DL", "Priv esc", "USB", "Geo anomaly", "Dormant"],
            datasets: [{ label: "Events", data: [42, 31, 27, 12, 19, 15, 8], backgroundColor: COLORS.accent, borderRadius: 5 }]
        },
        options: {
            ...baseOpts, indexAxis: "y", plugins: { legend: { display: false } },
            onClick: () => drill("Privileged access incidents", "Behavioral / privileged-access records", { category: "Privileged Access" })
        }
    });

    /* ===== Insider: Data Exfiltration Signals ===== */
    charts.exfil = new Chart(document.getElementById("exfilChart"), {
        type: "doughnut",
        data: {
            labels: ["Cloud upload", "Email forward", "Doc copy", "DLP violation", "USB transfer"],
            datasets: [{ data: [34, 22, 18, 41, 13], backgroundColor: [COLORS.accent, COLORS.accent2, COLORS.amber, COLORS.red, COLORS.green], borderWidth: 0 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: "60%",
            plugins: { legend: { position: "bottom", labels: { boxWidth: 11, padding: 10, font: { size: 10.5 } } } },
            onClick: () => drill("Email security incidents", "Data-movement / email records", { category: "Email Security" })
        }
    });

    /* ===== ROI: Enrichment Automation ===== */
    charts.enrich = new Chart(document.getElementById("enrichChart"), {
        type: "bar",
        data: {
            labels: ["IOC lookup", "TI search", "VirusTotal", "WHOIS", "User ctx", "Endpoint ctx", "Asset ctx"],
            datasets: [{ label: "Automated %", data: [98, 92, 96, 89, 84, 80, 76], backgroundColor: COLORS.green, borderRadius: 5 }]
        },
        options: {
            ...baseOpts, indexAxis: "y", scales: { x: { grid: { display: false }, max: 100 }, y: { grid: { color: COLORS.grid } } }, plugins: { legend: { display: false } },
            onClick: () => drill("Auto-enriched incidents", "Automated / enriched records", { automated: true })
        }
    });

    /* ===== ROI: Cumulative Cost Avoidance ===== */
    const cctx = document.getElementById("cumCostChart").getContext("2d");
    let running = 0;
    const cumData = Array.from({ length: range }, () => (running += rand(60, 95)) / 10);
    charts.cumCost = new Chart(cctx, {
        type: "line",
        data: { labels: L, datasets: [{ label: "Cost avoidance ($k, cumulative)", data: cumData, borderColor: COLORS.accent, backgroundColor: gradient(cctx, COLORS.accent), fill: true, tension: .4, pointRadius: 0, borderWidth: 2 }] },
        options: {
            ...baseOpts,
            onClick: () => drill("Automated incidents", "Cost-avoidance driven by automation", { automated: true })
        }
    });

    /* ===== SIEM: Alert Reduction ===== */
    const sctx = document.getElementById("siemChart").getContext("2d");
    charts.siem = new Chart(sctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [{ label: "Stored events", data: [], borderColor: COLORS.accent, backgroundColor: gradient(sctx, COLORS.accent), fill: true, tension: .3, pointRadius: 2, borderWidth: 2 }]
        },
        options: { ...baseOpts, plugins: { ...baseOpts.plugins, legend: { display: false } } }
    });

    /* ===== SIEM: Events by Platform ===== */
    charts.siemShare = new Chart(document.getElementById("siemShareChart"), {
        type: "polarArea",
        data: {
            labels: [],
            datasets: [{ data: [], backgroundColor: [COLORS.accent, COLORS.accent2, COLORS.amber, COLORS.red, COLORS.green], borderWidth: 0 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: "bottom", labels: { boxWidth: 11, padding: 10, font: { size: 10.5 } } } },
            scales: { r: { grid: { color: COLORS.grid }, ticks: { display: false } } }
        }
    });

    /* ===== Scorecard: OT Platform Capability Radar (spider) ===== */
    const rEl = document.getElementById("radarChart");
    if (rEl) {
        // Derive current capability scores from the report where possible.
        const autoScore = REPORT ? REPORT.kpis.automationRate : 74;
        const closureScore = REPORT ? REPORT.closurePct : 92;
        const total = REPORT ? REPORT.kpis.total : 700;
        const idPct = REPORT ? Math.round(((REPORT.categories.find(c => c[0] === "Identity Risk")?.[1] || 0) + (REPORT.categories.find(c => c[0] === "Privileged Access")?.[1] || 0)) / total * 100) : 12;
        const edrPct = REPORT ? Math.round(((REPORT.categories.find(c => c[0] === "EDR (CrowdStrike)")?.[1] || 0) + (REPORT.categories.find(c => c[0] === "Malware / AV")?.[1] || 0) + (REPORT.categories.find(c => c[0] === "Defender Experts")?.[1] || 0)) / total * 100) : 22;
        const coverage = REPORT ? Math.min(100, 55 + REPORT.categories.length * 3) : 88;
        const current = [coverage, autoScore, closureScore, 78, Math.min(100, 50 + idPct * 2), Math.min(100, 55 + edrPct)];
        const target = [90, 80, 95, 85, 80, 90];
        charts.radar = new Chart(rEl, {
            type: "radar",
            data: {
                labels: ["Detection Coverage", "Automation", "Closure Rate", "Threat Intel", "Identity Security", "Endpoint Security"],
                datasets: [
                    { label: "Current", data: current, borderColor: COLORS.accent, backgroundColor: COLORS.accent + "44", borderWidth: 2, pointBackgroundColor: COLORS.accent, pointRadius: 3 },
                    { label: "Target", data: target, borderColor: COLORS.green, backgroundColor: "transparent", borderWidth: 2, borderDash: [5, 4], pointBackgroundColor: COLORS.green, pointRadius: 2 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 12, font: { size: 11 } } } },
                scales: { r: { min: 0, max: 100, grid: { color: COLORS.grid }, angleLines: { color: COLORS.grid }, pointLabels: { color: COLORS.muted, font: { size: 10.5 } }, ticks: { display: false } } }
            }
        });
    }
}

/* Load the bundled SOC report while keeping xDome data on its live feed path. */
(async function initReports() {
    REPORT = null;
    const activeRange = () => +(document.querySelector(".range-btn.active")?.dataset.range || 30);
    // Overview charts must never be gated behind the long Claroty portal load,
    // otherwise a slow or failing xDome feed leaves every chart empty.
    const renderDashboardCharts = async () => {
        try {
            await build(activeRange());
            buildExtraCharts();
        } catch (error) {
            console.warn("[Dashboard] chart build failed:", error.message);
        }
    };
    let clarotyMessage = "Claroty connection status unavailable";
    try {
        const clarotyStatus = await ClarotyAPI.enableBackendUse();
        clarotyMessage = clarotyStatus.configured
            ? "Claroty xDome live feed · refreshes every 5 minutes"
            : "Claroty xDome paused · configure credentials in Settings";
    } catch (error) {
        clarotyMessage = `Claroty connection failed: ${error.message}`;
    }
    try {
        REPORT = await Reports.loadSample(activeRange());
        applyReportKpis();
        showReportBanner(`Bundled SOC report · ${REPORT.kpis.total.toLocaleString()} incidents analyzed · ${clarotyMessage}`);
    } catch (error) {
        console.warn("[Dashboard] bundled SOC report could not be loaded:", error.message);
        showReportBanner(`Bundled SOC report unavailable · ${clarotyMessage}`);
    }
    await renderDashboardCharts();
    try {
        await XDPortal.refresh();
    } catch (error) {
        showReportBanner(`Claroty live feed incomplete: ${error.message}`);
    }
    // Rebuild so Claroty-derived series pick up whatever finished loading.
    await renderDashboardCharts();
    try { updateCaseTrackingViews(); } catch (error) { /* tracking not loaded yet */ }
})();

const sampleSections = ["insider", "automation", "roi", "playbooks", "scorecard", "threatmap", "sla", "socopt", "incgraph"];
sampleSections.forEach(id => {
    const panel = document.getElementById(id);
    if (panel) panel.insertAdjacentHTML("afterbegin", `<div class="legacy-data-note">Sample analytics · This section is not connected to Claroty. Use the live xDome Home, Devices, Vulnerabilities, Risk &amp; Exposures, Alerts &amp; Threats, or Network views for current tenant data.</div>`);
});
const overview = document.getElementById("overview");
overview?.querySelector(".kpi-grid")?.insertAdjacentHTML("beforebegin", `<div class="legacy-data-note">Sample SOC KPIs and incident charts below. Live Claroty estate, risk, CVE, alert, and event data is shown above.</div>`);
document.querySelector("#threats .chart-row")?.insertAdjacentHTML("beforebegin", `<div class="legacy-data-note">The xDome vulnerability totals above are live. MITRE charts, aging, and high-risk users below use sample analytics; the xDome backlog table uses live Claroty findings.</div>`);
document.querySelector("#riskmanagement .integ-settings-header")?.insertAdjacentHTML("beforebegin", `<div class="legacy-data-note">The xDome Risk &amp; Exposures dashboard above is live. The CAB correlation, MTTR, revenue, and tool comparison below use sample records until those integrations are connected.</div>`);
document.querySelector("#alertfeed .alert-feed-toolbar")?.insertAdjacentHTML("beforebegin", `<div class="legacy-data-note">The xDome alerts above are live. SOC alert actions and rate charts below require a separate incident or SIEM integration; any charts shown there are sample analytics.</div>`);

/* ---------- High-Risk Users ---------- */
const riskUsers = [
    { name: "j.harmon", dept: "Finance", score: 92, cls: "hi" },
    { name: "svc-backup", dept: "Service Acct", score: 87, cls: "hi" },
    { name: "l.becker", dept: "Engineering", score: 74, cls: "md" },
    { name: "a.novak", dept: "Sales", score: 68, cls: "md" },
    { name: "admin-eu", dept: "IT Admin", score: 63, cls: "md" }
];
document.getElementById("riskUsers").innerHTML = riskUsers.map(u => `
    <li>
        <div class="risk-user">
            <div class="risk-avatar">${u.name.slice(0, 2).toUpperCase()}</div>
            <div><div class="risk-name">${u.name}</div><div class="risk-dept">${u.dept}</div></div>
        </div>
        <span class="risk-score ${u.cls}">${u.score}</span>
    </li>`).join("");

/* ---------- Playbook table ---------- */
const playbooks = [
    { uc: "Phishing Email Response", trig: "M365 / User Report", act: "Detonate URL, quarantine, block sender, purge mailbox", appr: "Analyst sign-off on bulk purge", integ: ["M365", "Defender", "Sentinel"], sla: "10 min", save: "80%" },
    { uc: "Malware Detection & Containment", trig: "CrowdStrike / Defender", act: "Isolate host, kill process, collect forensics", appr: "Approve host isolation", integ: ["CrowdStrike", "Defender", "ServiceNow"], sla: "15 min", save: "90%" },
    { uc: "Privileged Access Monitoring", trig: "Entra ID / AD logs", act: "Flag anomalous elevation, revoke session", appr: "Manager approval to revoke", integ: ["Entra ID", "AD", "Sentinel"], sla: "20 min", save: "65%" },
    { uc: "User Account Compromise", trig: "Sentinel UEBA", act: "Force MFA reset, disable account, notify user", appr: "Approve account disable", integ: ["Entra ID", "AD", "M365"], sla: "15 min", save: "75%" },
    { uc: "Vulnerability Remediation", trig: "Scanner / Splunk", act: "Create ticket, assign owner, track SLA", appr: "Change-board for patching", integ: ["ServiceNow", "Splunk"], sla: "SLA-based", save: "60%" },
    { uc: "SIEM Alert Triage", trig: "Sentinel / Splunk", act: "Enrich IOC, dedupe, auto-close FPs", appr: "None (auto)", integ: ["Sentinel", "Splunk"], sla: "5 min", save: "85%" },
    { uc: "Insider Threat Investigation", trig: "DLP / UEBA", act: "Correlate activity, preserve evidence", appr: "Legal + HR review", integ: ["Sentinel", "M365", "AD"], sla: "30 min", save: "55%" },
    { uc: "Endpoint Security Events", trig: "CrowdStrike / Palo Alto", act: "Block IP, update policy, isolate endpoint", appr: "Approve firewall change", integ: ["Palo Alto", "CrowdStrike"], sla: "15 min", save: "90%" }
];
document.querySelector("#playbookTable tbody").innerHTML = playbooks.map(p => `
    <tr>
        <td><strong>${p.uc}</strong></td>
        <td>${p.trig}</td>
        <td>${p.act}</td>
        <td>${p.appr}</td>
        <td>${p.integ.map(i => `<span class="tag">${i}</span>`).join("")}</td>
        <td>${p.sla}</td>
        <td><span class="up">${p.save}</span></td>
        <td class="playbook-cases" data-playbook="${p.uc}">0 / 0</td>
    </tr>`).join("");

/* ---------- KPI Scorecard (RAG) ---------- */
const kpis = [
    { name: "MTTD", target: "< 15 min", actual: "11 min", status: "green" },
    { name: "MTTR", target: "< 60 min", actual: "47 min", status: "green" },
    { name: "Automation Rate", target: "> 70%", actual: "74%", status: "green" },
    { name: "Phishing Containment", target: "< 10 min", actual: "8 min", status: "green" },
    { name: "Critical Incident Closure", target: "> 95%", actual: "91%", status: "amber" },
    { name: "Vulnerability Remediation SLA", target: "> 90%", actual: "84%", status: "amber" },
    { name: "Detection Coverage", target: "> 90%", actual: "88%", status: "amber" },
    { name: "Escalation Rate", target: "< 15%", actual: "22%", status: "red" }
];
const statusText = { green: "On Target", amber: "At Risk", red: "Off Target" };
document.querySelector("#kpiTable tbody").innerHTML = kpis.map(k => `
    <tr>
        <td><strong>${k.name}</strong></td>
        <td>${k.target}</td>
        <td>${k.actual}</td>
        <td><span class="status-dot ${k.status}">${statusText[k.status]}</span></td>
    </tr>`).join("");

/* ---------- Range picker + refresh ---------- */
document.querySelectorAll(".range-btn").forEach(btn => btn.addEventListener("click", () => {
    document.querySelectorAll(".range-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const range = +btn.dataset.range;
    if (REPORT?.sourceRows) {
        REPORT = Reports.build(REPORT.sourceRows, range);
        applyReportKpis();
    }
    build(range);
}));
let liveRefreshRunning = false;
async function refreshLiveDashboard(scheduled = false) {
    if (liveRefreshRunning || !ClarotyAPI.canGoLive()) return;
    if (scheduled && ["devices", "vulnerabilities"].some(feed => {
        const state = ClarotyAPI.feedState(feed);
        return state.source === "live" && !state.complete;
    })) return;
    liveRefreshRunning = true;
    const button = document.getElementById("refreshBtn");
    button.disabled = true;
    try {
        await XDPortal.refresh(true);
        const section = document.querySelector(".nav-item.active")?.dataset.section;
        if (section === "devices") await XDOME.renderDevices();
        if (section === "threats") await XDOME.renderVulnerabilities();
        showReportBanner("Claroty xDome live feed · updated " + new Date().toLocaleTimeString() + " · Refresh time: every 5 minutes");
    } catch (error) {
        showReportBanner(`Claroty refresh failed: ${error.message}`);
    } finally {
        button.disabled = false;
        liveRefreshRunning = false;
    }
}
document.getElementById("refreshBtn").addEventListener("click", refreshLiveDashboard);

window.addEventListener("swimlane-config-changed", () => {
    if (!SwimlaneAPI.canGoLive()) return;
    REPORT = null;
    hideReportBanner();
    build(+document.querySelector(".range-btn.active").dataset.range);
});

setInterval(() => {
    if (!document.hidden) refreshLiveDashboard(true);
}, 300000);

/* ---------- Theme toggle (dark / light) ---------- */
function syncSecumatTheme(mode) {
    const frame = document.querySelector("#udpSecumatPanel .secumat-workspace-frame");
    frame?.contentWindow?.postMessage({ type: "ot-platform-theme", theme: mode }, window.location.origin);
}

function applyTheme(theme, persist = true) {
    const mode = theme === "silver" ? "silver" : theme === "light" ? "light" : "dark";
    document.body.classList.toggle("light", mode === "light");
    document.body.classList.toggle("silver", mode === "silver");
    Chart.defaults.color = mode === "dark" ? COLORS.muted : "#404653";
    COLORS.grid = mode === "dark" ? "#2a2f3d" : "#ccd1d8";
    Chart.defaults.borderColor = COLORS.grid;
    const toggle = document.getElementById("themeToggle");
    if (toggle) { toggle.setAttribute("aria-label", `Theme: ${mode}. Click for next theme`); toggle.title = `Theme: ${mode}`; }
    if (persist) try { localStorage.setItem("soc-theme", mode); } catch (e) { /* ignore */ }
    syncSecumatTheme(mode);
}
document.querySelector("#udpSecumatPanel .secumat-workspace-frame")?.addEventListener("load", () => {
    const mode = document.body.classList.contains("light") ? "light" : document.body.classList.contains("silver") ? "silver" : "dark";
    syncSecumatTheme(mode);
});
const themeToggle = document.getElementById("themeToggle");
if (themeToggle) {
    themeToggle.addEventListener("click", () => {
        const current = document.body.classList.contains("light") ? "light" : document.body.classList.contains("silver") ? "silver" : "dark";
        applyTheme({ dark: "silver", silver: "light", light: "dark" }[current]);
    });
}
(function initTheme() {
    let saved = "dark";
    try { saved = localStorage.getItem("soc-theme") || "dark"; } catch (e) { /* ignore */ }
    applyTheme(saved, false);
})();

/* ---------- Report banner + CSV import ---------- */
function showReportBanner(text) {
    const b = document.getElementById("reportBanner");
    if (!b) return;
    document.getElementById("reportBannerText").textContent = text;
    b.hidden = false;
}
function hideReportBanner() {
    const b = document.getElementById("reportBanner");
    if (b) b.hidden = true;
}
const importBtn = document.getElementById("importBtn");
const csvInput = document.getElementById("csvInput");
if (importBtn && csvInput) {
    importBtn.addEventListener("click", () => csvInput.click());
    csvInput.addEventListener("change", () => {
        const file = csvInput.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            const range = +document.querySelector(".range-btn.active").dataset.range;
            try {
                const rows = Reports.parseCSV(reader.result);
                REPORT = Reports.build(rows, range);
                showReportBanner(`${file.name} · ${REPORT.kpis.total} incidents analyzed`);
                applyReportKpis();
                build(range);
            } catch (err) {
                showReportBanner("Could not parse CSV — expected columns: Tracking Id, Case Status, BMC Incident Title");
            }
        };
        reader.readAsText(file);
        csvInput.value = "";
    });
}

/* ---------- Insider Threat investigation KPIs ---------- */
const insiderKpis = [
    { name: "Alert Investigation Time", val: "34 min", status: "green" },
    { name: "Insider Case Closure Rate", val: "88%", status: "green" },
    { name: "False Positive Rate", val: "17%", status: "amber" },
    { name: "Escalation Rate", val: "21%", status: "amber" },
    { name: "Confirmed Insider Cases", val: "3", status: "red" },
    { name: "Mean Resolution Time", val: "2.4 days", status: "green" }
];
document.querySelector("#insiderKpiTable tbody").innerHTML = insiderKpis.map(k => `
    <tr>
        <td><strong>${k.name}</strong></td>
        <td>${k.val}</td>
        <td><span class="status-dot ${k.status}">${statusText[k.status]}</span></td>
    </tr>`).join("");

/* ---------- Automation ROI: metric targets ---------- */
const roiMetrics = [
    { name: "Alert Fatigue Reduction", target: "> 50%", actual: "63%", status: "green" },
    { name: "Automated Closure Rate", target: "> 65%", actual: "72%", status: "green" },
    { name: "Phishing Auto-Closure", target: "> 80%", actual: "84%", status: "green" },
    { name: "Low-Risk Auto-Closure", target: "> 90%", actual: "93%", status: "green" },
    { name: "Investigation Efficiency Gain", target: "40–70%", actual: "58%", status: "green" },
    { name: "Enrichment Automation", target: "> 85%", actual: "88%", status: "green" }
];
document.querySelector("#roiTable tbody").innerHTML = roiMetrics.map(k => `
    <tr>
        <td><strong>${k.name}</strong></td>
        <td>${k.target}</td>
        <td>${k.actual}</td>
        <td><span class="status-dot ${k.status}">${statusText[k.status]}</span></td>
    </tr>`).join("");

/* ---------- ROI Calculator ---------- */
function recalcRoi() {
    const incidents = +document.getElementById("roiIncidents").value || 0;
    const manual = +document.getElementById("roiMinutes").value || 0;
    const proc = +document.getElementById("roiProc").value || 0;
    const cost = +document.getElementById("roiCost").value || 0;

    const hoursSaved = Math.max(0, (incidents * manual - incidents * proc) / 60);   // per month
    const fte = (hoursSaved * 12) / (160 * 12);                                      // annual hours ÷ annual FTE hours
    const avoidance = fte * cost;

    document.getElementById("outHours").textContent = Math.round(hoursSaved).toLocaleString() + " h";
    document.getElementById("outFte").textContent = fte.toFixed(2) + " FTE";
    document.getElementById("outCost").textContent = "$" + Math.round(avoidance).toLocaleString();
}
["roiIncidents", "roiMinutes", "roiProc", "roiCost"].forEach(id =>
    document.getElementById(id).addEventListener("input", recalcRoi));
recalcRoi();

/* ---------- SIEM integration cards ---------- */
const siemIntegrations = [
    {
        id: "sentinel", name: "Microsoft Sentinel", color: "#0078d4",
        workflows: ["Incident creation", "Entity enrichment", "Defender correlation", "Automated isolation", "TI matching"],
        metrics: []
    },
    {
        id: "splunk", name: "Splunk Enterprise Security", color: "#65a637",
        workflows: ["Notable events", "Risk-based alerting", "UBA events", "Threat hunting results"],
        metrics: []
    },
    {
        id: "qradar", name: "IBM QRadar", color: "#1f70c1",
        workflows: ["Offense enrichment", "Asset context retrieval", "User behavior analysis", "Auto assignment"],
        metrics: []
    },
    {
        id: null, name: "Micro Focus ArcSight", color: "#0073e7",
        workflows: ["Case management", "TI correlation", "Alert deduplication", "Workflow routing"],
        metrics: []
    },
    {
        id: "elastic", name: "Elastic Security", color: "#00bfb3",
        workflows: ["Endpoint investigation", "Threat hunting", "IOC enrichment", "Automated response"],
        metrics: []
    },
    {
        id: "crowdstrike", name: "CrowdStrike + Defender XDR", color: "#e10600",
        workflows: ["Host isolation", "Process termination", "Forensic collection", "Detection sync"],
        metrics: []
    }
];
document.getElementById("siemCards").innerHTML = siemIntegrations.map(s => `
    <div class="integ-card">
        <div class="integ-head">
            <div class="integ-logo" style="background:${s.color}">${s.name.split(" ").map(w => w[0]).join("").slice(0, 2)}</div>
            <div>
                <div class="integ-title">${s.name}</div>
                <div class="integ-status">${s.id && INTEGRATIONS.isConfigured(s.id) ? "● Settings saved · unverified" : "○ Awaiting API credentials"}</div>
            </div>
        </div>
        <div class="integ-sub">Automated Workflows</div>
        <ul class="integ-list">${s.workflows.map(w => `<li>${w}</li>`).join("")}</ul>
        <div class="integ-sub">Readiness</div>
        <div class="integ-metrics"><div class="integ-metric"><b>${s.id && INTEGRATIONS.isConfigured(s.id) ? "Configured" : "Not configured"}</b><span>Connection and telemetry require verification</span></div></div>
    </div>`).join("");

function renderSettingsToolInventory() {
    const target = document.getElementById("settingsToolInventory");
    if (!target) return;
    target.innerHTML = siemIntegrations.map(s => `
    <div class="integ-card">
        <div class="integ-head">
            <div class="integ-logo" style="background:${s.color}">${s.name.split(" ").map(w => w[0]).join("").slice(0, 2)}</div>
            <div>
                <div class="integ-title">${s.name}</div>
                <div class="integ-status">${s.id && INTEGRATIONS.isConfigured(s.id) ? "● Settings saved · unverified" : "○ Awaiting API credentials"}</div>
            </div>
        </div>
        <div class="integ-sub">OT Platform Workflows</div>
        <ul class="integ-list">${s.workflows.map(w => `<li>${w}</li>`).join("")}</ul>
        <div class="integ-sub">Readiness</div>
        <div class="integ-metrics"><div class="integ-metric"><b>${s.id && INTEGRATIONS.isConfigured(s.id) ? "Configured · unverified" : "Not configured"}</b><span>Saved credentials do not verify data flow</span></div></div>
    </div>`).join("");
}

async function loadSiemDashboard() {
    const status = document.getElementById("siemDashboardStatus");
    const kpis = document.getElementById("siemLiveKpis");
    if (!status || !kpis) return;
    status.textContent = "Refreshing local event, feed and detection-engine data…";
    try {
        const response = await fetch("/api/siem/dashboard", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `SIEM dashboard request failed (${response.status})`);
        const counts = payload.counts || {};
        const metrics = [
            ["Stored events", counts.events],
            ["Events · 24 hours", counts.eventsLast24Hours],
            ["Alerts", counts.alerts],
            ["Vulnerability records", counts.vulnerabilities],
            ["Observed sources", counts.sources],
            ["Indexed indicators", counts.indicators],
            ["Feed-matched alerts", counts.feedMatchedAlerts],
            ["Feed-matched IOCs", counts.feedMatchedIndicators],
            ["Rule detections", counts.ruleDetections],
            ["Audit assignments", counts.auditAssignments],
            ["GitHub events", counts.githubEvents],
            ["GitLab events", counts.gitlabEvents]
        ];
        kpis.innerHTML = metrics.map(([label, value]) => `<div class="module-analytics-metric"><span>${escapeOverviewWidgetText(label)}</span><strong>${Number(value || 0).toLocaleString()}</strong></div>`).join("");
        const volume = Array.isArray(payload.dailyVolume) ? payload.dailyVolume : [];
        if (charts.siem) {
            charts.siem.data.labels = volume.map(item => item.date.slice(5));
            charts.siem.data.datasets[0].data = volume.map(item => item.count);
            charts.siem.update();
        }
        const sources = Array.isArray(payload.bySource) ? payload.bySource.slice(0, 7) : [];
        if (charts.siemShare) {
            charts.siemShare.data.labels = sources.map(item => item.source);
            charts.siemShare.data.datasets[0].data = sources.map(item => item.count);
            charts.siemShare.update();
        }
        const frameworks = Array.isArray(payload.frameworks) ? payload.frameworks : [];
        document.getElementById("siemFrameworkRows").innerHTML = frameworks.map(item =>
            `<tr><td>${escapeOverviewWidgetText(item.name)}</td><td>${Number(item.assignmentCount || 0).toLocaleString()}</td><td>${Number(item.reviewedCount || 0).toLocaleString()}</td><td>${escapeOverviewWidgetText(item.status.replaceAll("_", " "))}</td></tr>`
        ).join("") || `<tr><td colspan="4">No local audit evidence is available.</td></tr>`;
        const attack = payload.attack || {};
        document.getElementById("siemAttackStatus").innerHTML = `<div class="public-feed-source"><strong>${Number(attack.catalogueTacticsCovered || 0)}/${Number(attack.catalogueTacticsTotal || 0)} tactics</strong><span>Mapped loaded-rule coverage</span></div><div class="public-feed-source"><strong>${Number(attack.catalogueRules || 0).toLocaleString()} rules</strong><span>Rules in local catalogue</span></div><div class="public-feed-source"><strong>${(attack.observedTechniques || []).length.toLocaleString()} techniques</strong><span>Observed in local event records</span></div>`;
        document.getElementById("siemAttackRows").innerHTML = (attack.observedTechniques || []).map(item =>
            `<tr><td>${escapeOverviewWidgetText(item.techniqueId)}</td><td>${Number(item.occurrences || 0).toLocaleString()}</td><td>${escapeOverviewWidgetText(item.tactic || "Unmapped")}</td><td>${escapeOverviewWidgetText(item.catalogueEvidence.replaceAll("_", " "))}</td></tr>`
        ).join("") || `<tr><td colspan="4">No ATT&amp;CK techniques were reported in local events. Missing attribution is not proof of no activity.</td></tr>`;
        const publicSources = payload.feeds?.vulnerabilitySources || [];
        const indicatorSources = payload.feeds?.indicatorPartitions || [];
        const publicFeedCards = publicSources.map(feed =>
            `<div class="public-feed-source ${feed.status === "live" ? "live" : "error"}"><strong>${escapeOverviewWidgetText(feed.name)}</strong><span>${escapeOverviewWidgetText(feed.status)} · ${Number(feed.count || 0).toLocaleString()} records${feed.error ? ` · ${escapeOverviewWidgetText(feed.error)}` : ""}</span></div>`
        );
        const indicatorCards = indicatorSources.map(feed =>
            `<div class="public-feed-source ${feed.status === "live" ? "live" : feed.status === "error" ? "error" : ""}"><strong>${escapeOverviewWidgetText(feed.name)}</strong><span>${Number(feed.indicatorCount || 0).toLocaleString()} indicators · ${escapeOverviewWidgetText(feed.status)} · refresh ${Number(feed.refreshIntervalSeconds || 0) / 3600}h${feed.lastSuccess ? ` · ${new Date(feed.lastSuccess).toLocaleString()}` : ""}${feed.error ? ` · ${escapeOverviewWidgetText(feed.error)}` : ""}</span></div>`
        );
        document.getElementById("siemFeedStatus").innerHTML = [...publicFeedCards, ...indicatorCards].join("") || "No feed status is available.";
        const engine = payload.detectionEngine || {};
        const engineCards = [
            `<div class="public-feed-source ${engine.engine?.available ? "live" : "error"}"><strong>Snort engine</strong><span>${engine.engine?.available ? `Available · ${escapeOverviewWidgetText(engine.engine.path)}` : "Not installed or not on PATH · runtime validation not run"}</span></div>`,
            `<div class="public-feed-source ${engine.alternatives?.suricata?.available ? "live" : "error"}"><strong>Suricata alternative</strong><span>${engine.alternatives?.suricata?.available ? `Available · ${escapeOverviewWidgetText(engine.alternatives.suricata.path)}` : "Not installed or not on PATH"}</span></div>`,
            `<div class="public-feed-source ${engine.rules?.enabled ? "live" : ""}"><strong>Snort rule catalogue</strong><span>${Number(engine.rules?.enabled || 0).toLocaleString()} enabled / ${Number(engine.rules?.total || 0).toLocaleString()} catalogued · catalogue only, not running detection</span></div>`
        ];
        document.getElementById("siemDetectionStatus").innerHTML = engineCards.join("");
        document.getElementById("siemMethodNote").textContent = payload.method || "";
        status.textContent = `Local evidence refreshed ${new Date(payload.generatedAt).toLocaleString()} · ${Number(counts.eventsLast24Hours || 0).toLocaleString()} event(s) observed in the last 24 hours.`;
    } catch (error) {
        status.textContent = `SIEM dashboard data unavailable: ${error.message}`;
        kpis.replaceChildren();
    }
}

async function searchSiemEvents(queryText = "") {
    const status = document.getElementById("siemSearchStatus");
    const rows = document.getElementById("siemEventRows");
    if (!status || !rows) return;
    status.textContent = "Searching local event and module records…";
    try {
        const params = new URLSearchParams({ q: queryText, limit: "100" });
        const response = await fetch(`/api/siem/events?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Event search failed (${response.status})`);
        rows.innerHTML = (payload.records || []).map(item => {
            const details = JSON.stringify(item.details || {}, null, 2);
            return `<tr><td>${escapeOverviewWidgetText(item.time || "Not reported")}</td><td>${escapeOverviewWidgetText(item.eventType)}</td><td>${escapeOverviewWidgetText(item.source)}</td><td>${escapeOverviewWidgetText(item.severity)} / ${escapeOverviewWidgetText(item.status)}</td><td>${escapeOverviewWidgetText(item.device || "Not reported")}</td><td>${escapeOverviewWidgetText(item.path || "Not reported")}</td><td>${escapeOverviewWidgetText((item.iocs || []).filter(Boolean).join(", ") || "Not reported")}</td><td>${escapeOverviewWidgetText(item.module || "canonical event")}</td><td><details><summary>View</summary><pre>${escapeOverviewWidgetText(details || "No details reported")}</pre></details></td></tr>`;
        }).join("") || `<tr><td colspan="9">No local events match this query.</td></tr>`;
        status.textContent = `${Number(payload.count || 0).toLocaleString()} matching local record(s) · showing up to ${Number(payload.limit || 100).toLocaleString()}.`;
    } catch (error) {
        status.textContent = `Local event search unavailable: ${error.message}`;
        rows.innerHTML = `<tr><td colspan="9">Could not search local events.</td></tr>`;
    }
}

document.getElementById("siemSearchForm")?.addEventListener("submit", event => {
    event.preventDefault();
    searchSiemEvents(document.getElementById("siemSearchQuery").value);
});
document.getElementById("refreshSiemDashboard")?.addEventListener("click", () => loadSiemDashboard());
document.getElementById("refreshApiFeeds")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    const status = document.getElementById("apiFeedSyncStatus");
    button.disabled = true;
    status.textContent = "Syncing configured read-only API feeds…";
    try {
        const response = await fetch("/api/integrations/api-feeds/refresh", { method: "POST" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `API feed refresh failed (${response.status})`);
        status.textContent = `Sync finished · ${Number(payload.count || 0).toLocaleString()} event(s) routed.`;
        await Promise.all([loadSiemDashboard(), loadAuditEvents(true)]);
    } catch (error) {
        status.textContent = `API feed sync unavailable: ${error.message}`;
    } finally {
        button.disabled = false;
    }
});
document.querySelector('.nav-item[data-section="siem"]')?.addEventListener("click", () => {
    window.setTimeout(() => {
        loadSiemDashboard();
        searchSiemEvents(document.getElementById("siemSearchQuery")?.value || "");
    }, 0);
});
document.querySelectorAll('[data-soc-open-section="siem"]').forEach(button => button.addEventListener("click", () => {
    window.setTimeout(() => {
        loadSiemDashboard();
        searchSiemEvents(document.getElementById("siemSearchQuery")?.value || "");
    }, 0);
}));

let auditEventOffset = 0;
const auditEventLimit = 100;
let auditRubrikCursor = { activityAfter: null, auditAfter: null, activityDone: false, auditDone: false };

function auditEventQuery() {
    const source = document.getElementById("auditSourceFilter")?.value || "";
    const category = document.getElementById("auditCategoryFilter")?.value || "";
    const severity = document.getElementById("auditSeverityFilter")?.value || "";
    const text = document.getElementById("auditTextFilter")?.value.trim() || "";
    const filters = [];
    if (source) filters.push(`source:"${source.replaceAll('"', "")}"`);
    if (category) filters.push(`category:${category}`);
    if (severity) filters.push(`severity:${severity}`);
    if (text) filters.push(text);
    return filters.join(" ");
}

async function loadAuditEvents(resetPage = true) {
    const status = document.getElementById("auditEventStatus");
    const rows = document.getElementById("auditEventRows");
    const sourceSelect = document.getElementById("auditSourceFilter");
    const previous = document.getElementById("auditPrevPage");
    const next = document.getElementById("auditNextPage");
    if (!status || !rows || !sourceSelect) return;
    if (resetPage) auditEventOffset = 0;
    status.textContent = "Loading locally stored events and module records…";
    try {
        const params = new URLSearchParams({ q: auditEventQuery(), limit: String(auditEventLimit), offset: String(auditEventOffset) });
        const response = await fetch(`/api/siem/events?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Audit log request failed (${response.status})`);
        const selectedSource = sourceSelect.value;
        const sourceOptions = (payload.sourceOptions || []).map(source => `<option value="${escapeOverviewWidgetText(source)}">${escapeOverviewWidgetText(source)}</option>`).join("");
        sourceSelect.innerHTML = `<option value="">All tools</option>${sourceOptions}`;
        sourceSelect.value = (payload.sourceOptions || []).includes(selectedSource) ? selectedSource : "";
        rows.innerHTML = (payload.records || []).map(item => {
            const details = JSON.stringify(item.details || {}, null, 2);
            const routed = Array.isArray(item.routedModules) ? item.routedModules.join(", ") : "";
            const iocs = (item.iocs || []).filter(Boolean).join(", ");
            return `<tr><td>${escapeOverviewWidgetText(item.time || "Not reported")}</td><td>${escapeOverviewWidgetText(item.category || "other")}</td><td>${escapeOverviewWidgetText(item.eventType)}<br>${escapeOverviewWidgetText(item.summary || "")}</td><td>${escapeOverviewWidgetText(item.source || "Unspecified")}<br><small>${escapeOverviewWidgetText(item.origin || "Origin not reported")}</small></td><td>${escapeOverviewWidgetText(item.severity)} / ${escapeOverviewWidgetText(item.status)}</td><td>${escapeOverviewWidgetText(item.device || "Not reported")}</td><td>${escapeOverviewWidgetText(item.path || "Not reported")}${iocs ? `<br>${escapeOverviewWidgetText(iocs)}` : ""}</td><td>${escapeOverviewWidgetText(routed || item.module || "Not reported")}</td><td><details><summary>View</summary><pre>${escapeOverviewWidgetText(details || "No details reported")}</pre></details></td></tr>`;
        }).join("") || `<tr><td colspan="9">No local records match these filters.</td></tr>`;
        renderAuditRubrikOrigin(payload.sourceSummary?.["Rubrik Security Cloud"]);
        if (previous) previous.disabled = auditEventOffset === 0;
        if (next) next.disabled = auditEventOffset + auditEventLimit >= Number(payload.count || 0);
        const first = Number(payload.count || 0) ? auditEventOffset + 1 : 0;
        const last = Math.min(auditEventOffset + (payload.records || []).length, Number(payload.count || 0));
        status.textContent = `${Number(payload.count || 0).toLocaleString()} matching local record(s) · showing ${first.toLocaleString()}–${last.toLocaleString()}. Configured tools without ingested records are not included.`;
    } catch (error) {
        status.textContent = `Audit logs unavailable: ${error.message}`;
        rows.innerHTML = `<tr><td colspan="9">Could not load local audit and event records.</td></tr>`;
    }
}

function renderAuditRubrikOrigin(summary) {
    const panel = document.getElementById("auditRubrikOrigin");
    const body = document.getElementById("auditRubrikOriginBody");
    if (!panel || !body) return;
    const rubrikSelected = document.getElementById("auditSourceFilter")?.value === "Rubrik Security Cloud";
    panel.hidden = !rubrikSelected;
    if (!rubrikSelected) return;
    if (!summary) {
        body.textContent = "No Rubrik records are stored for these filters. Use Sync Rubrik now, or check Settings > Integrations for credentials and the Rubrik feed toggle.";
        return;
    }
    const origins = Object.entries(summary.origins || {}).map(([name, count]) => `${escapeOverviewWidgetText(name)}: ${Number(count).toLocaleString()}`).join(" · ");
    const paths = (summary.paths || []).map(escapeOverviewWidgetText).join(", ") || "None reported";
    body.innerHTML = `<strong>${Number(summary.count || 0).toLocaleString()}</strong> Rubrik record(s) detected · latest event ${escapeOverviewWidgetText(summary.latest || "Not reported")}<br>Log origin: ${origins}<br>Paths detected: ${paths}`;
}

function setAuditSourceTab(source) {
    const select = document.getElementById("auditSourceFilter");
    if (!select) return;
    select.value = source;
    document.getElementById("auditTabAll")?.setAttribute("aria-selected", String(!source));
    document.getElementById("auditTabRubrik")?.setAttribute("aria-selected", String(source === "Rubrik Security Cloud"));
    loadAuditEvents(true);
}
document.getElementById("auditTabAll")?.addEventListener("click", () => setAuditSourceTab(""));
document.getElementById("auditTabRubrik")?.addEventListener("click", () => setAuditSourceTab("Rubrik Security Cloud"));

document.getElementById("auditEventForm")?.addEventListener("submit", event => {
    event.preventDefault();
    loadAuditEvents(true);
});
["auditSourceFilter", "auditCategoryFilter", "auditSeverityFilter"].forEach(id => {
    document.getElementById(id)?.addEventListener("change", () => loadAuditEvents(true));
});
async function syncAuditRubrik(loadMore = false) {
    const status = document.getElementById("auditRubrikStatus");
    const syncButton = document.getElementById("auditRefresh");
    const moreButton = document.getElementById("auditRubrikMore");
    if (!status || !syncButton) return;
    if (!loadMore) {
        auditRubrikCursor = { activityAfter: null, auditAfter: null, activityDone: false, auditDone: false };
        if (moreButton) moreButton.hidden = true;
    }
    syncButton.disabled = true;
    if (moreButton) moreButton.disabled = true;
    status.textContent = loadMore ? "Loading the next Rubrik workload and audit pages…" : "Syncing Rubrik workload activity and audit events for the last 24 hours…";
    try {
        const params = new URLSearchParams({ lookback_minutes: "1440" });
        if (auditRubrikCursor.activityAfter) params.set("activity_after", auditRubrikCursor.activityAfter);
        if (auditRubrikCursor.auditAfter) params.set("audit_after", auditRubrikCursor.auditAfter);
        if (auditRubrikCursor.activityDone) params.set("activity_done", "true");
        if (auditRubrikCursor.auditDone) params.set("audit_done", "true");
        const response = await fetch(`/api/integrations/rubrik/events?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Rubrik sync failed (${response.status})`);
        auditRubrikCursor = {
            activityAfter: payload.nextActivityCursor || null,
            auditAfter: payload.nextAuditCursor || null,
            activityDone: !payload.hasMoreActivities,
            auditDone: !payload.hasMoreAuditEvents
        };
        if (moreButton) {
            moreButton.hidden = !payload.partial;
            moreButton.disabled = !payload.partial;
        }
        const completion = payload.partial ? "More Rubrik pages are available." : "Rubrik sync complete for the 24-hour window.";
        status.textContent = `${completion} Page received ${Number(payload.activityCount || 0)} workload event(s) and ${Number(payload.auditCount || 0)} audit event(s); ${Number(payload.routedCount || 0)} record(s) stored and linked to modules.`;
        await loadAuditEvents(true);
    } catch (error) {
        status.textContent = `Rubrik sync unavailable: ${error.message}. Previously stored events are still available below.`;
        await loadAuditEvents(false);
    } finally {
        syncButton.disabled = false;
        if (moreButton && !moreButton.hidden) moreButton.disabled = false;
    }
}

document.getElementById("auditRefresh")?.addEventListener("click", () => syncAuditRubrik(false));
document.getElementById("auditRubrikMore")?.addEventListener("click", () => syncAuditRubrik(true));
document.getElementById("auditPrevPage")?.addEventListener("click", () => {
    auditEventOffset = Math.max(0, auditEventOffset - auditEventLimit);
    loadAuditEvents(false);
});
document.getElementById("auditNextPage")?.addEventListener("click", () => {
    auditEventOffset += auditEventLimit;
    loadAuditEvents(false);
});
document.querySelector('.nav-item[data-section="audit"]')?.addEventListener("click", () => {
    window.setTimeout(() => syncAuditRubrik(false), 0);
});

/* ---------- OSINT Navigator: local technique catalogue and observable pivot ---------- */
const osintAccessLabels = {
    local: "Runs here",
    free: "Free",
    registration: "Registration",
    paid: "Paid"
};

const osintTypeLabels = {
    ip: "IP address",
    url: "URL",
    cve: "CVE",
    crypto_address: "Crypto address",
    coordinates: "Coordinates",
    hash: "File hash"
};

function osintLabel(value) {
    const key = String(value || "");
    if (osintTypeLabels[key]) return osintTypeLabels[key];
    return key.replace(/_/g, " ").replace(/\b\w/g, character => character.toUpperCase());
}

function renderOsintTechniqueRows(techniques) {
    const rows = document.getElementById("osintTechniqueRows");
    if (!rows) return;
    const count = document.getElementById("osintTechniqueCount");
    if (count) count.textContent = `Showing ${Number(techniques.length || 0).toLocaleString()} techniques`;
    if (!techniques.length) {
        rows.innerHTML = `<tr><td colspan="8">No technique matches these filters.</td></tr>`;
        return;
    }
    rows.innerHTML = techniques.map(item => {
        const detail = `${item.description}\n\nTypical use: ${item.useCase || "Not recorded"}`;
        const runsHere = item.runsLocally
            ? `<span class="pill green">Yes</span>`
            : `<span class="pill amber">Manual</span>`;
        return `<tr>
            <td>${escapeOverviewWidgetText(item.name)}</td>
            <td>${escapeOverviewWidgetText(item.categoryName)}</td>
            <td>${escapeOverviewWidgetText(item.subcategory)}</td>
            <td>${escapeOverviewWidgetText((item.inputs || []).map(osintLabel).join(", ") || "Any")}</td>
            <td>${escapeOverviewWidgetText((item.outputs || []).map(osintLabel).join(", "))}</td>
            <td>${escapeOverviewWidgetText(osintAccessLabels[item.access] || item.access)}</td>
            <td>${runsHere}</td>
            <td><details><summary>View</summary><pre>${escapeOverviewWidgetText(detail)}</pre></details></td>
        </tr>`;
    }).join("");
}

async function loadOsintFramework() {
    const status = document.getElementById("osintStatus");
    const kpis = document.getElementById("osintKpis");
    if (!status || !kpis) return;
    status.textContent = "Loading the local technique catalogue…";
    try {
        const response = await fetch("/api/osint/framework", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `OSINT catalogue request failed (${response.status})`);
        const summary = payload.summary || {};
        const metrics = [
            ["Disciplines", summary.categories],
            ["Techniques", summary.techniques],
            ["Run on this platform", summary.runsLocally],
            ["Manual procedures", summary.manualProcedures]
        ];
        kpis.innerHTML = metrics.map(([label, value]) => `<div class="module-analytics-metric"><span>${escapeOverviewWidgetText(label)}</span><strong>${Number(value || 0).toLocaleString()}</strong></div>`).join("");

        const categories = Array.isArray(payload.categories) ? payload.categories : [];
        const categorySelect = document.getElementById("osintCategory");
        if (categorySelect && categorySelect.options.length <= 1) {
            categorySelect.insertAdjacentHTML("beforeend", categories.map(item =>
                `<option value="${escapeOverviewWidgetText(item.id)}">${escapeOverviewWidgetText(item.name)}</option>`).join(""));
        }
        const inputSelect = document.getElementById("osintInput");
        if (inputSelect && inputSelect.options.length <= 1) {
            inputSelect.insertAdjacentHTML("beforeend", (payload.inputTypes || []).map(item =>
                `<option value="${escapeOverviewWidgetText(item)}">${escapeOverviewWidgetText(osintLabel(item))}</option>`).join(""));
        }
        const accessSelect = document.getElementById("osintAccess");
        if (accessSelect && accessSelect.options.length <= 1) {
            accessSelect.insertAdjacentHTML("beforeend", (payload.accessTiers || []).map(item =>
                `<option value="${escapeOverviewWidgetText(item)}">${escapeOverviewWidgetText(osintAccessLabels[item] || item)}</option>`).join(""));
        }

        const categoryRows = document.getElementById("osintCategoryRows");
        const disciplineCount = document.getElementById("osintDisciplineCount");
        if (disciplineCount) disciplineCount.textContent = `${categories.length.toLocaleString()} disciplines`;
        if (categoryRows) {
            categoryRows.innerHTML = categories.map(item => `<tr>
                <td>${escapeOverviewWidgetText(item.name)}</td>
                <td>${Number(item.techniqueCount || 0).toLocaleString()}</td>
                <td>${Number(item.localTechniqueCount || 0).toLocaleString()}</td>
                <td>${escapeOverviewWidgetText((item.subcategories || []).map(sub => sub.name).join(", "))}</td>
                <td>${escapeOverviewWidgetText(item.summary)}</td>
            </tr>`).join("") || `<tr><td colspan="5">No categories loaded.</td></tr>`;
        }

        const note = document.getElementById("osintMethodNote");
        if (note) note.textContent = payload.method || "";
        status.textContent = `${Number(summary.techniques || 0).toLocaleString()} techniques across ${Number(summary.categories || 0).toLocaleString()} disciplines · ${Number(summary.runsLocally || 0).toLocaleString()} execute against local indexes.`;
        renderOsintTechniqueRows(payload.techniques || []);
        const searchStatus = document.getElementById("osintSearchStatus");
        if (searchStatus) searchStatus.textContent = `Showing all ${Number(summary.techniques || 0).toLocaleString()} techniques.`;
    } catch (error) {
        status.textContent = `OSINT catalogue unavailable: ${error.message}`;
        kpis.innerHTML = "";
    }
}

async function searchOsintTechniques() {
    const status = document.getElementById("osintSearchStatus");
    if (!status) return;
    const params = new URLSearchParams({
        q: document.getElementById("osintQuery")?.value || "",
        category: document.getElementById("osintCategory")?.value || "",
        input: document.getElementById("osintInput")?.value || "",
        access: document.getElementById("osintAccess")?.value || ""
    });
    status.textContent = "Filtering techniques…";
    try {
        const response = await fetch(`/api/osint/search?${params.toString()}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Technique search failed (${response.status})`);
        renderOsintTechniqueRows(payload.techniques || []);
        status.textContent = `${Number(payload.count || 0).toLocaleString()} technique(s) match the current filters.`;
    } catch (error) {
        status.textContent = `Technique search unavailable: ${error.message}`;
    }
}

async function runOsintPivot(value) {
    const status = document.getElementById("osintPivotStatus");
    const result = document.getElementById("osintPivotResult");
    if (!status || !result) return;
    if (!String(value || "").trim()) {
        status.textContent = "Enter an observable to pivot on.";
        result.innerHTML = "";
        return;
    }
    status.textContent = "Classifying the observable and running local checks…";
    result.innerHTML = "";
    try {
        const response = await fetch("/api/osint/pivot", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ value })
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Pivot failed (${response.status})`);
        const summary = payload.summary || {};
        status.textContent = `Classified as ${osintLabel(payload.inputType)} · ${Number(summary.localChecksRun || 0)} local check(s) run · ${Number(summary.localHits || 0)} returned a hit · ${Number(payload.techniqueCount || 0)} applicable technique(s).`;

        const enrichment = Array.isArray(payload.enrichment) ? payload.enrichment : [];
        const enrichmentRows = enrichment.map(item => {
            const verdict = item.matched
                ? `<span class="pill red">Hit</span>`
                : `<span class="pill green">No hit</span>`;
            return `<tr><td>${escapeOverviewWidgetText(item.name)}</td><td>${verdict}</td><td>${escapeOverviewWidgetText(item.detail)}</td></tr>`;
        }).join("") || `<tr><td colspan="3">No local check applies to this observable type.</td></tr>`;

        const errors = Array.isArray(payload.errors) ? payload.errors : [];
        const errorBlock = errors.length
            ? `<div class="public-feed-status">${escapeOverviewWidgetText(`Checks that could not run: ${errors.join(" · ")}`)}</div>`
            : "";

        const nextSteps = (payload.techniques || []).filter(item => !item.runsLocally);
        const nextStepRows = nextSteps.map(item =>
            `<tr><td>${escapeOverviewWidgetText(item.name)}</td><td>${escapeOverviewWidgetText(item.categoryName)}</td><td>${escapeOverviewWidgetText(osintAccessLabels[item.access] || item.access)}</td><td>${escapeOverviewWidgetText(item.description)}</td></tr>`
        ).join("") || `<tr><td colspan="4">No further manual technique recorded for this observable type.</td></tr>`;

        result.innerHTML = `
            <h4 style="margin:14px 0 6px;">Local checks performed on ${escapeOverviewWidgetText(payload.observable)}</h4>
            <div class="table-wrap"><table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>${enrichmentRows}</tbody></table></div>
            ${errorBlock}
            <h4 style="margin:14px 0 6px;">Recorded next steps — not performed</h4>
            <div class="table-wrap"><table><thead><tr><th>Technique</th><th>Category</th><th>Access</th><th>Procedure</th></tr></thead><tbody>${nextStepRows}</tbody></table></div>
            <p class="muted siem-method-note">${escapeOverviewWidgetText(payload.method || "")}</p>`;
    } catch (error) {
        status.textContent = `Pivot unavailable: ${error.message}`;
    }
}

document.getElementById("osintPivotForm")?.addEventListener("submit", event => {
    event.preventDefault();
    runOsintPivot(document.getElementById("osintPivotValue").value);
});
document.getElementById("osintFilterForm")?.addEventListener("submit", event => {
    event.preventDefault();
    searchOsintTechniques();
});
document.getElementById("refreshOsint")?.addEventListener("click", () => loadOsintFramework());
document.querySelector('.nav-item[data-section="osint"]')?.addEventListener("click", () => {
    window.setTimeout(() => {
        if (!document.getElementById("osintKpis")?.childElementCount) loadOsintFramework();
    }, 0);
});
document.querySelectorAll('[data-soc-open-section="osint"]').forEach(button => button.addEventListener("click", () => {
    window.setTimeout(() => {
        if (!document.getElementById("osintKpis")?.childElementCount) loadOsintFramework();
    }, 0);
}));

/* ---------- Threat Intel: IOC enrichment catalog + universal search ---------- */
const iocSources = {
    ip:     ["VirusTotal", "AbuseIPDB", "AlienVault OTX", "Cisco Talos", "GreyNoise", "Shodan", "Censys"],
    url:    ["VirusTotal", "URLScan", "PhishTank", "URLHaus", "Google Safe Browsing"],
    domain: ["VirusTotal", "AlienVault OTX", "Cisco Talos", "URLScan", "Censys"],
    hash:   ["VirusTotal", "MalwareBazaar", "AlienVault OTX", "ThreatFox"],
    cve:    ["NIST NVD", "CISA KEV", "MITRE CVE"]
};
const iocLinks = {
    "VirusTotal":            v => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`,
    "AbuseIPDB":             v => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}`,
    "AlienVault OTX":        (v, t) => `https://otx.alienvault.com/indicator/${t === "hash" ? "file" : t}/${encodeURIComponent(v)}`,
    "Cisco Talos":           v => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}`,
    "GreyNoise":             v => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}`,
    "Shodan":                v => `https://www.shodan.io/search?query=${encodeURIComponent(v)}`,
    "Censys":                v => `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(v)}`,
    "URLScan":               v => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
    "PhishTank":             () => `https://phishtank.org/`,
    "URLHaus":               v => `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(v)}`,
    "Google Safe Browsing":  v => `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(v)}`,
    "MalwareBazaar":         v => `https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(v)}`,
    "ThreatFox":             v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(v)}`,
    "NIST NVD":              v => `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(v)}`,
    "CISA KEV":              () => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
    "MITRE CVE":             v => `https://www.cve.org/CVERecord?id=${encodeURIComponent(v)}`
};

function classifyIoc(raw) {
    const v = raw.trim();
    if (!v) return null;
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return "cve";
    if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return "ip";
    if (/^https?:\/\//i.test(v) || /\/.+/.test(v)) return "url";
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return "domain";
    return null;
}

const iocInput = document.getElementById("iocInput");
if (iocInput) {
    const iocType = document.getElementById("iocType");
    const iocResults = document.getElementById("iocResults");
    const localFeedLookup = document.getElementById("localFeedLookup");
    let localLookupSequence = 0;
    let localLookupTimer = null;

    async function checkLocalThreatFeed(raw, type) {
        let indicator = raw.trim();
        let feedType = type;
        if (type === "url") {
            try { indicator = new URL(indicator).hostname; feedType = "domain"; } catch {
                localFeedLookup.textContent = "Could not extract a hostname for local feed lookup.";
                return;
            }
        } else if (type === "hash") {
            feedType = indicator.length === 32 ? "md5" : indicator.length === 40 ? "sha1" : "sha256";
        }
        if (!["ip", "domain", "md5", "sha1", "sha256"].includes(feedType)) {
            localFeedLookup.textContent = type === "cve"
                ? "CVE checks use the existing vulnerability feeds; this local index contains IP, domain and file-hash indicators."
                : "Local feed lookup supports IP addresses, domains and MD5/SHA hashes.";
            return;
        }
        const requestId = ++localLookupSequence;
        localFeedLookup.textContent = "Checking the local indicator index…";
        try {
            const query = new URLSearchParams({ value: indicator, type: feedType });
            const response = await fetch(`/api/threat-intel/lookup?${query}`, { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || `Local feed lookup failed (${response.status})`);
            if (requestId !== localLookupSequence) return;
            localFeedLookup.className = `local-feed-lookup ${payload.matched ? "hit" : "miss"}`;
            localFeedLookup.textContent = payload.matched
                ? `Local threat-feed match · ${payload.type.toUpperCase()} ${payload.indicator} · ${payload.sources.map(source => source.name).join(", ")}`
                : `No local threat-feed match for ${payload.type.toUpperCase()} ${payload.indicator}.`;
        } catch (error) {
            if (requestId === localLookupSequence) {
                localFeedLookup.className = "local-feed-lookup error";
                localFeedLookup.textContent = `Local feed lookup unavailable: ${error.message}`;
            }
        }
    }

    function runIocSearch() {
        const raw = iocInput.value;
        const type = classifyIoc(raw);
        clearTimeout(localLookupTimer);
        if (!type) {
            iocType.textContent = raw.trim() ? "Unrecognized IOC format" : "Enter an IP, URL, domain, hash, or CVE";
            iocType.className = "ioc-type warn";
            iocResults.innerHTML = "";
            localFeedLookup.textContent = "Local indicator lookup is waiting for an IP, domain, or hash.";
            localFeedLookup.className = "local-feed-lookup";
            return;
        }
        iocType.textContent = `Detected: ${type.toUpperCase()}`;
        iocType.className = "ioc-type ok";
        const v = raw.trim();
        iocResults.innerHTML = iocSources[type].map(src => {
            const href = (iocLinks[src] || (() => "#"))(v, type);
            return `<a class="ioc-chip" href="${href}" target="_blank" rel="noopener noreferrer">${src} <span>↗</span></a>`;
        }).join("");
        localLookupTimer = setTimeout(() => checkLocalThreatFeed(v, type), 250);
    }
    iocInput.addEventListener("input", runIocSearch);
    document.getElementById("iocSearchBtn").addEventListener("click", runIocSearch);
    iocInput.addEventListener("keydown", e => { if (e.key === "Enter") runIocSearch(); });
}

async function loadThreatFeedStatus() {
    const status = document.getElementById("threatFeedStatus");
    const rows = document.getElementById("threatFeedRows");
    if (!status || !rows) return;
    try {
        const response = await fetch("/api/threat-intel/feeds", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Feed status request failed (${response.status})`);
        const displayTime = value => value ? new Date(value).toLocaleString() : "Not refreshed";
        rows.innerHTML = payload.feeds.map(feed => `<tr><td>${escapeOverviewWidgetText(feed.name)}</td><td>${escapeOverviewWidgetText(feed.type.toUpperCase())}</td><td>${Number(feed.indicatorCount || 0).toLocaleString()}</td><td title="${escapeOverviewWidgetText(feed.error || "")}">${escapeOverviewWidgetText(feed.status)}</td><td>${Number(feed.refreshIntervalSeconds || 0) / 3600} h</td><td>${escapeOverviewWidgetText(displayTime(feed.lastSuccess))}</td></tr>`).join("");
        status.textContent = `${Number(payload.indicatorCount || 0).toLocaleString()} unique indicators across ${Number(payload.feedCount || 0)} local feed partitions · last successful refresh ${displayTime(payload.lastSuccess)} · feeds are evidence sources, not automatic blocks.`;
    } catch (error) {
        status.textContent = `Threat feed status unavailable: ${error.message}`;
        rows.innerHTML = `<tr><td colspan="5">Could not load local feed status.</td></tr>`;
    }
}

const refreshThreatFeedsButton = document.getElementById("refreshThreatFeeds");
refreshThreatFeedsButton?.addEventListener("click", async () => {
    refreshThreatFeedsButton.disabled = true;
    const status = document.getElementById("threatFeedStatus");
    status.textContent = "Refreshing the public indicator feeds into the local index…";
    try {
        const response = await fetch("/api/threat-intel/feeds/refresh", { method: "POST" });
        const payload = await response.json();
        await loadThreatFeedStatus();
        if (!response.ok) {
            const failed = (payload.results || []).filter(item => item.status !== "live").length;
            status.textContent = `Feed refresh completed with ${failed} source error(s). Existing entries for failed sources were preserved.`;
        }
    } catch (error) {
        status.textContent = `Threat feed refresh failed: ${error.message}`;
    } finally {
        refreshThreatFeedsButton.disabled = false;
    }
});
loadThreatFeedStatus();

/* ---------- Threat Intel enrichment KPIs ---------- */
const enrichKpis = [
    { name: "IOC Search Count (30d)", val: "8,412" },
    { name: "IOC Match Rate", val: "34%" },
    { name: "TI Hit Rate", val: "27%" },
    { name: "Malicious URL Detection", val: "19%" },
    { name: "Automated IOC Enrichment", val: "88%" },
    { name: "KEV Vulnerabilities", val: "42" },
    { name: "External Lookup Success", val: "97%" },
    { name: "Analyst Time Saved", val: "310 h/mo" }
];
const enrichKpiEl = document.getElementById("enrichKpis");
if (enrichKpiEl) {
    enrichKpiEl.innerHTML = enrichKpis.map(k => `
        <div class="mini-kpi"><span>${k.name}</span><strong>${k.val}</strong></div>`).join("");
}

async function loadPublicFeeds() {
    const status = document.getElementById("publicFeedStatus");
    const table = document.querySelector("#publicFeedTable tbody");
    if (!status || !table) return;
    try {
        const response = await fetch("/api/public-feeds", { cache: "no-store" });
        if (!response.ok) throw new Error(`Feed API ${response.status}`);
        const payload = await response.json();
        status.innerHTML = payload.sources.map(source => `
            <div class="public-feed-source ${source.status}">
                <strong>${esc(source.name)}</strong>
                <span>${source.status === "live" ? `${Number(source.count).toLocaleString()} records · live` : `Unavailable · ${esc(source.error || "request failed")}`}</span>
            </div>`).join("");
        const rows = [];
        (payload.latest.pinned || []).forEach(item => rows.push([item.source, item.id, item.title, null, item.url]));
        (payload.latest.dotnet || []).forEach(item => rows.push([".NET Security", "Blog", item.title, item.published, item.link]));
        (payload.latest.cisa || []).forEach(item => rows.push(["CISA KEV", item.cveID, item.vulnerabilityName, item.dateAdded]));
        (payload.latest.msrc || []).forEach(item => rows.push(["Microsoft MSRC", item.ID, item.DocumentTitle, item.CurrentReleaseDate]));
        (payload.latest.nvd || []).forEach(item => rows.push(["NIST NVD", item.id, item.descriptions?.find(d => d.lang === "en")?.value || "CVE record", item.published]));
        (payload.latest.urlhaus || []).forEach(item => rows.push(["URLhaus", item.threat || "malware_download", item.url, item.dateadded]));
        table.innerHTML = rows.map(row => `<tr><td><strong>${esc(row[0])}</strong></td><td>${esc(row[1])}</td><td>${row[4] && /^https:\/\//.test(row[4]) ? `<a href="${esc(row[4])}" target="_blank" rel="noopener noreferrer">${esc(row[2])}</a>` : esc(row[2])}</td><td>${row[3] ? fmtDateTime(row[3]) : "Tracked"}</td></tr>`).join("");
        const updated = document.getElementById("publicFeedUpdated");
        if (updated) updated.textContent = `Official public APIs · refreshed ${fmtDateTime(payload.updatedAt)} · cached 15 min`;
    } catch (error) {
        status.innerHTML = `<div class="public-feed-source error"><strong>Public feeds unavailable</strong><span>${esc(error.message)}</span></div>`;
        table.innerHTML = `<tr><td colspan="4">Start the dashboard with py server.py to load public feeds.</td></tr>`;
    }
}

const CVE_RX = /CVE-\d{4}-\d{4,7}/gi;

function harvestLiveIndicators() {
    const cves = new Set();
    const ips = new Set();
    const addIp = value => {
        const text = String(value || "").trim();
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) ips.add(text);
    };
    const addCves = value => {
        if (Array.isArray(value)) return value.forEach(addCves);
        String(value || "").match(CVE_RX)?.forEach(match => cves.add(match.toUpperCase()));
    };
    const feed = name => (window.ClarotyAPI?.feedState(name)?.data) || [];
    feed("relations").forEach(row => {
        addCves(row.vulnerability_cve_ids);
        addCves(row.vulnerability_name);
        (Array.isArray(row.device_ip_list) ? row.device_ip_list : [row.device_ip_list]).forEach(addIp);
    });
    feed("events").forEach(row => { addIp(row.side_a_ip); addIp(row.side_b_ip); });
    feed("devices").forEach(row => (Array.isArray(row.ip_list) ? row.ip_list : [row.ip_list]).forEach(addIp));
    return { cves: [...cves].slice(0, 2000), ips: [...ips].slice(0, 2000) };
}

async function runIntelCorrelation() {
    const status = document.getElementById("intelCorrelateStatus");
    const table = document.querySelector("#intelCorrelateTable tbody");
    const kpis = document.getElementById("intelCorrelateKpis");
    const button = document.getElementById("intelCorrelateBtn");
    if (!status || !table) return;
    const indicators = harvestLiveIndicators();
    if (!indicators.cves.length && !indicators.ips.length) {
        status.textContent = "No CVEs or IP addresses are loaded yet — let the Claroty xDome feeds finish loading, then run the correlation.";
        return;
    }
    if (button) { button.disabled = true; button.textContent = "Correlating…"; }
    status.textContent = `Correlating ${indicators.cves.length.toLocaleString()} CVEs and ${indicators.ips.length.toLocaleString()} IP addresses against the open feeds…`;
    try {
        const response = await fetch("/api/intel/correlate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(indicators)
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Correlation ${response.status}`);
        if (kpis) kpis.hidden = false;
        const setKpi = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
        setKpi("intelKevCount", Number(payload.summary.kevMatches).toLocaleString());
        setKpi("intelRansomCount", Number(payload.summary.ransomwareLinked).toLocaleString());
        setKpi("intelC2Count", Number(payload.summary.c2Matches).toLocaleString());
        const kevRows = payload.kevMatches.map(hit => `<tr>
            <td>CISA KEV</td>
            <td>${escapeOverviewWidgetText(hit.cve)}</td>
            <td>${escapeOverviewWidgetText([hit.vendor, hit.product, hit.name].filter(Boolean).join(" · ") || "—")}</td>
            <td>${hit.epss == null ? "—" : (hit.epss * 100).toFixed(2) + "% (EPSS)"}</td>
            <td>${hit.knownRansomware ? `<span class="pill red">Ransomware</span>` : `<span class="pill amber">Exploited</span>`}</td>
        </tr>`).join("");
        const c2Rows = payload.c2Matches.map(hit => `<tr>
            <td>Feodo C2</td>
            <td>${escapeOverviewWidgetText(hit.ip)}</td>
            <td>${escapeOverviewWidgetText([hit.malware, hit.port ? `port ${hit.port}` : "", hit.firstSeen ? `first seen ${hit.firstSeen}` : ""].filter(Boolean).join(" · ") || "—")}</td>
            <td>—</td>
            <td><span class="pill red">C2</span></td>
        </tr>`).join("");
        table.innerHTML = (kevRows + c2Rows) || `<tr><td colspan="5">No loaded CVE or IP address matched the KEV catalogue or the Feodo C2 blocklist.</td></tr>`;
        const failed = Object.keys(payload.feedErrors || {});
        status.textContent = `Checked ${Number(payload.submitted.cves).toLocaleString()} CVEs and ${Number(payload.submitted.ips).toLocaleString()} IPs against ${Number(payload.catalogue.kev).toLocaleString()} KEV entries and ${Number(payload.catalogue.c2).toLocaleString()} C2 addresses${failed.length ? ` · feed errors: ${failed.join(", ")}` : ""}.`;
    } catch (error) {
        status.textContent = `Correlation failed: ${error.message}`;
    } finally {
        if (button) { button.disabled = false; button.textContent = "Correlate live data"; }
    }
}
document.getElementById("intelCorrelateBtn")?.addEventListener("click", runIntelCorrelation);

/* ---------- Offensive Security Assessment ---------- */
let offsecPathRows = [];
let offsecPathVisible = 25;

function offsecHarvestAssets() {
    const feed = name => (window.ClarotyAPI?.feedState(name)?.data) || [];
    const byAsset = new Map();
    feed("relations").forEach(row => {
        const id = String(row.device_uid || row.device_name || "").trim();
        if (!id) return;
        if (!byAsset.has(id)) {
            byAsset.set(id, {
                id, name: row.device_name || id, site: row.device_site_name || "",
                type: row.device_type || row.device_category || "",
                online: null, riskScore: null,
                ips: Array.isArray(row.device_ip_list) ? row.device_ip_list.filter(Boolean) : [row.device_ip_list].filter(Boolean),
                cves: []
            });
        }
        const asset = byAsset.get(id);
        const ids = row.vulnerability_cve_ids;
        (Array.isArray(ids) ? ids : [ids]).forEach(value => {
            String(value || "").match(CVE_RX)?.forEach(match => asset.cves.push(match.toUpperCase()));
        });
    });
    feed("devices").forEach(row => {
        const id = String(row.uid || row.device_name || "").trim();
        const asset = byAsset.get(id);
        if (!asset) return;
        asset.online = row.is_online == null ? null : Boolean(row.is_online);
        asset.riskScore = Number(row.risk_score) || null;
        if (!asset.ips.length && row.ip_list) asset.ips = Array.isArray(row.ip_list) ? row.ip_list : [row.ip_list];
    });
    return [...byAsset.values()].filter(asset => asset.cves.length).slice(0, 2000);
}

function offsecHarvestTechniques() {
    const techniques = [];
    ((window.ClarotyAPI?.feedState("alerts")?.data) || []).forEach(row => {
        ["mitre_technique_ics_ids", "mitre_technique_enterprise_ids", "mitre_technique_ics_names", "mitre_technique_enterprise_names"]
            .forEach(field => {
                const value = row[field];
                (Array.isArray(value) ? value : [value]).forEach(entry => {
                    String(entry || "").match(/\bT\d{4}(\.\d{3})?\b/g)?.forEach(match => techniques.push(match));
                });
            });
    });
    return techniques.slice(0, 2000);
}

function offsecRenderPaths() {
    const body = document.querySelector("#offsecPathTable tbody");
    const more = document.getElementById("offsecPathMore");
    if (!body) return;
    const rows = offsecPathRows.slice(0, offsecPathVisible);
    body.innerHTML = rows.length ? rows.map(path => {
        const band = path.band === "Critical" ? "red" : path.band === "High" ? "amber" : "";
        const chain = path.stages.map(stage => escapeOverviewWidgetText(stage.tactic)).join(" → ");
        return `<tr>
            <td><strong>${escapeOverviewWidgetText(path.asset)}</strong>${path.online === true ? ' <span class="pill green">Online</span>' : path.online === false ? ' <span class="pill amber">Offline</span>' : ""}</td>
            <td>${escapeOverviewWidgetText([path.site, path.type].filter(Boolean).join(" · ") || "—")}</td>
            <td><span class="pill ${band}">${path.score} ${escapeOverviewWidgetText(path.band)}</span></td>
            <td>${escapeOverviewWidgetText(path.kevCves.slice(0, 3).join(", "))}${path.kevCount > 3 ? ` +${path.kevCount - 3}` : ""}${path.ransomwareCves.length ? ' <span class="pill red">Ransomware</span>' : ""}</td>
            <td>${chain}</td>
        </tr>`;
    }).join("") : `<tr><td colspan="5">No loaded asset has a known-exploited CVE.</td></tr>`;
    if (more) more.hidden = offsecPathRows.length <= offsecPathVisible;
}

async function runOffsecAssessment() {
    const status = document.getElementById("offsecStatus");
    const button = document.getElementById("offsecRefresh");
    if (!status) return;
    if (button) { button.disabled = true; button.textContent = "Assessing…"; }
    const assets = offsecHarvestAssets();
    const techniques = offsecHarvestTechniques();
    status.textContent = `Assessing ${assets.length.toLocaleString()} vulnerable assets and ${techniques.length.toLocaleString()} observed techniques…`;
    try {
        const [methodology, coverage, paths, purple] = await Promise.all([
            fetch("/api/offsec/methodology", { cache: "no-store" }).then(r => r.json()),
            fetch("/api/offsec/attack-coverage", { cache: "no-store" }).then(r => r.json()),
            fetch("/api/offsec/attack-paths", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ assets }) }).then(r => r.json()),
            fetch("/api/offsec/purple-team", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ techniques }) }).then(r => r.json())
        ]);
        if (methodology.error || coverage.error || paths.error || purple.error) {
            throw new Error(methodology.error || coverage.error || paths.error || purple.error);
        }

        const kpis = document.getElementById("offsecKpis");
        if (kpis) kpis.hidden = false;
        const setKpi = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
        setKpi("offsecCritPaths", Number(paths.kpis.criticalPaths).toLocaleString());
        setKpi("offsecRansom", Number(paths.kpis.ransomwareExposedAssets).toLocaleString());
        setKpi("offsecTactics", `${coverage.tacticsCovered}/${coverage.tacticsTotal}`);
        setKpi("offsecGaps", Number(purple.kpis.detectionGaps).toLocaleString());
        setKpi("offsecDomains", `${methodology.kpis.domainsWithEvidence}/${methodology.kpis.domainsTotal}`);

        offsecPathRows = paths.paths || [];
        offsecPathVisible = 25;
        offsecRenderPaths();
        const pathMethod = document.getElementById("offsecPathMethod");
        if (pathMethod) pathMethod.textContent = `${paths.assetsWithPath.toLocaleString()} of ${paths.assetsSubmitted.toLocaleString()} loaded assets have a known-exploited CVE. ${paths.method}`;

        const coverageBody = document.querySelector("#offsecCoverageTable tbody");
        if (coverageBody) {
            coverageBody.innerHTML = coverage.tactics.map(row => `<tr>
                <td>${escapeOverviewWidgetText(row.tactic)} <small>${escapeOverviewWidgetText(row.tacticId)}</small></td>
                <td>${Number(row.ruleCount).toLocaleString()}</td>
                <td>${Number(row.enabledCount).toLocaleString()}</td>
                <td>${row.techniqueIds.length ? escapeOverviewWidgetText(row.techniqueIds.join(", ")) : "—"}</td>
                <td><span class="pill ${row.covered ? "green" : "red"}">${row.covered ? "Covered" : "No rules"}</span></td>
            </tr>`).join("");
        }
        const coverageMethod = document.getElementById("offsecCoverageMethod");
        if (coverageMethod) coverageMethod.textContent = `${coverage.totalRules.toLocaleString()} rules mapped, ${coverage.unmappedRules.toLocaleString()} unmapped. ${coverage.method}`;
        const canvas = document.getElementById("offsecCoverageChart");
        if (canvas && window.Chart) {
            if (window.offsecChart) window.offsecChart.destroy();
            window.offsecChart = new Chart(canvas, {
                type: "bar",
                data: {
                    labels: coverage.tactics.map(row => row.tactic),
                    datasets: [{ label: "Enabled rules", data: coverage.tactics.map(row => row.enabledCount), backgroundColor: coverage.tactics.map(row => row.covered ? COLORS.accent : COLORS.red) }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { font: { size: 10 } } }, y: { beginAtZero: true } } }
            });
        }

        const purpleBody = document.querySelector("#offsecPurpleTable tbody");
        if (purpleBody) {
            purpleBody.innerHTML = purple.techniques.length ? purple.techniques.map(row => {
                const pill = row.status === "technique_rule" ? "green" : row.status === "tactic_rules" ? "amber" : "red";
                const label = row.status === "technique_rule" ? "Technique rule" : row.status === "tactic_rules" ? "Tactic only" : row.status === "gap" ? "Gap" : "Unmapped";
                return `<tr>
                    <td>${escapeOverviewWidgetText(row.techniqueId)}</td>
                    <td>${escapeOverviewWidgetText(row.tactic || "—")}</td>
                    <td>${Number(row.occurrences).toLocaleString()}</td>
                    <td><span class="pill ${pill}">${label}</span></td>
                    <td>${escapeOverviewWidgetText(row.detail)}</td>
                </tr>`;
            }).join("") : `<tr><td colspan="5">No MITRE techniques present in the loaded xDome alerts yet.</td></tr>`;
        }
        const purpleMethod = document.getElementById("offsecPurpleMethod");
        if (purpleMethod) purpleMethod.textContent = `${purple.techniquesObserved.toLocaleString()} distinct techniques observed · ${purple.kpis.coveragePercent}% have matching loaded rules · ${purple.kpis.detectionConnectors} detection connector(s) configured. ${purple.method}`;

        const domainBody = document.querySelector("#offsecDomainTable tbody");
        if (domainBody) {
            domainBody.innerHTML = methodology.domains.map(domain => {
                const held = domain.status === "evidence_available";
                return `<tr>
                <td><strong>${escapeOverviewWidgetText(domain.name)}</strong>${domain.safety ? `<small class="device-cell-sub">${escapeOverviewWidgetText(domain.safety)}</small>` : ""}</td>
                <td>${escapeOverviewWidgetText(domain.objective)}</td>
                <td>${escapeOverviewWidgetText(domain.passiveEvidence.join("; "))}${domain.connectorsConfigured.length ? `<small class="device-cell-sub">Connected: ${escapeOverviewWidgetText(domain.connectorsConfigured.join(", "))}</small>` : ""}</td>
                <td>${escapeOverviewWidgetText(domain.activeTesting.join("; "))}</td>
                <td>
                    <span class="pill ${held ? "green" : "amber"}">${held ? "Partially Evidenced" : "No Local Evidence"}</span>
                    <small class="device-cell-sub">Evidence: ${escapeOverviewWidgetText(domain.evidenceMethod)}${domain.evidenceCount === null ? "" : ` · ${Number(domain.evidenceCount).toLocaleString()} shared catalogue rules (not tests)`}</small>
                    <small class="device-cell-sub">Validation: ${domain.validationStatus === "PENDING" ? "Pending" : "Not Validated"}</small>
                    <small class="device-cell-sub">Active testing required: ${escapeOverviewWidgetText(domain.activeTestingRequiredLabel)}</small>
                    <small class="device-cell-sub">Risk: ${escapeOverviewWidgetText(domain.riskStatus)}</small>
                </td>
            </tr>`;
            }).join("");
        }
        const kpiNote = document.getElementById("offsecKpiNote");
        if (kpiNote) {
            kpiNote.textContent = `${methodology.kpis.domainsAssessmentPending} domain(s) pending assessment · ${methodology.kpis.domainsValidated} of ${methodology.kpis.domainsTotal} validated · ${methodology.kpis.domainsRequiringActiveTesting} require authorized active testing. `
                + `Deferred metrics (not zero): ${methodology.deferredKpis.map(kpi => kpi.label).join(", ")}. An authorization reference alone does not authorize testing or validate a control.`;
        }
        const limits = document.getElementById("offsecLimits");
        if (limits) limits.textContent = methodology.limits;

        status.textContent = `Assessment complete · ${paths.assetsWithPath.toLocaleString()} exposed assets · ${coverage.tacticsCovered}/${coverage.tacticsTotal} ATT&CK tactics covered · ${purple.kpis.detectionGaps} detection gap(s).`;
    } catch (error) {
        status.textContent = `Assessment failed: ${error.message}`;
    } finally {
        if (button) { button.disabled = false; button.textContent = "Run assessment"; }
    }
}
document.getElementById("offsecRefresh")?.addEventListener("click", runOffsecAssessment);
document.getElementById("offsecPathMore")?.addEventListener("click", () => { offsecPathVisible += 25; offsecRenderPaths(); });

async function loadModuleThreatAnalytics() {
    const grid = document.getElementById("threatAnalyticsGrid");
    const breakdown = document.getElementById("threatAnalyticsBreakdown");
    const source = document.getElementById("threatAnalyticsSource");
    if (!grid || !breakdown || !source) return;
    source.textContent = "Loading persisted threat records…";
    try {
        const response = await fetch("/api/analytics/threats", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Threat analytics ${response.status}`);
        const counts = payload.counts || {};
        const metrics = [
            ["Threat intelligence", counts.threat_intel], ["Network events", counts.network_events],
            ["Alerts", counts.alerts], ["Vulnerabilities", counts.vulnerabilities],
            ["Local indicators", counts.indicators], ["Snort rules catalogued", counts.snort_rules]
        ];
        grid.innerHTML = metrics.map(([label, value]) => `<div class="module-analytics-metric"><span>${escapeOverviewWidgetText(label)}</span><strong>${Number(value || 0).toLocaleString()}</strong></div>`).join("");
        const severities = Object.entries(payload.by_severity || {}).map(([label, value]) => `<tr><td>${escapeOverviewWidgetText(label)}</td><td>${Number(value).toLocaleString()}</td></tr>`).join("");
        const types = Object.entries(payload.by_type || {}).map(([label, value]) => `<tr><td>${escapeOverviewWidgetText(label)}</td><td>${Number(value).toLocaleString()}</td></tr>`).join("");
        breakdown.innerHTML = `<div class="threat-analysis-columns"><table><thead><tr><th>Severity</th><th>Records</th></tr></thead><tbody>${severities || `<tr><td colspan="2">No local threat records.</td></tr>`}</tbody></table><table><thead><tr><th>Event type</th><th>Records</th></tr></thead><tbody>${types || `<tr><td colspan="2">No local threat records.</td></tr>`}</tbody></table></div>`;
        source.textContent = `${Number(payload.observed_records || 0).toLocaleString()} locally stored records · ${payload.live_sources?.vendor_connectors || "vendor connectors not connected"}. Public feeds and live xDome status are shown above and in their feed cards.`;
    } catch (error) {
        source.textContent = `Local threat analysis unavailable: ${error.message}`;
        grid.replaceChildren();
        breakdown.replaceChildren();
    }
}

/* =====================================================================
   DRILL-DOWN DRAWER — click any chart/KPI/row to view underlying records
   ===================================================================== */
const drawer = document.getElementById("drawer");
const drawerOverlay = document.getElementById("drawerOverlay");
const drawerTitle = document.getElementById("drawerTitle");
const drawerSub = document.getElementById("drawerSub");
const drawerBody = document.getElementById("drawerBody");

function closeDrawer() {
    drawer.classList.remove("open");
    drawerOverlay.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
}
document.getElementById("drawerClose").addEventListener("click", closeDrawer);
drawerOverlay.addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

const fmtDateTime = s => s ? new Date(s).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
const esc = s => String(s ?? "—").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
loadPublicFeeds();
loadModuleThreatAnalytics();
document.getElementById("refreshThreatAnalytics")?.addEventListener("click", loadModuleThreatAnalytics);

const snortArchive = document.getElementById("snortArchive");
const snortSource = document.getElementById("snortSource");
const snortRows = document.getElementById("snortRows");
const snortDialog = document.getElementById("snortDialog");
let snortOffset = 0;
let snortRequest = 0;
const snortPageSize = 100;

async function loadSnortRules() {
    const request = ++snortRequest;
    const params = new URLSearchParams({
        query: document.getElementById("snortSearch").value.trim(),
        state: document.getElementById("snortState").value,
        offset: String(snortOffset), limit: String(snortPageSize)
    });
    try {
        const response = await fetch(`/api/snort/rules?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Snort catalog request failed (${response.status})`);
        if (request !== snortRequest) return;
        const update = payload.update || {};
        const updateLabel = update.updating ? "Community update running" : update.lastError ? `Community update failed: ${update.lastError}` : update.lastChecked ? `Last community check ${new Date(update.lastChecked).toLocaleString()}` : "Community rules update daily when the official source is reachable";
        const sourceSummary = (payload.sources || []).map(source => `${source.name} · ${Number(source.files).toLocaleString()} files · ${new Date(source.updatedAt).toLocaleString()}`).join(" | ");
        snortSource.textContent = payload.configured ? `${Number(payload.total).toLocaleString()} rules · ${updateLabel}` : `No rule archive available · ${updateLabel}`;
        document.getElementById("snortStats").textContent = `${Number(payload.files).toLocaleString()} rule files · ${Number(payload.enabled).toLocaleString()} enabled · ${Number(payload.total - payload.enabled).toLocaleString()} disabled${sourceSummary ? ` · ${sourceSummary}` : ""} · Community rules refresh automatically every 24 hours; account-authorized packages can be imported separately. Rules are catalogued locally, not deployed to a sensor.`;
        snortRows.innerHTML = payload.records.map(row => `<tr><td><button type="button" class="xd-link" data-snort-rule="${row.id}">${esc(row.sid || "—")}</button></td><td>${esc(row.message || "—")}</td><td>${esc(row.action)}</td><td>${esc(row.file)}</td><td>${esc(row.source || "Imported")}</td><td>${row.enabled ? "Enabled" : "Disabled"}</td></tr>`).join("")
            || `<tr><td colspan="6">${payload.configured ? "No matching rules." : "No rules imported."}</td></tr>`;
        const start = payload.matched ? payload.offset + 1 : 0;
        document.getElementById("snortPageStatus").textContent = `${Number(start).toLocaleString()}-${Number(Math.min(payload.offset + payload.records.length, payload.matched)).toLocaleString()} of ${Number(payload.matched).toLocaleString()}`;
        document.getElementById("snortPrev").disabled = snortOffset === 0;
        document.getElementById("snortNext").disabled = snortOffset + snortPageSize >= payload.matched;
    } catch (error) {
        if (request !== snortRequest) return;
        snortSource.textContent = `Snort catalog unavailable: ${error.message}`;
        snortRows.innerHTML = '<tr><td colspan="6">Unable to load rules.</td></tr>';
        document.getElementById("snortPrev").disabled = true;
        document.getElementById("snortNext").disabled = true;
    }
}

async function loadSnortEngineStatus() {
    const status = document.getElementById("snortEngineStatus");
    if (!status) return;
    try {
        const response = await fetch("/api/snort/engine-status", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Engine status request failed (${response.status})`);
        status.textContent = payload.engine.available ? "Executable detected" : "Engine not detected";
        document.getElementById("snortEnginePath").textContent = payload.engine.path || "Not installed or not on PATH";
        const suricata = payload.alternatives?.suricata || {};
        document.getElementById("suricataEngineStatus").textContent = suricata.available ? `Detected · ${suricata.path}` : "Not installed or not on PATH";
        document.getElementById("snortEngineRuleCount").textContent = payload.rules.configured
            ? `${Number(payload.rules.enabled).toLocaleString()} enabled / ${Number(payload.rules.total).toLocaleString()} cataloged`
            : "No rule catalog loaded";
        document.getElementById("snortEngineRuntime").textContent = payload.runtimeValidation === "not_run" ? "Not run" : payload.runtimeValidation;
    } catch (error) {
        status.textContent = `Status unavailable: ${error.message}`;
        document.getElementById("snortEnginePath").textContent = "Unknown";
        document.getElementById("snortEngineRuleCount").textContent = "Unknown";
    }
}

document.querySelectorAll("[data-snort-panel-toggle]").forEach(button => {
    button.addEventListener("click", () => {
        const panel = document.getElementById(button.dataset.snortPanelToggle);
        if (!panel) return;
        const expanded = button.getAttribute("aria-expanded") === "true";
        panel.hidden = expanded;
        button.setAttribute("aria-expanded", String(!expanded));
        button.textContent = expanded ? "Expand" : "Minimize";
    });
});

let openAppIdOffset = 0;
let openAppIdRequest = 0;
const openAppIdPageSize = 100;

async function loadOpenAppId() {
    const status = document.getElementById("openAppIdStatus");
    const rows = document.getElementById("openAppIdRows");
    if (!status || !rows) return;
    const request = ++openAppIdRequest;
    const params = new URLSearchParams({
        query: document.getElementById("openAppIdSearch")?.value.trim() || "",
        offset: String(openAppIdOffset), limit: String(openAppIdPageSize)
    });
    try {
        const response = await fetch(`/api/snort/openappid?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `OpenAppID request failed (${response.status})`);
        if (request !== openAppIdRequest) return;
        status.textContent = payload.configured
            ? `Package loaded · ${new Date(payload.updatedAt).toLocaleString()}`
            : "No OpenAppID package loaded";
        document.getElementById("openAppIdVersion").textContent = payload.version ? `ODP ${payload.version}` : "—";
        document.getElementById("openAppIdApps").textContent = Number(payload.applications).toLocaleString();
        const kinds = payload.detectorsByKind || {};
        document.getElementById("openAppIdDetectors").textContent = `${Number(payload.detectors).toLocaleString()} (${["client", "service", "payload", "ssl", "content"].map(k => `${k} ${Number(kinds[k] || 0)}`).join(" · ")})`;
        document.getElementById("openAppIdMapped").textContent = `${Number(payload.mappedToSnort).toLocaleString()} of ${Number(payload.applications).toLocaleString()}`;
        rows.innerHTML = payload.records.map(row => `<tr><td>${esc(row.appId)}</td><td>${esc(row.name)}</td><td>${esc(row.snortName && row.snortName !== "~" ? row.snortName : "—")}</td><td>${esc(row.serviceId || "—")}</td><td>${esc(row.clientId || "—")}</td><td>${esc(row.payloadId || "—")}</td></tr>`).join("")
            || '<tr><td colspan="6">No matching applications.</td></tr>';
        const start = payload.matched ? payload.offset + 1 : 0;
        document.getElementById("openAppIdPageStatus").textContent = `${Number(start).toLocaleString()}-${Number(Math.min(payload.offset + payload.records.length, payload.matched)).toLocaleString()} of ${Number(payload.matched).toLocaleString()} applications · ${esc(payload.note || "")}`;
    } catch (error) {
        if (request !== openAppIdRequest) return;
        status.textContent = `OpenAppID unavailable: ${error.message}`;
        rows.innerHTML = '<tr><td colspan="6">Unable to load OpenAppID package.</td></tr>';
    }
}

async function refreshSnortCatalogKpis() {
    await Promise.all([loadSnortRules(), loadSnortEngineStatus(), loadOpenAppId(), loadModuleThreatAnalytics()]);
}

document.getElementById("openAppIdUpdateBtn")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
        const response = await fetch("/api/snort/openappid/update", { method: "POST" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.lastError || "OpenAppID download failed");
        openAppIdOffset = 0;
        await refreshSnortCatalogKpis();
    } catch (error) {
        document.getElementById("openAppIdStatus").textContent = `OpenAppID download failed: ${error.message}`;
    } finally {
        button.disabled = false;
    }
});

document.getElementById("openAppIdImportBtn")?.addEventListener("click", () => document.getElementById("openAppIdArchive").click());
document.getElementById("openAppIdArchive")?.addEventListener("change", async event => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;
    const status = document.getElementById("openAppIdStatus");
    status.textContent = "Importing OpenAppID package…";
    try {
        if (file.size > 60 * 1024 * 1024) throw new Error("OpenAppID package exceeds the 60 MB upload limit");
        const response = await fetch("/api/snort/openappid", { method: "POST", headers: { "Content-Type": "application/gzip" }, body: file });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `OpenAppID import failed (${response.status})`);
        openAppIdOffset = 0;
        await refreshSnortCatalogKpis();
    } catch (error) {
        status.textContent = `OpenAppID import failed: ${error.message}`;
    } finally {
        input.value = "";
    }
});

let openAppIdSearchTimer;
document.getElementById("openAppIdSearch")?.addEventListener("input", () => {
    clearTimeout(openAppIdSearchTimer);
    openAppIdSearchTimer = setTimeout(() => { openAppIdOffset = 0; loadOpenAppId(); }, 250);
});

document.getElementById("snortUpdateBtn").addEventListener("click", async event => {    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "Checking Snort...";
    try {
        const response = await fetch("/api/snort/update", { method: "POST" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.lastError || "Snort update failed");
        await refreshSnortCatalogKpis();
    } catch (error) {
        snortSource.textContent = `Snort update failed: ${error.message}`;
    } finally {
        button.disabled = false;
        button.textContent = "Check for rule updates";
    }
});

document.getElementById("snortImportBtn").addEventListener("click", () => snortArchive.click());
snortArchive.addEventListener("change", async () => {
    const file = snortArchive.files?.[0];
    if (!file) return;
    const button = document.getElementById("snortImportBtn");
    button.disabled = true;
    snortSource.textContent = "Importing Snort rules...";
    try {
        if (file.size > 50 * 1024 * 1024) throw new Error("Snort archive exceeds the 50 MB upload limit");
        const response = await fetch("/api/snort/rules", { method: "POST", headers: { "Content-Type": "application/gzip" }, body: file });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Snort import failed (${response.status})`);
        snortOffset = 0;
        await refreshSnortCatalogKpis();
    } catch (error) {
        snortSource.textContent = `Snort import failed: ${error.message}`;
    } finally {
        button.disabled = false;
        snortArchive.value = "";
    }
});
let snortSearchTimer;
document.getElementById("snortSearch").addEventListener("input", () => {
    clearTimeout(snortSearchTimer);
    snortSearchTimer = setTimeout(() => { snortOffset = 0; loadSnortRules(); }, 250);
});
document.getElementById("snortState").addEventListener("change", () => { snortOffset = 0; loadSnortRules(); });
document.getElementById("snortPrev").addEventListener("click", () => { snortOffset = Math.max(0, snortOffset - snortPageSize); loadSnortRules(); });
document.getElementById("snortNext").addEventListener("click", () => { snortOffset += snortPageSize; loadSnortRules(); });
snortRows.addEventListener("click", async event => {
    const ruleId = event.target.closest("[data-snort-rule]")?.dataset.snortRule;
    if (ruleId == null) return;
    try {
        const response = await fetch(`/api/snort/rules/${encodeURIComponent(ruleId)}`, { cache: "no-store" });
        const rule = await response.json();
        if (!response.ok) throw new Error(rule.error || "Unable to load Snort rule");
        document.getElementById("snortDialogTitle").textContent = `Snort SID ${rule.sid || rule.id}`;
        document.getElementById("snortRuleText").textContent = rule.rule;
        snortDialog.showModal();
    } catch (error) {
        snortSource.textContent = `Snort rule unavailable: ${error.message}`;
    }
});
document.getElementById("snortDialogClose").addEventListener("click", () => snortDialog.close());
refreshSnortCatalogKpis();
setInterval(refreshSnortCatalogKpis, 60 * 60 * 1000);

const snortIpFile = document.getElementById("snortIpFile");
const snortIpRows = document.getElementById("snortBlacklistRows");
let snortIpOffset = 0;
let snortIpRequest = 0;
const snortIpPageSize = 100;

async function loadSnortBlacklist() {
    const request = ++snortIpRequest;
    const params = new URLSearchParams({
        query: document.getElementById("snortBlacklistSearch").value.trim(),
        offset: String(snortIpOffset), limit: String(snortIpPageSize)
    });
    const source = document.getElementById("snortBlacklistSource");
    try {
        const response = await fetch(`/api/snort/blacklist?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `IP list request failed (${response.status})`);
        if (request !== snortIpRequest) return;
        source.textContent = payload.configured ? `${Number(payload.total).toLocaleString()} local entries` : "No IP list imported";
        document.getElementById("snortBlacklistStats").textContent = payload.configured
            ? `Updated ${new Date(payload.updatedAt).toLocaleString()} · UTF-8 IP/CIDR list · not deployed to a sensor`
            : "Import a UTF-8 text list or paste IP/CIDR entries. Imported entries stay local and are not deployed to a sensor.";
        snortIpRows.innerHTML = payload.records.map(row => `<tr><td>${esc(row.address)}</td></tr>`).join("") || `<tr><td>${payload.configured ? "No matching IPs." : "No IP list imported."}</td></tr>`;
        const start = payload.matched ? payload.offset + 1 : 0;
        document.getElementById("snortIpPageStatus").textContent = `${Number(start).toLocaleString()}-${Number(Math.min(payload.offset + payload.records.length, payload.matched)).toLocaleString()} of ${Number(payload.matched).toLocaleString()}`;
        document.getElementById("snortIpPrev").disabled = snortIpOffset === 0;
        document.getElementById("snortIpNext").disabled = snortIpOffset + snortIpPageSize >= payload.matched;
    } catch (error) {
        if (request !== snortIpRequest) return;
        source.textContent = `IP list unavailable: ${error.message}`;
        snortIpRows.innerHTML = "<tr><td>Unable to load IP list.</td></tr>";
        document.getElementById("snortIpPrev").disabled = true;
        document.getElementById("snortIpNext").disabled = true;
    }
}

async function importSnortIpList(contents) {
    const button = document.getElementById("snortIpAddBtn");
    button.disabled = true;
    document.getElementById("snortBlacklistSource").textContent = "Importing and validating IP list...";
    try {
        const response = await fetch("/api/snort/blacklist", { method: "POST", headers: { "Content-Type": "text/plain; charset=utf-8" }, body: contents });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `IP list import failed (${response.status})`);
        snortIpOffset = 0;
        document.getElementById("snortIpText").value = "";
        await loadSnortBlacklist();
    } catch (error) {
        document.getElementById("snortBlacklistSource").textContent = `IP list import failed: ${error.message}`;
    } finally {
        button.disabled = false;
    }
}

document.getElementById("snortIpImportBtn").addEventListener("click", () => snortIpFile.click());
snortIpFile.addEventListener("change", async () => {
    const file = snortIpFile.files?.[0];
    if (!file) return;
    try {
        if (file.size > 10 * 1024 * 1024) throw new Error("IP list exceeds the 10 MB upload limit");
        await importSnortIpList(await file.text());
    } catch (error) {
        document.getElementById("snortBlacklistSource").textContent = `IP list import failed: ${error.message}`;
    } finally {
        snortIpFile.value = "";
    }
});
document.getElementById("snortIpAddBtn").addEventListener("click", () => importSnortIpList(document.getElementById("snortIpText").value));
document.getElementById("snortBlacklistSearch").addEventListener("input", () => { snortIpOffset = 0; loadSnortBlacklist(); });
document.getElementById("snortIpPrev").addEventListener("click", () => { snortIpOffset = Math.max(0, snortIpOffset - snortIpPageSize); loadSnortBlacklist(); });
document.getElementById("snortIpNext").addEventListener("click", () => { snortIpOffset += snortIpPageSize; loadSnortBlacklist(); });
loadSnortBlacklist();
setInterval(loadSnortBlacklist, 60 * 60 * 1000);

function recordRow(r) {
    return `
    <div class="rec-item" data-id="${esc(r.id)}">
        <div class="rec-item-top">
            <span class="rec-id">${esc(r.id)}</span>
            <span>
                <span class="sev-badge sev-${esc(r.severity)}">${esc(r.severity)}</span>
                <span class="st-badge st-${esc(r.status)}">${esc(r.status)}</span>
            </span>
        </div>
        <div class="rec-title">${esc(r.title)}</div>
        <div class="rec-meta">
            <span>🕑 ${fmtDateTime(r.created)}</span>
            <span>👤 ${esc(r.assignee)}</span>
            <span>📡 ${esc(r.source)}</span>
            <span>🎯 ${esc(r.mitre)}</span>
        </div>
    </div>`;
}

function recordDetail(r) {
    const url = window.SwimlaneAPI && SwimlaneAPI.recordUrl(r.id);
    return `
    <div class="rec-detail">
        <table>
            <tr><td>Incident ID</td><td>${esc(r.id)}</td></tr>
            <tr><td>Title</td><td>${esc(r.title)}</td></tr>
            <tr><td>Category</td><td>${esc(r.category || r.mitre)}</td></tr>
            <tr><td>Severity</td><td>${esc(r.severity)}</td></tr>
            <tr><td>Status</td><td>${esc(r.status)}</td></tr>
            <tr><td>Created</td><td>${fmtDateTime(r.created)}</td></tr>
            <tr><td>Detected</td><td>${fmtDateTime(r.detected)}</td></tr>
            <tr><td>Responded</td><td>${fmtDateTime(r.responded)}</td></tr>
            <tr><td>Closed</td><td>${fmtDateTime(r.closed)}</td></tr>
            <tr><td>MTTD</td><td>${r.mttd != null ? r.mttd + " min" : "—"}</td></tr>
            <tr><td>MTTR</td><td>${r.mttr != null ? r.mttr + " min" : "—"}</td></tr>
            <tr><td>Assignee</td><td>${esc(r.assignee)}</td></tr>
            <tr><td>Source</td><td>${esc(r.source)}</td></tr>
            <tr><td>MITRE ATT&CK</td><td>${esc(r.mitre)}</td></tr>
            <tr><td>Automated</td><td>${r.automated ? "Yes" : "No"}</td></tr>
        </table>
        ${analystPanel(r)}
        ${url ? `<a class="rec-open-btn" href="${url}" target="_blank" rel="noopener noreferrer">Open in Swimlane ↗</a>`
              : `<div class="muted" style="margin-top:10px;font-size:12px;">Configure BASE_URL + APPS.incidents in config.js to enable “Open in Swimlane”.</div>`}
    </div>`;
}

/* ---------- Analyst workspace: ownership, ticket assignment, comments ---------- */
const annotations = {};
function getAnno(id) {
    if (!annotations[id]) annotations[id] = { owner: null, ticket: null, comments: [] };
    return annotations[id];
}
function renderComment(c) {
    return `<div class="ap-comment">
        <div class="ap-comment-meta"><b>${esc(c.author)}</b><span>${fmtDateTime(c.time)}</span></div>
        <div class="ap-comment-body">${esc(c.text)}</div>
    </div>`;
}
function analystPanel(r) {
    const a = getAnno(r.id);
    return `
    <div class="analyst-panel">
        <div class="ap-head">Analyst Workspace</div>
        <div class="ap-row">
            <div class="ap-field">
                <label>Ticket / Case</label>
                <div class="ap-inline">
                    <span class="ap-val" data-ticket>${a.ticket ? esc(a.ticket) : "Unassigned"}</span>
                    <button class="ap-btn" data-assign>${a.ticket ? "Reassign" : "Assign Ticket"}</button>
                </div>
            </div>
            <div class="ap-field">
                <label>Owner</label>
                <div class="ap-inline">
                    <span class="ap-val" data-owner>${a.owner ? esc(a.owner) : "Unowned"}</span>
                    <button class="ap-btn" data-own>${a.owner ? "Release" : "Take Ownership"}</button>
                </div>
            </div>
        </div>
        <div class="ap-field">
            <label>Analysis / Comment</label>
            <textarea class="ap-text" data-comment placeholder="Document your investigation — findings, root cause, actions taken, recommendation…"></textarea>
            <button class="ap-btn primary" data-addcomment>Add Comment</button>
        </div>
        <div class="ap-comments" data-commentlog>
            ${a.comments.length ? a.comments.map(renderComment).join("") : `<div class="ap-empty">No analyst comments yet.</div>`}
        </div>
    </div>`;
}
function wireDetail(el, r) {
    const panel = el.querySelector(".analyst-panel");
    if (!panel) return;
    const a = getAnno(r.id);
    panel.addEventListener("click", ev => ev.stopPropagation());
    panel.querySelector("[data-assign]").addEventListener("click", () => {
        const suggested = a.ticket || ("INC" + Math.floor(100000 + Math.random() * 900000));
        const val = prompt("Enter ticket / case ID to assign:", suggested);
        if (val && val.trim()) {
            a.ticket = val.trim();
            panel.querySelector("[data-ticket]").textContent = a.ticket;
            panel.querySelector("[data-assign]").textContent = "Reassign";
        }
    });
    panel.querySelector("[data-own]").addEventListener("click", () => {
        if (a.owner) {
            a.owner = null;
        } else {
            const who = prompt("Take ownership as (analyst name):", "OT Analyst");
            a.owner = who && who.trim() ? who.trim() : "OT Analyst";
        }
        panel.querySelector("[data-owner]").textContent = a.owner || "Unowned";
        panel.querySelector("[data-own]").textContent = a.owner ? "Release" : "Take Ownership";
    });
    panel.querySelector("[data-addcomment]").addEventListener("click", () => {
        const ta = panel.querySelector("[data-comment]");
        const text = (ta.value || "").trim();
        if (!text) { ta.focus(); return; }
        a.comments.unshift({ author: a.owner || "OT Analyst", time: new Date().toISOString(), text });
        panel.querySelector("[data-commentlog]").innerHTML = a.comments.map(renderComment).join("");
        ta.value = "";
    });
}

let currentRecords = [];
async function openRecords(title, sub, filter) {
    drawerTitle.textContent = title;
    drawerSub.textContent = sub || "";
    drawerBody.innerHTML = `<div class="drawer-loading">Loading records…</div>`;
    drawer.classList.add("open");
    drawerOverlay.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");

    let badge;
    if (REPORT) {
        currentRecords = filterReportRecords(filter);
        badge = "report data";
    } else {
        const res = await SwimlaneAPI.getRecords(filter);
        currentRecords = res.data || [];
        badge = res.source === "live" ? "live data" : "fallback data";
    }

    if (!currentRecords.length) {
        const message = REPORT && filter.status === "Open"
            ? `No open incidents. All ${REPORT.kpis.total.toLocaleString()} report records are closed.`
            : "No matching records found.";
        drawerBody.innerHTML = `<div class="rec-empty">${message}</div>`;
        return;
    }

    const crit = currentRecords.filter(r => r.severity === "Critical").length;
    const open = currentRecords.filter(r => r.status === "Open").length;
    const mttrVals = currentRecords.filter(r => r.mttr != null).map(r => r.mttr);
    const avgMttr = mttrVals.length ? Math.round(mttrVals.reduce((a, b) => a + b, 0) / mttrVals.length) : "—";

    drawerBody.innerHTML = `
        <div class="rec-summary">
            <div class="rec-stat"><b>${currentRecords.length}</b><span>records · ${badge}</span></div>
            <div class="rec-stat"><b>${crit}</b><span>critical</span></div>
            <div class="rec-stat"><b>${open}</b><span>open</span></div>
            <div class="rec-stat"><b>${avgMttr}${avgMttr === "—" ? "" : "m"}</b><span>avg MTTR</span></div>
        </div>
        <div id="recList">${currentRecords.map(recordRow).join("")}</div>`;

    drawerBody.querySelectorAll(".rec-item").forEach(el => {
        el.addEventListener("click", () => {
            const existing = el.querySelector(".rec-detail");
            if (existing) { existing.remove(); return; }
            drawerBody.querySelectorAll(".rec-detail").forEach(d => d.remove());
            const rec = currentRecords.find(r => String(r.id) === el.dataset.id);
            if (rec) {
                el.insertAdjacentHTML("beforeend", recordDetail(rec));
                wireDetail(el, rec);
            }
        });
    });
}
window.openRecords = openRecords;

async function openClarotyFindings(severity) {
    drawerTitle.textContent = `${severity} Claroty findings`;
    drawerSub.textContent = "Live xDome device-vulnerability relations";
    drawerBody.innerHTML = `<div class="drawer-loading">Loading Claroty findings…</div>`;
    drawer.classList.add("open");
    drawerOverlay.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    const result = await ClarotyAPI.fetchVulnerabilities();
    if (result.source !== "live") {
        drawerBody.innerHTML = `<div class="rec-empty">${result.source === "error" ? `Claroty live request failed: ${esc(result.error)}` : "Connect Claroty to view live findings."}</div>`;
        return;
    }
    const findings = result.data.filter(item => item.severity === severity);
    if (!findings.length) {
        drawerBody.innerHTML = `<div class="rec-empty">No ${esc(severity)} findings were returned by Claroty.</div>`;
        return;
    }
    drawerBody.innerHTML = `<div class="rec-summary"><div class="rec-stat"><b>${findings.length}</b><span>live findings</span></div></div>
        <div class="table-wrap"><table><thead><tr><th>CVE</th><th>Asset</th><th>CVSS</th><th>Status</th><th>Updated</th></tr></thead><tbody>
        ${findings.slice(0, 300).map(item => `<tr><td>${esc(item.cve)}</td><td>${esc(item.asset)}</td><td>${Number(item.cvss || 0).toFixed(1)}</td><td>${esc(item.status)}</td><td>${esc(String(item.detected || "").slice(0, 10))}</td></tr>`).join("")}
        </tbody></table></div>`;
}

/* ---------- Make Overview KPI cards clickable ---------- */
(function wireKpiCards() {
    const map = {
        "MTTR": { title: "All incidents (MTTR)", sub: "Response-time detail", filter: {} },
        "MTTD": { title: "All incidents (MTTD)", sub: "Detection-time detail", filter: {} },
        "Open Incidents": { title: "Open incidents", sub: "Currently open", filter: { status: "Open" } },
        "Automation Rate": { title: "Automated incidents", sub: "Handled by playbooks", filter: { automated: true } }
    };
    document.querySelectorAll("#overview .kpi-card").forEach(card => {
        const label = (card.querySelector(".kpi-label")?.textContent || "").trim();
        const conf = map[label];
        if (!conf) return;
        card.classList.add("clickable");
        card.addEventListener("click", () => {
            const range = +document.querySelector(".range-btn.active").dataset.range;
            openRecords(conf.title, conf.sub, { ...conf.filter, range });
        });
    });
})();

/* ---------- Make playbook rows clickable ---------- */
document.querySelectorAll("#playbookTable tbody tr").forEach((tr, i) => {
    tr.classList.add("clickable");
    tr.addEventListener("click", () => {
        const p = playbooks[i];
        drawerTitle.textContent = p.uc;
        drawerSub.textContent = "Playbook definition";
        drawerBody.innerHTML = `
            <div class="rec-detail">
                <table>
                    <tr><td>Trigger Source</td><td>${esc(p.trig)}</td></tr>
                    <tr><td>Automated Actions</td><td>${esc(p.act)}</td></tr>
                    <tr><td>Human Approval</td><td>${esc(p.appr)}</td></tr>
                    <tr><td>Integrations</td><td>${p.integ.map(esc).join(", ")}</td></tr>
                    <tr><td>SLA Target</td><td>${esc(p.sla)}</td></tr>
                    <tr><td>Automation Savings</td><td>${esc(p.save)}</td></tr>
                </table>
            </div>`;
        drawer.classList.add("open");
        drawerOverlay.classList.add("open");
        drawer.setAttribute("aria-hidden", "false");
    });
});

/* ---------- Mermaid init ---------- */
if (window.mermaid) {
    mermaid.initialize({
        startOnLoad: false,
        theme: "dark",
        themeVariables: {
            primaryColor: "#1e2230", primaryTextColor: "#e7e9f0", primaryBorderColor: "#464feb",
            lineColor: "#6a72f0", fontFamily: "Segoe UI, sans-serif"
        }
    });
}

/* ---------- Connection badge (live vs demo) ---------- */
(function setConnStatus() {
    const status = window.SwimlaneAPI ? SwimlaneAPI.connectionStatus() : "demo";
    const dot = document.querySelector("#connFoot .conn-dot");
    const label = document.getElementById("connLabel");
    if (!dot || !label) return;
    const map = {
        live: ["", "Connected · Live"],
        demo: ["demo", "Claroty live pending"],
        misconfigured: ["misconfigured", "Config incomplete"]
    };
    const [cls, text] = map[status] || map.demo;
    dot.className = "conn-dot" + (cls ? " " + cls : "");
    label.textContent = text;
})();

/* ====================================================================
   FEATURE ADDITIONS — Items 1–15
   ==================================================================== */

/* ------------------------------------------------------------------ */
/* 3. ACTIVITY HEATMAP (selectable weekly GitHub-style calendar)       */
/* ------------------------------------------------------------------ */
let heatmapGeneration = 0;
async function buildHeatmap() {
    const wrap = document.getElementById("heatmapWrap");
    if (!wrap) return;
    const generation = ++heatmapGeneration;
    const rangeSelect = document.getElementById("heatmapRange");
    const requestedWeeks = Number(rangeSelect?.value || 52);
    const WEEKS = [2, 4, 12, 26, 52].includes(requestedWeeks) ? requestedWeeks : 52;
    const DAYS = 7;
    const today = new Date();
    const todayDate = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    const currentWeekStart = new Date(todayDate);
    currentWeekStart.setDate(currentWeekStart.getDate() - ((currentWeekStart.getDay() + 6) % 7));
    const dateKey = date => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
    const rangeStart = new Date(currentWeekStart);
    rangeStart.setDate(currentWeekStart.getDate() - ((WEEKS - 1) * DAYS));
    let sourceRecords = REPORT ? REPORT.records : [];
    let dataSource = REPORT ? "report data" : "unavailable";
    if (!REPORT) {
        try {
            const result = await SwimlaneAPI.getRecords({
                range: WEEKS * DAYS,
                dateFrom: dateKey(rangeStart),
                dateTo: dateKey(todayDate)
            });
            if (generation !== heatmapGeneration) return;
            sourceRecords = Array.isArray(result.data) ? result.data : [];
            dataSource = result.source === "live" ? "live data" : "sample fallback data";
        } catch (error) {
            if (generation !== heatmapGeneration) return;
            dataSource = `unavailable: ${error.message}`;
        }
    }
    const countsByDay = new Map();
    sourceRecords.forEach(record => {
        const created = new Date(record.created);
        if (Number.isNaN(created.getTime())) return;
        const key = dateKey(created);
        countsByDay.set(key, (countsByDay.get(key) || 0) + 1);
    });
    const cells = [];
    for (let w = 0; w < WEEKS; w++) {
        const weekStart = new Date(currentWeekStart);
        weekStart.setDate(currentWeekStart.getDate() - ((WEEKS - 1 - w) * DAYS));
        const weekCells = [];
        for (let d = 0; d < DAYS; d++) {
            const date = new Date(weekStart);
            date.setDate(weekStart.getDate() + d);
            const iso = dateKey(date);
            const count = countsByDay.get(iso) || 0;
            const cell = { date, count, w, d };
            weekCells.push(cell);
            cells.push(cell);
        }
        const weekEnd = weekCells[DAYS - 1].date;
        const weekCount = weekCells.reduce((total, cell) => total + cell.count, 0);
        weekCells.forEach(cell => { cell.weekStart = weekCells[0].date; cell.weekEnd = weekEnd; cell.weekCount = weekCount; });
    }
    const maxCount = Math.max(...cells.map(c => c.count), 1);
    function levelClass(n) {
        if (n === 0) return "";
        const pct = n / maxCount;
        if (pct < .2) return "l1"; if (pct < .4) return "l2";
        if (pct < .65) return "l3"; if (pct < .85) return "l4"; return "l5";
    }

    // Month labels
    const monthNames = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const monthPositions = [];
    let lastMonth = -1;
    for (let w = 0; w < WEEKS; w++) {
        const cell = cells[w * 7];
        if (cell && (cell.date.getMonth() !== lastMonth || cell.date.getFullYear() !== (cells[(w - 1) * 7]?.date.getFullYear()))) {
            monthPositions.push({ w, label: monthNames[cell.date.getMonth()] });
            lastMonth = cell.date.getMonth();
        }
    }

    const monthRow = document.createElement("div");
    monthRow.className = "heatmap-months";
    monthRow.style.cssText = "padding-left:0; display:flex; gap:3px;";
    for (let w = 0; w < WEEKS; w++) {
        const label = monthPositions.find(m => m.w === w);
        const span = document.createElement("span");
        span.style.width = "13px";
        span.style.flex = "0 0 13px";
        span.textContent = label ? label.label : "";
        monthRow.appendChild(span);
    }

    const grid = document.createElement("div");
    grid.className = "heatmap-grid";

    for (let w = 0; w < WEEKS; w++) {
        const col = document.createElement("div");
        col.className = "heatmap-col";
        const weekCells = cells.slice(w * DAYS, (w + 1) * DAYS);
        const weekCount = weekCells.reduce((total, cell) => total + cell.count, 0);
        const weekStart = weekCells[0].date;
        const weekEnd = weekCells[DAYS - 1].date;
        const dateFrom = dateKey(weekStart);
        const dateTo = dateKey(weekEnd);
        col.setAttribute("role", "button");
        col.setAttribute("tabindex", "0");
        col.setAttribute("aria-label", `Week ${dateFrom} to ${dateTo}: ${weekCount} incidents. Open weekly incident records.`);
        col.title = `Week of ${weekStart.toLocaleDateString()} – ${weekEnd.toLocaleDateString()}: ${weekCount} incident${weekCount !== 1 ? "s" : ""}. Click to drill in.`;
        const openWeek = () => openRecords(
            `Incidents · week of ${weekStart.toLocaleDateString()}`,
            `${weekCount} incident${weekCount !== 1 ? "s" : ""} · ${dateFrom} to ${dateTo}`,
            { dateFrom, dateTo, range: WEEKS * DAYS }
        );
        col.addEventListener("click", openWeek);
        col.addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                openWeek();
            }
        });
        for (let d = 0; d < DAYS; d++) {
            const cell = cells[w * DAYS + d];
            const el = document.createElement("div");
            el.className = "heatmap-cell " + levelClass(cell.count);
            el.title = `${cell.date.toDateString()}: ${cell.count} incident${cell.count !== 1 ? "s" : ""}`;
            el.setAttribute("aria-hidden", "true");
            col.appendChild(el);
        }
        grid.appendChild(col);
    }

    const legend = document.createElement("div");
    legend.className = "heatmap-legend";
    legend.innerHTML = `<span>Less</span>
        <div class="heatmap-cell"></div>
        <div class="heatmap-cell l1"></div><div class="heatmap-cell l2"></div>
        <div class="heatmap-cell l3"></div><div class="heatmap-cell l4"></div>
        <div class="heatmap-cell l5"></div>
        <span>More</span>`;

    wrap.innerHTML = "";
    wrap.appendChild(monthRow);
    wrap.appendChild(grid);
    wrap.appendChild(legend);
    const description = document.getElementById("heatmapDescription");
    if (description) {
        description.textContent = `${WEEKS}-week view · ${dataSource} · darker cells = more incidents · click any week to drill in`;
    }
}
buildHeatmap();
document.getElementById("heatmapRange")?.addEventListener("change", buildHeatmap);

/* ------------------------------------------------------------------ */
/* 5. MITRE ATT&CK COVERAGE MATRIX                                     */
/* ------------------------------------------------------------------ */
(function buildMitreMatrix() {
    const el = document.getElementById("mitreMatrix");
    if (!el) return;
    const tactics = [
        { name: "Initial\nAccess",    techs: [["Phishing","detected"],["Drive-by","partial"],["Pub-facing App","detected"],["Supply Chain","gap"]] },
        { name: "Execution",          techs: [["PowerShell","detected"],["WMI","detected"],["Scripting","partial"],["Sched Task","detected"]] },
        { name: "Persistence",        techs: [["Registry Run","detected"],["Boot Autorun","partial"],["Account Manip","detected"],["Cron Job","gap"]] },
        { name: "Privilege\nEscal.",  techs: [["Token Impersonate","detected"],["Sudo Abuse","partial"],["DLL Hijack","gap"],["Access Token","detected"]] },
        { name: "Defense\nEvasion",   techs: [["Obfuscation","partial"],["Log Clearing","detected"],["File Deletion","partial"],["Rootkit","gap"]] },
        { name: "Credential\nAccess", techs: [["Credential Dump","detected"],["Brute Force","detected"],["Pass-the-Hash","partial"],["Keylogger","detected"]] },
        { name: "Discovery",          techs: [["Net Scanning","detected"],["Account Discovery","detected"],["File & Dir","partial"],["System Info","detected"]] },
        { name: "Lateral\nMovement",  techs: [["Pass-the-Ticket","detected"],["RDP Hijack","partial"],["SMB/Windows","detected"],["SSH Hijack","gap"]] },
        { name: "Collection",         techs: [["Data Staged","partial"],["Email Collection","detected"],["Screen Capture","gap"],["Audio Capture","gap"]] },
        { name: "C2",                 techs: [["DNS Tunneling","detected"],["HTTP/S C2","detected"],["Non-std Ports","partial"],["Steganography","gap"]] },
        { name: "Exfiltration",       techs: [["Over C2","partial"],["Cloud Storage","detected"],["DNS Exfil","detected"],["Alt Protocol","gap"]] },
        { name: "Impact",             techs: [["Ransomware","detected"],["Data Wipe","partial"],["DoS","detected"],["Defacement","gap"]] }
    ];
    el.innerHTML = tactics.map(t => `
        <div class="mitre-tactic">
            <div class="mitre-tactic-head">${t.name.replace("\n","<br>")}</div>
            ${t.techs.map(([name, status]) => `
            <div class="mitre-tech ${status}" title="${name}: ${status}" onclick="openRecords('MITRE: ${name}','ATT&CK technique drill-down',{})">
                ${name}
            </div>`).join("")}
        </div>`).join("");
})();

/* ------------------------------------------------------------------ */
/* 6. ANALYST LEADERBOARD                                              */
/* ------------------------------------------------------------------ */
(function buildLeaderboard() {
    const wrap = document.getElementById("leaderboard");
    if (!wrap) return;
    const medals = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣"];
    const analysts = REPORT
        ? (() => {
            const m = {};
            REPORT.records.forEach(r => { if (r.assignee) m[r.assignee] = (m[r.assignee] || 0) + 1; });
            return Object.entries(m).sort((a,b) => b[1]-a[1]).slice(0,5).map(([n,c],i) => ({
                name: n, dept: "OT Platform", cases: c,
                auto: Math.round(60 + Math.random() * 30),
                mttr: rand(30, 75), fp: rand(5, 18)
            }));
          })()
        : [
            { name: "A. Chen",    dept: "Tier-2 Analyst", cases: 71, auto: 88, mttr: 38, fp: 6 },
            { name: "M. Petrov",  dept: "Tier-2 Analyst", cases: 64, auto: 82, mttr: 44, fp: 9 },
            { name: "L. Becker",  dept: "Tier-3 Analyst", cases: 60, auto: 74, mttr: 51, fp: 11 },
            { name: "R. Sharma",  dept: "Tier-1 Analyst", cases: 55, auto: 79, mttr: 58, fp: 14 },
            { name: "Y. Nakamura",dept: "Tier-2 Analyst", cases: 49, auto: 91, mttr: 47, fp: 7 }
          ];
    wrap.innerHTML = analysts.map((a, i) => `
        <div class="leader-row">
            <div class="leader-badge">${medals[i] || String(i+1)}</div>
            <div class="leader-avatar">${a.name.slice(0,2).toUpperCase()}</div>
            <div class="leader-info">
                <div class="leader-name">${a.name}</div>
                <div class="leader-dept">${a.dept}</div>
            </div>
            <div class="leader-stats">
                <div class="leader-stat"><b>${a.cases}</b><span>Cases</span></div>
                <div class="leader-stat"><b>${a.auto}%</b><span>Auto</span></div>
                <div class="leader-stat"><b>${a.mttr}m</b><span>MTTR</span></div>
            </div>
        </div>`).join("");
})();

/* ------------------------------------------------------------------ */
/* 9. SCATTER CHART (MTTD vs Severity) + 8. TIMELINE + GEO CHARTS     */
/* Added inside build() via post-build call                            */
/* ------------------------------------------------------------------ */
function buildExtraCharts() {
    // 9 — Scatter: MTTD by severity cluster
    const scEl = document.getElementById("scatterChart");
    if (scEl && !Chart.getChart(scEl)) {
        const scatterData = {
            Critical: { color: COLORS.red,    pts: Array.from({length:18},(_,i)=>({x:rand(5,25),  y:rand(8,15)})) },
            High:     { color: COLORS.amber,  pts: Array.from({length:40},(_,i)=>({x:rand(10,45), y:rand(10,20)})) },
            Medium:   { color: COLORS.accent, pts: Array.from({length:30},(_,i)=>({x:rand(20,80), y:rand(12,30)})) },
            Low:      { color: COLORS.muted,  pts: Array.from({length:20},(_,i)=>({x:rand(30,90), y:rand(18,40)})) }
        };
        new Chart(scEl, {
            type: "scatter",
            data: { datasets: Object.entries(scatterData).map(([sev,d]) => ({
                label: sev, data: d.pts,
                backgroundColor: d.color + "88", borderColor: d.color, pointRadius: 5, pointHoverRadius: 8
            }))},
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } },
                           tooltip: { callbacks: { label: ctx => `${ctx.dataset.label}: MTTD ${ctx.raw.x}m, Volume ${ctx.raw.y}` } } },
                scales: {
                    x: { title: { display: true, text: "MTTD (minutes)", font: { size: 11 } }, grid: { display: false } },
                    y: { title: { display: true, text: "Incident Volume", font: { size: 11 } }, grid: { color: COLORS.grid }, beginAtZero: true }
                },
                onClick: (e, els) => { if (!els.length) return; openRecords("Scatter selection", "Incidents matching this cluster", {}); }
            }
        });
    }

    // 8 — Correlation Timeline (floating bar Gantt)
    const tlEl = document.getElementById("timelineChart");
    if (tlEl && !Chart.getChart(tlEl)) {
        const now = Date.now();
        const h = 3600000;
        const incidents = [
            { label: "INC-4901 Phishing Campaign",     range: [now - 14*h, now - 2*h],  color: COLORS.red },
            { label: "INC-4887 Identity Pivot",         range: [now - 12*h, now - 1*h],  color: COLORS.amber },
            { label: "INC-4923 Lateral Movement",       range: [now - 8*h,  now - 0.5*h],color: COLORS.amber },
            { label: "INC-4930 C2 Beaconing",           range: [now - 6*h,  now + 2*h],  color: COLORS.red },
            { label: "INC-4944 Data Staging",           range: [now - 3*h,  now + 4*h],  color: COLORS.accent },
            { label: "INC-4951 Exfil Attempt",          range: [now - 1*h,  now + 6*h],  color: COLORS.red },
            { label: "INC-4878 Endpoint Isolation",     range: [now - 20*h, now - 8*h],  color: COLORS.green },
            { label: "INC-4902 Vuln Exploitation",      range: [now - 18*h, now - 4*h],  color: COLORS.amber },
        ];
        new Chart(tlEl, {
            type: "bar",
            data: {
                labels: incidents.map(i => i.label),
                datasets: [{ data: incidents.map(i => i.range), backgroundColor: incidents.map(i => i.color + "88"), borderColor: incidents.map(i => i.color), borderWidth: 2, borderRadius: 4, borderSkipped: false }]
            },
            options: {
                indexAxis: "y", responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { callbacks: {
                    label: ctx => {
                        const [s,e] = ctx.raw;
                        const fmt = v => new Date(v).toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"});
                        return ` ${fmt(s)} → ${fmt(e)}`;
                    }
                } } },
                scales: {
                    x: { type: "linear", min: now - 24*h, max: now + 8*h,
                         grid: { color: COLORS.grid },
                         ticks: { callback: v => { const h = Math.round((v - now)/3600000); return (h >= 0 ? "+" : "") + h + "h"; }, maxTicksLimit: 12 } },
                    y: { grid: { display: false }, ticks: { font: { size: 10 } } }
                }
            }
        });
    }

    // 7 — Geo charts (threat origin bubble + type breakdown + time)
    const geoEl = document.getElementById("geoChart");
    if (geoEl && !Chart.getChart(geoEl)) {
        const countries = [
            { name: "Russia",       flag: "🇷🇺", x: 62, y: 38, count: 142 },
            { name: "China",        flag: "🇨🇳", x: 79, y: 42, count: 118 },
            { name: "North Korea",  flag: "🇰🇵", x: 83, y: 40, count: 67 },
            { name: "Iran",         flag: "🇮🇷", x: 58, y: 45, count: 54 },
            { name: "Vietnam",      flag: "🇻🇳", x: 80, y: 49, count: 41 },
            { name: "Brazil",       flag: "🇧🇷", x: 32, y: 61, count: 35 },
            { name: "Romania",      flag: "🇷🇴", x: 52, y: 37, count: 28 },
            { name: "India",        flag: "🇮🇳", x: 68, y: 46, count: 24 },
            { name: "USA",          flag: "🇺🇸", x: 18, y: 38, count: 19 },
            { name: "Germany",      flag: "🇩🇪", x: 50, y: 34, count: 12 }
        ];
        // Render geo table
        const table = document.getElementById("geoTable");
        if (table) {
            const maxC = countries[0].count;
            table.innerHTML = countries.map(c => `
                <div class="geo-row">
                    <span class="geo-flag">${c.flag}</span>
                    <div style="flex:1"><div class="geo-country">${c.name}</div>
                    <div class="geo-bar"><div class="geo-bar-fill" style="width:${Math.round(c.count/maxC*100)}%"></div></div></div>
                    <span class="geo-count">${c.count}</span>
                </div>`).join("");
        }
        // Bubble chart over map background
        new Chart(geoEl, {
            type: "bubble",
            data: { datasets: [{ label: "Threat Origin", data: countries.map(c => ({ x: c.x, y: 100 - c.y, r: Math.max(4, Math.sqrt(c.count) * 1.4) })), backgroundColor: countries.map(() => COLORS.red + "99"), borderColor: COLORS.red, borderWidth: 1 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => `${countries[ctx.dataIndex].name}: ${countries[ctx.dataIndex].count} incidents` } } },
                scales: { x: { min: 0, max: 100, grid: { color: COLORS.grid + "44" }, ticks: { display: false } }, y: { min: 0, max: 100, grid: { color: COLORS.grid + "44" }, ticks: { display: false } } }
            }
        });
    }
    const geoTypeEl = document.getElementById("geoTypeChart");
    if (geoTypeEl && !Chart.getChart(geoTypeEl)) {
        new Chart(geoTypeEl, {
            type: "bar",
            data: {
                labels: ["Russia", "China", "N.Korea", "Iran", "Vietnam", "Brazil", "Romania"],
                datasets: [
                    { label: "Phishing",   data: [42,28,18,14,12,10,8],  backgroundColor: COLORS.amber, borderRadius: 4 },
                    { label: "Malware",    data: [38,40,25,20,15,12,10], backgroundColor: COLORS.red,   borderRadius: 4 },
                    { label: "Ransomware", data: [22,14,10,8,6,8,5],     backgroundColor: COLORS.accent, borderRadius: 4 }
                ]
            },
            options: { ...baseOpts, plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } } }
        });
    }
    const geoTimeEl = document.getElementById("geoTimeChart");
    if (geoTimeEl && !Chart.getChart(geoTimeEl)) {
        const L = days(30);
        new Chart(geoTimeEl, {
            type: "line",
            data: { labels: L, datasets: [
                { label: "Russia",  data: series(30, 2, 8),  borderColor: COLORS.red,    tension: .4, pointRadius: 0, borderWidth: 2 },
                { label: "China",   data: series(30, 2, 7),  borderColor: COLORS.amber,  tension: .4, pointRadius: 0, borderWidth: 2 },
                { label: "Others",  data: series(30, 3, 10), borderColor: COLORS.muted,  tension: .4, pointRadius: 0, borderWidth: 2 }
            ] },
            options: { ...baseOpts, plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } } }
        });
    }

    // SLA section charts
    const slaTrendEl = document.getElementById("slaTrendChart");
    if (slaTrendEl && !Chart.getChart(slaTrendEl)) {
        const L = days(30);
        new Chart(slaTrendEl, {
            type: "line",
            data: { labels: L, datasets: [
                { label: "SLA Compliance %", data: series(30, 72, 96, -0.1), borderColor: COLORS.green, backgroundColor: gradient(slaTrendEl.getContext("2d"), COLORS.green), fill: true, tension: .4, pointRadius: 0, borderWidth: 2 },
                { label: "Target (90%)",      data: Array(30).fill(90),       borderColor: COLORS.amber, borderDash: [5,4], pointRadius: 0, borderWidth: 1.5 }
            ] },
            options: { ...baseOpts, plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } }, scales: { ...baseOpts.scales, y: { ...baseOpts.scales.y, max: 100 } } }
        });
    }
    const slaBreachEl = document.getElementById("slaBreachChart");
    if (slaBreachEl && !Chart.getChart(slaBreachEl)) {
        new Chart(slaBreachEl, {
            type: "doughnut",
            data: {
                labels: ["Malware/AV", "Phishing", "Identity Risk", "DNS Threats", "SIEM Alerts"],
                datasets: [{ data: [8, 5, 4, 3, 2], backgroundColor: [COLORS.red, COLORS.amber, COLORS.accent, COLORS.accent2, COLORS.muted], borderWidth: 0 }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: "60%", plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } } }
        });
    }
    // Alert feed mini charts
    const feedRateEl = document.getElementById("feedRateChart");
    if (feedRateEl && !Chart.getChart(feedRateEl)) {
        const rateLabels = Array.from({length: 12}, (_, i) => `${(11-i) * 5}s`).reverse();
        new Chart(feedRateEl, {
            type: "bar",
            data: { labels: rateLabels, datasets: [{ label: "Alerts/5s", data: Array.from({length:12}, () => rand(0,6)), backgroundColor: COLORS.accent + "aa", borderRadius: 4 }] },
            options: { ...baseOpts, plugins: { legend: { display: false } } }
        });
    }
    const feedSevEl = document.getElementById("feedSevChart");
    if (feedSevEl && !Chart.getChart(feedSevEl)) {
        new Chart(feedSevEl, {
            type: "polarArea",
            data: {
                labels: ["Critical", "High", "Medium", "Low"],
                datasets: [{ data: [8, 22, 35, 15], backgroundColor: [COLORS.red, COLORS.amber, COLORS.accent, COLORS.muted], borderWidth: 0 }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } }, scales: { r: { grid: { color: COLORS.grid }, ticks: { display: false } } } }
        });
    }
}

/* Run extra chart builds after a tick so the DOM is settled */
setTimeout(buildExtraCharts, 200);

/* ------------------------------------------------------------------ */
/* 10. SLA BREACH TRACKER (live countdown)                             */
/* ------------------------------------------------------------------ */
const SLA_DEFINITIONS = { Critical: 60, High: 240, Medium: 480, Low: 1440 }; // minutes
function fmtRemain(mins) {
    if (mins == null) return "No detection time";
    if (mins < 0) return `BREACHED (${Math.abs(Math.round(mins))}m ago)`;
    const h = Math.floor(mins / 60), m = Math.round(mins % 60);
    return h > 0 ? `${h}h ${m}m` : `${m}m`;
}
function slaDeviceLine(inc) {
    if (!inc.devices.length) return `<div class="sla-devices muted">No device identity in loaded alert/event data</div>`;
    const shown = inc.devices.slice(0, 3).map(d =>
        `<span class="sla-dev" title="${esc(`${d.name}${d.ip ? ` · ${d.ip}` : ""}${d.site ? ` · ${d.site}` : ""}`)}">🖥 ${esc(d.name)}${d.ip ? ` <small>${esc(d.ip)}</small>` : ""}</span>`).join("");
    const more = inc.devices.length > 3 ? `<span class="sla-dev more">+${inc.devices.length - 3} more</span>` : "";
    return `<div class="sla-devices">${shown}${more}</div>`;
}
/* Analyst, playbook and case status are tracked locally; xDome does not supply them. */
const CASE_STATUS_LABELS = { new: "New", in_progress: "In progress", resolved: "Resolved" };
const caseTracking = new Map();
let caseTrackingLoaded = false;
function updateCaseTrackingViews() {
    const records = [...caseTracking.values()];
    document.querySelectorAll("#playbookTable .playbook-cases").forEach(cell => {
        const mine = records.filter(r => r.playbook === cell.dataset.playbook);
        cell.textContent = `${mine.filter(r => r.caseStatus !== "resolved").length} / ${mine.length}`;
    });
    const chart = charts.analyst;
    const owners = {};
    records.filter(r => r.owner).forEach(r => {
        owners[r.owner] = owners[r.owner] || { open: 0, resolved: 0 };
        owners[r.owner][r.caseStatus === "resolved" ? "resolved" : "open"]++;
    });
    const names = Object.keys(owners).sort();
    if (!chart || !names.length || typeof REPORT !== "undefined" && REPORT) return;
    const head = document.querySelector("#operations .chart-row .card:first-child .card-head");
    if (head) head.innerHTML = `<h3>Analyst Productivity</h3><span class="muted">Tracked cases per analyst (local)</span>`;
    chart.data.labels = names;
    chart.data.datasets = [
        { label: "Resolved", data: names.map(n => owners[n].resolved), backgroundColor: COLORS.accent, borderRadius: 6 },
        { label: "Open", data: names.map(n => owners[n].open), backgroundColor: "#f59e0b", borderRadius: 6 }
    ];
    chart.options.plugins.legend = { display: true, position: "bottom" };
    chart.update();
}
async function loadCaseTracking() {
    try {
        const response = await fetch("/api/modules/operations?q=case_tracking&limit=500", { credentials: "same-origin", cache: "no-store" });
        if (!response.ok) return;
        const payload = await response.json();
        (payload.records || []).filter(r => r.kind === "case_tracking" && r.incidentId).forEach(r => caseTracking.set(r.incidentId, r));
        caseTrackingLoaded = true;
        renderSlaCards();
        updateCaseTrackingViews();
    } catch (error) { /* tracking stays empty; cards still render from xDome */ }
}
async function saveCaseTracking(incidentId, fields) {
    const existing = caseTracking.get(incidentId);
    const recordId = `case-${incidentId}`;
    const body = JSON.stringify({ ...fields, kind: "case_tracking", incidentId, id: recordId });
    const response = await fetch(existing ? `/api/modules/operations/${encodeURIComponent(recordId)}` : "/api/modules/operations", {
        method: existing ? "PUT" : "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Save failed (${response.status})`);
    caseTracking.set(incidentId, payload.record);
    renderSlaCards();
    updateCaseTrackingViews();
}
function trackedCase(inc) {
    const t = caseTracking.get(inc.id) || {};
    return { owner: t.owner || "", playbook: t.playbook || "", caseStatus: t.caseStatus || "new", notes: t.notes || "" };
}
const slaFilters = { text: "", severity: "", status: "", owner: "", playbook: "", site: "", from: "", to: "" };
function slaMatches(inc) {
    const t = trackedCase(inc);
    const f = slaFilters;
    if (f.severity && inc.severity !== f.severity) return false;
    if (f.status && t.caseStatus !== f.status) return false;
    if (f.owner && (f.owner === "__none" ? t.owner : t.owner !== f.owner)) return false;
    if (f.playbook && t.playbook !== f.playbook) return false;
    if (f.site && !inc.devices.some(d => d.site === f.site)) return false;
    const detected = Date.parse(inc.detectedTime);
    if (f.from && !(detected >= Date.parse(f.from))) return false;
    if (f.to && !(detected < Date.parse(f.to) + 86400000)) return false;
    if (f.text) {
        const hay = `${inc.id} ${inc.title} ${inc.category} ${inc.devices.map(d => `${d.name} ${d.ip}`).join(" ")}`.toLowerCase();
        if (!hay.includes(f.text.toLowerCase())) return false;
    }
    return true;
}
function refreshSlaFilterOptions(all) {
    const fill = (id, values, current, extra = "") => {
        const el = document.getElementById(id);
        if (!el) return;
        const options = [...new Set(values.filter(Boolean))].sort();
        el.innerHTML = el.options[0].outerHTML + extra + options.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
        el.value = options.includes(current) || current === "__none" ? current : "";
    };
    fill("slaFOwner", all.map(i => trackedCase(i).owner), slaFilters.owner, '<option value="__none">Unassigned</option>');
    fill("slaFPlaybook", all.map(i => trackedCase(i).playbook), slaFilters.playbook);
    fill("slaFSite", all.flatMap(i => i.devices.map(d => d.site)), slaFilters.site);
}
function renderSlaCards() {
    const cards = document.getElementById("slaCards");
    if (!cards) return;
    const status = XDIncidents.readiness();
    const all = status.ready ? XDIncidents.build() : [];
    refreshSlaFilterOptions(all);
    const incs = (slaFilter === "all" ? all : all.filter(i => i.state === slaFilter)).filter(slaMatches);
    const sourceEl = document.getElementById("slaSource");
    if (sourceEl) sourceEl.textContent = status.message;

    const filterBar = document.getElementById("slaActiveFilter");
    const filterLabel = document.getElementById("slaFilterLabel");
    if (filterBar) filterBar.hidden = slaFilter === "all";
    if (filterLabel) filterLabel.textContent = `Showing: ${{ breached: "Breached SLAs", atrisk: "At Risk (<2h)", ontrack: "On Track" }[slaFilter] || "All"}`;

    if (!all.length) {
        ["slaBreached", "slaAtRisk", "slaOnTrack"].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = "0"; });
        const avg = document.getElementById("slaAvg");
        if (avg) avg.textContent = "—";
        cards.innerHTML = `<div class="rec-empty">${esc(status.message)} SLA tracking needs loaded xDome alerts — open Overview and let the xDome feeds finish loading.</div>`;
        return;
    }

    const breached = all.filter(i => i.state === "breached").length;
    const atRisk = all.filter(i => i.state === "atrisk").length;
    const onTrack = all.filter(i => i.state === "ontrack").length;
    document.getElementById("slaBreached").textContent = breached;
    document.getElementById("slaAtRisk").textContent = atRisk;
    document.getElementById("slaOnTrack").textContent = onTrack;
    const remaining = all.filter(i => i.remainMins != null && i.remainMins > 0).map(i => i.remainMins);
    const avgRemain = remaining.length ? Math.round(remaining.reduce((a, b) => a + b, 0) / remaining.length) : null;
    document.getElementById("slaAvg").textContent = avgRemain == null ? "—" : `${Math.floor(avgRemain / 60)}h ${avgRemain % 60}m`;

    cards.innerHTML = incs.slice(0, slaVisible).map(inc => `        <div class="sla-card ${inc.state}" data-sla-incident="${esc(inc.id)}">
            <div class="sla-card-head">
                <span class="sla-inc-id">${esc(inc.id)}</span>
                <span class="sla-badge ${inc.state}">${inc.state === "breached" ? "⛔ Breached" : inc.state === "atrisk" ? "⚠ At Risk" : inc.state === "ontrack" ? "✓ On Track" : "• Unknown"}</span>
            </div>
            <div class="sla-title">${esc(inc.title)}</div>
            <div class="sla-meta">
                <span class="sev-badge sev-${esc(inc.severity)}">${esc(inc.severity)}</span>
                <span>${esc(inc.category)}</span>
                <span>SLA: ${inc.slaMins}min</span>
                <span>Open: ${inc.openedMinsAgo == null ? "—" : `${inc.openedMinsAgo}min`}</span>
                <span>${esc(inc.status)}</span>
            </div>
            <div class="sla-meta">
                <span>Analyst: ${esc(trackedCase(inc).owner || "Unassigned")}</span>
                <span>Playbook: ${esc(trackedCase(inc).playbook || "None")}</span>
                <span>Case: ${esc(CASE_STATUS_LABELS[trackedCase(inc).caseStatus] || "New")}</span>
            </div>
            ${slaDeviceLine(inc)}
            ${inc.mitre.length ? `<div class="sla-mitre">${inc.mitre.slice(0, 4).map(m => `<span class="tag" title="${esc(m.name)}">${esc(m.id)}</span>`).join("")}${inc.mitre.length > 4 ? `<span class="tag">+${inc.mitre.length - 4}</span>` : ""}</div>` : ""}
            <div class="sla-countdown ${inc.state}">${fmtRemain(inc.remainMins)}</div>
            <div class="sla-progress" style="margin-top:8px">
                <div class="sla-progress-fill" style="width:${inc.openedMinsAgo == null ? 0 : Math.min(100, Math.max(0, (inc.openedMinsAgo / inc.slaMins) * 100))}%; background:${inc.state === "ontrack" ? "var(--green)" : inc.state === "atrisk" ? "var(--amber)" : "var(--red)"}"></div>
            </div>
        </div>`).join("")
        + (incs.length > slaVisible ? `<button type="button" class="device-details-btn" id="slaLoadMore">Load more incidents (${incs.length - slaVisible} remaining)</button>` : "");

    cards.querySelectorAll("[data-sla-incident]").forEach(el => {
        el.addEventListener("click", () => {
            const inc = incs.find(i => i.id === el.dataset.slaIncident);
            if (inc) openIncidentDetail(inc);
        });
    });
    document.getElementById("slaLoadMore")?.addEventListener("click", () => { slaVisible += 12; renderSlaCards(); });
}
let slaVisible = 12;
let slaFilter = "all";
document.querySelectorAll("[data-sla-filter]").forEach(card => {
    card.addEventListener("click", () => {
        slaFilter = card.dataset.slaFilter;
        slaVisible = 12;
        renderSlaCards();
    });
});
document.getElementById("slaFilterClear")?.addEventListener("click", () => { slaFilter = "all"; slaVisible = 12; renderSlaCards(); });
document.getElementById("slaRefreshBtn")?.addEventListener("click", () => renderSlaCards());
[["slaFText", "text"], ["slaFSeverity", "severity"], ["slaFStatus", "status"], ["slaFOwner", "owner"], ["slaFPlaybook", "playbook"], ["slaFSite", "site"], ["slaFFrom", "from"], ["slaFTo", "to"]].forEach(([id, key]) => {
    document.getElementById(id)?.addEventListener("input", e => { slaFilters[key] = e.target.value; slaVisible = 12; renderSlaCards(); });
});
document.getElementById("slaFReset")?.addEventListener("click", () => {
    Object.keys(slaFilters).forEach(k => { slaFilters[k] = ""; });
    document.querySelectorAll("#slaFilters input, #slaFilters select").forEach(el => { el.value = ""; });
    slaFilter = "all"; slaVisible = 12; renderSlaCards();
});
loadCaseTracking();
document.addEventListener("xdome:feed-ready", e => {
    if (["alerts", "events", "devices"].includes(e.detail?.feed)) renderSlaCards();
});

/* Full incident detail: real device records, MITRE chain and linked events. */
function openIncidentDetail(inc) {
    drawerTitle.textContent = `${inc.id} · ${inc.title}`;
    drawerSub.textContent = `${inc.severity} · ${inc.category} · detected ${inc.detectedTime ? fmtDateTime(inc.detectedTime) : "unknown"}`;
    drawer.classList.add("open");
    drawerOverlay.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");

    const story = XDIncidents.attackStory(inc);
    const deviceRows = inc.devices.map(d => `<tr>
        <td><strong>${esc(d.name)}</strong>${d.fromEvent ? ' <span class="tag">from event</span>' : ""}</td>
        <td>${esc(d.ip || "—")}</td><td>${esc(d.site || "—")}</td>
        <td>${esc(d.manufacturer || "—")}</td><td>${esc(d.type || "—")}</td>
        <td>${esc(d.risk)}${d.riskScore != null ? ` (${d.riskScore})` : ""}</td>
        <td>${d.online == null ? "Unknown" : d.online ? "Online" : "Offline"}</td></tr>`).join("");

    const eventRows = story.events.slice(0, 100).map(e => `<tr>
        <td>${esc(story.offsetFor(e.timestamp))}</td>
        <td>${esc(e.timestamp ? fmtDateTime(e.timestamp) : "—")}</td>
        <td>${esc(e.event_type || "—")}</td>
        <td>${esc(e.side_a_name || e.side_a_ip || "—")}</td>
        <td>${esc(e.side_b_name || e.side_b_ip || "—")}</td>
        <td>${esc(e.protocol || "—")}</td>
        <td>${esc(e.description || "—")}</td></tr>`).join("");

    const tracked = trackedCase(inc);
    const playbookNames = [...document.querySelectorAll("#playbookTable tbody tr td:first-child")].map(td => td.textContent.trim()).filter(Boolean);
    drawerBody.innerHTML = `
        <div class="xd-surface"><h4>Case tracking (stored locally)</h4>
            <form id="caseTrackForm" style="display:flex;flex-wrap:wrap;gap:8px">
                <input name="owner" placeholder="Analyst / owner" value="${esc(tracked.owner)}" maxlength="80">
                <input name="playbook" list="caseTrackPlaybooks" placeholder="Playbook" value="${esc(tracked.playbook)}" maxlength="120">
                <datalist id="caseTrackPlaybooks">${playbookNames.map(n => `<option value="${esc(n)}">`).join("")}</datalist>
                <select name="caseStatus">${Object.entries(CASE_STATUS_LABELS).map(([k, v]) => `<option value="${k}"${k === tracked.caseStatus ? " selected" : ""}>${v}</option>`).join("")}</select>
                <input name="notes" placeholder="Notes" value="${esc(tracked.notes)}" maxlength="500" style="flex:1;min-width:200px">
                <button type="submit" class="device-details-btn">Save</button>
                <span class="muted" id="caseTrackMsg"></span>
            </form>
        </div>
        <div class="rec-summary">
            <div class="rec-stat"><b>${inc.devicesCount}</b><span>devices affected</span></div>
            <div class="rec-stat"><b>${inc.unresolvedDevicesCount}</b><span>unresolved</span></div>
            <div class="rec-stat"><b>${inc.events.length}</b><span>linked events</span></div>
            <div class="rec-stat"><b>${fmtRemain(inc.remainMins)}</b><span>SLA remaining</span></div>
        </div>
        <div class="xd-surface"><h4>Alert detail</h4><div class="xd-detail">
            <div><b>Status / class</b><span>${esc(inc.status)} · ${esc(inc.alertClass || "—")}</span></div>
            <div><b>Detected / updated</b><span>${esc(inc.detectedTime ? fmtDateTime(inc.detectedTime) : "—")} · ${esc(inc.updatedTime ? fmtDateTime(inc.updatedTime) : "—")}</span></div>
            <div><b>Device mix</b><span>OT ${inc.otCount} · IT ${inc.itCount} · IoT ${inc.iotCount}</span></div>
            <div><b>Description</b><span>${esc(inc.description || "No description provided by xDome")}</span></div>
        </div></div>
        <div class="xd-surface"><h4>MITRE ATT&amp;CK chain · ${inc.mitre.length} technique(s)</h4>
            ${story.steps.length ? story.steps.map(s => `
                <div class="ig-story-step">
                    <div class="ig-story-icon" style="background:${s.color}22;border-color:${s.color}">${s.icon}</div>
                    <div class="ig-story-body">
                        <div class="ig-story-title">${esc(s.title)}</div>
                        <div class="ig-story-desc">${esc(s.desc)}</div>
                        <div class="ig-story-tags">${s.techniques.map(t => `<span class="tag">${esc(t.id)}</span>`).join("")}</div>
                    </div>
                </div>`).join("")
            : `<p class="rec-empty">xDome reported no MITRE technique for this alert. An empty chain is missing attribution, not proof of a benign event.</p>`}
        </div>
        <div class="xd-surface"><h4>Affected devices · ${inc.devices.length}</h4>
            ${deviceRows ? `<div class="table-wrap"><table><thead><tr><th>Device</th><th>IP</th><th>Site</th><th>Manufacturer</th><th>Type</th><th>Risk</th><th>Connectivity</th></tr></thead><tbody>${deviceRows}</tbody></table></div>`
            : `<p class="rec-empty">No device identity was present in the loaded alert or event records.</p>`}
        </div>
        <div class="xd-surface"><h4>Linked events · ${inc.events.length}</h4>
            ${eventRows ? `<div class="table-wrap"><table><thead><tr><th>Offset</th><th>Time</th><th>Event</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Description</th></tr></thead><tbody>${eventRows}</tbody></table></div>${inc.events.length > 100 ? `<p class="muted">Showing the first 100 of ${inc.events.length}.</p>` : ""}`
            : `<p class="rec-empty">No events in the loaded event store reference this alert ID.</p>`}
        </div>`;
    document.getElementById("caseTrackForm")?.addEventListener("submit", async e => {
        e.preventDefault();
        const msg = document.getElementById("caseTrackMsg");
        const form = new FormData(e.target);
        try {
            await saveCaseTracking(inc.id, { owner: String(form.get("owner")).trim(), playbook: String(form.get("playbook")).trim(), caseStatus: form.get("caseStatus"), notes: String(form.get("notes")).trim() });
            msg.textContent = "Saved";
        } catch (error) { msg.textContent = error.message; }
    });
}
window.openIncidentDetail = openIncidentDetail;
renderSlaCards();
// Refresh SLA countdown every 30s
setInterval(() => {
    if (document.getElementById("sla") && document.getElementById("sla").classList.contains("active")) renderSlaCards();
}, 30000);

/* ------------------------------------------------------------------ */
/* 2. LIVE ALERT FEED                                                  */
/* ------------------------------------------------------------------ */
const ALERT_TEMPLATES = [
    { title: "Phishing email with malicious attachment", sev: "High", src: "M365 Defender" },
    { title: "CrowdStrike: Ransomware pre-cursor detected", sev: "Critical", src: "CrowdStrike" },
    { title: "Failed login spike on privileged account", sev: "High", src: "Entra ID" },
    { title: "DNS tunneling exfiltration pattern", sev: "Critical", src: "DNS Monitor" },
    { title: "Lateral movement: pass-the-hash detected", sev: "High", src: "Sentinel" },
    { title: "Vulnerability scan: CVE-2024-21338 found", sev: "Medium", src: "Tenable" },
    { title: "User account created outside normal hours", sev: "Medium", src: "Entra ID" },
    { title: "Bulk email forward rule created by user", sev: "Medium", src: "M365" },
    { title: "C2 beacon to known malicious IP detected", sev: "Critical", src: "Palo Alto" },
    { title: "Privilege escalation: sudo abuse pattern", sev: "High", src: "Splunk ES" },
    { title: "Data exfiltration via cloud storage", sev: "High", src: "DLP" },
    { title: "Endpoint isolation auto-triggered", sev: "Low", src: "CrowdStrike", auto: true },
    { title: "IOC match: known malware hash", sev: "High", src: "VirusTotal" },
    { title: "Brute force attack on VPN gateway", sev: "Medium", src: "QRadar" },
    { title: "Anomalous access to Finance SharePoint", sev: "High", src: "Sentinel" },
    { title: "PowerShell obfuscation script executed", sev: "Critical", src: "Defender XDR" },
    { title: "Unmanaged device accessing corp resources", sev: "Medium", src: "Entra ID" },
    { title: "Service account used interactively", sev: "Medium", src: "AD Monitor" },
    { title: "Ransomware file extension change detected", sev: "Critical", src: "CrowdStrike", auto: true },
    { title: "DLP: sensitive data in outbound email", sev: "High", src: "M365 DLP" }
];
let alertFeedItems = [];
let alertFeedInterval = null;
let alertFeedTotal = { Critical: 0, High: 0, Medium: 0, Low: 0 };
let alertFeedSource = "sample fallback";
const sampleAlertDevices = ["OT-PLC-1001", "SCADA-HMI-1002", "OT-ENG-WS-1003", "HIST-SRV-1004"];

function createAlert() {
    const tmpl = ALERT_TEMPLATES[Math.floor(Math.random() * ALERT_TEMPLATES.length)];
    const now = new Date();
    alertFeedTotal[tmpl.sev] = (alertFeedTotal[tmpl.sev] || 0) + 1;
    return {
        ...tmpl,
        id: `ALT-${rand(9000,9999)}`,
        deviceName: sampleAlertDevices[rand(0, sampleAlertDevices.length - 1)],
        dataSource: "sample",
        time: now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        ts: now,
        state: tmpl.auto ? "Contained" : "New",
        owner: tmpl.auto ? "Automation" : null,
        ticket: null
    };
}
function renderAlertFeed() {
    const ticker = document.getElementById("alertTicker");
    if (!ticker) return;
    const sevFilter = document.getElementById("afSevFilter")?.value || "";
    const catFilter = document.getElementById("afCatFilter")?.value || "";
    const stateFilter = document.getElementById("afStateFilter")?.value || "";
    const filtered = alertFeedItems.filter(a => {
        if (sevFilter && a.sev !== sevFilter) return false;
        if (catFilter && !a.title.toLowerCase().includes(catFilter.toLowerCase()) && !a.src.toLowerCase().includes(catFilter.toLowerCase())) return false;
        if (stateFilter && a.state !== stateFilter) return false;
        return true;
    });
    const total = Object.values(alertFeedTotal).reduce((a,b) => a+b, 0);
    const newCount = alertFeedItems.filter(a => a.state === "New").length;
    const escalated = alertFeedItems.filter(a => a.state === "Escalated").length;
    const statsEl = document.getElementById("afStats");
    if (statsEl) statsEl.textContent = `${total} sample alerts · ${newCount} new · ${escalated} escalated · ${alertFeedItems.filter(a => a.auto).length} auto-contained · ${alertFeedSource}`;
    if (!filtered.length) { ticker.innerHTML = `<div class="rec-empty">${alertFeedItems.length ? "No alerts match the current filter" : "No SOC incident feed connected. Current Claroty alerts are shown above."}</div>`; return; }
    ticker.innerHTML = filtered.slice(-40).reverse().map((a, i) => `
        <div class="alert-item${i === 0 ? " new" : ""}" data-alert-id="${esc(a.id)}" tabindex="0" role="button">
            <span class="alert-sev sev-${a.sev}">${a.sev}</span>
            <span class="alert-title">${a.title}</span>
            <span class="alert-device">Device / host: ${esc(a.deviceName || a.device_name || "Not provided")}</span>
            <span class="alert-source">${a.src}</span>
            ${a.auto ? `<span class="alert-auto">⚡ Auto</span>` : ""}
            <span class="alert-state state-${a.state.toLowerCase()}">${a.state}</span>
            <span class="alert-time">${a.time}</span>
        </div>`).join("");
}

async function updateAlert(alert, action) {
    const apiAction = { ack: "acknowledge", own: "own", escalate: "escalate" }[action];
    try {
        const response = await fetch(`/api/alerts/${encodeURIComponent(alert.id)}/actions`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: apiAction, owner: "OT Analyst" })
        });
        if (!response.ok) throw new Error(`API ${response.status}`);
        Object.assign(alert, await response.json());
        return;
    } catch { /* use local fallback below */ }
    if (action === "ack") alert.state = "Acknowledged";
    if (action === "own") { alert.owner = "OT Analyst"; alert.state = "Investigating"; }
    if (action === "escalate") {
        alert.ticket = alert.ticket || `INC-${Math.floor(100000 + Math.random() * 900000)}`;
        alert.state = "Escalated";
        alert.owner = alert.owner || "OT Analyst";
    }
}

function openAlert(alert) {
    drawerTitle.textContent = alert.title;
    drawerSub.textContent = `${alert.id} · ${alert.src}`;
    drawerBody.innerHTML = `
        <div class="rec-summary">
            <div class="rec-stat"><b>${esc(alert.sev)}</b><span>severity</span></div>
            <div class="rec-stat"><b>${esc(alert.state)}</b><span>triage state</span></div>
            <div class="rec-stat"><b>${esc(alert.owner || "Unowned")}</b><span>owner</span></div>
        </div>
        <div class="alert-detail-card">
            <table>
                <tr><td>Alert ID</td><td>${esc(alert.id)}</td></tr>
                <tr><td>Device / host</td><td>${esc(alert.deviceName || alert.device_name || "Not provided by source")}</td></tr>
                <tr><td>Detected</td><td>${esc(alert.time)}</td></tr>
                <tr><td>Source</td><td>${esc(alert.src)}</td></tr>
                <tr><td>Automation</td><td>${alert.auto ? "Auto-contained" : "Manual triage required"}</td></tr>
                <tr><td>Incident</td><td>${esc(alert.ticket || "Not escalated")}</td></tr>
            </table>
            <div class="alert-actions">
                <button class="ap-btn" data-alert-action="ack" ${alert.state === "Contained" ? "disabled" : ""}>Acknowledge</button>
                <button class="ap-btn" data-alert-action="own">Take Ownership</button>
                <button class="ap-btn primary" data-alert-action="escalate" ${alert.ticket ? "disabled" : ""}>Escalate to Incident</button>
            </div>
        </div>`;
    drawer.classList.add("open");
    drawerOverlay.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    drawerBody.querySelectorAll("[data-alert-action]").forEach(button => button.addEventListener("click", async () => {
        const action = button.dataset.alertAction;
        button.disabled = true;
        await updateAlert(alert, action);
        if (action === "escalate" && alert.ticket) {
            addNotification({ title: "Alert escalated", msg: `${alert.id} created ${alert.ticket}`, color: COLORS.amber, cat: "system" });
        }
        renderAlertFeed();
        openAlert(alert);
    }));
}

document.getElementById("alertTicker")?.addEventListener("click", event => {
    const row = event.target.closest("[data-alert-id]");
    if (!row) return;
    const alert = alertFeedItems.find(item => item.id === row.dataset.alertId);
    if (alert) openAlert(alert);
});
document.getElementById("alertTicker")?.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    event.target.closest("[data-alert-id]")?.click();
});
async function syncAlertFeed() {
    try {
        const response = await fetch("/api/alerts", { cache: "no-store" });
        if (!response.ok) throw new Error(`API ${response.status}`);
        const payload = await response.json();
        alertFeedItems = payload.alerts.map((alert, index) => ({
            ...alert,
            deviceName: alert.deviceName || alert.device_name || sampleAlertDevices[index % sampleAlertDevices.length],
            dataSource: "sample",
            ts: new Date(alert.timestamp)
        }));
        alertFeedTotal = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        alertFeedItems.forEach(alert => alertFeedTotal[alert.sev]++);
        alertFeedSource = "simulated sample queue";
        return true;
    } catch {
        alertFeedSource = "sample fallback";
        return false;
    }
}

async function startAlertFeed() {
    if (!await syncAlertFeed()) {
        for (let i = 0; i < 15; i++) alertFeedItems.push(createAlert());
    }
    renderAlertFeed();
    alertFeedInterval = setInterval(async () => {
        const autoPlay = document.getElementById("afAutoPlay");
        if (!autoPlay || !autoPlay.checked) return;
        if (!await syncAlertFeed()) {
            const count = rand(0, 2);
            for (let i = 0; i < count; i++) alertFeedItems.push(createAlert());
            if (alertFeedItems.length > 200) alertFeedItems = alertFeedItems.slice(-200);
        }
        const feedSection = document.getElementById("alertfeed");
        if (feedSection && feedSection.classList.contains("active")) renderAlertFeed();
        // Push notification for Critical
        const crits = alertFeedItems.filter(a => a.sev === "Critical" && (Date.now() - a.ts) < 8000);
        crits.forEach(a => addNotification({
            title: "🔴 Critical Alert",
            msg: `${a.title} · ${a.deviceName || a.device_name || "Host not provided"}`,
            color: COLORS.red,
            cat: "alert",
            detail: { "Device / host": a.deviceName || a.device_name || "Host not provided", "Source": a.src, "Severity": a.sev, "Time": a.time, "Auto-handled": a.auto ? "Yes ⚡" : "No" },
            action: { label: "View Alert Feed →", fn: "showSection('alertfeed'); document.getElementById('notifPanel').hidden=true;" }
        }));
    }, 5000);
}
// The legacy simulated alert queue is not started in the Claroty live workspace.
document.getElementById("afSevFilter")?.addEventListener("change", renderAlertFeed);
document.getElementById("afCatFilter")?.addEventListener("change", renderAlertFeed);
document.getElementById("afStateFilter")?.addEventListener("change", renderAlertFeed);

/* ------------------------------------------------------------------ */
/* 11. NOTIFICATION CENTRE (rich tabbed — alerts, SLA, system)        */
/* ------------------------------------------------------------------ */
const notifications = [];
let unreadCount = 0;
let activeNotifTab = "all";

/* Category config */
const NOTIF_CATS = {
    alert:  { label: "Alert",  icon: "🔴", iconBg: "rgba(239,68,68,.15)",  tag: "alert"  },
    sla:    { label: "SLA",   icon: "⏱",  iconBg: "rgba(245,158,11,.15)", tag: "sla"    },
    system: { label: "System", icon: "⚙",  iconBg: "rgba(70,79,235,.15)",  tag: "system" },
    ok:     { label: "OK",    icon: "✅",  iconBg: "rgba(34,197,94,.15)",  tag: "ok"     }
};

function addNotification({ title, msg, color = COLORS.accent, cat = "system", detail = null, action = null }) {
    if (notifications.length && notifications[0].msg === msg && (Date.now() - notifications[0].ts) < 15000) return;
    notifications.unshift({
        title, msg, color, cat, detail, action,
        read: false,
        time: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
        ts: Date.now()
    });
    if (notifications.length > 80) notifications.pop();
    unreadCount++;
    updateBellBadge();
    const panel = document.getElementById("notifPanel");
    if (panel && !panel.hidden) renderNotifications();
}

function updateBellBadge() {
    const badge = document.getElementById("bellBadge");
    const btn   = document.getElementById("bellBtn");
    if (!badge) return;
    badge.textContent = unreadCount > 9 ? "9+" : String(unreadCount);
    badge.dataset.count = unreadCount;
    badge.style.display = unreadCount > 0 ? "" : "none";
    if (btn) btn.classList.toggle("has-unread", unreadCount > 0);
    const total = document.getElementById("notifTotalBadge");
    if (total) total.textContent = notifications.length;
}

function renderNotifications() {
    const list = document.getElementById("notifList");
    if (!list) return;

    const filtered = activeNotifTab === "all"
        ? notifications
        : notifications.filter(n => n.cat === activeNotifTab);

    /* Update tab counts */
    const counts = { all: notifications.length, alert: 0, sla: 0, system: 0 };
    notifications.forEach(n => { if (counts[n.cat] !== undefined) counts[n.cat]++; });
    const ids = { all: "ntcAll", alert: "ntcAlerts", sla: "ntcSla", system: "ntcSystem" };
    Object.entries(ids).forEach(([k, id]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = counts[k] || 0;
    });

    if (!filtered.length) {
        list.innerHTML = `<div class="notif-empty">No ${activeNotifTab === "all" ? "" : activeNotifTab + " "}notifications</div>`;
        return;
    }

    list.innerHTML = filtered.map((n, i) => {
        const cfg = NOTIF_CATS[n.cat] || NOTIF_CATS.system;
        const detailHtml = n.detail
            ? `<div class="notif-item-detail" style="display:${n.expanded ? "block" : "none"}">${Object.entries(n.detail).map(([k,v]) =>
                `<div class="notif-detail-row"><span>${k}</span><span>${v}</span></div>`).join("")}
               ${n.action ? `<button class="notif-action-btn" onclick="event.stopPropagation();${n.action.fn}">${n.action.label}</button>` : ""}
              </div>`
            : "";
        return `
        <div class="notif-item${n.read ? "" : " unread"}${n.expanded ? " expanded" : ""}" data-ni="${notifications.indexOf(n)}">
            <div class="notif-item-icon-wrap" style="background:${cfg.iconBg}">${cfg.icon}</div>
            <div class="notif-item-content">
                <div class="notif-item-title">${n.title}</div>
                <div class="notif-item-msg">${n.msg}</div>
                <div class="notif-item-meta">
                    <span class="notif-item-time">${n.time}</span>
                    <span class="notif-item-tag ${cfg.tag}">${cfg.label}</span>
                </div>
                ${detailHtml}
            </div>
            ${n.detail ? `<span class="notif-expand-ico">▾</span>` : ""}
        </div>`;
    }).join("");

    /* Click to expand detail / mark read */
    list.querySelectorAll(".notif-item").forEach(el => {
        el.addEventListener("click", () => {
            const idx = +el.dataset.ni;
            const n = notifications[idx];
            n.read = true;
            if (n.detail) {
                n.expanded = !n.expanded;
                el.classList.toggle("expanded", n.expanded);
                const detailEl = el.querySelector(".notif-item-detail");
                if (detailEl) detailEl.style.display = n.expanded ? "block" : "none";
                const ico = el.querySelector(".notif-expand-ico");
                if (ico) ico.style.transform = n.expanded ? "rotate(180deg)" : "";
            }
            el.classList.remove("unread");
            updateBellBadge();
        });
    });
}

/* Tab switching */
document.querySelectorAll(".notif-tab").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".notif-tab").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        activeNotifTab = btn.dataset.tab;
        renderNotifications();
    });
});

/* Bell toggle */
const bellBtn = document.getElementById("bellBtn");
const notifPanel = document.getElementById("notifPanel");
if (bellBtn && notifPanel) {
    bellBtn.addEventListener("click", e => {
        e.stopPropagation();
        const opening = notifPanel.hidden;
        notifPanel.hidden = !notifPanel.hidden;
        if (opening) {
            notifications.forEach(n => n.read = true);
            unreadCount = 0;
            updateBellBadge();
            renderNotifications();
        }
        if (typeof bmPanel !== "undefined" && bmPanel) bmPanel.hidden = true;
    });
}
document.getElementById("notifMarkAll")?.addEventListener("click", () => {
    notifications.forEach(n => n.read = true);
    unreadCount = 0;
    updateBellBadge();
    renderNotifications();
});
document.getElementById("notifClearAll")?.addEventListener("click", () => {
    notifications.length = 0;
    unreadCount = 0;
    updateBellBadge();
    renderNotifications();
});
document.addEventListener("click", e => {
    if (notifPanel && !notifPanel.hidden && !notifPanel.contains(e.target) && e.target !== bellBtn) notifPanel.hidden = true;
});

/* ---- Seed rich initial notifications (report-aware where possible) ---- */
(function seedNotifications() {
    const total  = REPORT ? REPORT.kpis.total : 700;
    const auto   = REPORT ? REPORT.kpis.automationRate : 82;
    const topCat = REPORT ? REPORT.kpis.topCategory : "DNS Threats";
    const crit   = REPORT ? REPORT.severity.Critical : 18;
    const high   = REPORT ? REPORT.severity.High : 310;

    addNotification({
        title: "🔴 Critical Incidents Open",
        msg: `${crit} Critical + ${high} High severity incidents require immediate attention`,
        color: COLORS.red, cat: "alert",
        detail: {
            "Critical": crit, "High": high,
            "Top Category": topCat,
            "SLA Status": "1 Breached · 4 At Risk",
            "Auto-handled": `${auto}%`
        },
        action: { label: "View SLA Tracker →", fn: "showSection('sla'); document.getElementById('notifPanel').hidden=true;" }
    });
    addNotification({
        title: "⛔ SLA Breach — INC-4901",
        msg: "Ransomware on finance workstation: SLA breached 20 min ago (Critical — 60min SLA)",
        color: COLORS.red, cat: "sla",
        detail: {
            "Incident": "INC-4901",
            "Severity": "Critical",
            "Category": "Malware/AV",
            "Opened": "80 min ago",
            "SLA Limit": "60 min",
            "Status": "BREACHED"
        },
        action: { label: "Open Incident →", fn: "openRecords('INC-4901','Ransomware SLA breach',{}); document.getElementById('notifPanel').hidden=true;" }
    });
    addNotification({
        title: "⚠ SLA At Risk — 4 Incidents",
        msg: "INC-4887, INC-4944, INC-4951, INC-4930 are approaching SLA within 2 hours",
        color: COLORS.amber, cat: "sla",
        detail: {
            "INC-4887": "30 min remaining",
            "INC-4944": "60 min remaining",
            "INC-4951": "140 min remaining",
            "INC-4930": "180 min remaining"
        },
        action: { label: "View SLA Tracker →", fn: "showSection('sla'); document.getElementById('notifPanel').hidden=true;" }
    });
    addNotification({
        title: "📡 Live Alert Feed Active",
        msg: `Auto-refreshing every 5s · ${Math.round(total * 0.04)} new alerts in last 30 min`,
        color: COLORS.accent, cat: "alert",
        detail: {
            "Critical alerts": "8",
            "High alerts": "22",
            "Auto-handled": "2 (⚡ auto)",
            "Feed status": "Running"
        },
        action: { label: "View Alert Feed →", fn: "showSection('alertfeed'); document.getElementById('notifPanel').hidden=true;" }
    });
    addNotification({
        title: "✅ Claroty Live Data Ready",
        msg: "Encrypted Claroty xDome backend connection is available for OT device and vulnerability modules",
        color: COLORS.green, cat: "system",
        detail: {
            "Total incidents": total,
            "Automation rate": auto + "%",
            "Top category": topCat,
            "Critical": crit,
            "High": high,
            "Source": "Claroty xDome API"
        }
    });
    addNotification({
        title: "🤖 AI Investigation Ready",
        msg: "AI auto-investigate is enabled for SLA breaches. Click 'Create with AI' in SLA Tracker.",
        color: COLORS.accent2 || COLORS.accent, cat: "system",
        detail: {
            "Mode": "Auto-enabled",
            "Trigger": "SLA breach / Critical alert",
            "Action": "Triage + response plan"
        },
        action: { label: "Open SLA Tracker →", fn: "showSection('sla'); document.getElementById('notifPanel').hidden=true;" }
    });
    addNotification({
        title: "⚙ Settings - Integrations",
        msg: "All security-tool integrations and API settings are consolidated under Settings - Integrations",
        color: COLORS.accent, cat: "system",
        detail: {
            "Total tools": "17",
            "Settings saved · unverified": `${INTEGRATIONS.configuredCount()} / ${INTEGRATIONS.TOOLS.length}`,
            "EDR": "CrowdStrike · Trellix · Defender",
            "SIEM": "Sentinel · Splunk · QRadar"
        },
        action: { label: "Open Settings →", fn: "showSection('integrations'); document.getElementById('notifPanel').hidden=true;" }
    });
    addNotification({
        title: "🌍 Threat Map Updated",
        msg: `Top threat origins: Russia (142), China (118), N.Korea (67) — ${total} incidents mapped`,
        color: COLORS.red, cat: "alert",
        detail: {
            "Russia": "142 incidents · Malware + Ransomware",
            "China": "118 incidents · Phishing + C2",
            "N.Korea": "67 incidents · APT campaigns",
            "Iran": "54 incidents · Targeted attacks"
        },
        action: { label: "View Threat Map →", fn: "showSection('threatmap'); document.getElementById('notifPanel').hidden=true;" }
    });
})();

/* ------------------------------------------------------------------ */
/* 12. SAVED FILTERS / BOOKMARKS                                       */
/* ------------------------------------------------------------------ */
const BM_KEY = "soc-bookmarks";
function loadBookmarks() { try { return JSON.parse(localStorage.getItem(BM_KEY) || "[]"); } catch { return []; } }
function saveBookmarks(bms) { try { localStorage.setItem(BM_KEY, JSON.stringify(bms)); } catch {} }

function renderBookmarks() {
    const list = document.getElementById("bmList");
    if (!list) return;
    const bms = loadBookmarks();
    if (!bms.length) { list.innerHTML = `<div class="bm-empty">No saved views yet. Navigate to a section and click + Save current.</div>`; return; }
    list.innerHTML = bms.map((bm, i) => `
        <div class="bm-item" data-bi="${i}">
            <div>
                <div class="bm-name">${bm.name}</div>
                <div class="bm-meta">${bm.section} · ${bm.date}</div>
            </div>
            <button class="bm-del" data-bi="${i}" title="Delete">✕</button>
        </div>`).join("");
    list.querySelectorAll(".bm-item").forEach(el => {
        el.addEventListener("click", e => {
            if (e.target.classList.contains("bm-del")) return;
            const bm = loadBookmarks()[+el.dataset.bi];
            if (bm) showSection(bm.section);
            if (bmPanel) bmPanel.hidden = true;
        });
    });
    list.querySelectorAll(".bm-del").forEach(btn => {
        btn.addEventListener("click", e => {
            e.stopPropagation();
            const bms = loadBookmarks(); bms.splice(+btn.dataset.bi, 1);
            saveBookmarks(bms); renderBookmarks();
        });
    });
}

const bookmarksBtn = document.getElementById("bookmarksBtn");
const bmPanel = document.getElementById("bmPanel");
if (bookmarksBtn && bmPanel) {
    bookmarksBtn.addEventListener("click", e => {
        e.stopPropagation();
        bmPanel.hidden = !bmPanel.hidden;
        if (!bmPanel.hidden) renderBookmarks();
        if (notifPanel) notifPanel.hidden = true;
    });
}
document.getElementById("bmSaveBtn")?.addEventListener("click", () => {
    const activeSection = document.querySelector(".panel.active")?.id || "overview";
    const sectionName = document.querySelector(`.panel.active [data-section-view="${activeSection}"]`)?.textContent.trim()
        || document.querySelector(`.nav-item[data-section="${activeSection}"]`)?.textContent.trim() || activeSection;
    const name = prompt(`Save current view "${sectionName}" as:`, sectionName);
    if (!name) return;
    const bms = loadBookmarks();
    bms.unshift({ name, section: activeSection, date: new Date().toLocaleDateString() });
    if (bms.length > 20) bms.pop();
    saveBookmarks(bms); renderBookmarks();
});
document.addEventListener("click", e => {
    if (bmPanel && !bmPanel.hidden && !bmPanel.contains(e.target) && e.target !== bookmarksBtn) bmPanel.hidden = true;
});
renderBookmarks();

/* ------------------------------------------------------------------ */
/* 13. AUTO OS DARK/LIGHT MODE (respects prefers-color-scheme)         */
/* ------------------------------------------------------------------ */
(function initOsTheme() {
    const saved = (() => { try { return localStorage.getItem("soc-theme"); } catch { return null; } })();
    if (saved) return; // user manually set theme — don't override
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    if (!prefersDark) applyTheme("light", false);
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", e => {
        const manuallySaved = (() => { try { return localStorage.getItem("soc-theme"); } catch { return null; } })();
        if (!manuallySaved) applyTheme(e.matches ? "dark" : "light", false);
    });
})();

/* ------------------------------------------------------------------ */
/* 14. KEYBOARD SHORTCUTS                                              */
/* ------------------------------------------------------------------ */
const sectionKeys = { "1": "overview", "2": "operations", "3": "threats", "4": "intel", "5": "insider", "6": "automation", "7": "roi", "8": "siem", "9": "playbooks", "0": "scorecard", "a": "alertfeed", "m": "threatmap", "s": "sla", "i": "integrations", "u": "zerotrust" };
sectionKeys["3"] = "devices";
sectionKeys["4"] = "threats";
sectionKeys.r = "riskmanagement";
document.addEventListener("keydown", e => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.isContentEditable) return;
    if (e.key === "?" || e.key === "/") {
        const help = document.getElementById("shortcutHelp");
        if (help) { help.hidden = !help.hidden; return; }
        const h = document.createElement("div");
        h.id = "shortcutHelp"; h.className = "shortcut-help";
        h.innerHTML = `<div class="shortcut-item"><kbd class="kbd">1-9</kbd> Jump to section</div><div class="shortcut-item"><kbd class="kbd">A</kbd> Alert Feed</div><div class="shortcut-item"><kbd class="kbd">M</kbd> Threat Map</div><div class="shortcut-item"><kbd class="kbd">S</kbd> SLA Tracker</div><div class="shortcut-item"><kbd class="kbd">I</kbd> Settings</div><div class="shortcut-item"><kbd class="kbd">R</kbd> Refresh</div><div class="shortcut-item"><kbd class="kbd">T</kbd> Toggle theme</div><div class="shortcut-item"><kbd class="kbd">Esc</kbd> Close panels</div><button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px;margin-left:8px">✕</button>`;
        document.body.appendChild(h);
        return;
    }
    if (e.key === "Escape") {
        closeDrawer();
        if (notifPanel) notifPanel.hidden = true;
        if (bmPanel) bmPanel.hidden = true;
        const help = document.getElementById("shortcutHelp"); if (help) help.remove();
        return;
    }
    if (e.key === "r" || e.key === "R") { document.getElementById("refreshBtn")?.click(); return; }
    if (e.key === "t" || e.key === "T") { document.getElementById("themeToggle")?.click(); return; }
    const sec = sectionKeys[e.key.toLowerCase()];
    if (sec) showSection(sec);
});

/* ------------------------------------------------------------------ */
/* 15. COLLAPSIBLE SIDEBAR  (toggle + pin lock)                        */
/* ------------------------------------------------------------------ */
(function initSidebar() {
    const sidebar    = document.querySelector(".sidebar");
    const toggleBtn  = document.getElementById("sidebarToggle");
    const pinBtn     = document.getElementById("sidebarPin");
    const pinIco     = pinBtn?.querySelector(".sb-pin-ico");
    const toggleLbl  = toggleBtn?.querySelector(".sb-toggle-label");
    if (!sidebar) return;

    /* Restore saved state */
    let isCollapsed = false, isPinned = false;
    try {
        isCollapsed = localStorage.getItem("soc-sidebar") === "collapsed";
        isPinned    = localStorage.getItem("soc-sidebar-pin") === "1";
    } catch(e) { /* ignore */ }

    function applyState() {
        sidebar.classList.toggle("collapsed", isCollapsed);
        sidebar.classList.toggle("pinned", isPinned);
        if (toggleLbl) toggleLbl.textContent = isCollapsed ? "Expand" : "Collapse";
        const toggleIco = toggleBtn?.querySelector(".sb-toggle-ico");
        if (toggleIco) toggleIco.textContent = isCollapsed ? "☰" : "✕";
        if (pinIco) pinIco.textContent = isPinned ? "📌" : "📍";
        if (pinBtn) pinBtn.title = isPinned ? "Unpin sidebar" : "Pin sidebar open";
        try {
            localStorage.setItem("soc-sidebar", isCollapsed ? "collapsed" : "expanded");
            localStorage.setItem("soc-sidebar-pin", isPinned ? "1" : "0");
        } catch(e) { /* ignore */ }
    }

    /* Toggle collapse/expand */
    toggleBtn?.addEventListener("click", () => {
        isCollapsed = !isCollapsed;
        /* When expanding, also remove pin if it was pinning a collapsed state */
        if (!isCollapsed && !isPinned) isPinned = false;
        applyState();
    });

    /* Pin lock — when pinned, hover-expand is disabled and width is locked */
    pinBtn?.addEventListener("click", () => {
        isPinned = !isPinned;
        /* Pinning while collapsed → auto-expand so it makes sense */
        if (isPinned && isCollapsed) { isCollapsed = false; }
        applyState();
    });

    /* Keyboard shortcut: [ to toggle sidebar */
    document.addEventListener("keydown", e => {
        if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
        if (e.key === "[" || (e.key === "b" && e.ctrlKey)) {
            e.preventDefault();
            isCollapsed = !isCollapsed;
            applyState();
        }
    });

    applyState();
})();

/* ------------------------------------------------------------------ */
/* 4. PDF / PNG EXPORT                                                 */
/* ------------------------------------------------------------------ */
document.getElementById("exportBtn")?.addEventListener("click", async () => {
    const btn = document.getElementById("exportBtn");
    btn.textContent = "⏳ Rendering…"; btn.disabled = true;
    try {
        const mainEl = document.querySelector(".main");
        const canvas = await html2canvas(mainEl, { scale: 1.5, useCORS: true, backgroundColor: getComputedStyle(document.body).backgroundColor });
        const imgData = canvas.toDataURL("image/jpeg", 0.95);
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF({ orientation: canvas.width > canvas.height ? "landscape" : "portrait", unit: "px", format: [canvas.width / 1.5, canvas.height / 1.5] });
        pdf.addImage(imgData, "JPEG", 0, 0, canvas.width / 1.5, canvas.height / 1.5);
        const activeSection = document.querySelector(".nav-item.active")?.dataset.section || "dashboard";
        pdf.save(`OT-Platform-${activeSection}-${new Date().toISOString().slice(0,10)}.pdf`);
        addNotification({ title: "✅ Export Complete", msg: `PDF exported for ${activeSection} section`, color: COLORS.green, cat: "ok" });
    } catch (err) {
        alert("Export failed: " + err.message);
    } finally {
        btn.textContent = "📄 Export"; btn.disabled = false;
    }
});

/* ------------------------------------------------------------------ */
/* 1. API INTEGRATION SETTINGS — render panel on nav                  */
/* ------------------------------------------------------------------ */
(function initIntegrations() {
    const integrationsSection = document.getElementById("integrations");
    if (!integrationsSection || typeof INTEGRATIONS === "undefined") return;
    // Render when the section becomes visible
    const observer = new MutationObserver(() => {
        if (integrationsSection.classList.contains("active")) {
            INTEGRATIONS.render("integFormContainer");
            INTEGRATIONS.updateConfiguredCount();
            renderSettingsToolInventory();
            observer.disconnect();
        }
    });
    observer.observe(integrationsSection, { attributes: true });
})();

let moduleDataRecords = [];
let moduleDataEditingId = null;

async function loadModuleDataRegistry() {
    const select = document.getElementById("moduleDataSelect");
    const status = document.getElementById("moduleDataStatus");
    if (!select || !status) return;
    if (!select.options.length) {
        try {
            const response = await fetch("/api/modules", { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || `Module registry ${response.status}`);
            select.innerHTML = (payload.modules || []).map(module => `<option value="${escapeOverviewWidgetText(module.id)}" data-read-only="${module.writable === false}">${escapeOverviewWidgetText(module.name)}</option>`).join("");
        } catch (error) {
            status.textContent = `Module registry unavailable: ${error.message}`;
            return;
        }
    }
    await loadModuleDataRecords();
}

async function loadModuleDataRecords() {
    const select = document.getElementById("moduleDataSelect");
    const search = document.getElementById("moduleDataSearch");
    const rows = document.getElementById("moduleDataRows");
    const status = document.getElementById("moduleDataStatus");
    if (!select || !rows || !status || !select.value) return;
    const readOnly = select.selectedOptions[0]?.dataset.readOnly === "true";
    document.getElementById("moduleDataJson").disabled = readOnly;
    document.getElementById("saveModuleRecord").disabled = readOnly;
    document.getElementById("newModuleRecord").disabled = readOnly;
    const params = new URLSearchParams({ limit: "500" });
    if (search?.value.trim()) params.set("q", search.value.trim());
    status.textContent = "Loading persisted records…";
    try {
        const response = await fetch(`/api/modules/${encodeURIComponent(select.value)}?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Module records ${response.status}`);
        moduleDataRecords = payload.records || [];
        rows.innerHTML = moduleDataRecords.map(record => `<tr><td>${escapeOverviewWidgetText(String(record.id))}</td><td><code>${escapeOverviewWidgetText(JSON.stringify(record).slice(0, 260))}</code></td><td>${escapeOverviewWidgetText(record.updated_at || record.created_at || "—")}</td><td>${readOnly ? "Audit API" : `<button type="button" data-module-record-edit="${escapeOverviewWidgetText(String(record.id))}">Edit</button> <button type="button" data-module-record-delete="${escapeOverviewWidgetText(String(record.id))}">Delete</button>`}</td></tr>`).join("") || `<tr><td colspan="4">No records in this module.</td></tr>`;
        status.textContent = `${payload.total ?? moduleDataRecords.length} persisted records · ${readOnly ? "read-only audit data" : "local server store"}`;
    } catch (error) {
        rows.innerHTML = `<tr><td colspan="4">${escapeOverviewWidgetText(error.message)}</td></tr>`;
        status.textContent = `Could not load module records: ${error.message}`;
    }
}

function resetModuleRecordEditor() {
    moduleDataEditingId = null;
    const editor = document.getElementById("moduleDataJson");
    const button = document.getElementById("saveModuleRecord");
    if (editor) editor.value = "";
    if (button) button.textContent = "Create record";
}

async function saveModuleDataRecord() {
    const select = document.getElementById("moduleDataSelect");
    const editor = document.getElementById("moduleDataJson");
    const status = document.getElementById("moduleDataStatus");
    if (!select || !editor || !status) return;
    if (select.selectedOptions[0]?.dataset.readOnly === "true") {
        status.textContent = "Use the SECUMAT audit workflow to edit these records.";
        return;
    }
    let record;
    try {
        record = JSON.parse(editor.value);
        if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("Record JSON must be an object.");
    } catch (error) {
        status.textContent = `Invalid record JSON: ${error.message}`;
        return;
    }
    const path = `/api/modules/${encodeURIComponent(select.value)}${moduleDataEditingId ? `/${encodeURIComponent(moduleDataEditingId)}` : ""}`;
    try {
        const response = await fetch(path, { method: moduleDataEditingId ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(record) });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Save failed (${response.status})`);
        status.textContent = `Record ${moduleDataEditingId ? "updated" : "created"}.`;
        resetModuleRecordEditor();
        await loadModuleDataRecords();
    } catch (error) {
        status.textContent = `Could not save record: ${error.message}`;
    }
}

document.getElementById("moduleDataSelect")?.addEventListener("change", () => { resetModuleRecordEditor(); loadModuleDataRecords(); });
document.getElementById("moduleDataSearch")?.addEventListener("input", () => loadModuleDataRecords());
document.getElementById("refreshModuleData")?.addEventListener("click", loadModuleDataRecords);
document.getElementById("newModuleRecord")?.addEventListener("click", resetModuleRecordEditor);
document.getElementById("cancelModuleRecord")?.addEventListener("click", resetModuleRecordEditor);
document.getElementById("saveModuleRecord")?.addEventListener("click", saveModuleDataRecord);
document.getElementById("moduleDataRows")?.addEventListener("click", async event => {
    const editButton = event.target.closest("[data-module-record-edit]");
    if (editButton) {
        const record = moduleDataRecords.find(item => String(item.id) === editButton.dataset.moduleRecordEdit);
        if (!record) return;
        moduleDataEditingId = String(record.id);
        document.getElementById("moduleDataJson").value = JSON.stringify(record, null, 2);
        document.getElementById("saveModuleRecord").textContent = "Save changes";
        document.getElementById("moduleDataStatus").textContent = `Editing ${moduleDataEditingId}.`;
        return;
    }
    const deleteButton = event.target.closest("[data-module-record-delete]");
    if (!deleteButton || !window.confirm(`Delete ${deleteButton.dataset.moduleRecordDelete}?`)) return;
    try {
        const response = await fetch(`/api/modules/${encodeURIComponent(document.getElementById("moduleDataSelect").value)}/${encodeURIComponent(deleteButton.dataset.moduleRecordDelete)}`, { method: "DELETE" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Delete failed (${response.status})`);
        document.getElementById("moduleDataStatus").textContent = "Record deleted.";
        await loadModuleDataRecords();
    } catch (error) {
        document.getElementById("moduleDataStatus").textContent = `Could not delete record: ${error.message}`;
    }
});

(function initSettingsTabs() {
    document.querySelectorAll("#settingsTabs .settings-tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const tab = btn.dataset.settingsTab;
            document.querySelectorAll("#settingsTabs .settings-tab-btn").forEach(item => item.classList.toggle("active", item === btn));
            document.getElementById("settingsIntegrationsView").hidden = tab !== "integrations";
            document.getElementById("settingsModuleDataView").hidden = tab !== "moduledata";
            document.getElementById("settingsUsersView").hidden = tab !== "users";
            document.getElementById("settingsProfileView").hidden = tab !== "profile";
            if (tab === "integrations") renderSettingsToolInventory();
            if (tab === "moduledata") loadModuleDataRegistry();
        });
    });
})();

/* Re-build heatmap and leaderboard when range changes */
const origShowSection = showSection;
const phishingDiagramSource = document.getElementById("phishingDiagram")?.textContent.trim();
let phishingDiagramRendering = false;
window.showSection = function(id) {
    origShowSection(id);
    if (id === "devices" && window.XDOME) window.XDOME.renderDevices();
    if (id === "threats" && window.XDOME) window.XDOME.renderVulnerabilities();
    if (id === "riskmanagement" && window.XDOME) window.XDOME.renderRiskManagement();
    if (id === "operations" && window.XDPortal) window.XDPortal.renderOperations();
    if (id === "zerotrust" && window.ZeroTrustView) window.ZeroTrustView.refresh();
    if (id === "intel") loadModuleThreatAnalytics();
    if (id === "overview") buildHeatmap();
    if (id === "sla") renderSlaCards();
    if (id === "alertfeed") renderAlertFeed();
    if (id === "threatmap" || id === "sla" || id === "alertfeed") setTimeout(buildExtraCharts, 150);
    if (id === "playbooks" && window.mermaid) {
        const el = document.getElementById("phishingDiagram");
        if (el && !phishingDiagramRendering && !el.querySelector("svg") && phishingDiagramSource) {
            phishingDiagramRendering = true;
            el.removeAttribute("data-processed");
            el.textContent = phishingDiagramSource;
            Promise.resolve(mermaid.init(undefined, el)).catch(error => {
                el.textContent = "Workflow diagram unavailable";
                console.error("Playbook diagram failed:", error);
            }).finally(() => { phishingDiagramRendering = false; });
        }
    }
    if (id === "incgraph") initIncidentGraph();
    if (id === "socopt") initSocOpt();
};

/* ================================================================== */
/* INCIDENT GRAPH ENGINE                                               */
/* ================================================================== */
(function() {
/* ---- Entity type config ---- */
const NODE_TYPES = {
    incident:  { label: "Incident",  color: "#ef4444", icon: "⚠",  size: 22 },
    alert:     { label: "Alert",     color: "#f59e0b", icon: "🔔", size: 16 },
    host:      { label: "Host",      color: "#464feb", icon: "🖥",  size: 18 },
    user:      { label: "User",      color: "#22c55e", icon: "👤", size: 16 },
    ip:        { label: "IP Address",color: "#e879f9", icon: "🌐", size: 14 },
    domain:    { label: "Domain",    color: "#06b6d4", icon: "🌍", size: 14 },
    file:      { label: "File/Hash", color: "#a78bfa", icon: "📄", size: 13 },
    process:   { label: "Process",   color: "#fb923c", icon: "⚙",  size: 13 },
    cve:       { label: "CVE",       color: "#f87171", icon: "🛡",  size: 14 }
};

/* ---- Incident graph datasets ---- */
const INCIDENT_GRAPHS = {
    "INC-4901": {
        title: "Ransomware on Finance Workstation",
        sev: "Critical", cat: "Malware/AV", mitre: "T1486 – Data Encrypted for Impact",
        nodes: [
            { id: "i1",  type: "incident", label: "INC-4901",         desc: "Ransomware – Critical" },
            { id: "a1",  type: "alert",    label: "ALT-7731",          desc: "CrowdStrike: Ransom pre-cursor" },
            { id: "a2",  type: "alert",    label: "ALT-7735",          desc: "File extension mass-change" },
            { id: "a3",  type: "alert",    label: "ALT-7742",          desc: "Sentinel: C2 traffic detected" },
            { id: "h1",  type: "host",     label: "WKST-FIN-042",      desc: "Finance workstation – Windows 11" },
            { id: "h2",  type: "host",     label: "FS-CORP-01",        desc: "File server – SMB share" },
            { id: "u1",  type: "user",     label: "j.harmon",          desc: "Finance – Risk score 92" },
            { id: "u2",  type: "user",     label: "svc-backup",        desc: "Service account – elevated" },
            { id: "ip1", type: "ip",       label: "185.220.101.47",    desc: "Known C2 – Tor exit node (RU)" },
            { id: "ip2", type: "ip",       label: "10.10.5.42",        desc: "Internal lateral source" },
            { id: "f1",  type: "file",     label: "explorer.exe.bin",  desc: "SHA256: a3f2… – malicious" },
            { id: "p1",  type: "process",  label: "powershell.exe",    desc: "Obfuscated command execution" },
            { id: "c1",  type: "cve",      label: "CVE-2024-21338",    desc: "CVSS 8.8 – kernel priv esc" }
        ],
        edges: [
            { s: "i1", t: "a1", rel: "triggered" }, { s: "i1", t: "a2", rel: "triggered" }, { s: "i1", t: "a3", rel: "triggered" },
            { s: "a1", t: "h1", rel: "detected_on" }, { s: "a2", t: "h2", rel: "detected_on" },
            { s: "h1", t: "u1", rel: "logged_in" }, { s: "u2", t: "h2", rel: "accessed" },
            { s: "h1", t: "ip1", rel: "communicates" }, { s: "ip2", t: "h1", rel: "lateral_from" },
            { s: "h1", t: "f1", rel: "executed" }, { s: "h1", t: "p1", rel: "spawned" },
            { s: "p1", t: "c1", rel: "exploits" }, { s: "a3", t: "ip1", rel: "correlates" }
        ]
    },
    "INC-4887": {
        title: "Phishing Campaign with Credential Harvest",
        sev: "High", cat: "Phishing", mitre: "T1566.002 – Spearphishing Link",
        nodes: [
            { id: "i1",  type: "incident", label: "INC-4887",       desc: "Phishing – High" },
            { id: "a1",  type: "alert",    label: "ALT-7640",        desc: "M365: Malicious link clicked" },
            { id: "a2",  type: "alert",    label: "ALT-7644",        desc: "Entra: Credential stuffing" },
            { id: "u1",  type: "user",     label: "a.novak",         desc: "Sales – Clicked phishing link" },
            { id: "u2",  type: "user",     label: "l.becker",        desc: "Engineering – Credential reuse" },
            { id: "d1",  type: "domain",   label: "secure-m365.co",  desc: "Lookalike phishing domain (RO)" },
            { id: "ip1", type: "ip",       label: "91.108.4.101",    desc: "Phishing kit server (RO)" },
            { id: "h1",  type: "host",     label: "LAPTOP-SALES-07", desc: "Sales laptop – Windows 10" },
            { id: "f1",  type: "file",     label: "invoice_Q3.html", desc: "HTML smuggling payload" }
        ],
        edges: [
            { s: "i1", t: "a1", rel: "triggered" }, { s: "i1", t: "a2", rel: "triggered" },
            { s: "a1", t: "u1", rel: "victim" }, { s: "a2", t: "u2", rel: "victim" },
            { s: "u1", t: "h1", rel: "logged_in" }, { s: "d1", t: "ip1", rel: "resolves_to" },
            { s: "u1", t: "d1", rel: "visited" }, { s: "h1", t: "f1", rel: "downloaded" },
            { s: "f1", t: "ip1", rel: "calls_back" }
        ]
    },
    "INC-4930": {
        title: "CrowdStrike C2 Beaconing",
        sev: "High", cat: "EDR (CrowdStrike)", mitre: "T1071.001 – Web Protocols C2",
        nodes: [
            { id: "i1",  type: "incident", label: "INC-4930",       desc: "C2 Beaconing – High" },
            { id: "a1",  type: "alert",    label: "ALT-7800",        desc: "CrowdStrike: Periodic beacon" },
            { id: "a2",  type: "alert",    label: "ALT-7805",        desc: "Palo Alto: Encrypted tunnel" },
            { id: "h1",  type: "host",     label: "SRV-APP-03",      desc: "App server – compromised" },
            { id: "ip1", type: "ip",       label: "185.220.101.47",  desc: "C2 server – Tor exit (RU)" },
            { id: "ip2", type: "ip",       label: "45.142.212.100",  desc: "Secondary C2 – bulletproof VPS" },
            { id: "d1",  type: "domain",   label: "update-cdn.net",  desc: "DGA domain – typosquatted" },
            { id: "p1",  type: "process",  label: "svchost.exe",     desc: "Hollow process – injected" },
            { id: "u1",  type: "user",     label: "admin-eu",        desc: "IT Admin – session hijacked" }
        ],
        edges: [
            { s: "i1", t: "a1", rel: "triggered" }, { s: "i1", t: "a2", rel: "triggered" },
            { s: "a1", t: "h1", rel: "detected_on" }, { s: "h1", t: "ip1", rel: "beacons_to" },
            { s: "h1", t: "ip2", rel: "beacons_to" }, { s: "ip1", t: "d1", rel: "resolves_to" },
            { s: "h1", t: "p1", rel: "spawned" }, { s: "u1", t: "h1", rel: "logged_in" },
            { s: "a2", t: "ip1", rel: "correlates" }
        ]
    },
    "INC-4923": {
        title: "Lateral Movement via Pass-the-Hash",
        sev: "Critical", cat: "Identity Risk", mitre: "T1550.002 – Pass the Hash",
        nodes: [
            { id: "i1",  type: "incident", label: "INC-4923",       desc: "Lateral Movement – Critical" },
            { id: "a1",  type: "alert",    label: "ALT-7755",        desc: "Sentinel: PtH technique" },
            { id: "a2",  type: "alert",    label: "ALT-7760",        desc: "AD: Abnormal NTLM auth" },
            { id: "u1",  type: "user",     label: "svc-backup",      desc: "Compromised service acct" },
            { id: "u2",  type: "user",     label: "admin-eu",        desc: "Target – privilege escalation" },
            { id: "h1",  type: "host",     label: "WKST-FIN-042",    desc: "Source – hash extracted" },
            { id: "h2",  type: "host",     label: "DC-CORP-01",      desc: "Domain controller – target" },
            { id: "h3",  type: "host",     label: "FS-CORP-01",      desc: "File server – lateral target" },
            { id: "ip1", type: "ip",       label: "10.10.5.42",      desc: "Internal attacker source" },
            { id: "p1",  type: "process",  label: "lsass.exe",       desc: "Credential dump target" }
        ],
        edges: [
            { s: "i1", t: "a1", rel: "triggered" }, { s: "i1", t: "a2", rel: "triggered" },
            { s: "a1", t: "h1", rel: "detected_on" }, { s: "h1", t: "p1", rel: "dumped" },
            { s: "u1", t: "h2", rel: "lateral_to" }, { s: "u1", t: "h3", rel: "lateral_to" },
            { s: "ip1", t: "h2", rel: "source" }, { s: "u2", t: "h2", rel: "target" },
            { s: "h1", t: "h2", rel: "lateral_from" }
        ]
    }
};

/* ---- Physics simulation ---- */
let igNodes = [], igEdges = [], igSelectedNode = null;
let igGrouped = false, igZoom = 1, igOffX = 0, igOffY = 0;
let igDragging = null, igDragStartX = 0, igDragStartY = 0;
let igPanning = false, igPanStartX = 0, igPanStartY = 0;
let igAnimFrame = null, igCanvas, igCtx, igWrap;
let igCurrentGraph = null;

const REL_COLORS = {
    triggered: "#ef4444", detected_on: "#f59e0b", logged_in: "#22c55e", accessed: "#06b6d4",
    communicates: "#e879f9", lateral_from: "#ef4444", lateral_to: "#ef4444",
    executed: "#a78bfa", spawned: "#fb923c", exploits: "#f87171",
    correlates: "#8b90a3", visited: "#f59e0b", downloaded: "#a78bfa",
    calls_back: "#ef4444", resolves_to: "#06b6d4", beacons_to: "#ef4444",
    victim: "#f59e0b", source: "#ef4444", target: "#e879f9", dumped: "#a78bfa"
};

function initForceNodes(graphData) {
    const cW = igCanvas.width / igZoom, cH = igCanvas.height / igZoom;
    igNodes = graphData.nodes.map((n, i) => {
        const angle = (i / graphData.nodes.length) * Math.PI * 2;
        const r = Math.min(cW, cH) * 0.28;
        return { ...n, ...NODE_TYPES[n.type],
            x: cW/2 + r * Math.cos(angle),
            y: cH/2 + r * Math.sin(angle),
            vx: 0, vy: 0, fixed: false
        };
    });
    igEdges = graphData.edges.map(e => ({
        ...e,
        source: igNodes.find(n => n.id === e.s),
        target: igNodes.find(n => n.id === e.t),
        color: REL_COLORS[e.rel] || "#8b90a3"
    }));
}

function tickPhysics() {
    const alpha = 0.6, repulse = 3200, spring = 0.04, springLen = 120, damp = 0.82, center = 0.006;
    const cW = igCanvas.width / igZoom, cH = igCanvas.height / igZoom;
    igNodes.forEach(n => { if (!n.fixed) { n.vx += (cW/2 - n.x) * center; n.vy += (cH/2 - n.y) * center; } });
    for (let i = 0; i < igNodes.length; i++) {
        for (let j = i+1; j < igNodes.length; j++) {
            const a = igNodes[i], b = igNodes[j];
            const dx = b.x - a.x, dy = b.y - a.y;
            const d = Math.max(1, Math.sqrt(dx*dx+dy*dy));
            const f = repulse / (d*d);
            const fx = dx/d * f, fy = dy/d * f;
            if (!a.fixed) { a.vx -= fx; a.vy -= fy; }
            if (!b.fixed) { b.vx += fx; b.vy += fy; }
        }
    }
    igEdges.forEach(e => {
        if (!e.source || !e.target) return;
        const dx = e.target.x - e.source.x, dy = e.target.y - e.source.y;
        const d = Math.max(1, Math.sqrt(dx*dx+dy*dy));
        const f = (d - springLen) * spring;
        const fx = dx/d * f, fy = dy/d * f;
        if (!e.source.fixed) { e.source.vx += fx; e.source.vy += fy; }
        if (!e.target.fixed) { e.target.vx -= fx; e.target.vy -= fy; }
    });
    igNodes.forEach(n => {
        if (n.fixed) return;
        n.vx *= damp; n.vy *= damp;
        n.x += n.vx; n.y += n.vy;
    });
}

function igDraw() {
    igAnimFrame = requestAnimationFrame(igDraw);
    tickPhysics();
    const dpr = window.devicePixelRatio || 1;
    igCtx.clearRect(0, 0, igCanvas.width, igCanvas.height);
    igCtx.save();
    igCtx.scale(dpr, dpr);
    igCtx.translate(igOffX, igOffY);
    igCtx.scale(igZoom, igZoom);

    const light = document.body.classList.contains("light");
    const bgColor = light ? "#f4f6fb" : "#171a23";
    const textColor = light ? "#1b2030" : "#e7e9f0";

    // Draw edges
    igEdges.forEach(e => {
        if (!e.source || !e.target) return;
        const sx = e.source.x, sy = e.source.y, tx = e.target.x, ty = e.target.y;
        const dx = tx - sx, dy = ty - sy, d = Math.sqrt(dx*dx+dy*dy);
        if (d < 1) return;
        igCtx.beginPath();
        igCtx.moveTo(sx, sy);
        igCtx.lineTo(tx, ty);
        igCtx.strokeStyle = e.color + "88";
        igCtx.lineWidth = 1.5 / igZoom;
        igCtx.stroke();
        // Arrow
        const ax = tx - (dx/d)*(e.target.size || 14), ay = ty - (dy/d)*(e.target.size || 14);
        const aLen = 8 / igZoom, aAngle = 0.4;
        igCtx.beginPath();
        igCtx.moveTo(ax, ay);
        igCtx.lineTo(ax - aLen*Math.cos(Math.atan2(dy,dx)-aAngle), ay - aLen*Math.sin(Math.atan2(dy,dx)-aAngle));
        igCtx.lineTo(ax - aLen*Math.cos(Math.atan2(dy,dx)+aAngle), ay - aLen*Math.sin(Math.atan2(dy,dx)+aAngle));
        igCtx.closePath();
        igCtx.fillStyle = e.color + "aa";
        igCtx.fill();
        // Relationship label
        const mx = (sx+tx)/2, my = (sy+ty)/2;
        igCtx.save();
        igCtx.font = `${9/igZoom}px Segoe UI`;
        igCtx.fillStyle = e.color;
        igCtx.textAlign = "center";
        igCtx.fillText(e.rel.replace(/_/g," "), mx, my - 4/igZoom);
        igCtx.restore();
    });

    // Draw nodes
    igNodes.forEach(n => {
        const isSelected = igSelectedNode && igSelectedNode.id === n.id;
        const r = n.size || 14;
        // Glow for selected
        if (isSelected) {
            igCtx.beginPath();
            igCtx.arc(n.x, n.y, r + 8/igZoom, 0, Math.PI*2);
            igCtx.fillStyle = n.color + "33";
            igCtx.fill();
        }
        // Node circle
        igCtx.beginPath();
        igCtx.arc(n.x, n.y, r, 0, Math.PI*2);
        igCtx.fillStyle = n.color + (isSelected ? "ff" : "cc");
        igCtx.fill();
        igCtx.strokeStyle = isSelected ? "#fff" : n.color;
        igCtx.lineWidth = isSelected ? 2.5/igZoom : 1.5/igZoom;
        igCtx.stroke();
        // Icon
        igCtx.font = `${r * 0.9}px serif`;
        igCtx.textAlign = "center";
        igCtx.textBaseline = "middle";
        igCtx.fillStyle = "#fff";
        igCtx.fillText(n.icon, n.x, n.y);
        // Label
        igCtx.font = `bold ${10/igZoom}px Segoe UI`;
        igCtx.textAlign = "center";
        igCtx.textBaseline = "top";
        igCtx.fillStyle = textColor;
        igCtx.fillText(n.label, n.x, n.y + r + 4/igZoom);
    });
    igCtx.restore();
}

/* Build a graph structure from a real xDome incident so the canvas, attack story,
   assets and similar-incident panels all render from loaded data. */
function graphFromIncident(inc) {
    const nodes = [{ id: "i1", type: "incident", label: inc.id, desc: `${inc.title} — ${inc.severity}` }];
    const edges = [];
    nodes.push({ id: "a1", type: "alert", label: `ALT-${inc.alertId}`, desc: inc.category });
    edges.push({ s: "i1", t: "a1", rel: "triggered" });

    inc.devices.slice(0, 12).forEach((device, index) => {
        const id = `h${index}`;
        nodes.push({ id, type: "host", label: device.name,
            desc: [device.ip, device.site, device.type, device.riskScore != null ? `Risk ${device.riskScore}` : ""].filter(Boolean).join(" · ") });
        edges.push({ s: "a1", t: id, rel: "detected_on" });
    });

    const ips = [...new Set(inc.events.flatMap(e => [e.side_a_ip, e.side_b_ip]).map(v => String(v || "").trim()).filter(Boolean))].slice(0, 8);
    ips.forEach((ip, index) => {
        const id = `ip${index}`;
        nodes.push({ id, type: "ip", label: ip, desc: "Observed in linked xDome events" });
        edges.push({ s: "i1", t: id, rel: "communicates" });
    });

    inc.mitre.slice(0, 8).forEach((technique, index) => {
        const id = `m${index}`;
        nodes.push({ id, type: "cve", label: technique.id, desc: `${technique.name || "MITRE technique"} (${technique.domain})` });
        edges.push({ s: "a1", t: id, rel: "maps_to" });
    });

    return {
        title: inc.title, sev: inc.severity, cat: inc.category,
        mitre: inc.mitre.length ? `${inc.mitre[0].id} – ${inc.mitre[0].name || "technique"}` : "No MITRE technique reported",
        nodes, edges, incident: inc
    };
}

function igPopulateIncidents() {
    const select = document.getElementById("igIncidentSelect");
    if (!select) return;
    const status = XDIncidents.readiness();
    if (!status.ready) return;
    const incidents = XDIncidents.build().slice(0, 100);
    if (!incidents.length) return;
    igLiveIncidents = new Map(incidents.map(inc => [inc.id, inc]));
    select.innerHTML = incidents.map(inc => `<option value="${esc(inc.id)}">${esc(inc.id)} · ${esc(inc.title)}</option>`).join("");
    const hint = document.getElementById("igSourceHint");
    if (hint) hint.textContent = status.message;
    igStart(incidents[0].id);
}
let igLiveIncidents = new Map();
let igSimilarVisible = 5;

function igStart(graphKey) {
    igCurrentGraph = igLiveIncidents.has(graphKey)
        ? graphFromIncident(igLiveIncidents.get(graphKey))
        : INCIDENT_GRAPHS[graphKey];
    if (!igCurrentGraph) return;
    if (igAnimFrame) { cancelAnimationFrame(igAnimFrame); igAnimFrame = null; }
    igZoom = 1; igOffX = 0; igOffY = 0; igSelectedNode = null; igGrouped = false;
    initForceNodes(igCurrentGraph);
    renderAttackStory(igCurrentGraph);
    renderAssets(igCurrentGraph);
    renderSimilarIncidents(igCurrentGraph);
    renderAlertActivities(igCurrentGraph);
    renderInvestigationSummary(igCurrentGraph);
    document.getElementById("igDetailHint").style.display = "";
    const dc = document.getElementById("igDetailContent");
    if (dc) { dc.hidden = true; }
    igDraw();
}

function igGroupByType() {
    if (!igNodes.length) return;
    igGrouped = !igGrouped;
    if (igGrouped) {
        const types = [...new Set(igNodes.map(n => n.type))];
        const cW = igCanvas.width / igZoom / (window.devicePixelRatio||1);
        const cH = igCanvas.height / igZoom / (window.devicePixelRatio||1);
        const R = Math.min(cW, cH) * 0.32;
        types.forEach((type, ti) => {
            const angle = (ti / types.length) * Math.PI * 2;
            const cx = cW/2 + R * Math.cos(angle), cy = cH/2 + R * Math.sin(angle);
            const group = igNodes.filter(n => n.type === type);
            group.forEach((n, ni) => {
                const ga = (ni / group.length) * Math.PI * 2;
                n.x = cx + 35 * Math.cos(ga); n.y = cy + 35 * Math.sin(ga);
                n.vx = 0; n.vy = 0;
            });
        });
    }
    document.getElementById("igGroupBtn").textContent = igGrouped ? "⬡ Ungroup" : "⬡ Group by Type";
}

function showNodeDetail(node) {
    igSelectedNode = node;
    const hint = document.getElementById("igDetailHint");
    const content = document.getElementById("igDetailContent");
    if (!hint || !content) return;
    hint.style.display = "none"; content.hidden = false;
    const cfg = NODE_TYPES[node.type] || {};
    const conns = igEdges.filter(e => e.source?.id === node.id || e.target?.id === node.id);
    content.innerHTML = `
        <div>
            <span class="ig-node-type-badge" style="background:${cfg.color}22;color:${cfg.color}">${cfg.icon} ${cfg.label}</span>
            <div class="ig-detail-title">${node.label}</div>
            <div class="ig-detail-id">${node.id}</div>
        </div>
        <table class="ig-detail-table" style="width:100%">
            <tr><td>Type</td><td>${cfg.label}</td></tr>
            <tr><td>Description</td><td>${node.desc}</td></tr>
            ${node.type === "incident" ? `<tr><td>Severity</td><td>${igCurrentGraph.sev}</td></tr><tr><td>Category</td><td>${igCurrentGraph.cat}</td></tr><tr><td>MITRE</td><td>${igCurrentGraph.mitre}</td></tr>` : ""}
            <tr><td>Connections</td><td>${conns.length} edges</td></tr>
        </table>
        <div class="ig-detail-conn">Connected to:</div>
        <div>${conns.map(e => {
            const other = e.source.id === node.id ? e.target : e.source;
            const cfg2 = NODE_TYPES[other?.type] || {};
            return `<span class="ig-conn-chip" style="border-color:${cfg2.color}44">${cfg2.icon||""} ${other?.label||""} <span class="tag">${e.rel}</span></span>`;
        }).join("")}</div>
        <div class="ig-detail-actions">
            <button class="ifc-btn test" onclick="openRecords('${node.label}','Node entity records',{})">🔍 Drill Down</button>
            <button class="ifc-btn" onclick="showSection('intel')">🔗 IOC Search</button>
        </div>`;
}

function igHitTest(canvasX, canvasY) {
    const x = (canvasX - igOffX) / igZoom, y = (canvasY - igOffY) / igZoom;
    for (let i = igNodes.length - 1; i >= 0; i--) {
        const n = igNodes[i];
        const dx = x - n.x, dy = y - n.y;
        if (Math.sqrt(dx*dx+dy*dy) <= (n.size||14) + 4) return n;
    }
    return null;
}

function getCanvasPos(e) {
    const rect = igCanvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const touch = e.touches?.[0] || e;
    return { x: (touch.clientX - rect.left), y: (touch.clientY - rect.top) };
}

/* ---- Build legend ---- */
function buildLegend() {
    const el = document.getElementById("igLegend");
    if (!el) return;
    el.innerHTML = Object.entries(NODE_TYPES).map(([key, cfg]) =>
        `<div class="ig-legend-item" data-type="${key}">
            <div class="ig-legend-dot" style="background:${cfg.color}"></div>${cfg.icon} ${cfg.label}
         </div>`).join("") +
        `<div class="ig-legend-item" style="margin-left:auto;color:var(--muted);font-size:11px">Scroll = zoom · Drag = pan/move</div>`;
    el.querySelectorAll(".ig-legend-item[data-type]").forEach(item => {
        item.addEventListener("click", () => {
            const type = item.dataset.type;
            igNodes.forEach(n => { if (n.type === type) { n.vx += (Math.random()-.5)*10; n.vy += (Math.random()-.5)*10; } });
        });
    });
}

/* ---- Attack story ---- */
function renderAttackStory(g) {
    const el = document.getElementById("igAttackStory");
    if (!el) return;
    if (g.incident) {
        const story = XDIncidents.attackStory(g.incident);
        if (!story.length) {
            el.innerHTML = `<p class="muted">No MITRE-mapped stages were reported for ${esc(g.incident.id)}. xDome returned ${g.incident.events.length} linked event(s) with no technique mapping — an unreconstructed chain is not evidence that no attack path exists.</p>`;
            return;
        }
        el.innerHTML = story.map(s => `
        <div class="ig-story-step">
            <div class="ig-story-icon" style="background:${s.color}22;border-color:${s.color}">${s.icon}</div>
            <div class="ig-story-body">
                <div class="ig-story-time">${esc(s.time)}</div>
                <div class="ig-story-title">${esc(s.tactic)}</div>
                <div class="ig-story-desc">${esc(s.desc)}</div>
                <div class="ig-story-tags">${s.techniques.map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</div>
            </div>
        </div>`).join("");
        return;
    }
    const steps = [
        { time: "T-00:00", icon: "📧", color: "#f59e0b", title: "Initial Vector",
          desc: g.cat.includes("Phishing") ? "Spearphishing email delivered to target mailbox with malicious link" : g.cat.includes("Ransomware") || g.cat.includes("Malware") ? "Malware delivered via drive-by download or weaponised document" : "Suspicious inbound connection from known threat actor IP",
          tags: ["Initial Access", g.mitre.split("–")[0].trim()] },
        { time: "T+00:05", icon: "⚡", color: "#ef4444", title: "Execution & Persistence",
          desc: "Payload executed, persistence mechanism established via registry run keys or scheduled task",
          tags: ["Execution", "Persistence"] },
        { time: "T+00:22", icon: "🔑", color: "#e879f9", title: "Credential Access",
          desc: "LSASS memory dumped or credential harvested from browser/vault for privilege escalation",
          tags: ["Credential Access", "T1003"] },
        { time: "T+01:10", icon: "🔀", color: "#464feb", title: "Lateral Movement",
          desc: "Attacker pivoted to adjacent hosts using harvested credentials and Pass-the-Hash technique",
          tags: ["Lateral Movement", "T1550.002"] },
        { time: "T+02:45", icon: "📡", color: "#06b6d4", title: "Command & Control",
          desc: `Periodic beacon established to ${g.nodes?.find(n=>n.type==="ip")?.label || "external C2 server"} over encrypted HTTPS channel`,
          tags: ["C2", "T1071.001"] },
        { time: "T+03:30", icon: "🛑", color: "#22c55e", title: "Detection & Response",
          desc: "CrowdStrike + Sentinel correlation triggered automated containment; host isolated pending investigation",
          tags: ["Detected", "Contained"] }
    ];
    el.innerHTML = steps.map(s => `
        <div class="ig-story-step">
            <div class="ig-story-icon" style="background:${s.color}22;border-color:${s.color}">${s.icon}</div>
            <div class="ig-story-body">
                <div class="ig-story-time">${s.time}</div>
                <div class="ig-story-title">${s.title}</div>
                <div class="ig-story-desc">${s.desc}</div>
                <div class="ig-story-tags">${s.tags.map(t=>`<span class="tag">${t}</span>`).join("")}</div>
            </div>
        </div>`).join("");
}

/* ---- Assets ---- */
function renderAssets(g) {
    const el = document.getElementById("igAssetsList");
    if (!el) return;
    if (g.incident) {
        const devices = g.incident.devices;
        if (!devices.length) {
            el.innerHTML = `<p class="muted">xDome linked no inventory device to ${esc(g.incident.id)}. The alert references ${g.incident.events.length} event(s) whose endpoints did not resolve to a known asset.</p>`;
            return;
        }
        el.innerHTML = devices.map(d => {
            const band = XDIncidents.riskBand(d.riskScore);
            const meta = [d.ip, d.mac, d.type, d.vendor, d.site, d.riskScore != null ? `Risk ${d.riskScore}` : null]
                .filter(Boolean).join(" · ");
            return `
        <div class="ig-asset-item">
            <div class="ig-asset-icon">🖥</div>
            <div class="ig-asset-info">
                <div class="ig-asset-name">${esc(d.name)}</div>
                <div class="ig-asset-meta">${esc(meta || "No further attributes reported")}</div>
            </div>
            <span class="ig-asset-status ${band === "Critical" || band === "High" ? "compromised" : "isolated"}">${esc(band)}</span>
        </div>`;
        }).join("");
        return;
    }
    const hosts = g.nodes.filter(n => n.type === "host");
    const users = g.nodes.filter(n => n.type === "user");
    const items = [
        ...hosts.map(h => ({ icon: "🖥", name: h.label, meta: h.desc, status: "compromised" })),
        ...users.map(u => ({ icon: "👤", name: u.label, meta: u.desc, status: u.desc.includes("Risk") ? "compromised" : "isolated" }))
    ];
    el.innerHTML = items.map(a => `
        <div class="ig-asset-item">
            <div class="ig-asset-icon">${a.icon}</div>
            <div class="ig-asset-info">
                <div class="ig-asset-name">${a.name}</div>
                <div class="ig-asset-meta">${a.meta}</div>
            </div>
            <span class="ig-asset-status ${a.status}">${a.status}</span>
        </div>`).join("");
}

/* ---- Similar Incidents ---- */
function renderSimilarIncidents(g) {
    const el = document.getElementById("igSimilarList");
    if (!el) return;
    if (g.incident) {
        const matches = XDIncidents.similarTo(g.incident);
        if (!matches.length) {
            el.innerHTML = `<p class="muted">No other loaded incident shares a MITRE technique, device or category with ${esc(g.incident.id)}.</p>`;
            return;
        }
        const shown = matches.slice(0, igSimilarVisible);
        el.innerHTML = shown.map(m => {
            const devices = m.devices.slice(0, 4).map(d => `<span class="tag">${esc(d.name)}${d.ip ? ` · ${esc(d.ip)}` : ""}</span>`).join("");
            const more = m.devices.length > 4 ? `<span class="tag">+${m.devices.length - 4} more</span>` : "";
            return `
        <div class="ig-similar-item" data-sim-id="${esc(m.id)}">
            <div class="ig-sim-head">
                <span class="ig-sim-id">${esc(m.id)}</span>
                <span class="ig-sim-score">↔ ${m.score}% match</span>
            </div>
            <div class="ig-sim-title">${esc(m.title)}</div>
            <div class="ig-sim-tags">
                <span class="sev-badge sev-${esc(m.severity)}">${esc(m.severity)}</span>
                <span class="tag">${esc(m.category)}</span>
            </div>
            <div class="ig-sim-why">Shared: ${esc(m.reasons.join(", ") || "category only")}</div>
            <div class="ig-sim-devices">${devices || `<span class="tag muted">No device linked</span>`}${more}</div>
        </div>`;
        }).join("") + (matches.length > shown.length
            ? `<button class="btn-secondary" id="igSimilarMore">Load more (${matches.length - shown.length} remaining)</button>` : "");
        el.querySelectorAll("[data-sim-id]").forEach(node => {
            node.addEventListener("click", () => {
                const select = document.getElementById("igIncidentSelect");
                if (select) select.value = node.dataset.simId;
                igSimilarVisible = 5;
                igStart(node.dataset.simId);
            });
        });
        document.getElementById("igSimilarMore")?.addEventListener("click", () => {
            igSimilarVisible += 5;
            renderSimilarIncidents(g);
        });
        return;
    }
    const similar = Object.entries(INCIDENT_GRAPHS)
        .filter(([k]) => k !== document.getElementById("igIncidentSelect")?.value)
        .map(([k, v]) => ({ id: k, ...v, score: Math.round(50 + Math.random() * 45) }))
        .sort((a,b) => b.score - a.score).slice(0, 4);

    // Also add from REPORT if available
    const reportSimilar = REPORT
        ? REPORT.records.filter(r => r.category === g.cat).slice(0, 3).map(r => ({
            id: r.id, title: r.title, sev: r.severity, cat: r.category, score: rand(55,90)
          }))
        : [];

    const all = [...similar.map(s => ({ id: s.id, title: s.title, sev: s.sev, cat: s.cat, score: s.score })), ...reportSimilar].slice(0, 5);
    el.innerHTML = all.map(s => `
        <div class="ig-similar-item" onclick="openRecords('${s.id}','Similar incident records',{category:'${s.cat || ""}'})" >
            <div class="ig-sim-head">
                <span class="ig-sim-id">${s.id}</span>
                <span class="ig-sim-score">↔ ${s.score}% match</span>
            </div>
            <div class="ig-sim-title">${s.title}</div>
            <div class="ig-sim-tags">
                <span class="sev-badge sev-${s.sev}">${s.sev}</span>
                <span class="tag">${s.cat || "Similar"}</span>
            </div>
        </div>`).join("");
}

/* ---- Alert Activities ---- */
function renderAlertActivities(g) {
    const el = document.getElementById("igActivities");
    if (!el) return;
    const alerts = g.nodes.filter(n => n.type === "alert");
    const activities = [
        ...alerts.map((a, i) => ({ time: `T+${String(i*8).padStart(2,"0")}m`, icon: "🔔", title: a.desc, meta: `Alert ID: ${a.label}`, sev: i === 0 ? "Critical" : "High" })),
        { time: "T+12m", icon: "⚡", title: "Swimlane playbook triggered — auto-triage started", meta: "Playbook: Malware Detection & Containment", sev: "Medium" },
        { time: "T+14m", icon: "🛡", title: "CrowdStrike isolation request sent to endpoint", meta: `Host: ${g.nodes.find(n=>n.type==="host")?.label || "N/A"}`, sev: "Medium" },
        { time: "T+18m", icon: "🔍", title: "IOC enrichment: VirusTotal + GreyNoise lookup completed", meta: "C2 IP confirmed malicious (95% confidence)", sev: "High" },
        { time: "T+25m", icon: "✅", title: "Host isolated, incident escalated to Tier-2 analyst", meta: "Assignee: OT Analyst · SLA: On Track", sev: "Low" }
    ];
    el.innerHTML = activities.map(a => `
        <div class="ig-activity">
            <span class="ig-act-time">${a.time}</span>
            <span class="ig-act-icon">${a.icon}</span>
            <div class="ig-act-body">
                <div class="ig-act-title">${a.title}</div>
                <div class="ig-act-meta">${a.meta}</div>
            </div>
            <span class="ig-act-sev sev-${a.sev}">${a.sev}</span>
        </div>`).join("");
}

/* ---- Investigation Summary ---- */
function renderInvestigationSummary(g) {
    const el = document.getElementById("igSummaryBody");
    if (!el) return;
    const hosts = g.nodes.filter(n => n.type === "host");
    const users = g.nodes.filter(n => n.type === "user");
    const ips   = g.nodes.filter(n => n.type === "ip");
    el.innerHTML = `
        <div class="ig-sum-section">
            <div class="ig-sum-title">Incident Overview</div>
            <div class="ig-sum-row"><span>Incident ID</span><span>${document.getElementById("igIncidentSelect")?.value || "—"}</span></div>
            <div class="ig-sum-row"><span>Title</span><span>${g.title}</span></div>
            <div class="ig-sum-row"><span>Severity</span><span class="sev-badge sev-${g.sev}">${g.sev}</span></div>
            <div class="ig-sum-row"><span>Category</span><span>${g.cat}</span></div>
            <div class="ig-sum-row"><span>MITRE ATT&CK</span><span>${g.mitre}</span></div>
            <div class="ig-sum-row"><span>Graph nodes</span><span>${g.nodes.length}</span></div>
            <div class="ig-sum-row"><span>Graph edges</span><span>${g.edges.length}</span></div>
        </div>
        <div class="ig-sum-section">
            <div class="ig-sum-title">Affected Entities</div>
            <div class="ig-sum-row"><span>Hosts</span><span>${hosts.map(h=>h.label).join(", ") || "—"}</span></div>
            <div class="ig-sum-row"><span>Users</span><span>${users.map(u=>u.label).join(", ") || "—"}</span></div>
            <div class="ig-sum-row"><span>External IPs</span><span>${ips.filter(i=>!i.label.startsWith("10.")).map(i=>i.label).join(", ") || "—"}</span></div>
            <div class="ig-sum-row"><span>Internal IPs</span><span>${ips.filter(i=>i.label.startsWith("10.")).map(i=>i.label).join(", ") || "—"}</span></div>
        </div>
        <div class="ig-sum-section">
            <div class="ig-sum-title">Response Actions</div>
            <div class="ig-sum-row"><span>Host isolated</span><span class="up">✓ ${hosts[0]?.label || "N/A"}</span></div>
            <div class="ig-sum-row"><span>IPs blocked</span><span class="up">✓ Palo Alto + Sentinel</span></div>
            <div class="ig-sum-row"><span>Credentials reset</span><span class="amber">Pending</span></div>
            <div class="ig-sum-row"><span>Forensics collected</span><span class="up">✓ CrowdStrike RTR</span></div>
        </div>
        <div class="ig-sum-section">
            <div class="ig-sum-title">Analyst Findings</div>
            <div class="ig-sum-text">Auto-generated: ${g.title}. Detected via ${g.nodes.find(n=>n.type==="alert")?.desc || "automated alerting"}. MITRE technique: ${g.mitre}. Recommend full forensic investigation of affected hosts and credential rotation for all impacted accounts.</div>
        </div>`;
    document.getElementById("igSummaryExport")?.addEventListener("click", () => {
        addNotification({ title: "📄 Investigation exported", msg: `${document.getElementById("igIncidentSelect")?.value} summary saved`, color: COLORS.green, cat: "ok" });
    }, { once: true });
}

/* ---- Wire canvas events ---- */
function wireCanvasEvents() {
    igCanvas.addEventListener("mousedown", e => {
        const pos = getCanvasPos(e);
        const hit = igHitTest(pos.x, pos.y);
        if (hit) {
            igDragging = hit;
            hit.fixed = true;
            igDragStartX = pos.x - igOffX - hit.x * igZoom;
            igDragStartY = pos.y - igOffY - hit.y * igZoom;
            showNodeDetail(hit);
        } else {
            igPanning = true;
            igPanStartX = pos.x - igOffX;
            igPanStartY = pos.y - igOffY;
        }
    });
    igCanvas.addEventListener("mousemove", e => {
        const pos = getCanvasPos(e);
        if (igDragging) {
            igDragging.x = (pos.x - igOffX - igDragStartX) / igZoom;
            igDragging.y = (pos.y - igOffY - igDragStartY) / igZoom;
            igDragging.vx = 0; igDragging.vy = 0;
        } else if (igPanning) {
            igOffX = pos.x - igPanStartX;
            igOffY = pos.y - igPanStartY;
        } else {
            const hit = igHitTest(pos.x, pos.y);
            const tt = document.getElementById("igTooltip");
            if (hit && tt) {
                tt.hidden = false;
                tt.style.left = (pos.x + 14) + "px"; tt.style.top = (pos.y - 8) + "px";
                tt.innerHTML = `<div class="ig-tt-title">${hit.icon} ${hit.label}</div><div class="ig-tt-meta">${hit.desc}</div>`;
                igCanvas.style.cursor = "pointer";
            } else if (tt) { tt.hidden = true; igCanvas.style.cursor = "grab"; }
        }
    });
    window.addEventListener("mouseup", e => {
        if (igDragging) { igDragging.fixed = false; igDragging = null; }
        igPanning = false;
    });
    igCanvas.addEventListener("wheel", e => {
        e.preventDefault();
        const pos = getCanvasPos(e);
        const delta = e.deltaY > 0 ? 0.85 : 1.15;
        const newZoom = Math.min(3, Math.max(0.3, igZoom * delta));
        igOffX = pos.x - (pos.x - igOffX) * (newZoom / igZoom);
        igOffY = pos.y - (pos.y - igOffY) * (newZoom / igZoom);
        igZoom = newZoom;
    }, { passive: false });
    document.getElementById("igZoomIn")?.addEventListener("click", () => { igZoom = Math.min(3, igZoom * 1.25); });
    document.getElementById("igZoomOut")?.addEventListener("click", () => { igZoom = Math.max(0.3, igZoom * 0.8); });
    document.getElementById("igFit")?.addEventListener("click", () => { igZoom = 1; igOffX = 0; igOffY = 0; });
    document.getElementById("igGroupBtn")?.addEventListener("click", igGroupByType);
    document.getElementById("igResetBtn")?.addEventListener("click", () => {
        const sel = document.getElementById("igIncidentSelect")?.value;
        if (sel) igStart(sel);
    });
    document.getElementById("igIncidentSelect")?.addEventListener("change", e => igStart(e.target.value));
}

/* ---- Resize handler ---- */
function igResize() {
    if (!igCanvas || !igWrap) return;
    const dpr = window.devicePixelRatio || 1;
    igCanvas.width  = igWrap.clientWidth  * dpr;
    igCanvas.height = igWrap.clientHeight * dpr;
    igCanvas.style.width  = igWrap.clientWidth  + "px";
    igCanvas.style.height = igWrap.clientHeight + "px";
}

/* ---- Init (called on first nav to incgraph) ---- */
let igInited = false;
window.initIncidentGraph = function() {
    if (igInited) return;
    igInited = true;
    igCanvas = document.getElementById("igCanvas");
    igWrap   = document.getElementById("igCanvasWrap");
    if (!igCanvas || !igWrap) return;
    igCtx = igCanvas.getContext("2d");
    buildLegend();
    igResize();
    window.addEventListener("resize", igResize);
    wireCanvasEvents();
    igStart("INC-4901");
    igPopulateIncidents();
    document.addEventListener("xdome:feed-ready", () => igPopulateIncidents());
};
})();

/* ================================================================== */
/* OT PLATFORM OPTIMIZATION PAGE                                       */
/* ================================================================== */
window.initSocOpt = (function() {
let inited = false;
return function() {
    if (inited) return; inited = true;

    /* ---- Maturity domains ---- */
    const domains = [
        { name: "Detection Coverage",  score: 3.8, target: 4.5, priority: "High" },
        { name: "Automation & SOAR",   score: 4.1, target: 4.5, priority: "Medium" },
        { name: "Threat Intelligence", score: 3.2, target: 4.0, priority: "High" },
        { name: "Incident Response",   score: 3.9, target: 4.5, priority: "Medium" },
        { name: "Vulnerability Mgmt",  score: 2.9, target: 4.0, priority: "Critical" },
        { name: "Identity Security",   score: 3.5, target: 4.5, priority: "High" },
        { name: "Log Management",      score: 4.2, target: 4.5, priority: "Low" },
        { name: "Team Capability",     score: 3.0, target: 4.0, priority: "High" }
    ];
    const overallScore = Math.round(domains.reduce((a,d) => a + d.score, 0) / domains.length * 20);

    /* Animate ring */
    const ring = document.querySelector(".soco-ring-fill");
    const scoreText = document.querySelector(".soco-score-ring text:first-of-type");
    if (ring && scoreText) {
        const circumference = 264;
        ring.style.strokeDashoffset = circumference - (circumference * overallScore / 100);
        scoreText.textContent = overallScore;
    }

    /* KPI strip */
    const recommendations = [
        { title: "Enable continuous vulnerability scanning",      domain: "Vulnerability Mgmt",  priority: "Critical", effort: "Low",    impact: 5, saving: "$180k/yr",  status: "open",        steps: ["Deploy Tenable.io agent on all endpoints","Schedule weekly scans","Integrate findings into Swimlane for auto-ticket creation","Set remediation SLAs by CVSS score"] },
        { title: "Automate phishing triage with ML classifier",  domain: "Detection Coverage",  priority: "High",     effort: "Medium", impact: 4, saving: "$95k/yr",   status: "in-progress", steps: ["Train classifier on 12 months of labelled phishing emails","Deploy to M365 mail flow","Integrate with Swimlane playbook trigger","Monitor FP rate weekly"] },
        { title: "Deploy UEBA for insider threat detection",     domain: "Identity Security",   priority: "High",     effort: "High",   impact: 4, saving: "$120k/yr",  status: "open",        steps: ["Configure Sentinel UEBA baseline (30 days)","Define anomaly thresholds by role","Create insider-threat playbook in Swimlane","Conduct tabletop exercise"] },
        { title: "Implement threat hunting programme",           domain: "Threat Intelligence", priority: "High",     effort: "Medium", impact: 4, saving: "$75k/yr",   status: "open",        steps: ["Define hunting hypotheses from MITRE ATT&CK gaps","Allocate 20% analyst time for proactive hunting","Build custom KQL/SPL hunting queries","Track hunter finds vs MTTD improvement"] },
        { title: "Consolidate EDR tools (3 → 1 platform)",      domain: "Detection Coverage",  priority: "High",     effort: "High",   impact: 5, saving: "$240k/yr",  status: "open",        steps: ["Evaluate CrowdStrike Falcon One vs Trellix XDR","Run 90-day POC on 100 endpoints","Define migration runbook","Decommission redundant agents"] },
        { title: "Automate CVE-to-ticket via Swimlane+Tenable", domain: "Vulnerability Mgmt",  priority: "Critical", effort: "Low",    impact: 5, saving: "$60k/yr",   status: "open",        steps: ["Configure Tenable.io → Swimlane connector","Map CVE severity to ticket priority","Auto-assign by asset owner from CMDB","Add SLA escalation playbook"] },
        { title: "Add SOAR runbook for ransomware containment", domain: "Automation & SOAR",   priority: "Medium",   effort: "Low",    impact: 4, saving: "$55k/yr",   status: "in-progress", steps: ["Define isolation triggers (file entropy + process pattern)","Build Swimlane runbook with CrowdStrike RTR","Add analyst approval gate for production hosts","Test in sandbox quarterly"] },
        { title: "Integrate CMDB for asset context in alerts",  domain: "Log Management",      priority: "Medium",   effort: "Medium", impact: 3, saving: "$40k/yr",   status: "open",        steps: ["Sync ServiceNow CMDB to Sentinel","Add asset tags to alert enrichment","Build 'business context' widget in Swimlane records","Reduce analyst lookup time"] },
        { title: "Build 24x7 on-call rotation playbook",        domain: "Team Capability",     priority: "High",     effort: "Medium", impact: 3, saving: "$50k/yr",   status: "open",        steps: ["Define P1/P2 escalation matrix","Configure PagerDuty / Teams alert routing","Quarterly tabletop for on-call analysts","Track MTTD after-hours vs business-hours"] },
        { title: "Automate IOC blocking to firewall via SOAR",  domain: "Automation & SOAR",   priority: "Medium",   effort: "Low",    impact: 4, saving: "$45k/yr",   status: "done",        steps: ["Swimlane → Palo Alto Panorama connector configured","Auto-block confirmed malicious IPs","Review block list monthly","Alert on expired blocks"] }
    ];

    const quickWins = recommendations.filter(r => r.effort === "Low" && (r.priority === "Critical" || r.priority === "High"));
    document.getElementById("socoQuickWins").textContent = quickWins.length;
    document.getElementById("socoGaps").textContent = domains.filter(d => d.target - d.score > 0.8).length;
    const totalSavings = recommendations.reduce((a, r) => a + parseInt((r.saving || "$0").replace(/[^0-9]/g,"")), 0);
    document.getElementById("socoSavings").textContent = "$" + (totalSavings / 1000).toFixed(0) + "k/yr";
    document.getElementById("socoBenchmark").textContent = `+${overallScore - 68}% vs avg`;

    /* Maturity table */
    document.querySelector("#socoMaturityTable tbody").innerHTML = domains.map(d => {
        const gap = (d.target - d.score).toFixed(1);
        const pct = Math.round(d.score / 5 * 100);
        const clr = d.score >= 4 ? COLORS.green : d.score >= 3 ? COLORS.amber : COLORS.red;
        return `<tr>
            <td><strong>${d.name}</strong></td>
            <td><div class="soco-score-bar"><div class="soco-bar-track"><div class="soco-bar-fill" style="width:${pct}%;background:${clr}"></div></div>${d.score}/5</div></td>
            <td>${d.target}/5</td>
            <td class="${gap > 0.5 ? "down" : "up"}">${gap > 0 ? "+"+gap+" needed" : "✓ Met"}</td>
            <td><span class="soco-priority ${d.priority}">${d.priority}</span></td>
        </tr>`;
    }).join("");

    /* Maturity radar */
    const mrEl = document.getElementById("socoMaturityChart");
    if (mrEl) {
        new Chart(mrEl, {
            type: "radar",
            data: {
                labels: domains.map(d => d.name),
                datasets: [
                    { label: "Current", data: domains.map(d => d.score), borderColor: COLORS.accent, backgroundColor: COLORS.accent+"33", borderWidth: 2, pointBackgroundColor: COLORS.accent, pointRadius: 3 },
                    { label: "Target",  data: domains.map(d => d.target), borderColor: COLORS.green, backgroundColor: "transparent", borderWidth: 2, borderDash: [4,3], pointBackgroundColor: COLORS.green, pointRadius: 2 },
                    { label: "Industry Avg", data: domains.map(() => 3.4), borderColor: COLORS.muted, backgroundColor: "transparent", borderWidth: 1.5, borderDash: [2,3], pointBackgroundColor: COLORS.muted, pointRadius: 1 }
                ]
            },
            options: { responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } },
                scales: { r: { min: 0, max: 5, grid: { color: COLORS.grid }, angleLines: { color: COLORS.grid }, pointLabels: { color: COLORS.muted, font: { size: 10 } }, ticks: { display: false } } } }
        });
    }

    /* Benchmark chart */
    const benchEl = document.getElementById("socoBenchChart");
    if (benchEl) {
        new Chart(benchEl, { type: "bar",
            data: { labels: domains.map(d => d.name.slice(0,14)),
                    datasets: [
                        { label: "Your OT Platform", data: domains.map(d => d.score), backgroundColor: COLORS.accent, borderRadius: 5 },
                        { label: "Industry Avg",  data: domains.map(() => 3.4 + (Math.random()*.2)), backgroundColor: COLORS.muted+"88", borderRadius: 5 },
                        { label: "Top Quartile",  data: domains.map(() => 4.2 + (Math.random()*.3)), backgroundColor: COLORS.green+"88", borderRadius: 5 }
                    ] },
            options: { ...baseOpts, scales: { x: { grid: { display: false } }, y: { max: 5, grid: { color: COLORS.grid } } },
                plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } } }
        });
    }

    /* Gap heatmap (radar-style polar) */
    const gapEl = document.getElementById("socoGapChart");
    if (gapEl) {
        new Chart(gapEl, { type: "polarArea",
            data: { labels: domains.map(d => d.name.slice(0,12)),
                    datasets: [{ data: domains.map(d => +(d.target - d.score).toFixed(1)),
                                 backgroundColor: domains.map(d => d.target - d.score > 0.8 ? COLORS.red+"aa" : d.target - d.score > 0.3 ? COLORS.amber+"aa" : COLORS.green+"aa"),
                                 borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 10.5 } } } },
                scales: { r: { grid: { color: COLORS.grid }, ticks: { display: false } } } }
        });
    }

    /* Roadmap chart */
    const roadEl = document.getElementById("socoRoadmapChart");
    if (roadEl) {
        const months = ["Sep","Oct","Nov","Dec","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug"];
        let cumSavings = 0;
        new Chart(roadEl, { type: "line",
            data: { labels: months,
                    datasets: [
                        { label: "Cumulative savings ($k)", data: months.map((_, i) => { cumSavings += rand(25, 90); return Math.round(cumSavings); }), borderColor: COLORS.green, backgroundColor: gradient(roadEl.getContext("2d"), COLORS.green), fill: true, tension: .4, pointRadius: 3, borderWidth: 2 },
                        { label: "Maturity score",          data: months.map((_, i) => +(3.5 + i * 0.06).toFixed(2)), borderColor: COLORS.accent, backgroundColor: "transparent", tension: .4, pointRadius: 2, borderWidth: 2, yAxisID: "y2" }
                    ] },
            options: { responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } },
                scales: { x: { grid: { display: false } }, y: { grid: { color: COLORS.grid }, beginAtZero: true }, y2: { position: "right", min: 3, max: 5, grid: { display: false }, ticks: { color: COLORS.accent } } } }
        });
    }

    /* Recommendations table */
    let recFilter = "all";
    function renderRecs() {
        const filtered = recFilter === "all" ? recommendations : recFilter === "Quick Win" ? recommendations.filter(r => r.effort === "Low" && r.priority !== "Low") : recommendations.filter(r => r.priority === recFilter);
        document.querySelector("#socoRecsTable tbody").innerHTML = filtered.map((r, i) => {
            const impDots = Array.from({length:5}, (_,di) => `<div class="soco-impact-dot" style="background:${di < r.impact ? COLORS.accent : COLORS.grid}"></div>`).join("");
            return `<tr data-ri="${recommendations.indexOf(r)}">
                <td>${recommendations.indexOf(r)+1}</td>
                <td><strong>${r.title}</strong></td>
                <td>${r.domain}</td>
                <td><span class="soco-priority ${r.priority}">${r.priority}</span></td>
                <td><span class="soco-effort-tag ${r.effort}">${r.effort}</span></td>
                <td><div class="soco-impact-bar">${impDots}</div></td>
                <td class="soco-saving-tag">${r.saving}</td>
                <td><span class="soco-status-badge ${r.status.replace(" ","-")}">${r.status}</span></td>
            </tr>
            <tr><td colspan="8" style="padding:0;border-top:none">
                <div class="soco-rec-detail" id="soco-detail-${recommendations.indexOf(r)}">
                    <strong>Implementation steps:</strong>
                    <ul class="soco-rec-steps">${r.steps.map(s=>`<li>${s}</li>`).join("")}</ul>
                </div>
            </td></tr>`;
        }).join("");
        document.querySelectorAll("#socoRecsTable tbody tr[data-ri]").forEach(tr => {
            tr.addEventListener("click", () => {
                const detail = document.getElementById(`soco-detail-${tr.dataset.ri}`);
                tr.classList.toggle("expanded-rec");
                if (detail) detail.classList.toggle("open");
            });
        });
    }
    renderRecs();
    document.querySelectorAll(".soco-filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".soco-filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active"); recFilter = btn.dataset.rf; renderRecs();
        });
    });

    /* Quick wins */
    document.getElementById("socoQuickWinList").innerHTML = quickWins.map(r => `
        <div class="soco-qw-item">
            <div class="soco-qw-icon">⚡</div>
            <div class="soco-qw-body">
                <div class="soco-qw-title">${r.title}</div>
                <div class="soco-qw-desc">${r.steps[0]}</div>
                <div class="soco-qw-meta">
                    <span class="up">${r.saving}</span>
                    <span class="soco-priority ${r.priority}">${r.priority}</span>
                    <span style="color:var(--muted)">Effort: ${r.effort}</span>
                </div>
            </div>
        </div>`).join("");

    /* Tool consolidation — derived from integrations actually configured locally */
    const toolListEl = document.getElementById("socoToolList");
    if (toolListEl) {
        toolListEl.innerHTML = `<div class="soco-tool-item"><div class="soco-tool-desc">Loading configured integrations…</div></div>`;
        fetch("/api/optimization/tool-overlap", { cache: "no-store" })
            .then(response => response.json().then(payload => {
                if (!response.ok) throw new Error(payload.error || "Tool overlap API unavailable");
                return payload;
            }))
            .then(payload => {
                const overlaps = payload.overlaps || [];
                toolListEl.innerHTML = overlaps.length
                    ? overlaps.map(item => `
            <div class="soco-tool-item">
                <div class="soco-tool-head"><span class="soco-tool-name">${esc(item.category)}</span><span class="soco-tool-save">${item.configuredCount} configured</span></div>
                <div class="soco-tool-desc">${item.configuredCount} integrations are configured for the same capability. Review whether all are required before renewal; this app holds no licence or cost data.</div>
                <div class="soco-tool-tags">${item.configured.map(tag => `<span class="tag">${esc(tag)}</span>`).join("")}</div>
            </div>`).join("")
                    : `<div class="soco-tool-item"><div class="soco-tool-head"><span class="soco-tool-name">No overlap detected</span><span class="soco-tool-save">${payload.configuredTotal || 0} configured</span></div><div class="soco-tool-desc">No capability category has more than one configured integration. Add credentials under Settings → Integrations to surface real consolidation candidates.</div></div>`;
                renderToolOverlapChart(payload);
            })
            .catch(error => {
                toolListEl.innerHTML = `<div class="soco-tool-item"><div class="soco-tool-desc">Tool overlap unavailable: ${esc(error.message)}</div></div>`;
            });
    }

    function renderToolOverlapChart(payload) {
        const chartEl = document.getElementById("socoToolChart");
        if (!chartEl || typeof Chart === "undefined") return;
        const rows = (payload.categories || []).filter(item => item.configuredCount > 0);
        if (!rows.length) return;
        if (chartEl._overlapChart) chartEl._overlapChart.destroy();
        chartEl._overlapChart = new Chart(chartEl, {
            type: "bar",
            data: {
                labels: rows.map(item => item.category),
                datasets: [{
                    label: "Configured integrations",
                    data: rows.map(item => item.configuredCount),
                    backgroundColor: rows.map(item => item.overlap ? COLORS.red : COLORS.accent),
                    borderRadius: 4
                }]
            },
            options: {
                ...baseOpts,
                indexAxis: "y",
                scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: COLORS.grid } }, y: { grid: { display: false } } },
                plugins: { legend: { display: false } }
            }
        });
    }

    /* Skill gap chart */
    const skillEl = document.getElementById("socoSkillChart");
    if (skillEl) {
        new Chart(skillEl, { type: "bar",
            data: { labels: ["Threat Hunting","Cloud Security","ICS/OT","Malware RE","Threat Intel","Forensics","SOAR Dev"],
                    datasets: [
                        { label: "Current (avg/5)", data: [2.8, 3.0, 1.8, 2.5, 3.2, 3.0, 3.5], backgroundColor: COLORS.accent, borderRadius: 4 },
                        { label: "Required",         data: [4.0, 4.0, 3.0, 3.5, 4.0, 4.0, 4.0], backgroundColor: COLORS.muted+"55", borderRadius: 4 }
                    ] },
            options: { ...baseOpts, indexAxis: "y", scales: { x: { max: 5, grid: { color: COLORS.grid } }, y: { grid: { display: false } } },
                plugins: { legend: { position: "bottom", labels: { boxWidth: 11, font: { size: 11 } } } } }
        });
    }
};
})();
