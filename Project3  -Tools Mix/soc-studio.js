(function() {
    "use strict";

    const root = document.getElementById("socStudioView");
    const tabButtons = [...document.querySelectorAll("[data-soc-view]")];
    const status = document.getElementById("socStudioStatus");
    if (!root || !tabButtons.length) return;

    const reportSeries = [
        "Daily SOC Summary", "Weekly SOC Operations", "Monthly SOC Performance", "Incident After-Action Review",
        "Critical Incident Briefing", "Ransomware Incident", "Phishing Investigation", "Identity Threat Review",
        "Cloud Security Incident", "OT/ICS Incident", "Vulnerability Remediation", "Threat Hunting Activity",
        "Detection Coverage Gap", "SIEM Data Quality", "Alert Triage Efficiency", "SLA Compliance",
        "Threat Intelligence Briefing", "MITRE ATT&CK Coverage", "Security Automation Impact"
    ];
    const reportTemplates = reportSeries.flatMap((name, index) => [
        { id: `R${String(index * 2 + 1).padStart(2, "0")}`, name: `${name} - Executive`, audience: "Executive" },
        { id: `R${String(index * 2 + 2).padStart(2, "0")}`, name: `${name} - Analyst`, audience: "Analyst" }
    ]);

    const handbook = [
        ["Purpose and scope", "State the SOC mission, supported business units, systems, and operating boundaries. Replace each bracketed prompt with approved organization details."],
        ["Mission and objectives", "Define measurable outcomes for detection, response, resilience, and stakeholder communication. Name the accountable executive."],
        ["Service catalog", "List monitoring, triage, incident coordination, threat hunting, detection engineering, and reporting services with service owners."],
        ["Governance and RACI", "Name decision makers and map Responsible, Accountable, Consulted, and Informed roles for high-impact actions."],
        ["Policies and standards", "Link approved security policies, data handling rules, evidence retention, and regulatory requirements."],
        ["Operating model", "Document business hours, on-call arrangements, escalation paths, and boundaries between internal teams and providers."],
        ["Roles and responsibilities", "Describe analyst, incident commander, detection engineer, threat intelligence, IT, legal, and communications responsibilities."],
        ["Shift handoff", "Record open cases, owners, severity, next action, due time, dependencies, and acknowledgement by the incoming shift."],
        ["Case management", "Define required case fields, evidence references, status transitions, ownership, and closure quality checks."],
        ["Severity and prioritization", "Set severity criteria using business impact, confidence, exposure, safety, and service criticality."],
        ["Incident response", "Document preparation, detection, analysis, containment, eradication, recovery, and lessons learned with approval gates."],
        ["Detection lifecycle", "Specify use-case intake, data prerequisites, engineering review, testing, deployment approval, tuning, and retirement."],
        ["Threat intelligence", "Define source trust, relevance scoring, expiry, handling markings, enrichment, and analyst validation requirements."],
        ["Vulnerability management", "Set ownership, risk-based prioritization, remediation targets, exception approvals, and verification evidence."],
        ["SIEM data sources", "Inventory source owner, event types, collection method, parsing, retention, health checks, and privacy constraints."],
        ["Metrics and SLAs", "Define metric formulas, clock start/stop rules, exclusions, reporting cadence, and accountable owners."],
        ["Technology architecture", "Describe approved platforms, identity boundaries, network paths, resilient dependencies, and data residency constraints."],
        ["Third-party coordination", "Record provider contacts, notification thresholds, evidence-sharing rules, and contractual response obligations."],
        ["OT and ICS safeguards", "Require asset-owner coordination, safety review, passive-first validation, change control, and approved maintenance windows."],
        ["Training and competency", "Define role-based onboarding, practice exercises, skill evidence, refresh cadence, and escalation coaching."],
        ["Continuous improvement", "Track after-action findings, control owners, due dates, validation evidence, and accepted residual risk.]"]
    ].map(([title, starter], index) => ({ id: `H${String(index + 1).padStart(2, "0")}`, title, starter }));

    const dashboards = [
        ["Executive risk and service health", "Business risk, critical open cases, SLA attainment, top control gaps, and trend context."],
        ["SOC queue and analyst workload", "Backlog by severity and age, assignment balance, reassignment rate, and unowned cases."],
        ["Detection quality", "True-positive yield, suppression volume, alert duplicates, rule health, and tuning backlog."],
        ["Incident lifecycle", "Time to acknowledge, investigate, contain, recover, and close with severity slices."],
        ["Identity threat monitoring", "Risky sign-ins, privileged changes, authentication failures, and identity response status."],
        ["Endpoint response", "EDR alert health, isolation requests, device coverage, and containment approvals."],
        ["Cloud security posture", "Cloud control findings, exposed services, identity risks, and owner remediation status."],
        ["Network and perimeter", "Firewall events, unusual egress, denied traffic trends, and monitored network segments."],
        ["Email and collaboration", "Phishing reports, malicious messages, user reports, and remediation status."],
        ["Vulnerability exposure", "Known-exploited findings, asset criticality, remediation age, and verified closure."],
        ["Threat intelligence operations", "Source freshness, indicator disposition, enrichment coverage, and expiring intelligence."],
        ["MITRE ATT&CK coverage", "Mapped detections by tactic and technique, validation date, confidence, and uncovered priorities."],
        ["OT/ICS monitoring", "Passive asset visibility, safety-relevant alerts, site context, and owner-approved actions."],
        ["Data pipeline health", "Source freshness, parsing failures, ingestion delay, volume changes, and retention status."]
    ].map(([title, purpose], index) => ({ id: `D${String(index + 1).padStart(2, "0")}`, title, purpose }));

    const detections = [
        { id: "ELK-001", name: "Repeated authentication failures", mitre: "T1110", tactic: "Credential Access", query: "event.category:authentication and event.outcome:failure", rationale: "Baseline by identity and source; alert on a tuned rate threshold, not a single failure." },
        { id: "ELK-002", name: "Successful sign-in after failure burst", mitre: "T1078", tactic: "Initial Access", query: "event.category:authentication and event.outcome:success", rationale: "Correlate a success after repeated failures for the same account and source window." },
        { id: "ELK-003", name: "PowerShell with unusual parent process", mitre: "T1059.001", tactic: "Execution", query: "process.name:powershell.exe and process.parent.name:(winword.exe or excel.exe or outlook.exe)", rationale: "Validate process lineage and signed administration tools before escalation." },
        { id: "ELK-004", name: "New privileged group membership", mitre: "T1098", tactic: "Persistence", query: "event.action:(added-to-group or member-added) and group.name:(Administrators or Domain Admins)", rationale: "Compare with approved change records and known identity lifecycle automation." },
        { id: "ELK-005", name: "Remote service logon outside baseline", mitre: "T1021", tactic: "Lateral Movement", query: "event.category:authentication and winlog.logon.type:3", rationale: "Prioritize rare source-to-destination pairs and unusual accounts." },
        { id: "ELK-006", name: "Suspicious scheduled task creation", mitre: "T1053.005", tactic: "Persistence", query: "event.category:process and process.command_line:*schtasks*", rationale: "Inspect task creator, command line, host role, and approved deployment windows." },
        { id: "ELK-007", name: "Unusual outbound data volume", mitre: "T1041", tactic: "Exfiltration", query: "network.direction:outgoing and network.bytes > 50000000", rationale: "Use per-site and per-service baselines; exclude approved backups and replication." },
        { id: "ELK-008", name: "Ransomware-like file activity", mitre: "T1486", tactic: "Impact", query: "event.category:file and file.extension:(locked or encrypted)", rationale: "Require endpoint context and safe triage; do not automate disruptive containment by default." },
        { id: "ELK-009", name: "New remote administration service", mitre: "T1219", tactic: "Command and Control", query: "process.name:(anydesk.exe or teamviewer.exe or screenconnect.exe)", rationale: "Compare software inventory, signed publisher, asset owner, and approved remote support." },
        { id: "ELK-010", name: "DNS query volume anomaly", mitre: "T1071.004", tactic: "Command and Control", query: "dns.question.name:* and dns.question.type:(TXT or NULL)", rationale: "Use domain age, entropy, resolver context, and host baselines to reduce false positives." }
    ];

    const playbooks = [
        { id: "PB-01", name: "Phishing report triage", trigger: "User-reported suspicious message", steps: ["Preserve message and headers", "Check sender, URLs, and attachment metadata", "Search for recipients and related detections", "Request analyst approval before purge or account action", "Notify reporter and record evidence"] },
        { id: "PB-02", name: "Endpoint malware investigation", trigger: "EDR high-confidence malware alert", steps: ["Confirm device identity and business owner", "Collect endpoint and process context", "Check related identity and network activity", "Obtain owner approval before isolation", "Record recovery and verification evidence"] },
        { id: "PB-03", name: "Credential compromise", trigger: "Identity risk or suspicious authentication", steps: ["Validate identity and sign-in context", "Review MFA and privileged activity", "Contact identity owner through approved channel", "Require human approval for session revocation or reset", "Verify recovery and watchlist duration"] },
        { id: "PB-04", name: "Cloud exposure response", trigger: "High-risk cloud configuration finding", steps: ["Confirm resource, account, and environment", "Check exposure and data classification", "Assign service owner and change window", "Approve containment or configuration change", "Verify control and document residual risk"] },
        { id: "PB-05", name: "Vulnerability exploitation review", trigger: "Known-exploited vulnerability on an asset", steps: ["Confirm finding and affected asset", "Validate exploitability and network exposure", "Check service and safety criticality", "Agree mitigation with system owner", "Verify remediation or document exception"] },
        { id: "PB-06", name: "OT/ICS alert coordination", trigger: "Safety-relevant OT monitoring alert", steps: ["Preserve passive telemetry and timestamps", "Notify the site and asset owner", "Assess process and safety impact", "Require site authority approval before active action", "Record disposition and monitor through handoff"] }
    ];

    const courses = [
        { id: "L1", title: "SOC foundations", lessons: ["SOC roles and operating model", "Severity, confidence, and business impact", "Evidence handling and case notes"] },
        { id: "L2", title: "SIEM data onboarding", lessons: ["Source ownership and event contracts", "Parsing, normalization, and timestamps", "Freshness, retention, and privacy checks"] },
        { id: "L3", title: "Detection engineering", lessons: ["Hypothesis and ATT&CK mapping", "Query testing and false-positive review", "Change control and post-deployment monitoring"] },
        { id: "L4", title: "Alert triage", lessons: ["Validate signal and scope", "Pivot across identity, endpoint, and network", "Escalation and handoff quality"] },
        { id: "L5", title: "Incident command", lessons: ["Assign incident roles", "Communicate decisions and approvals", "Containment, recovery, and after-action review"] },
        { id: "L6", title: "Threat intelligence operations", lessons: ["Assess source reliability", "Enrich and expire indicators", "Translate intelligence into validated detections"] }
    ];

    const shiftDays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    const shiftBands = [["00:00-08:00", "Night"], ["08:00-16:00", "Day"], ["16:00-24:00", "Evening"]];
    let activeView = "reports";
    let artifacts = [];
    let selectedHandbook = handbook[0].id;
    let generatedReport = "";
    let generatedPlan = "";
    let lastIoc = null;
    let liveAnalysis = null;
    let liveSummary = null;
    let threatAnalytics = null;
    let liveRefreshPromise = null;
    let liveIncidentRecords = [];
    let liveClarotyRecords = [];
    let activeLiveDetail = null;
    let liveDetailLimit = 25;

    function esc(value) {
        return String(value ?? "").replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
    }

    function setStatus(message, error = false) {
        if (!status) return;
        status.textContent = message;
        status.classList.toggle("error", error);
    }

    async function request(url, options = {}) {
        const response = await fetch(url, { credentials: "same-origin", cache: "no-store", ...options });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
        return payload;
    }

    async function loadArtifacts() {
        try {
            const payload = await request("/api/modules/soc_studio?limit=500");
            artifacts = payload.records || [];
            render();
        } catch (error) {
            setStatus(`Saved work is unavailable: ${error.message}`, true);
        }
    }

    async function saveArtifact(record) {
        const existingId = record.id;
        const payload = await request(existingId ? `/api/modules/soc_studio/${encodeURIComponent(existingId)}` : "/api/modules/soc_studio", {
            method: existingId ? "PUT" : "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(record)
        });
        const saved = payload.record || payload;
        artifacts = [saved, ...artifacts.filter(item => item.id !== saved.id)];
        setStatus(`Saved locally: ${saved.title}`);
        render();
        return saved;
    }

    function tabs() {
        tabButtons.forEach(button => {
            const selected = button.dataset.socView === activeView;
            button.classList.toggle("active", selected);
            button.setAttribute("aria-selected", String(selected));
        });
    }

    function savedSummary() {
        const recent = artifacts.slice(0, 4);
        return `<div class="soc-studio-summary"><div><strong>${reportTemplates.length}</strong><span>report templates</span></div><div><strong>${handbook.length}</strong><span>handbook sections</span></div><div><strong>${dashboards.length}</strong><span>dashboard designs</span></div><div><strong>${artifacts.length}</strong><span>saved artifacts</span></div><div class="soc-studio-recent"><b>Recent saved work</b><span>${recent.length ? recent.map(item => esc(item.title)).join(" · ") : "No saved work yet"}</span></div></div>`;
    }

    function sourceClass(source) {
        return source === "live" ? "live" : source === "mock" || source === "sample" ? "sample" : source === "local" ? "local" : source === "configured" ? "configured" : "pending";
    }

    function renderLiveOverview() {
        const target = document.getElementById("socStudioLiveOverview");
        if (!target) return;
        if (!liveAnalysis) {
            target.innerHTML = `<div class="soc-live-state"><span class="soc-live-pulse"></span><span>Checking connected data sources…</span></div>`;
            return;
        }
        const incident = liveAnalysis.sources?.find(item => item.name === "Swimlane incidents");
        const claroty = liveAnalysis.sources?.find(item => item.name === "Claroty alerts");
        const liveSources = (liveAnalysis.sources || []).filter(item => item.source === "live").length;
        const totalRecords = (liveAnalysis.sources || []).reduce((sum, item) => sum + Number(item.record_count || 0), 0);
        const severity = incident?.severity || {};
        const levels = [["Critical", "critical"], ["High", "high"], ["Medium", "medium"], ["Low", "low"]];
        const largest = Math.max(1, ...levels.map(([name]) => Number(severity[name] || 0)));
        const severityRows = levels.map(([name, tone]) => `<button type="button" class="soc-severity-row" data-soc-live-severity="${name}" aria-label="Show ${name} incidents"><span>${name}</span><span class="soc-severity-track"><i class="${tone}" style="width:${Math.round((Number(severity[name] || 0) / largest) * 100)}%"></i></span><b>${Number(severity[name] || 0).toLocaleString()}</b></button>`).join("");
        const connectorRows = Object.entries(liveSummary?.connectors || {}).map(([name, state]) => `<span class="soc-connector-chip ${state === "configured_not_verified" ? "configured" : ""}"><i></i>${esc(name)} · ${state === "configured_not_verified" ? "configured, unverified" : "not configured"}</span>`).join("");
        target.innerHTML = `<div class="soc-live-metrics"><button type="button" class="soc-live-card" data-soc-live-source="incidents" aria-label="Open incident records"><span>Incident records · 30 days</span><strong>${Number(incident?.record_count || 0).toLocaleString()}</strong><small class="soc-source ${sourceClass(incident?.source)}">${esc(incident?.source || "unavailable")}</small></button><button type="button" class="soc-live-card" data-soc-live-source="claroty-alerts" aria-label="Open Claroty alert records"><span>Claroty alert records</span><strong>${Number(claroty?.record_count || 0).toLocaleString()}</strong><small class="soc-source ${sourceClass(claroty?.source)}">${esc(claroty?.source || "pending")} · ${claroty?.complete ? "complete" : "partial / pending"}</small></button><button type="button" class="soc-live-card" data-soc-live-source="sources" aria-label="Show all five data-source states"><span>Live sources</span><strong>${liveSources}</strong><small>${(liveAnalysis.sources || []).length} sources checked · ${totalRecords.toLocaleString()} records</small></button><article class="soc-live-card soc-live-severity"><span>Incident severity</span><div>${severityRows}</div></article></div><div class="soc-connectors"><span class="soc-connectors-label">Connector readiness</span>${connectorRows || `<span class="soc-connector-chip">No connector status</span>`}<small>Configured means credentials are saved, not that a live connection was verified.</small></div>${renderLiveDetail()}`;
        target.querySelectorAll("[data-soc-live-source]").forEach(button => button.addEventListener("click", () => {
            activeLiveDetail = { type: button.dataset.socLiveSource };
            liveDetailLimit = 25;
            renderLiveOverview();
        }));
        target.querySelectorAll("[data-soc-live-severity]").forEach(button => button.addEventListener("click", () => {
            activeLiveDetail = { type: "severity", severity: button.dataset.socLiveSeverity };
            liveDetailLimit = 25;
            renderLiveOverview();
        }));
        target.querySelector("[data-soc-live-close]")?.addEventListener("click", () => {
            activeLiveDetail = null;
            renderLiveOverview();
        });
        target.querySelector("[data-soc-live-more]")?.addEventListener("click", () => {
            liveDetailLimit += 25;
            renderLiveOverview();
        });
        target.querySelectorAll("[data-soc-live-detail-source]").forEach(button => button.addEventListener("click", () => {
            activeLiveDetail = { type: button.dataset.socLiveDetailSource };
            liveDetailLimit = 25;
            renderLiveOverview();
        }));
    }

    function liveFeedState(type) {
        if (type === "incidents") return liveAnalysis?.sources?.find(item => item.name === "Swimlane incidents");
        if (type === "claroty-alerts") return liveAnalysis?.sources?.find(item => item.name === "Claroty alerts");
        const name = type.replace("claroty-", "");
        return liveAnalysis?.sources?.find(item => item.name === `Claroty ${name}`);
    }

    function liveDetailRecords(type, severity = "") {
        if (type === "incidents") return liveIncidentRecords;
        if (type === "claroty-alerts") return liveClarotyRecords;
        if (type === "severity") return [
            ...liveIncidentRecords.map(item => ({ ...item, _source: "Swimlane" })),
            ...liveClarotyRecords.map(item => ({ ...item, _source: "Claroty" }))
        ].filter(item => String(item.severity || "").toLowerCase() === severity.toLowerCase());
        if (type.startsWith("claroty-") && window.ClarotyAPI) return ClarotyAPI.feedState(type.replace("claroty-", "")).data || [];
        return [];
    }

    function renderLiveDetail() {
        if (!activeLiveDetail) return "";
        const type = activeLiveDetail.type;
        const feedNames = [
            ["incidents", "Swimlane incidents"], ["claroty-alerts", "Claroty alerts"],
            ["claroty-devices", "Claroty devices"], ["claroty-vulnerabilities", "Claroty vulnerabilities"],
            ["claroty-events", "Claroty events"]
        ];
        if (type === "sources") {
            const rows = feedNames.map(([key, name]) => {
                const feed = liveFeedState(key);
                return `<button type="button" data-soc-live-detail-source="${key}"><strong>${esc(name)}</strong><span class="soc-source ${sourceClass(feed?.source)}">${esc(feed?.source || "unavailable")}</span><small>${Number(feed?.record_count || 0).toLocaleString()} loaded · ${feed?.complete ? "complete" : "partial / pending"}</small></button>`;
            }).join("");
            return `<section class="soc-live-detail"><header><div><span class="soc-eyebrow">Source drill-down</span><h3>Five data sources</h3></div><button type="button" data-soc-live-close aria-label="Close live data details">Close</button></header><div class="soc-live-source-list">${rows}</div></section>`;
        }
        const severity = activeLiveDetail.severity || "";
        const records = liveDetailRecords(type, severity);
        const source = type === "severity" ? null : liveFeedState(type);
        const title = type === "severity" ? `${severity} incidents` : feedNames.find(([key]) => key === type)?.[1] || "Loaded records";
        const rows = records.slice(0, liveDetailLimit).map((record, index) => {
            const label = type === "claroty-devices" ? record.device_name || record.name || record.uid || "Device" :
                type === "claroty-vulnerabilities" ? record.name || record.vulnerability_name || (record.cve_ids || []).join(", ") || "Vulnerability" :
                type === "claroty-events" ? record.event_type || record.description || "Network event" :
                record.title || record.alert_name || record.name || `Record ${index + 1}`;
            const detail = type === "claroty-devices" ? [record.site_name, record.manufacturer, record.device_type].filter(Boolean).join(" · ") :
                type === "claroty-vulnerabilities" ? [record.cve_ids, record.cvss_v3_score, record.adjusted_vulnerability_score_level].flat().filter(Boolean).join(" · ") :
                type === "claroty-events" ? [record.timestamp, record.protocol, record.side_a_name, record.side_b_name].filter(Boolean).join(" · ") :
                [record.status, record.assignee, record.source || record._source, record.detectedTime || record.created].filter(Boolean).join(" · ");
            return `<article class="soc-live-record"><div><strong>${esc(label)}</strong><span class="soc-record-severity ${sourceClass(String(record.severity || "").toLowerCase() === "critical" ? "sample" : "local")}">${esc(record.severity || "Loaded")}</span></div><small>${esc(detail || "No additional summary fields loaded")}</small></article>`;
        }).join("");
        const sourceStatus = type === "severity" ? "Swimlane and Claroty records · source labels shown per row" : `${source?.source || "unavailable"} · ${source?.complete ? "complete" : "partial / pending"}`;
        return `<section class="soc-live-detail"><header><div><span class="soc-eyebrow">Loaded data</span><h3>${esc(title)}</h3><small>${records.length.toLocaleString()} records · ${esc(sourceStatus)}</small></div><button type="button" data-soc-live-close aria-label="Close live data details">Close</button></header><div class="soc-live-record-list">${rows || `<p>No records are loaded for this source yet.</p>`}</div>${records.length > liveDetailLimit ? `<button type="button" class="soc-secondary" data-soc-live-more>Load 25 more</button>` : ""}</section>`;
    }

    async function refreshLiveAnalysis() {
        if (liveRefreshPromise) return liveRefreshPromise;
        liveRefreshPromise = (async () => {
            renderLiveOverview();
            try {
                liveSummary = await request("/api/soc-studio/summary");
                try { threatAnalytics = await request("/api/analytics/threats"); }
                catch { threatAnalytics = null; }
                const sources = [];
                if (window.SwimlaneAPI) {
                    try {
                        const result = await SwimlaneAPI.getRecords({ range: 30 });
                        liveIncidentRecords = (result.data || []).slice(0, 5000);
                        const records = liveIncidentRecords.map(item => ({
                            severity: item.severity,
                            status: item.status,
                            created: item.created || item.detected,
                            mitre: item.mitre
                        }));
                        sources.push({ name: "Swimlane incidents", source: result.source || "unavailable", records, record_count: records.length, complete: true });
                    } catch (error) {
                        liveIncidentRecords = [];
                        sources.push({ name: "Swimlane incidents", source: "unavailable", records: [], record_count: 0, complete: false });
                    }
                }
                if (window.ClarotyAPI) {
                    const alertFeed = ClarotyAPI.feedState("alerts");
                    const xdIncidents = window.XDIncidents ? XDIncidents.build() : [];
                    liveClarotyRecords = alertFeed.source === "live" ? xdIncidents : [];
                    const records = (alertFeed.source === "live" ? xdIncidents : []).slice(0, 5000).map(item => ({
                        severity: item.severity,
                        status: item.status,
                        detected: item.detectedTime,
                        mitre: (item.mitre || []).map(technique => technique.id).join(" ")
                    }));
                    sources.push({
                        name: "Claroty alerts",
                        source: alertFeed.source === "live" ? "live" : alertFeed.source === "pending" ? "pending" : "unavailable",
                        complete: Boolean(alertFeed.complete),
                        record_count: alertFeed.data?.length || 0,
                        records
                    });
                    ["devices", "vulnerabilities", "events"].forEach(name => {
                        const feed = ClarotyAPI.feedState(name);
                        sources.push({
                            name: `Claroty ${name}`,
                            source: feed.source === "live" ? "live" : feed.source === "pending" ? "pending" : "unavailable",
                            complete: Boolean(feed.complete),
                            record_count: feed.data?.length || 0,
                            records: []
                        });
                    });
                }
                else {
                    liveClarotyRecords = [];
                }
                liveAnalysis = await request("/api/soc-studio/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ sources })
                });
                setStatus(`Local analysis updated ${new Date(liveAnalysis.generated_at).toLocaleTimeString()}; source labels and feed completeness are preserved.`);
            } catch (error) {
                setStatus(`Live analysis unavailable: ${error.message}`, true);
            } finally {
                liveRefreshPromise = null;
                if (activeView === "dashboards") render();
                else renderLiveOverview();
            }
        })();
        return liveRefreshPromise;
    }

    function dashboardMetrics(id) {
        const source = name => liveAnalysis?.sources?.find(item => item.name === name);
        const incidents = source("Swimlane incidents");
        const clarotyAlerts = source("Claroty alerts");
        const clarotyDevices = source("Claroty devices");
        const clarotyVulnerabilities = source("Claroty vulnerabilities");
        const clarotyEvents = source("Claroty events");
        const connectors = liveSummary?.connectors || {};
        const local = liveSummary?.local_records || {};
        const threats = threatAnalytics?.counts || {};
        const connectorState = tool => connectors[tool] === "configured_not_verified" ? "Configured · unverified" : "Not connected";
        const sourceState = item => item ? `${item.source}${item.complete ? " · complete" : " · partial/pending"}` : "Not loaded";
        const feedMetric = (label, item) => ({ label, value: item ? Number(item.record_count || 0).toLocaleString() : "—", source: sourceState(item), sourceKind: item?.source || "unavailable", count: item ? Number(item.record_count || 0) : null });
        const localMetric = (label, key) => ({ label, value: Number(local[key] || 0).toLocaleString(), source: "Local records", sourceKind: "local", count: Number(local[key] || 0) });
        const connectorMetric = (label, tool) => ({ label, value: connectorState(tool), source: "Credential status", sourceKind: connectors[tool] === "configured_not_verified" ? "configured" : "unavailable", count: null });
        const severity = incidents?.severity || {};
        const status = incidents?.status || {};
        const techniques = Object.keys(incidents?.mitre_techniques || {});
        const mappedCount = Object.values(incidents?.mitre_techniques || {}).reduce((sum, count) => sum + Number(count || 0), 0);
        const models = {
            D01: [feedMetric("Incidents · 30d", incidents), { label: "Critical incidents", value: severity.Critical ?? "—", source: sourceState(incidents), count: Number(severity.Critical || 0) }, feedMetric("Claroty alerts", clarotyAlerts)],
            D02: [{ label: "Open queue", value: status.open ?? "—", source: sourceState(incidents), count: Number(status.open || 0) }, { label: "Closed", value: status.closed ?? "—", source: sourceState(incidents), count: Number(status.closed || 0) }, { label: "Assignment balance", value: "Not available", source: "Assignee data not loaded", count: null }],
            D03: [{ label: "ATT&CK techniques observed", value: techniques.length || "—", source: sourceState(incidents), count: techniques.length }, connectorMetric("ELK / Elastic", "elastic"), { label: "Detection quality", value: "Not available", source: "True-positive labels not loaded", count: null }],
            D04: [{ label: "Open cases", value: status.open ?? "—", source: sourceState(incidents), count: Number(status.open || 0) }, { label: "Closed cases", value: status.closed ?? "—", source: sourceState(incidents), count: Number(status.closed || 0) }, { label: "Lifecycle durations", value: "Not available", source: "Timestamp fields incomplete", count: null }],
            D05: [connectorMetric("Entra identity", "entra"), { label: "Risky sign-ins", value: "Not available", source: "Identity events not loaded", count: null }],
            D06: [connectorMetric("CrowdStrike", "crowdstrike"), connectorMetric("Defender", "defender"), { label: "Endpoint events", value: "Not available", source: "EDR telemetry not loaded", count: null }],
            D07: [connectorMetric("Wiz", "wiz"), connectorMetric("Prisma Cloud", "prismacloud"), { label: "Cloud findings", value: "Not available", source: "Cloud telemetry not loaded", count: null }],
            D08: [feedMetric("Claroty network events", clarotyEvents), localMetric("Local network events", "network_events")],
            D09: [connectorMetric("Microsoft 365", "m365"), { label: "Email events", value: "Not available", source: "Email telemetry not loaded", count: null }],
            D10: [feedMetric("Claroty vulnerabilities", clarotyVulnerabilities), localMetric("Saved vulnerabilities", "vulnerabilities")],
            D11: [{ label: "Local indicators", value: Number(threats.indicators || 0).toLocaleString(), source: "Local indicator catalog", count: Number(threats.indicators || 0) }, localMetric("Threat intel records", "threat_intel"), { label: "Threat sources", value: threatAnalytics ? "Loaded" : "Unavailable", source: threatAnalytics?.source || "Not loaded", count: threatAnalytics ? 1 : null }],
            D12: [{ label: "Distinct techniques observed", value: techniques.length || "—", source: sourceState(incidents), count: techniques.length }, { label: "Mapped observations", value: mappedCount || "—", source: "Observed records · not coverage", count: mappedCount }],
            D13: [feedMetric("Claroty OT assets", clarotyDevices), feedMetric("Claroty alerts", clarotyAlerts)],
            D14: [feedMetric("Alerts feed", clarotyAlerts), feedMetric("Device feed", clarotyDevices), feedMetric("Vulnerability feed", clarotyVulnerabilities), feedMetric("Event feed", clarotyEvents)]
        };
        return models[id] || [];
    }

    function reportsView() {
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">AI-ready SOC reporting</p><h2>AnySIEM Reports</h2><p>Choose a report pattern and create an evidence-aware draft. No metrics are invented; add source data and validate findings before distribution.</p></div><span class="soc-count">38 templates</span></div>
            <div class="soc-work-grid"><form id="socReportForm" class="soc-form"><label>Report template<select id="socReportTemplate">${reportTemplates.map(item => `<option value="${item.id}">${item.id} · ${esc(item.name)}</option>`).join("")}</select></label><label>Organization or client<input id="socReportOrg" maxlength="100" placeholder="Organization name" required></label><label>Reporting period<input id="socReportPeriod" maxlength="80" placeholder="e.g. 2026-10-01 to 2026-10-07" required></label><label>Audience context<textarea id="socReportContext" rows="3" maxlength="800" placeholder="Scope, systems, and decisions this report should support"></textarea></label><button class="soc-primary" type="submit">Generate report draft</button></form><div id="socReportOutput" class="soc-output" aria-live="polite">Select a template and provide the reporting context to create a draft.</div></div>`;
    }

    function planView() {
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">Infrastructure-specific adoption</p><h2>MSP Sentinel AI</h2><p>Build a phased Microsoft Sentinel adoption plan from the infrastructure details you provide. This produces a plan only; it does not create Azure resources or deploy connectors.</p></div><span class="soc-status-tag">Planning mode</span></div>
            <div class="soc-work-grid"><form id="socPlanForm" class="soc-form"><label>MSP / customer name<input id="socPlanOrg" maxlength="100" placeholder="Organization name" required></label><label>Sentinel workspace region<input id="socPlanRegion" maxlength="80" placeholder="Azure region or undecided"></label><label>Analyst team size<input id="socPlanTeam" type="number" min="1" max="500" value="4"></label><label>Current identity platform<select id="socPlanIdentity"><option>Microsoft Entra ID</option><option>Hybrid Active Directory and Entra ID</option><option>Third-party identity provider</option><option>Not yet confirmed</option></select></label><fieldset><legend>In-scope data sources</legend>${["Microsoft 365", "Azure activity", "Endpoint security", "Firewall and DNS", "AWS", "OT/ICS passive monitoring"].map((item, index) => `<label class="soc-check"><input type="checkbox" name="socPlanSource" value="${esc(item)}" ${index < 2 ? "checked" : ""}>${esc(item)}</label>`).join("")}</fieldset><button class="soc-primary" type="submit">Build adoption plan</button></form><div id="socPlanOutput" class="soc-output">Select the infrastructure in scope to build a phased plan with dependencies and decision gates.</div></div>`;
    }

    function shiftView() {
        const existing = artifacts.find(item => item.artifact_type === "shift_roster");
        const savedOwners = existing?.owners || {};
        const minimum = Math.min(10, Math.max(1, Number(existing?.minimum_coverage) || 2));
        const rows = shiftDays.flatMap((day, dayIndex) => shiftBands.map(([hours, name], shiftIndex) => {
            const key = `${dayIndex}-${shiftIndex}`;
            return `<tr><th>${day}</th><td>${name}<small>${hours}</small></td><td><input data-shift-owner="${key}" value="${esc(savedOwners[key] || "")}" maxlength="160" placeholder="Names, comma-separated"></td><td data-shift-state="${key}" class="soc-gap">Gap</td></tr>`;
        })).join("");
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">Coverage with gaps disclosed</p><h2>ShiftGuard</h2><p>Plan weekly SOC staffing. Blank assignments and under-covered shifts remain visible; the roster is a planning artifact, not a live scheduling system.</p></div><span class="soc-status-tag">No auto-fill</span></div><div class="soc-shift-tools"><label>Minimum analysts per shift<input id="socMinimumCoverage" type="number" min="1" max="10" value="${minimum}"></label><div id="socCoverageSummary" role="status"></div><button class="soc-primary" id="socSaveRoster" type="button">Save roster</button></div><div class="table-wrap soc-roster-wrap"><table class="soc-roster"><thead><tr><th>Day</th><th>Shift</th><th>Assigned analysts</th><th>Coverage</th></tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    function handbookView() {
        const saved = artifacts.filter(item => item.artifact_type === "handbook_section");
        const active = handbook.find(item => item.id === selectedHandbook) || handbook[0];
        const content = saved.find(item => item.section_id === active.id)?.content || active.starter;
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">Organization-specific working document</p><h2>SOC Operations Handbook</h2><p>21 editable section starters. Replace prompts with approved policy, named owners, and organization-specific procedures before adoption.</p></div><span class="soc-count">21 sections</span></div><div class="soc-handbook-layout"><nav class="soc-handbook-nav" aria-label="Handbook sections">${handbook.map(item => `<button type="button" data-handbook-section="${item.id}" class="${active.id === item.id ? "active" : ""}">${item.id} · ${esc(item.title)}</button>`).join("")}</nav><form id="socHandbookForm" class="soc-form soc-handbook-editor"><label>Section<select id="socHandbookSelect">${handbook.map(item => `<option value="${item.id}" ${active.id === item.id ? "selected" : ""}>${item.id} · ${esc(item.title)}</option>`).join("")}</select></label><label>Working content<textarea id="socHandbookContent" rows="15" maxlength="12000">${esc(content)}</textarea></label><button class="soc-primary" type="submit">Save section locally</button></form></div>`;
    }

    function learningView() {
        const progress = artifacts.find(item => item.artifact_type === "learning_progress")?.completed || [];
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">SOC Career Launchpad</p><h2>Learning path and tutor</h2><p>Six role-ready modules with practical lessons. The local tutor retrieves authored guidance; no hosted AI model is connected.</p></div><span class="soc-count">${progress.length}/${courses.length} complete</span></div><div class="soc-learning-grid"><div class="soc-course-list">${courses.map(course => `<article class="soc-course"><label class="soc-course-check"><input type="checkbox" data-course="${course.id}" ${progress.includes(course.id) ? "checked" : ""}><strong>${course.id} · ${esc(course.title)}</strong></label><ul>${course.lessons.map(lesson => `<li>${esc(lesson)}</li>`).join("")}</ul></article>`).join("")}</div><form id="socTutorForm" class="soc-form soc-tutor"><h3>AI-ready tutor</h3><label>Your question<input id="socTutorQuestion" maxlength="400" placeholder="e.g. How should we test a new detection?" required></label><button class="soc-primary" type="submit">Find guidance</button><div id="socTutorAnswer" class="soc-output" aria-live="polite">Ask about SOC foundations, data onboarding, detections, triage, incident command, or threat intelligence.</div></form></div>`;
    }

    function dashboardsView() {
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">Vendor-neutral SIEM Dashboard Framework</p><h2>Dashboard design library</h2><p>Fourteen dashboard blueprints define useful panels and questions. They are design specs, not installed Kibana or Sentinel workspaces.</p></div><span class="soc-count">14 designs</span></div><div class="soc-design-grid">${dashboards.map(item => `<article class="soc-design"><div><span>${item.id}</span><h3>${esc(item.title)}</h3></div><p>${esc(item.purpose)}</p><button type="button" data-save-dashboard="${item.id}">Save design</button></article>`).join("")}</div>`;
    }

    function elkView() {
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">Detection engineering and response</p><h2>ELK detections and playbooks</h2><p>Starter query patterns mapped to MITRE ATT&amp;CK. Validate ECS fields, thresholds, permissions, and false positives in a test environment before deployment.</p></div><span class="soc-status-tag">Not deployed</span></div><div class="soc-subsection"><div class="soc-subsection-head"><h3>Detection rules</h3><button class="soc-secondary" id="socSaveDetectionPack" type="button">Save detection pack</button></div><div class="soc-detection-list">${detections.map(rule => `<details class="soc-detection"><summary><strong>${esc(rule.name)}</strong><span>${esc(rule.mitre)} · ${esc(rule.tactic)}</span></summary><p>${esc(rule.rationale)}</p><code>${esc(rule.query)}</code><button type="button" data-save-detection="${rule.id}">Save rule</button></details>`).join("")}</div></div><div class="soc-subsection"><div class="soc-subsection-head"><h3>Incident-response playbooks</h3></div><div class="soc-playbook-grid">${playbooks.map(item => `<details class="soc-playbook"><summary><strong>${esc(item.name)}</strong><span>${esc(item.trigger)}</span></summary><ol>${item.steps.map(step => `<li>${esc(step)}</li>`).join("")}</ol><button type="button" data-save-playbook="${item.id}">Save playbook</button></details>`).join("")}</div></div>`;
    }

    function ctiView() {
        return `<div class="soc-studio-view-head"><div><p class="soc-eyebrow">CTI Automation Chain</p><h2>IOC enrichment console</h2><p>Normalize an indicator and search only records already loaded in this browser. Nothing is sent to external vendors by this console.</p></div><span class="soc-status-tag">Local evidence only</span></div><ol class="soc-cti-chain"><li><b>1</b><span>Validate format</span></li><li><b>2</b><span>Normalize indicator</span></li><li><b>3</b><span>Search loaded feeds</span></li><li><b>4</b><span>Review source and time</span></li><li><b>5</b><span>Analyst disposition</span></li><li class="soc-cti-unavailable"><b>6</b><span>Vendor actions not connected</span></li></ol><form id="socIocForm" class="soc-ioc-form"><label for="socIocInput">Indicator of compromise</label><div><input id="socIocInput" maxlength="512" placeholder="IP, domain, URL, hash, or CVE" required><button class="soc-primary" type="submit">Enrich locally</button></div></form><div id="socIocOutput" class="soc-output" aria-live="polite">Enter one indicator to inspect its format and search locally loaded Claroty feeds.</div>`;
    }

    function render() {
        tabs();
        const views = { reports: reportsView, sentinel: planView, shifts: shiftView, handbook: handbookView, learning: learningView, dashboards: dashboardsView, elk: elkView, cti: ctiView };
        root.innerHTML = `${savedSummary()}${(views[activeView] || reportsView)()}`;
        decorateStudioView();
        renderLiveOverview();
        if (window.lucide) window.lucide.createIcons();
        bindView();
    }

    function decorateStudioView() {
        if (activeView === "handbook") {
            const saved = new Set(artifacts.filter(item => item.artifact_type === "handbook_section").map(item => item.section_id));
            const progress = document.createElement("div");
            progress.className = "soc-visual-progress";
            progress.innerHTML = `<strong>${saved.size}<small>/${handbook.length}</small></strong><span>handbook sections personalized</span><div><i style="width:${Math.round(saved.size / handbook.length * 100)}%"></i></div>`;
            root.querySelector(".soc-handbook-layout")?.before(progress);
            root.querySelectorAll("[data-handbook-section]").forEach(button => {
                const state = document.createElement("span");
                state.className = `soc-section-state ${saved.has(button.dataset.handbookSection) ? "complete" : "starter"}`;
                state.textContent = saved.has(button.dataset.handbookSection) ? "Saved" : "Starter";
                button.append(state);
            });
        }
        if (activeView === "learning") {
            const completed = root.querySelectorAll("[data-course]:checked").length;
            const progress = document.createElement("div");
            progress.className = "soc-visual-progress learning-progress";
            progress.innerHTML = `<strong>${completed}<small>/${courses.length}</small></strong><span>learning modules completed</span><div><i style="width:${Math.round(completed / courses.length * 100)}%"></i></div>`;
            root.querySelector(".soc-learning-grid")?.before(progress);
        }
        if (activeView === "dashboards") {
            root.querySelectorAll(".soc-design").forEach(card => {
                const id = card.querySelector("[data-save-dashboard]")?.dataset.saveDashboard;
                const metrics = dashboardMetrics(id);
                const numeric = metrics.map(item => item.count).filter(value => value != null);
                const maxValue = Math.max(1, ...numeric);
                const chart = document.createElement("div");
                chart.className = "soc-design-preview";
                chart.setAttribute("aria-hidden", "true");
                chart.innerHTML = metrics.slice(0, 5).map(item => `<i class="${sourceClass(item.sourceKind)}" style="height:${item.count == null ? 4 : Math.max(4, Math.round(item.count / maxValue * 100))}%"></i>`).join("");
                const livePanel = document.createElement("div");
                livePanel.className = "soc-design-live-data";
                livePanel.innerHTML = metrics.map(item => `<div class="soc-design-metric"><span>${esc(item.label)}</span><strong>${esc(item.value)}</strong><small class="soc-design-source ${sourceClass(item.sourceKind)}">${esc(item.source)}</small><i class="${sourceClass(item.sourceKind)}" style="width:${item.count == null ? 0 : Math.max(0, Math.round(item.count / maxValue * 100))}%"></i></div>`).join("");
                card.querySelector("p")?.before(chart, livePanel);
            });
        }
        if (activeView === "elk") {
            root.querySelectorAll(".soc-detection summary span").forEach(label => {
                label.classList.add("soc-rule-technique");
            });
        }
        if (activeView === "shifts") {
            const meter = document.createElement("div");
            meter.className = "soc-coverage-meter";
            meter.innerHTML = "<i></i>";
            root.querySelector(".soc-shift-tools")?.after(meter);
        }
    }

    async function submitReport(event) {
        event.preventDefault();
        await refreshLiveAnalysis();
        const template = reportTemplates.find(item => item.id === document.getElementById("socReportTemplate").value) || reportTemplates[0];
        const organization = document.getElementById("socReportOrg").value.trim();
        const period = document.getElementById("socReportPeriod").value.trim();
        const context = document.getElementById("socReportContext").value.trim();
        const sourceSummary = (liveAnalysis?.sources || []).map(item => `${item.name}: ${item.record_count} loaded (${item.source}${item.complete ? ", complete" : ", partial or pending"})`).join("\n");
        const incidentSummary = liveAnalysis?.sources?.find(item => item.name === "Swimlane incidents");
        const severitySummary = Object.entries(incidentSummary?.severity || {}).map(([name, count]) => `${name}: ${count}`).join(" · ") || "No incident severity data loaded";
        const sourceQualifier = incidentSummary?.source === "live" ? "live" : `${incidentSummary?.source || "unavailable"} sample`;
        generatedReport = `${template.name}\nOrganization: ${organization}\nReporting period: ${period}\n\nExecutive summary\n${incidentSummary?.analyzed_count ? `${incidentSummary.analyzed_count} incident records analyzed from ${sourceQualifier} data. Severity mix: ${severitySummary}. Validate findings and decisions before distribution.` : "No incident records were available from a verified live source. Add findings and decision requests from approved evidence."}\n\nScope and sources\n${context || "No additional scope entered."}\n${sourceSummary || "No source status is available."}\n\nMITRE ATT&CK coverage\n${Object.entries(incidentSummary?.mitre_techniques || {}).map(([technique, count]) => `${technique}: ${count}`).join("\n") || "No mapped techniques in the selected incident records."}\n\nFindings and evidence\n[Add finding, source record, timestamp, confidence, and business impact.]\n\nResponse and outcomes\n[Add actions taken, approvals, owner, and verification evidence.]\n\nLimitations\n${incidentSummary?.source === "live" ? "Live records were summarized locally; raw incident records were not stored by SOC Studio." : "Data is sample, unavailable, or incomplete. Do not present these figures as live telemetry."} Validate every statement before distribution.`;
        const output = document.getElementById("socReportOutput");
        const severityTiles = Object.entries(incidentSummary?.severity || {}).map(([name, count]) => `<span class="soc-report-stat ${name.toLowerCase()}"><b>${Number(count).toLocaleString()}</b>${esc(name)}</span>`).join("");
        const sourceBadges = (liveAnalysis?.sources || []).map(source => `<span class="soc-report-source ${sourceClass(source.source)}"><i></i>${esc(source.name)} · ${Number(source.record_count || 0).toLocaleString()} · ${esc(source.source)}</span>`).join("");
        output.innerHTML = `<h3>${esc(template.name)}</h3><div class="soc-report-visuals"><div class="soc-report-stats">${severityTiles || "<span>No severity data</span>"}</div><div class="soc-report-sources">${sourceBadges || "No sources analyzed"}</div></div><pre>${esc(generatedReport)}</pre><button class="soc-secondary" id="socSaveReport" type="button">Save draft locally</button>`;
        document.getElementById("socSaveReport").addEventListener("click", () => saveArtifact({ artifact_type: "report_draft", title: `${organization} - ${template.name}`, template_id: template.id, content: generatedReport }));
    }

    function submitPlan(event) {
        event.preventDefault();
        const organization = document.getElementById("socPlanOrg").value.trim();
        const region = document.getElementById("socPlanRegion").value.trim() || "To be confirmed";
        const team = Number(document.getElementById("socPlanTeam").value) || 1;
        const identity = document.getElementById("socPlanIdentity").value;
        const sources = [...document.querySelectorAll("[name='socPlanSource']:checked")].map(input => input.value);
        const phases = [
            ["1. Discover", `Confirm ${organization}'s data owners, retention, privacy boundaries, incident priorities, and target Azure region (${region}).`],
            ["2. Establish controls", `Validate ${identity}, least-privilege roles, workspace access, change approval, and break-glass procedures for a ${team}-analyst team.`],
            ["3. Onboard sources", sources.length ? `Plan connector owners and test events for: ${sources.join(", ")}.` : "Select in-scope sources and confirm owners before onboarding."],
            ["4. Validate detections", "Use test data, documented ATT&CK mappings, false-positive review, and a change ticket before enabling production rules."],
            ["5. Operate and improve", "Set data-health alerts, escalation coverage, content review cadence, response approvals, and monthly service reporting."]
        ];
        generatedPlan = `Sentinel adoption plan - ${organization}\nRegion: ${region}\nIdentity: ${identity}\nTeam size: ${team}\nSources: ${sources.join(", ") || "None selected"}\n\n${phases.map(([title, text]) => `${title}\n${text}\nOwner: [Assign]\nExit evidence: [Define and verify]`).join("\n\n")}\n\nDependencies and caveats\nAzure tenant, licensing, permissions, data residency, source connector support, and customer change approval must be verified. This plan performs no deployment.`;
        const output = document.getElementById("socPlanOutput");
        output.innerHTML = `<h3>Adoption plan · ${esc(organization)}</h3><pre>${esc(generatedPlan)}</pre><button class="soc-secondary" id="socSavePlan" type="button">Save plan locally</button>`;
        document.getElementById("socSavePlan").addEventListener("click", () => saveArtifact({ artifact_type: "sentinel_adoption_plan", title: `${organization} - Sentinel adoption plan`, content: generatedPlan, sources }));
    }

    function updateCoverage() {
        const minimum = Math.min(10, Math.max(1, Number(document.getElementById("socMinimumCoverage")?.value) || 1));
        let covered = 0;
        document.querySelectorAll("[data-shift-owner]").forEach(input => {
            const names = input.value.split(",").map(value => value.trim()).filter(Boolean);
            const filled = names.length >= minimum;
            const cell = document.querySelector(`[data-shift-state="${input.dataset.shiftOwner}"]`);
            if (filled) covered++;
            if (cell) { cell.textContent = filled ? `${names.length} assigned` : `${names.length ? `${names.length} assigned; ` : ""}gap` ; cell.className = filled ? "soc-covered" : "soc-gap"; }
        });
        const total = document.querySelectorAll("[data-shift-owner]").length;
        const summary = document.getElementById("socCoverageSummary");
        if (summary) summary.textContent = `${covered}/${total} shifts meet the ${minimum}-analyst target; ${total - covered} coverage gaps disclosed.`;
        const meter = document.querySelector(".soc-coverage-meter");
        if (meter) {
            const percent = total ? Math.round(covered / total * 100) : 0;
            meter.style.setProperty("--coverage", `${percent}%`);
            meter.setAttribute("role", "progressbar");
            meter.setAttribute("aria-valuemin", "0");
            meter.setAttribute("aria-valuemax", "100");
            meter.setAttribute("aria-valuenow", String(percent));
        }
    }

    async function saveRoster() {
        const owners = Object.fromEntries([...document.querySelectorAll("[data-shift-owner]")].map(input => [input.dataset.shiftOwner, input.value.trim()]));
        const minimum = Math.min(10, Math.max(1, Number(document.getElementById("socMinimumCoverage").value) || 1));
        const existing = artifacts.find(item => item.artifact_type === "shift_roster");
        await saveArtifact({ ...(existing || {}), artifact_type: "shift_roster", title: "ShiftGuard weekly roster", owners, minimum_coverage: minimum });
    }

    function loadHandbookSection(id) {
        selectedHandbook = handbook.some(item => item.id === id) ? id : handbook[0].id;
        render();
    }

    async function saveHandbookSection(event) {
        event.preventDefault();
        const section = handbook.find(item => item.id === document.getElementById("socHandbookSelect").value) || handbook[0];
        const content = document.getElementById("socHandbookContent").value.trim();
        const existing = artifacts.find(item => item.artifact_type === "handbook_section" && item.section_id === section.id);
        selectedHandbook = section.id;
        await saveArtifact({ ...(existing || {}), artifact_type: "handbook_section", section_id: section.id, title: `Handbook - ${section.title}`, content });
    }

    function courseProgress() {
        const completed = [...document.querySelectorAll("[data-course]:checked")].map(input => input.dataset.course);
        const existing = artifacts.find(item => item.artifact_type === "learning_progress");
        return saveArtifact({ ...(existing || {}), artifact_type: "learning_progress", title: "SOC Career Launchpad progress", completed });
    }

    function tutorAnswer(event) {
        event.preventDefault();
        const question = document.getElementById("socTutorQuestion").value.trim();
        const normalized = question.toLowerCase();
        const matches = courses.flatMap(course => course.lessons.map(lesson => ({ course, lesson })))
            .filter(item => item.lesson.toLowerCase().split(/\W+/).some(word => word.length > 4 && normalized.includes(word)) || normalized.includes(item.course.title.toLowerCase()));
        const suggestions = (matches.length ? matches.slice(0, 3) : courses.slice(0, 3).map(course => ({ course, lesson: course.lessons[0] })))
            .map(item => `<li><strong>${esc(item.course.title)}:</strong> ${esc(item.lesson)}</li>`).join("");
        document.getElementById("socTutorAnswer").innerHTML = `<h3>Local learning guidance</h3><p>Use this as a study prompt, then check your organization's approved procedures and source material.</p><ul>${suggestions}</ul><small>Source: SOC Career Launchpad course notes. No hosted model was queried.</small>`;
    }

    function saveDashboard(id) {
        const item = dashboards.find(entry => entry.id === id);
        if (item) saveArtifact({ artifact_type: "dashboard_design", title: item.title, design_id: item.id, content: item.purpose });
    }

    async function saveDetection(id) {
        const rule = detections.find(item => item.id === id);
        if (rule) await saveArtifact({ artifact_type: "elk_detection", title: rule.name, rule_id: rule.id, mitre_id: rule.mitre, tactic: rule.tactic, query: rule.query, rationale: rule.rationale, status: "draft_not_deployed" });
    }

    async function saveDetectionPack() {
        await saveArtifact({ artifact_type: "elk_detection_pack", title: "ELK starter detections - ATT&CK mapped", rules: detections, status: "draft_not_deployed" });
    }

    async function savePlaybook(id) {
        const item = playbooks.find(entry => entry.id === id);
        if (item) await saveArtifact({ artifact_type: "elk_response_playbook", title: item.name, playbook_id: item.id, trigger: item.trigger, steps: item.steps, status: "draft_requires_review" });
    }

    function identifyIoc(value) {
        const input = value.trim();
        if (/^CVE-\d{4}-\d{4,}$/i.test(input)) return { type: "CVE", normalized: input.toUpperCase() };
        if (/^https?:\/\//i.test(input)) {
            try { const url = new URL(input); return { type: "URL", normalized: url.toString() }; } catch { return null; }
        }
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) {
            const octets = input.split(".").map(Number);
            return octets.every(part => part >= 0 && part <= 255) ? { type: "IPv4", normalized: octets.join(".") } : null;
        }
        if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(input)) return { type: "File hash", normalized: input.toLowerCase() };
        if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(input)) return { type: "Domain", normalized: input.toLowerCase() };
        return null;
    }

    function localFeedMatches(indicator) {
        if (!window.ClarotyAPI) return [];
        return ["alerts", "events", "devices", "vulnerabilities"].map(name => {
            const feed = window.ClarotyAPI.feedState(name) || { data: [], source: "pending" };
            const rows = (feed.data || []).filter(record => JSON.stringify(record).toLowerCase().includes(indicator.toLowerCase()));
            return { name, source: feed.source || "unknown", count: rows.length, complete: Boolean(feed.complete) };
        });
    }

    async function enrichIoc(event) {
        event.preventDefault();
        const raw = document.getElementById("socIocInput").value;
        const indicator = identifyIoc(raw);
        const output = document.getElementById("socIocOutput");
        if (!indicator) {
            lastIoc = null;
            output.innerHTML = `<p class="soc-gap">Unsupported or malformed indicator. Use an IPv4 address, domain, URL, MD5/SHA-1/SHA-256 hash, or CVE ID.</p>`;
            return;
        }
        const matches = localFeedMatches(indicator.normalized);
        lastIoc = { ...indicator, matches };
        const sourceRows = matches.map(item => `<li>${esc(item.name)}: ${item.count} matching loaded records (${esc(item.source)}${item.complete ? ", complete" : ", partial or pending"})</li>`).join("");
        output.innerHTML = `<h3>${esc(indicator.type)} · ${esc(indicator.normalized)}</h3><p>Matches are exact text matches in the currently loaded browser data only. A zero count does not prove an indicator is benign.</p><ul>${sourceRows || "<li>Claroty data client is not available.</li>"}</ul><p class="soc-status-tag">External CTI providers and response actions are not connected by this console.</p><button class="soc-secondary" id="socSaveIoc" type="button">Save analysis locally</button>`;
        document.getElementById("socSaveIoc").addEventListener("click", () => saveArtifact({ artifact_type: "ioc_analysis", title: `${indicator.type} ${indicator.normalized}`, indicator_type: indicator.type, indicator: indicator.normalized, matches, content: "Local loaded-feed exact-match preview; not a verdict." }));
    }

    function bindView() {
        document.getElementById("socReportForm")?.addEventListener("submit", submitReport);
        document.getElementById("socPlanForm")?.addEventListener("submit", submitPlan);
        document.querySelectorAll("[data-shift-owner]").forEach(input => input.addEventListener("input", updateCoverage));
        document.getElementById("socMinimumCoverage")?.addEventListener("input", updateCoverage);
        document.getElementById("socSaveRoster")?.addEventListener("click", saveRoster);
        document.getElementById("socHandbookForm")?.addEventListener("submit", saveHandbookSection);
        document.getElementById("socHandbookSelect")?.addEventListener("change", event => loadHandbookSection(event.target.value));
        document.querySelectorAll("[data-handbook-section]").forEach(button => button.addEventListener("click", () => loadHandbookSection(button.dataset.handbookSection)));
        document.querySelectorAll("[data-course]").forEach(input => input.addEventListener("change", courseProgress));
        document.getElementById("socTutorForm")?.addEventListener("submit", tutorAnswer);
        document.querySelectorAll("[data-save-dashboard]").forEach(button => button.addEventListener("click", () => saveDashboard(button.dataset.saveDashboard)));
        document.querySelectorAll("[data-save-detection]").forEach(button => button.addEventListener("click", () => saveDetection(button.dataset.saveDetection)));
        document.getElementById("socSaveDetectionPack")?.addEventListener("click", saveDetectionPack);
        document.querySelectorAll("[data-save-playbook]").forEach(button => button.addEventListener("click", () => savePlaybook(button.dataset.savePlaybook)));
        document.getElementById("socIocForm")?.addEventListener("submit", enrichIoc);
        if (activeView === "shifts") updateCoverage();
    }

    tabButtons.forEach(button => button.addEventListener("click", () => {
        activeView = button.dataset.socView;
        render();
    }));
    document.getElementById("socStudioRefresh")?.addEventListener("click", refreshLiveAnalysis);
    document.querySelectorAll("[data-soc-open-section]").forEach(button => button.addEventListener("click", () => {
        if (typeof window.showSection === "function") window.showSection(button.dataset.socOpenSection);
    }));
    document.addEventListener("xdome:feed-ready", event => {
        if (event.detail?.complete || event.detail?.source !== "live") refreshLiveAnalysis();
    });

    render();
    loadArtifacts();
    refreshLiveAnalysis();
    setInterval(() => {
        if (!document.hidden && document.querySelector("#socstudio")?.classList.contains("active")) refreshLiveAnalysis();
    }, 60000);
})();
