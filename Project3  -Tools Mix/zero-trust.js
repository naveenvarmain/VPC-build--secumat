/* Zero Trust operations view: live xDome context plus auditable local APIs. */
const ZeroTrustView = (() => {
    const host = document.getElementById("zeroTrustApp");
    const viewTabs = document.getElementById("udpViewTabs");
    viewTabs?.addEventListener("click", event => {
        const selectedTab = event.target.closest("[data-udp-view]");
        if (!selectedTab) return;
        const selectedView = selectedTab.dataset.udpView;
        viewTabs.querySelectorAll("[data-udp-view]").forEach(tab => {
            const isSelected = tab === selectedTab;
            tab.classList.toggle("active", isSelected);
            tab.setAttribute("aria-selected", String(isSelected));
        });
        document.getElementById("udpProgramPanel").hidden = selectedView !== "program";
        document.getElementById("udpSecumatPanel").hidden = selectedView !== "secumat";
    });
    const escape = value => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
    const format = value => Number(value || 0).toLocaleString();
    const PILLARS = ["Identity", "Devices", "Networks", "Applications & Workloads", "Data", "PKI", "Visibility & Analytics", "Automation & Orchestration", "Governance", "Risk & Resilience", "IT/OT Convergence"];
    const LIVE_FEEDS = [["devices", "OT asset inventory"], ["alerts", "xDome alerts"], ["vulnerabilities", "Vulnerabilities and CVEs"], ["events", "Network events"]];
    const MATURITY_DOMAINS = [
        ["identity", "Identity"], ["device", "Device / endpoint"], ["network", "Network / SASE"], ["application", "Applications / workloads"],
        ["data", "Data security"], ["pki", "PKI / certificates"], ["analytics", "Visibility / analytics"], ["automation", "Automation / response"],
        ["governance", "Governance / accountability"], ["risk", "Risk / resilience"], ["it_ot", "IT/OT convergence"], ["ai", "AI / agent security"]
    ];
    const MATURITY_LEVELS = ["0 · Not implemented", "1 · Initial", "2 · Developing", "3 · Defined", "4 · Managed", "5 · Optimized"];
    const PROGRAM_PHASES = [
        ["awareness", "Awareness & foundation"], ["concept", "Zero Trust concept defined"], ["assessment", "Maturity assessment & gap analysis"],
        ["governance", "Governance baseline & roadmap"], ["architecture", "Target architecture & priorities"], ["initial_controls", "Initial identity/network/device controls"],
        ["all_domains", "Controls across all domains"], ["automation", "Automation, monitoring & risk-based access"],
        ["ai_controls", "AI agents, LLMs & platform controls"], ["continuous_assurance", "Continuous assurance & compliance"]
    ];
    const CONTROL_DEFINITIONS = [
        ["identity_mfa", "Phishing-resistant MFA and identity risk"], ["identity_least_privilege", "Least privilege / JIT approvals"],
        ["device_posture", "Managed device posture and EDR health"], ["network_segmentation", "Network segmentation and session policy"],
        ["sase_access", "SASE / ZTNA policy and session logging"], ["application_workload_identity", "Application and workload identity"],
        ["data_classification", "Data classification, DLP and egress control"], ["pki_certificate_health", "Certificate lifecycle and revocation checks"],
        ["central_event_analytics", "Central telemetry, detections and audit"], ["approved_response", "Approved response with rollback and evidence"],
        ["it_ot_asset_mapping", "IT/OT identity, asset and ownership mapping"]
    ];
    const AI_CONTROL_DEFINITIONS = [
        ["ai_inventory", "Approved inventory of agents, models and platforms"], ["approved_models", "Model allowlist, versioning and change review"],
        ["strong_agent_identity", "Unique workload identity and short-lived credentials"], ["least_privilege_tools", "Tool/API allowlists and scoped permissions"],
        ["sensitive_data_guardrails", "Sensitive-data classification and egress controls"], ["prompt_input_filtering", "Prompt injection and untrusted-input checks"],
        ["output_validation", "Output validation and downstream action checks"], ["human_approval", "Human approval for high-impact actions"],
        ["ai_activity_logging", "Prompt/tool/model audit with secrets excluded"], ["model_risk_review", "Model risk, provider and supply-chain review"]
    ];
    const MAX_FEED_RECORDS = 100000;
    let integrationData = null;
    let eventRows = [];
    let analyticsData = null;
    let detectionsData = null;
    let playbookData = null;
    let playbookRunResults = {};
    let autoRunDone = false;
    let eventFilter = "";
    let busy = false;
    let feedLoadBusy = false;
    let feedLoadStatus = "";
    let udpProgram = null;
    let programSaving = false;
    let programSaveStatus = "";

    function liveDeviceSummary() {
        if (!window.ClarotyAPI) return { source: "unavailable", devices: [], counts: {} };
        const state = ClarotyAPI.feedState("devices");
        const unique = [...new Map((state.data || []).filter(row => row.uid).map(row => [String(row.uid), row])).values()];
        const highRisk = unique.filter(row => ["High", "Critical"].includes(String(row.risk_score)));
        const counts = {
            unique: unique.length,
            highRisk: highRisk.length,
            critical: unique.filter(row => String(row.risk_score) === "Critical").length,
            suspicious: unique.filter(row => Array.isArray(row.suspicious) ? row.suspicious.length > 0 : Boolean(row.suspicious) && String(row.suspicious).toLowerCase() !== "false").length,
            unmanagedEvidence: unique.filter(row => row.device_category === "OT" || row.device_category === "IoT").length,
            offline: unique.filter(row => row.is_online === false || row.is_online === "false").length
        };
        return { source: state.source, complete: state.complete, fetchedAt: state.fetchedAt, error: state.error, devices: highRisk.slice(0, 12), counts };
    }

    function liveFeedRows() {
        return LIVE_FEEDS.map(([feed, label]) => {
            const state = window.ClarotyAPI?.feedState(feed);
            const records = Array.isArray(state?.data) ? state.data.length : 0;
            const status = state?.source === "error"
                ? `Error: ${state.error || "refresh to retry"}`
                : state?.source === "live"
                    ? state.complete ? "Live · all pages loaded" : "Live · partial; more pages available"
                    : state?.source === "mock" ? "Simulated data · not live" : "Not loaded";
            return `<tr><td>${escape(label)}</td><td>${format(records)}</td><td>${escape(status)}</td><td>${escape(state?.fetchedAt ? new Date(state.fetchedAt).toLocaleString() : "—")}</td></tr>`;
        }).join("");
    }

    function integrationCards() {
        const connectors = integrationData?.connectors || [];
        return PILLARS.map(pillar => {
            const entries = connectors.filter(item => item.pillar === pillar);
            const clarotyLive = Boolean(window.ClarotyAPI && ClarotyAPI.feedState("devices").source === "live");
            const liveCount = entries.filter(item => item.claroty && clarotyLive).length;
            const telemetryCount = entries.filter(item => item.status === "telemetry_received").length;
            const configuredCount = entries.filter(item => !item.claroty && item.status === "credentials_configured").length;
            const receiverCount = entries.filter(item => item.status === "event_receiver_registered").length;
            const status = liveCount ? `${liveCount} verified feed` : telemetryCount ? `${telemetryCount} sending telemetry` : configuredCount ? `${configuredCount} configured · unverified` : receiverCount ? `${receiverCount} receiver · awaiting events` : "Connector required";
            return `<article class="zt-pillar"><header><h3>${escape(pillar)}</h3><span class="zt-state ${liveCount || telemetryCount || configuredCount ? "zt-state-live" : ""}">${status}</span></header>${entries.map(item => {
                const receiverStatus = item.status === "event_receiver_registered" ? `Receiver registered · ${format(item.eventReceiver?.eventCount)} events received; vendor API not verified` : "";
                const telemetryStatus = item.status === "telemetry_received" ? `Telemetry received · ${format(item.eventReceiver?.eventCount)} events; vendor API not verified` : "";
                const itemStatus = item.claroty && clarotyLive ? "Live xDome device feed verified" : telemetryStatus || (item.status === "credentials_configured" ? "Credential configured; live connection not verified" : receiverStatus || "Not connected");
                return `<div class="zt-connector"><strong>${escape(item.capability)}</strong><span>${escape(item.providers)}</span><small>${escape(item.integration)} · ${itemStatus}</small></div>`;
            }).join("") || `<div class="zt-connector"><span>Define a provider and integration owner.</span></div>`}</article>`;
        }).join("");
    }

    const OPEN_SOURCE_ENGINES = [
        { id: "wazuh", name: "Wazuh", domain: "Endpoint SIEM / XDR", api: "REST API; agent/server alerts and JSON", connect: "Credentials · Integrations → Wazuh", href: "https://wazuh.com/platform/" },
        { id: "opensearch", name: "OpenSearch", domain: "Search / analytics", api: "REST APIs; OpenTelemetry and log shippers", connect: "Credentials · Integrations → OpenSearch", href: "https://opensearch.org/faq/" },
        { id: "suricata", name: "Suricata", domain: "Network IDS / IPS / NSM", api: "EVE JSON logs; HTTP output support", connect: "Event receiver · name it \"Suricata\"", href: "https://suricata.io/features/" },
        { id: "zeek", name: "Zeek", domain: "Network security monitoring", api: "Structured transaction logs and custom outputs", connect: "Event receiver · name it \"Zeek\"", href: "https://zeek.org/about/" },
        { id: "misp", name: "MISP", domain: "Threat intelligence / IOC sharing", api: "REST API; PyMISP; open data formats", connect: "Credentials · Integrations → MISP", href: "https://misp-project.org/" },
        { id: "keycloak", name: "Keycloak", domain: "Identity / federation", api: "OpenID Connect, OAuth 2.0, SAML 2.0", connect: "Credentials · Integrations → Keycloak", href: "https://www.keycloak.org/" },
        { id: "falco", name: "Falco", domain: "Cloud-native runtime detection", api: "Rules; HTTP, syslog, and other outputs", connect: "Event receiver · name it \"Falco\"", href: "https://falco.org/docs/" },
        { id: "trivy", name: "Trivy", domain: "Vulnerability / image / IaC scan", api: "CLI and machine-readable scan results", connect: "Credentials · Integrations → Trivy", href: "https://aquasecurity.github.io/trivy/" },
        { id: "snort_openappid", name: "Snort OpenAppID", domain: "Application identification (ODP)", api: "ODP package: appMapping.data + Lua detectors", connect: "Package · Integrations → Load OpenAppID", href: "https://www.snort.org/downloads/#openappid" }
    ];

    function openSourceEngineRows() {
        return OPEN_SOURCE_ENGINES.map(engine => {
            const readiness = integrationData?.openSourceEngines?.find(item => item.id === engine.id);
            const status = readiness?.status === "package_loaded"
                ? `Package loaded · ${escape(readiness.detail || "")}`
                : readiness?.status === "telemetry_received"
                    ? `Telemetry received · ${format(readiness.eventCount)} events`
                    : readiness?.status === "event_receiver_registered"
                        ? "Receiver registered · awaiting events"
                        : readiness?.status === "credentials_configured"
                            ? "Credentials saved · unverified"
                            : "Candidate · not connected";
            return `<tr><td><a href="${escape(engine.href)}" target="_blank" rel="noopener noreferrer">${escape(engine.name)}</a></td><td>${escape(engine.domain)}</td><td>${escape(engine.api)}</td><td>${escape(engine.connect)}</td><td>${status}</td></tr>`;
        }).join("");
    }

    function eventTable() {
        const filtered = eventRows.filter(row => !eventFilter || [row.event_type, row.source?.system, row.outcome, row.subject?.identity_id, row.device?.device_id, row.resource?.resource_id, row.network?.source_ip, row.network?.destination_ip, row.policy?.id].join(" ").toLowerCase().includes(eventFilter));
        return `<div class="zt-table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Source</th><th>Subject</th><th>Device</th><th>Resource</th><th>Network / IPs</th><th>Policy</th><th>Outcome</th></tr></thead><tbody>${filtered.map(row => `<tr><td>${escape(new Date(row.event_time).toLocaleString())}</td><td>${escape(row.event_type)}</td><td>${escape(row.source?.system)}</td><td>${escape(row.subject?.identity_id)}</td><td>${escape(row.device?.device_id || "—")}</td><td>${escape(row.resource?.resource_id || "—")}</td><td>${escape([row.network?.source_ip, row.network?.destination_ip].filter(Boolean).join(" → ") || row.context?.network_zone || "—")}</td><td>${escape(row.policy?.id || "—")}</td><td>${escape(row.outcome || "—")}</td></tr>`).join("") || `<tr><td colspan="9">No matching audit events.</td></tr>`}</tbody></table></div>`;
    }

    function defaultUdpProgram() {
        return {
            owner: "", executive_sponsor: "", review_date: "",
            maturity: Object.fromEntries(MATURITY_DOMAINS.map(([id]) => [id, null])),
            targets: Object.fromEntries(MATURITY_DOMAINS.map(([id]) => [id, 4])),
            phases: Object.fromEntries(PROGRAM_PHASES.map(([id]) => [id, "not_started"])),
            controls: Object.fromEntries(CONTROL_DEFINITIONS.map(([id]) => [id, false])),
            ai_controls: Object.fromEntries(AI_CONTROL_DEFINITIONS.map(([id]) => [id, false]))
        };
    }

    function updateUdpProgramPreview() {
        const form = document.getElementById("udpProgramForm");
        if (!form) return;
        const assessed = [];
        let gaps = 0;
        MATURITY_DOMAINS.forEach(([id]) => {
            const currentValue = form.elements[`maturity_${id}`]?.value ?? "";
            const targetValue = Number(form.elements[`target_${id}`]?.value ?? 4);
            const current = currentValue === "" ? null : Number(currentValue);
            const gap = form.querySelector(`[data-udp-domain-gap="${id}"]`);
            if (current == null || !Number.isFinite(current)) {
                if (gap) gap.textContent = "Not assessed";
                return;
            }
            assessed.push(current);
            if (current < targetValue) gaps += 1;
            if (gap) gap.textContent = current < targetValue ? `${targetValue - current} levels` : "At target";
        });
        const average = assessed.length ? assessed.reduce((sum, value) => sum + value, 0) / assessed.length : null;
        const averageNode = host.querySelector("[data-udp-average]");
        const gapsNode = host.querySelector("[data-udp-gaps]");
        const controlsNode = host.querySelector("[data-udp-controls-count]");
        const aiNode = host.querySelector("[data-udp-ai-controls-count]");
        const phasesNode = host.querySelector("[data-udp-phases-count]");
        if (averageNode) averageNode.textContent = average == null ? "Not assessed" : `${average.toFixed(1)} / 5`;
        if (gapsNode) gapsNode.textContent = String(gaps);
        if (controlsNode) controlsNode.textContent = `${CONTROL_DEFINITIONS.filter(([id]) => form.elements[`control_${id}`]?.checked).length} / ${CONTROL_DEFINITIONS.length}`;
        if (aiNode) aiNode.textContent = `${AI_CONTROL_DEFINITIONS.filter(([id]) => form.elements[`ai_${id}`]?.checked).length} / ${AI_CONTROL_DEFINITIONS.length}`;
        if (phasesNode) phasesNode.textContent = `${PROGRAM_PHASES.filter(([id]) => form.elements[`phase_${id}`]?.value === "complete").length} / ${PROGRAM_PHASES.length}`;
        const assessedNode = host.querySelector("[data-udp-assessed-count]");
        if (assessedNode) assessedNode.textContent = `${assessed.length} of ${MATURITY_DOMAINS.length} domains assessed`;
    }

    function udpProgramSection() {
        const profile = udpProgram || defaultUdpProgram();
        const assessed = MATURITY_DOMAINS.filter(([id]) => profile.maturity[id] != null);
        const average = assessed.length ? assessed.reduce((sum, [id]) => sum + profile.maturity[id], 0) / assessed.length : null;
        const gaps = assessed.filter(([id]) => profile.maturity[id] < profile.targets[id]).length;
        const implementedControls = CONTROL_DEFINITIONS.filter(([id]) => profile.controls[id]).length;
        const aiControls = AI_CONTROL_DEFINITIONS.filter(([id]) => profile.ai_controls[id]).length;
        const phaseOptions = [["not_started", "Not started"], ["planned", "Planned"], ["in_progress", "In progress"], ["complete", "Complete"], ["blocked", "Blocked"]];
        const maturityOptions = `<option value="">Not assessed</option>${MATURITY_LEVELS.map((label, value) => `<option value="${value}">${escape(label)}</option>`).join("")}`;
        return `<section class="zt-section udp-program"><div class="zt-section-head"><div><h3>UDP program foundation &amp; maturity</h3><p>Saved on this server · maturity and implementation status are self-assessed, not automatically certified.</p></div><span class="zt-state">${profile.updated_at ? `Updated ${escape(new Date(profile.updated_at).toLocaleString())}` : "Not assessed"}</span></div>
            <div class="zt-kpis udp-kpis"><div><span>Average maturity</span><strong data-udp-average>${average == null ? "Not assessed" : `${average.toFixed(1)} / 5`}</strong><small data-udp-assessed-count>${assessed.length} of ${MATURITY_DOMAINS.length} domains assessed</small></div><div><span>Domains below target</span><strong data-udp-gaps>${format(gaps)}</strong><small>Current score below target</small></div><div><span>Controls marked implemented</span><strong data-udp-controls-count>${implementedControls} / ${CONTROL_DEFINITIONS.length}</strong><small>Owner-attested · not independently verified</small></div><div><span>AI safeguards marked implemented</span><strong data-udp-ai-controls-count>${aiControls} / ${AI_CONTROL_DEFINITIONS.length}</strong><small>Evidence and review still required</small></div></div>
            <form id="udpProgramForm" class="zt-program-form"><div class="zt-program-governance"><label>Cybersecurity program owner<input name="owner" maxlength="160" value="${escape(profile.owner)}" placeholder="Team or accountable role"></label><label>Executive sponsor<input name="executive_sponsor" maxlength="160" value="${escape(profile.executive_sponsor)}" placeholder="Business owner"></label><label>Next governance review<input name="review_date" type="date" value="${escape(profile.review_date)}"></label></div>
            <p class="zt-footnote">Average maturity = mean of assessed domains only (0–5). Gap count excludes unassessed domains. Scores and implementation checks are owner-attested until evidence is connected.</p><h4>Domain maturity and target</h4><div class="zt-table-wrap"><table><thead><tr><th>Domain</th><th>Current</th><th>Target</th><th>Gap</th></tr></thead><tbody>${MATURITY_DOMAINS.map(([id, label]) => { const current = profile.maturity[id]; const target = profile.targets[id]; const gap = current == null ? "Not assessed" : current < target ? `${target - current} levels` : "At target"; return `<tr data-udp-domain="${id}"><td>${escape(label)}</td><td><select name="maturity_${id}" aria-label="${escape(label)} current maturity">${maturityOptions.replace(`value="${current}"`, `value="${current}" selected`)}</select></td><td><select name="target_${id}" aria-label="${escape(label)} target maturity">${MATURITY_LEVELS.map((level, value) => `<option value="${value}" ${value === target ? "selected" : ""}>${value} · ${escape(level.split(" · ")[1])}</option>`).join("")}</select></td><td data-udp-domain-gap="${id}">${escape(gap)}</td></tr>`; }).join("")}</tbody></table></div>
            <h4>Transformation roadmap</h4><p class="zt-footnote">Completed phases: <strong data-udp-phases-count>${PROGRAM_PHASES.filter(([id]) => profile.phases[id] === "complete").length} / ${PROGRAM_PHASES.length}</strong>. Phase state is tracked separately from control evidence.</p><div class="zt-program-phase-grid">${PROGRAM_PHASES.map(([id, label]) => `<label>${escape(label)}<select name="phase_${id}">${phaseOptions.map(([value, title]) => `<option value="${value}" ${profile.phases[id] === value ? "selected" : ""}>${title}</option>`).join("")}</select></label>`).join("")}</div>
            <h4>Cross-domain control implementation</h4><div class="zt-program-check-grid">${CONTROL_DEFINITIONS.map(([id, label]) => `<label><input type="checkbox" name="control_${id}" ${profile.controls[id] ? "checked" : ""}>${escape(label)}</label>`).join("")}</div>
            <h4>AI agents, LLMs and platform safeguards</h4><div class="zt-program-check-grid">${AI_CONTROL_DEFINITIONS.map(([id, label]) => `<label><input type="checkbox" name="ai_${id}" ${profile.ai_controls[id] ? "checked" : ""}>${escape(label)}</label>`).join("")}</div>
            <div class="zt-program-save"><button type="submit" class="xd-command" ${busy || programSaving ? "disabled" : ""}>${programSaving ? "Saving…" : "Save UDP program profile"}</button><span id="udpProgramStatus" role="status" aria-live="polite">${escape(programSaveStatus || "No credentials or secrets are stored in this profile.")}</span></div></form></section>`;
    }

    function saseSessionEvidence() {
        const rows = eventRows.filter(row => /network\.session|sase|cato/i.test(`${row.event_type || ""} ${row.source?.system || ""}`));
        const count = rows.length;
        return `<section class="zt-section"><div class="zt-section-head"><div><h3>SASE / global access telemetry</h3><p>${format(count)} matching canonical events · local audit store · no global Cato polling unless a server connector is deployed</p></div><button type="button" class="xd-link" data-xd-navigate="integrations">Configure Cato SASE</button></div>${count ? `<div class="zt-table-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Identity</th><th>Device</th><th>Resource</th><th>Zone</th><th>Decision</th><th>Policy</th></tr></thead><tbody>${rows.slice(0, 100).map(row => `<tr><td>${escape(new Date(row.event_time).toLocaleString())}</td><td>${escape(row.source?.system)}</td><td>${escape(row.subject?.identity_id || "—")}</td><td>${escape(row.device?.device_id || "—")}</td><td>${escape(row.resource?.resource_id || "—")}</td><td>${escape(row.context?.network_zone || row.network?.zone || "—")}</td><td>${escape(row.outcome || "—")}</td><td>${escape(row.policy?.id || "—")}</td></tr>`).join("")}</tbody></table></div>` : `<p class="zt-footnote">No Cato/SASE session events are loaded. Configure a Cato API card or send normalized session events to the local REST/webhook receiver. This list only shows observed local events; it does not enforce access.</p>`}</section>`;
    }

    function metricRows() {
        const metrics = analyticsData?.metrics || {};
        return Object.entries(metrics).map(([key, item]) => `<div class="zt-metric-row"><span>${escape(key.replaceAll("_", " "))}</span><strong>${item.value == null ? "Not observed" : format(item.value)}</strong><small>${item.status === "requires_source" ? `Requires ${escape(item.required_source)}` : item.status === "no_telemetry" ? "No matching telemetry in the selected window" : `${format(item.observedEvents)} events`}</small></div>`).join("");
    }

    function detectionRows() {
        const detections = detectionsData?.detections || [];
        return detections.map(item => `<article class="zt-detection"><div><span class="zt-severity zt-severity-${escape(item.severity)}">${escape(item.severity)}</span><strong>${escape(item.title)}</strong><small>${escape(item.rule_id)} · ${format(item.matched_count)} matching events · ${escape(item.response_mode)}</small></div><p>${escape(item.explanation)}</p>${item.playbook_id ? `<button type="button" class="xd-link" data-zt-open-playbook="${escape(item.playbook_id)}">Open related playbook</button>` : ""}</article>`).join("") || `<p>No rules matched the loaded event store in the selected window. Missing telemetry is not proof of no risk.</p>`;
    }

    function providerBadge(status) {
        const availability = status?.availability || "connector_required";
        const label = availability === "credentials_configured"
            ? `credentials saved${status.configured_tools?.length ? ` · ${status.configured_tools.join(", ")}` : ""}`
            : availability === "event_receiver_registered"
                ? `receiver registered${status.event_receivers?.length ? ` · ${status.event_receivers.join(", ")}` : ""}`
                : availability === "manual_human_step"
                    ? "manual human step"
                    : "no connector";
        return `<span class="zt-prov zt-prov-${escape(availability)}">${escape(status?.provider || "")} · ${escape(label)}</span>`;
    }

    function latestRunFor(playbookId) {
        return (playbookData?.runs || []).find(run => run.playbook_id === playbookId) || null;
    }

    function runActionRows(run) {
        if (!run) return `<p class="zt-footnote">No dry run recorded yet.</p>`;
        return `<div class="zt-run-actions"><strong>Last dry run ${escape(new Date(run.created_at).toLocaleString())}</strong><ol>${(run.actions || []).map(action => `<li>${escape(action.name)} <small>${escape(action.provider)} · ${escape(action.provider_availability || "connector_required")}${action.requires_approval ? " · approval required" : ""} · not executed</small></li>`).join("")}</ol></div>`;
    }

    function playbookRows() {
        const playbooks = playbookData?.playbooks || [];
        return playbooks.map(book => {
            const statuses = book.provider_status || [];
            const connected = book.connected_providers ?? 0;
            const total = book.total_providers ?? (book.requires || []).length;
            const chips = statuses.length
                ? statuses.map(providerBadge).join("")
                : (book.requires || []).map(escape).join(" · ");
            return `<article class="zt-playbook"><div><h4>${escape(book.name)}</h4><p>Trigger: ${escape(book.trigger)}</p><p class="zt-prov-summary">Connectors available: ${format(connected)} of ${format(total)}</p><div class="zt-prov-list">${chips}</div><ol>${book.actions.map(action => `<li>${escape(action)}</li>`).join("")}</ol>${runActionRows(latestRunFor(book.id))}</div><label>Dry-run trigger<input type="text" maxlength="500" data-zt-playbook-trigger="${escape(book.id)}" placeholder="Optional detection or event context"></label><button type="button" class="xd-command" data-zt-playbook-run="${escape(book.id)}">Run dry run</button><div role="status" data-zt-playbook-result="${escape(book.id)}">${escape(playbookRunResults[book.id] || "External actions are not connected and will not execute.")}</div></article>`;
        }).join("");
    }

    function render() {
        if (!host) return;
        const live = liveDeviceSummary();
        const source = live.source === "live" ? `${format(live.counts.unique)} unique xDome devices · ${live.complete ? "all pages loaded" : "partial feed"}${live.fetchedAt ? ` · ${escape(new Date(live.fetchedAt).toLocaleString())}` : ""}` : live.source === "error" ? `xDome feed failed: ${escape(live.error || "refresh to retry")}` : "xDome device feed is not loaded";
        const displayedEvents = eventTable();
        host.innerHTML = `<div class="zt-header"><div><span class="zt-eyebrow">CYBERSECURITY &amp; TRUST · IT/OT CONVERGENCE</span><h2>Unified Defense Platform</h2><p>Identity · Data · Network · Device · Risk</p></div><button type="button" class="xd-command" data-zt-refresh ${busy || feedLoadBusy ? "disabled" : ""}>${busy ? "Refreshing…" : feedLoadBusy ? "Loading xDome feeds…" : "Refresh live context"}</button></div>
            <div class="zt-notice"><strong>Unified analytics; enforcement is not connected.</strong> Analytics use canonical local audit events and available provider feeds. Policy results below are simulations; this console does not grant access, revoke sessions, isolate devices, or change Cato/DC2Cloud policy.</div>
            <div class="zt-kpis"><div><span>Live xDome devices</span><strong>${format(live.counts.unique)}</strong><small>${escape(source)}</small></div><div><span>High / critical risk</span><strong>${format(live.counts.highRisk)}</strong><small>${format(live.counts.critical)} critical · loaded feed</small></div><div><span>OT / IoT assets</span><strong>${format(live.counts.unmanagedEvidence)}</strong><small>Category signal, not a compliance verdict</small></div><div><span>Suspicious signal</span><strong>${format(live.counts.suspicious)}</strong><small>From xDome suspicious field; zero can mean no signal reported</small></div></div>
            ${udpProgramSection()}
            <section class="zt-section"><div class="zt-section-head"><div><h3>Live xDome telemetry</h3><p>Live OT feeds are shown independently from canonical security-event analytics. Partial feeds have more pages available.</p></div><button type="button" class="xd-command" data-zt-load-all-feeds ${busy || feedLoadBusy ? "disabled" : ""}>${feedLoadBusy ? "Loading pages…" : "Load remaining xDome pages"}</button></div><div class="zt-table-wrap"><table><thead><tr><th>Feed</th><th>Records loaded</th><th>Coverage</th><th>Last update</th></tr></thead><tbody>${liveFeedRows()}</tbody></table></div><p class="zt-footnote" role="status">${escape(feedLoadStatus || `Loads up to ${format(MAX_FEED_RECORDS)} records per feed. Provider limits can leave feeds partial.`)}</p></section>
            <div class="zt-two-col"><section class="zt-section"><div class="zt-section-head"><div><h3>Security analytics coverage</h3><p>${format(analyticsData?.events_evaluated)} canonical events · ${format(analyticsData?.lookback_hours || 24)} hour window · ${escape(analyticsData?.source || "loading")} · xDome feeds shown above</p></div></div><div class="zt-metric-grid">${metricRows()}</div></section>
            <section class="zt-section"><div class="zt-section-head"><div><h3>AI risk score</h3><p>Deterministic five-factor score. This is not machine learning or an enforcement decision.</p></div></div><form id="ztRiskForm" class="zt-form"><label>Subject ID<input name="subjectId" maxlength="160" placeholder="user-id"></label>${["identity", "device", "application", "data", "location"].map(name => `<label>${escape(name)} risk (0–100)<input name="${name}" type="number" min="0" max="100" value="0" required></label>`).join("")}<button class="xd-command" type="submit">Calculate risk score</button></form><div id="ztRiskResult" class="zt-result" role="status" aria-live="polite"></div></section></div>
            <section class="zt-section"><div class="zt-section-head"><div><h3>Detection rules</h3><p>${format(detectionsData?.events_evaluated)} canonical events · ${format(detectionsData?.rules_evaluated)} rules · ${format(detectionsData?.lookback_minutes || 30)} minute window · local event store only</p></div><button type="button" class="xd-command" data-zt-run-detections>Run rules</button></div><div class="zt-detection-list">${detectionRows()}</div></section>
            <section class="zt-section"><div class="zt-section-head"><div><h3>Cybersecurity &amp; Trust Integration Matrix</h3><p>Identity, data, network/SASE, devices, risk, and IT/OT capabilities. Credentials and registered receivers are not verified live connections.</p></div><button type="button" class="xd-link" data-xd-navigate="integrations">Open integration settings</button></div><div class="zt-pillar-grid">${integrationCards()}</div></section>
            ${saseSessionEvidence()}
            <section class="zt-section"><div class="zt-section-head"><div><h3>Free / open-source engine fit</h3><p>Self-hostable core projects; operations, infrastructure, commercial support, and threat-feed subscriptions may still cost money.</p></div></div><div class="zt-table-wrap"><table><thead><tr><th>Project</th><th>Domain</th><th>Integration surface</th><th>How to connect</th><th>Local readiness</th></tr></thead><tbody>${openSourceEngineRows()}</tbody></table></div></section>
            <section class="zt-section"><div class="zt-section-head"><div><h3>Automation playbooks</h3><p>Audited dry runs only. Provider actions require their named connector and approval.</p></div></div><div class="zt-playbook-grid">${playbookRows()}</div><h4>Recent playbook runs</h4>${(playbookData?.runs || []).slice(0, 10).map(run => `<div class="zt-run-row"><strong>${escape(run.playbook_name)}</strong><span>${escape(new Date(run.created_at).toLocaleString())}</span><span>${escape(run.mode)} · no external actions executed</span></div>`).join("") || `<p>No playbook runs yet.</p>`}</section>
            <div class="zt-two-col"><section class="zt-section"><div class="zt-section-head"><div><h3>Policy Decision Tester</h3><p>Submits a canonical subject, device, resource, and session context to the local decision API.</p></div></div><form id="ztPolicyForm" class="zt-form">
                <label>Identity ID<input name="identity" maxlength="160" placeholder="user-id" required></label>
                <label>Identity risk<select name="identityRisk"><option>unknown</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
                <label>Authentication strength<select name="authStrength"><option value="none">Not verified</option><option value="mfa">MFA</option><option value="phishing-resistant">Phishing-resistant</option><option value="fido2">FIDO2</option><option value="certificate">Certificate</option></select></label>
                <label>Device ID<input name="device" maxlength="160" placeholder="device-id" required></label>
                <label>Managed<select name="managed"><option value="unknown">Unknown</option><option value="true">Managed</option><option value="false">Unmanaged</option></select></label>
                <label>Compliant<select name="compliant"><option value="unknown">Unknown</option><option value="true">Compliant</option><option value="false">Noncompliant</option></select></label>
                <label>EDR risk<select name="edrRisk"><option>unknown</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
                <label>Device certificate<select name="certificate"><option>unknown</option><option>valid</option><option>expired</option><option>revoked</option><option>invalid</option></select></label>
                <label>Resource ID<input name="resource" maxlength="160" placeholder="application-or-data-id" required></label>
                <label>Data classification<select name="classification"><option>internal</option><option>public</option><option>confidential</option><option>restricted</option></select></label>
                <label>Action<input name="action" maxlength="160" value="read" required></label>
                <label>Network zone<select name="networkZone"><option>unknown</option><option>trusted</option><option>managed</option><option>untrusted</option></select></label>
                <label>Session age (minutes)<input name="sessionAge" type="number" min="0" max="100000" value="0" required></label>
                <button class="xd-command" type="submit">Evaluate simulated policy</button>
            </form><div id="ztDecisionResult" class="zt-result" role="status" aria-live="polite"></div></section>
            <section class="zt-section"><div class="zt-section-head"><div><h3>Device Trust Evidence</h3><p>Live risk evidence only. MDM compliance, EDR health, encryption, and certificate status require their own connectors.</p></div><button type="button" class="xd-link" data-xd-navigate="devices">Open device inventory</button></div><div class="zt-table-wrap"><table><thead><tr><th>Device</th><th>Site</th><th>Category</th><th>Risk</th><th>Connectivity</th></tr></thead><tbody>${live.devices.map(row => `<tr><td>${escape(row.device_name || row.uid)}</td><td>${escape(row.site_name || "—")}</td><td>${escape(row.device_category || "—")}</td><td>${escape(row.risk_score || "Unknown")}</td><td>${row.is_online == null ? "Unknown" : row.is_online === true || row.is_online === "true" ? "Online" : "Offline"}</td></tr>`).join("") || `<tr><td colspan="5">${escape(source)}</td></tr>`}</tbody></table></div><p class="zt-footnote">A device is not marked trusted from a single Boolean. Current xDome inventory is context, not a complete trust decision.</p></section></div>
            <div class="zt-two-col"><section class="zt-section"><div class="zt-section-head"><div><h3>Security Event Ingestion</h3><p>Canonical audit events for identity, SASE, workload, data, and device telemetry. Never submit passwords, tokens, keys, or other secrets.</p></div></div><form id="ztEventForm" class="zt-form zt-event-form"><label>Event type<select name="eventType"><option>device.posture.changed</option><option>credential.lifecycle</option><option>certificate.status</option><option>security.alert</option><option>network.session</option><option>sase.access.session</option><option>cloud.workload.finding</option><option>data.activity</option><option>ai.agent.activity</option><option>ai.policy.denied</option><option>access.policy.decided</option></select></label><label>Source system<input name="source" maxlength="100" value="zero-trust-console" required></label><label>Subject ID<input name="subject" maxlength="160" placeholder="user-id, service-id, or agent-id"></label><label>Subject type<select name="subjectType"><option value="workforce">Workforce</option><option value="service">Service</option><option value="agent">AI agent</option><option value="workload">Workload</option></select></label><label>Device ID<input name="device" maxlength="160" placeholder="device-id"></label><label>Resource ID<input name="resource" maxlength="160" placeholder="application, data, or cloud resource"></label><label>Source IP<input name="sourceIp" maxlength="64" placeholder="10.0.0.10"></label><label>Destination IP<input name="destinationIp" maxlength="64" placeholder="10.0.0.20"></label><label>Network zone<input name="networkZone" maxlength="80" placeholder="trusted, remote, OT zone"></label><label>Policy ID<input name="policyId" maxlength="160" placeholder="policy reference"></label><label>Outcome<select name="outcome"><option>observed</option><option>allowed</option><option>success</option><option>step_up</option><option>denied</option><option>blocked</option><option>failure</option></select></label><label>Reason code<input name="reason" maxlength="120" placeholder="OPTIONAL_REASON_CODE"></label><button class="xd-command" type="submit">Write audit event</button></form><div id="ztEventStatus" role="status"></div></section>
            <section class="zt-section"><div class="zt-section-head"><div><h3>Local Audit Events</h3><p>Newest 100 local events · ${eventRows.length} loaded</p></div><button type="button" class="xd-link" data-zt-events-refresh>Reload events</button></div><label class="zt-event-filter">Filter events<input id="ztEventSearch" type="search" placeholder="Event, source, outcome, subject"></label><div id="ztEventTable">${displayedEvents}</div></section></div>`;
    }

    async function loadEvents() {
        const response = await fetch("/api/zero-trust/events?limit=100", { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Audit event API unavailable");
        eventRows = payload.records || [];
    }

    async function autoRunPlaybooks() {
        if (autoRunDone) return;
        autoRunDone = true;
        try {
            const response = await fetch("/api/zero-trust/playbooks/run-all", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ trigger: "automatic dry run on dashboard load" })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Playbook auto-run failed");
            (payload.runs || []).forEach(run => {
                playbookRunResults[run.playbook_id] = `Auto dry run ${run.run_id} recorded · ${run.connected_providers ?? 0} of ${run.total_providers ?? (run.actions || []).length} connectors available · no external action executed.`;
            });
            const [playbooksResponse, analyticsResponse, detectionsResponse] = await Promise.all([
                fetch("/api/zero-trust/playbooks?limit=100", { cache: "no-store" }),
                fetch("/api/zero-trust/analytics?hours=24", { cache: "no-store" }),
                fetch("/api/zero-trust/detections?lookback_minutes=30", { cache: "no-store" })
            ]);
            if (playbooksResponse.ok) playbookData = await playbooksResponse.json();
            if (analyticsResponse.ok) analyticsData = await analyticsResponse.json();
            if (detectionsResponse.ok) detectionsData = await detectionsResponse.json();
        } catch (error) {
            playbookRunResults.autoRunError = error.message;
        }
    }

    async function loadLocalContext() {
        const integrationResponse = await fetch("/api/zero-trust/integrations", { cache: "no-store" });
        integrationData = await integrationResponse.json();
        if (!integrationResponse.ok) throw new Error(integrationData.error || "Integration status unavailable");
        const [analyticsResponse, detectionsResponse, playbooksResponse, programResponse] = await Promise.all([
            fetch("/api/zero-trust/analytics?hours=24", { cache: "no-store" }),
            fetch("/api/zero-trust/detections?lookback_minutes=30", { cache: "no-store" }),
            fetch("/api/zero-trust/playbooks?limit=100", { cache: "no-store" }),
            fetch("/api/zero-trust/program", { cache: "no-store" })
        ]);
        const [analytics, detections, playbooks, program] = await Promise.all([analyticsResponse.json(), detectionsResponse.json(), playbooksResponse.json(), programResponse.json()]);
        if (!analyticsResponse.ok || !detectionsResponse.ok || !playbooksResponse.ok || !programResponse.ok) throw new Error("Zero Trust analytics or program API unavailable");
        analyticsData = analytics;
        detectionsData = detections;
        playbookData = playbooks;
        udpProgram = program?.profile || defaultUdpProgram();
    }

    function reportError(message) {
        const target = document.getElementById("ztEventStatus");
        if (target) target.textContent = message;
    }

    async function refresh(refreshLiveContext = false) {
        if (busy) return;
        busy = true;
        render();
        // Local APIs are fast; render them before the multi-minute xDome feed load so the
        // page is never left blank showing "Connector required" for every pillar.
        try {
            await loadLocalContext();
            await autoRunPlaybooks();
            await loadEvents();
        } catch (error) {
            reportError(error.message);
        }
        busy = false;
        render();

        try {
            if (window.ClarotyAPI && !ClarotyAPI.canGoLive()) await ClarotyAPI.enableBackendUse();
            const deviceFeed = window.ClarotyAPI?.feedState("devices");
            const shouldLoadLive = refreshLiveContext || (ClarotyAPI?.canGoLive() && deviceFeed?.source === "pending");
            if (shouldLoadLive && window.XDPortal) {
                feedLoadBusy = true;
                render();
                await window.XDPortal.refresh(refreshLiveContext);
            }
        } catch (error) {
            reportError(error.message);
        } finally {
            feedLoadBusy = false;
            render();
        }
    }

    host?.addEventListener("click", async event => {
        if (event.target.closest("[data-zt-load-all-feeds]")) {
            if (busy || feedLoadBusy) return;
            feedLoadBusy = true;
            feedLoadStatus = "Starting xDome feed pagination…";
            render();
            try {
                if (!window.ClarotyAPI?.canGoLive()) throw new Error("Configure and verify Claroty credentials before loading live feeds.");
                for (const [feed, label] of LIVE_FEEDS) {
                    feedLoadStatus = `Loading ${label}…`;
                    render();
                    const result = await ClarotyAPI.loadAllFeed(feed, 5000, MAX_FEED_RECORDS, progress => {
                        feedLoadStatus = `${label}: ${format(progress.loaded)} records${progress.complete ? " · complete" : " loaded"}`;
                        render();
                    });
                    if (result.source !== "live") throw new Error(`${label}: ${result.error || "live feed unavailable"}`);
                }
                feedLoadStatus = LIVE_FEEDS.every(([feed]) => ClarotyAPI.feedState(feed).complete)
                    ? "All available xDome feed pages are loaded."
                    : `The ${format(MAX_FEED_RECORDS)}-record per-feed limit was reached; some feeds remain partial.`;
            } catch (error) {
                feedLoadStatus = `Feed loading stopped: ${error.message}`;
            } finally {
                feedLoadBusy = false;
                render();
            }
        }
        if (event.target.closest("[data-zt-refresh]")) {
            await refresh(true);
        }
        if (event.target.closest("[data-zt-events-refresh]")) await refresh();
        if (event.target.closest("[data-zt-run-detections]")) {
            const button = event.target.closest("[data-zt-run-detections]");
            button.disabled = true;
            try {
                const response = await fetch("/api/zero-trust/detections/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ lookback_minutes: 30 }) });
                detectionsData = await response.json();
                if (!response.ok) throw new Error(detectionsData.error || "Detection API failed");
                render();
            } catch (error) {
                button.disabled = false;
                button.textContent = error.message;
            }
        }
        const playbookButton = event.target.closest("[data-zt-playbook-run]");
        if (playbookButton) {
            const playbookId = playbookButton.dataset.ztPlaybookRun;
            const trigger = host.querySelector(`[data-zt-playbook-trigger="${playbookId}"]`)?.value.trim() || "manual dry run";
            const result = host.querySelector(`[data-zt-playbook-result="${playbookId}"]`);
            playbookButton.disabled = true;
            if (result) result.textContent = "Recording dry run…";
            try {
                const response = await fetch("/api/zero-trust/playbooks/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ playbook_id: playbookId, trigger }) });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.error || "Playbook API failed");
                playbookRunResults[playbookId] = `Dry run ${payload.run_id} recorded; all ${payload.actions.length} external actions remain connector-required.`;
                const listResponse = await fetch("/api/zero-trust/playbooks?limit=100", { cache: "no-store" });
                playbookData = await listResponse.json();
                render();
            } catch (error) {
                if (result) result.textContent = error.message;
                playbookButton.disabled = false;
            }
        }
        const openPlaybook = event.target.closest("[data-zt-open-playbook]");
        if (openPlaybook) host.querySelector(`[data-zt-playbook-trigger="${openPlaybook.dataset.ztOpenPlaybook}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
    host?.addEventListener("input", event => {
        if (event.target.closest("#udpProgramForm")) {
            updateUdpProgramPreview();
            return;
        }
        if (event.target.id === "ztEventSearch") {
            eventFilter = event.target.value.trim().toLowerCase();
            const table = document.getElementById("ztEventTable");
            if (table) table.innerHTML = eventTable();
        }
    });
    host?.addEventListener("change", event => {
        if (event.target.closest("#udpProgramForm")) updateUdpProgramPreview();
    });
    host?.addEventListener("submit", async event => {
        event.preventDefault();
        const form = event.target;
        if (form.id === "udpProgramForm") {
            const data = new FormData(form);
            const payload = {
                owner: data.get("owner") || "",
                executive_sponsor: data.get("executive_sponsor") || "",
                review_date: data.get("review_date") || "",
                maturity: Object.fromEntries(MATURITY_DOMAINS.map(([id]) => [id, data.get(`maturity_${id}`) === "" ? null : Number(data.get(`maturity_${id}`))])),
                targets: Object.fromEntries(MATURITY_DOMAINS.map(([id]) => [id, Number(data.get(`target_${id}`))])),
                phases: Object.fromEntries(PROGRAM_PHASES.map(([id]) => [id, data.get(`phase_${id}`)])),
                controls: Object.fromEntries(CONTROL_DEFINITIONS.map(([id]) => [id, data.has(`control_${id}`)])),
                ai_controls: Object.fromEntries(AI_CONTROL_DEFINITIONS.map(([id]) => [id, data.has(`ai_${id}`)]))
            };
            programSaving = true;
            programSaveStatus = "Saving UDP profile…";
            render();
            try {
                const response = await fetch("/api/zero-trust/program", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Could not save UDP profile");
                udpProgram = result.profile;
                programSaveStatus = "Saved to this local server · self-assessment is not independently verified";
            } catch (error) {
                programSaveStatus = `Save failed: ${error.message}`;
            } finally {
                programSaving = false;
                render();
            }
            return;
        }
        if (form.id === "ztPolicyForm") {
            const data = new FormData(form);
            const payload = {
                subject: { id: data.get("identity"), risk: data.get("identityRisk"), authentication_strength: data.get("authStrength") },
                device: { id: data.get("device"), managed: data.get("managed") === "unknown" ? null : data.get("managed") === "true", compliant: data.get("compliant") === "unknown" ? null : data.get("compliant") === "true", edr_risk: data.get("edrRisk"), certificate_status: data.get("certificate") },
                resource: { id: data.get("resource"), classification: data.get("classification") },
                action: data.get("action"),
                context: { network_zone: data.get("networkZone"), session_age_minutes: Number(data.get("sessionAge")) }
            };
            const resultHost = document.getElementById("ztDecisionResult");
            resultHost.textContent = "Evaluating…";
            try {
                const response = await fetch("/api/zero-trust/policy/decision", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Decision API failed");
                resultHost.innerHTML = `<div class="zt-decision zt-decision-${escape(result.decision)}"><strong>${escape(result.decision.replaceAll("_", " ").toUpperCase())}</strong><span>Simulation only · ${escape(result.decision_id)}</span><span>Expires ${escape(new Date(result.expires_at).toLocaleTimeString())} · ${escape(result.policy_version)}</span><h4>Reason codes</h4><p>${result.reason_codes.map(escape).join(" · ")}</p><h4>Obligations</h4><p>${result.obligations.map(escape).join(" · ")}</p></div>`;
                await loadEvents();
                const table = document.getElementById("ztEventTable");
                if (table) table.innerHTML = eventTable();
            } catch (error) { resultHost.textContent = error.message; }
        }
        if (form.id === "ztRiskForm") {
            const data = new FormData(form);
            const components = Object.fromEntries(["identity", "device", "application", "data", "location"].map(name => [name, Number(data.get(name))]));
            const resultHost = document.getElementById("ztRiskResult");
            resultHost.textContent = "Calculating…";
            try {
                const response = await fetch("/api/zero-trust/risk/score", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subject_id: data.get("subjectId") || "unknown", components }) });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Risk API failed");
                resultHost.innerHTML = `<div class="zt-decision zt-decision-${escape(result.decision)}"><strong>${format(result.score)} / 100 · ${escape(result.decision.replaceAll("_", " ").toUpperCase())}</strong><span>Raw sum ${format(result.raw_total)} · ${escape(result.method)} · ${escape(result.enforcement)}</span></div>`;
                await loadEvents();
            } catch (error) { resultHost.textContent = error.message; }
        }
        if (form.id === "ztEventForm") {
            const data = new FormData(form);
            const resourceId = String(data.get("resource") || "").trim();
            const sourceIp = String(data.get("sourceIp") || "").trim();
            const destinationIp = String(data.get("destinationIp") || "").trim();
            const networkZone = String(data.get("networkZone") || "").trim();
            const policyId = String(data.get("policyId") || "").trim();
            const event = {
                event_version: "1.0", event_type: data.get("eventType"), event_time: new Date().toISOString(),
                source: { system: data.get("source"), environment: "local" },
                subject: { identity_id: data.get("subject") || "unknown", identity_type: data.get("subjectType") || "workforce" },
                device: { device_id: data.get("device") || "unknown" }, outcome: data.get("outcome"), reason_code: data.get("reason") || null,
                context: { network_zone: networkZone || null },
                ...(resourceId ? { resource: { resource_id: resourceId } } : {}),
                ...(sourceIp || destinationIp ? { network: { source_ip: sourceIp || null, destination_ip: destinationIp || null } } : {}),
                ...(policyId ? { policy: { id: policyId } } : {})
            };
            const status = document.getElementById("ztEventStatus");
            status.textContent = "Submitting…";
            try {
                const response = await fetch("/api/zero-trust/events", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(event) });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Event API failed");
                status.textContent = `Accepted ${result.event.event_id} · ${result.event.received_at}`;
                form.reset();
                form.querySelector('[name="source"]').value = "zero-trust-console";
                await loadEvents();
                const table = document.getElementById("ztEventTable");
                if (table) table.innerHTML = eventTable();
            } catch (error) { status.textContent = error.message; }
        }
    });

    return { render, refresh };
})();

window.ZeroTrustView = ZeroTrustView;