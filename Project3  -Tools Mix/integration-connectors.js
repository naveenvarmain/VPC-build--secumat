const ConnectorManager = (() => {
    const form = document.getElementById("connectorCreateForm");
    const status = document.getElementById("connectorStatus");
    const rows = document.getElementById("connectorRows");
    const created = document.getElementById("connectorCreated");
    const rubrikLiveRows = document.getElementById("rubrikLiveRows");
    const rubrikLiveStatus = document.getElementById("rubrikLiveStatus");
    const rubrikFeedToggle = document.getElementById("rubrikFeedToggle");
    const rubrikFeedReadiness = document.getElementById("rubrikFeedReadiness");
    const connectedConnectorFeeds = document.getElementById("connectedConnectorFeeds");
    const connectedToolsStatus = document.getElementById("connectedToolsStatus");
    const integrationEventRows = document.getElementById("integrationEventRows");
    const integrationEventStatus = document.getElementById("integrationEventStatus");
    let currentConnector = null;
    let rubrikLiveRequestActive = false;
    let rubrikFeedEnabled = true;
    let rubrikCursor = { activity: null, audit: null, activityDone: false, auditDone: false };
    let rubrikEvents = new Map();
    let rubrikCounts = { activity: 0, audit: 0, routed: 0 };

    const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
    const displayTime = value => value ? new Date(value).toLocaleString() : "Never";
    const displayRubrikTime = value => value ? new Date(value).toLocaleString() : "Unknown";
    const connectorUrlKey = id => `integration-connector-url:${id}`;
    const connectorEndpoint = connector => connector.endpoint || `/api/integrations/connectors/${encodeURIComponent(connector.id)}/ingest`;
    const connectorEnabled = connector => connector.enabled !== false;
    const integrationPanelVisible = () => document.visibilityState === "visible"
        && Boolean(document.getElementById("rubrikLiveTitle")?.getClientRects().length);
    function savedIngestUrl(connector) {
        try {
            return localStorage.getItem(connectorUrlKey(connector.id)) || location.origin + connectorEndpoint(connector);
        } catch {
            return location.origin + connectorEndpoint(connector);
        }
    }
    function validIngestUrl(value) {
        try {
            return ["http:", "https:"].includes(new URL(value).protocol);
        } catch {
            return false;
        }
    }

    async function loadRubrikActivities() {
        if (!rubrikLiveRows || rubrikLiveRequestActive || !integrationPanelVisible()) return;
        if (!rubrikFeedEnabled) {
            rubrikLiveStatus.textContent = "Rubrik API feed is disabled. Turn it on in Connected tool feeds to resume polling.";
            rubrikLiveRows.innerHTML = `<tr><td colspan="10">Rubrik polling is disabled; existing module records remain available.</td></tr>`;
            return;
        }
        rubrikLiveRequestActive = true;
        rubrikCursor = { activity: null, audit: null, activityDone: false, auditDone: false };
        rubrikEvents = new Map();
        rubrikCounts = { activity: 0, audit: 0, routed: 0 };
        rubrikLiveStatus.textContent = "Fetching recent activity from Rubrik…";
        try {
            await loadRubrikPage();
            loadIntegrationEvents();
        } catch (error) {
            rubrikLiveStatus.textContent = `Rubrik live data unavailable: ${error.message}`;
            if (!rubrikEvents.size) rubrikLiveRows.innerHTML = `<tr><td colspan="10">Could not load Rubrik activity. Check the integration credentials and API access.</td></tr>`;
        } finally {
            rubrikLiveRequestActive = false;
        }
    }

    async function loadRubrikPage() {
        const params = new URLSearchParams({ lookback_minutes: "1440" });
        if (rubrikCursor.activity) params.set("activity_after", rubrikCursor.activity);
        if (rubrikCursor.audit) params.set("audit_after", rubrikCursor.audit);
        if (rubrikCursor.activityDone) params.set("activity_done", "true");
        if (rubrikCursor.auditDone) params.set("audit_done", "true");
        const response = await fetch(`/api/integrations/rubrik/events?${params}`, { cache: "no-store" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `Rubrik API request failed (${response.status})`);
        (Array.isArray(payload.events) ? payload.events : []).forEach(item => {
            const key = `${item.eventClass}:${item.id || `${item.time}:${item.title}`}`;
            rubrikEvents.set(key, item);
        });
        rubrikCounts.activity += Number(payload.activityCount) || 0;
        rubrikCounts.audit += Number(payload.auditCount) || 0;
        rubrikCounts.routed += Number(payload.routedCount) || 0;
        rubrikCursor.activity = payload.nextActivityCursor || null;
        rubrikCursor.audit = payload.nextAuditCursor || null;
        rubrikCursor.activityDone = !payload.hasMoreActivities;
        rubrikCursor.auditDone = !payload.hasMoreAuditEvents;

        const events = [...rubrikEvents.values()].sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
        rubrikLiveRows.innerHTML = events.map(item => {
            const details = JSON.stringify(item, null, 2);
            const route = Array.isArray(item.routedModules) ? item.routedModules.join(", ") : "integration events";
            const indicatorText = Array.isArray(item.indicators) && item.indicators.length
                ? item.indicators.map(indicator => typeof indicator === "string" ? indicator : `${indicator.type || "IOC"}: ${indicator.value || ""}`).join(", ")
                : "Not provided by Rubrik API";
            return `<tr><td>${escapeHtml(displayRubrikTime(item.time))}</td><td>${escapeHtml(item.eventClass)} · ${escapeHtml(item.activityType)}</td><td>${escapeHtml(item.title || item.activityType)}</td><td>${escapeHtml(item.status)} / ${escapeHtml(item.severity)}</td><td>${escapeHtml(item.source || "Rubrik Security Cloud API")}</td><td>${escapeHtml(item.deviceName || item.actor || item.id || "Not reported")}${item.deviceType ? ` · ${escapeHtml(item.deviceType)}` : ""}</td><td>${escapeHtml(item.path || "Not provided by Rubrik API")}</td><td>${escapeHtml(indicatorText)}</td><td>${escapeHtml(route)}</td><td><details><summary>View details</summary><pre>${escapeHtml(details)}</pre></details></td></tr>`;
        }).join("") || `<tr><td colspan="10">No Rubrik activity or audit events found in this time range.</td></tr>`;
        const more = !rubrikCursor.activityDone || !rubrikCursor.auditDone;
        const loadMore = document.getElementById("rubrikLiveLoadMore");
        if (loadMore) {
            loadMore.hidden = !more;
            loadMore.disabled = false;
        }
        const pageNote = more ? " · more records available — load the next page" : "";
        rubrikLiveStatus.textContent = `Live API data · ${rubrikCounts.activity} workload activities + ${rubrikCounts.audit} audit events loaded from the last 24 hours · ${rubrikCounts.routed} records synchronized to module storage · synced ${displayRubrikTime(payload.syncedAt)}${pageNote}`;
    }

    async function loadMoreRubrikActivities() {
        const button = document.getElementById("rubrikLiveLoadMore");
        if (rubrikLiveRequestActive || !rubrikFeedEnabled || (rubrikCursor.activityDone && rubrikCursor.auditDone)) return;
        rubrikLiveRequestActive = true;
        if (button) button.disabled = true;
        rubrikLiveStatus.textContent = "Loading the next page of Rubrik activity…";
        try {
            await loadRubrikPage();
            loadIntegrationEvents();
        } catch (error) {
            rubrikLiveStatus.textContent = `Could not load the next Rubrik page: ${error.message}`;
            if (button) button.disabled = false;
        } finally {
            rubrikLiveRequestActive = false;
        }
    }

    async function loadIntegrationEvents() {
        if (!integrationEventRows || !integrationPanelVisible()) return;
        try {
            const response = await fetch("/api/zero-trust/events?limit=100", { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || `Integration logs request failed (${response.status})`);
            const events = Array.isArray(payload.records) ? payload.records : [];
            integrationEventRows.innerHTML = events.map(event => {
                const source = event.source?.system || "Unknown source";
                const device = event.device?.device_name || event.device?.device_id || event.resource?.resource_name || event.resource?.resource_id || "Not reported";
                const path = event.path || event.network?.request_path || event.details?.request_path || "Not reported";
                const indicators = Array.isArray(event.indicators) ? event.indicators : [];
                const iocs = indicators.length
                    ? indicators.map(item => typeof item === "string" ? item : `${item.type || "IOC"}: ${item.value || ""}`).join(", ")
                    : event.ioc || "Not reported";
                const route = event.routing?.modules || event.routed_modules || ["integration events"];
                return `<tr><td>${escapeHtml(displayRubrikTime(event.event_time))}</td><td>${escapeHtml(event.event_type)}</td><td>${escapeHtml(source)}</td><td>${escapeHtml(device)}</td><td>${escapeHtml(path)}</td><td>${escapeHtml(iocs)}</td><td>${escapeHtml(Array.isArray(route) ? route.join(", ") : route)}</td><td><details><summary>View full event</summary><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre></details></td></tr>`;
            }).join("") || `<tr><td colspan="8">No inbound canonical events have been received yet.</td></tr>`;
            integrationEventStatus.textContent = `${payload.count || 0} canonical events loaded from the local event log; newest first.`;
        } catch (error) {
            integrationEventStatus.textContent = `Could not load integration logs: ${error.message}`;
            integrationEventRows.innerHTML = `<tr><td colspan="8">Integration log request failed.</td></tr>`;
        }
    }

    async function loadFeedSettings() {
        try {
            const response = await fetch("/api/integrations/feed-state", { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not load feed settings");
            rubrikFeedEnabled = payload.rubrikApiEnabled !== false;
            rubrikFeedToggle?.setAttribute("aria-checked", String(rubrikFeedEnabled));
            rubrikFeedToggle.textContent = rubrikFeedEnabled ? "On" : "Off";
            rubrikFeedToggle.disabled = false;
            const configured = payload.rubrikApiConfigured === true;
            rubrikFeedReadiness.textContent = configured
                ? (rubrikFeedEnabled ? "Enabled · API access checked on refresh" : "Disabled")
                : "Not configured · add credentials below";
            rubrikFeedReadiness.className = `ifc-status ${rubrikFeedEnabled && configured ? "ok" : "uncfg"}`;
            document.getElementById("otherFeedStatus").textContent =
                "Vendor settings without implemented server polling are not shown as connected. Configure inbound sources below to accept their events.";
        } catch (error) {
            connectedToolsStatus.textContent = `Could not load feed settings: ${error.message}`;
            if (rubrikFeedToggle) {
                rubrikFeedToggle.disabled = true;
                rubrikFeedToggle.textContent = "Unavailable";
            }
        }
    }

    async function setRubrikFeedEnabled(enabled) {
        rubrikFeedToggle.disabled = true;
        try {
            const response = await fetch("/api/integrations/feed-state", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ rubrikApiEnabled: enabled })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not update Rubrik feed state");
            rubrikFeedEnabled = payload.rubrikApiEnabled;
            await loadFeedSettings();
            connectedToolsStatus.textContent = `Rubrik API feed ${rubrikFeedEnabled ? "enabled" : "disabled"}.`;
            if (rubrikFeedEnabled) loadRubrikActivities();
            else rubrikLiveStatus.textContent = "Rubrik API feed is disabled.";
        } catch (error) {
            connectedToolsStatus.textContent = error.message;
            throw error;
        } finally {
            rubrikFeedToggle.disabled = false;
        }
    }

    async function load() {
        try {
            const response = await fetch("/api/integrations/connectors", { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not load connector status");
            rows.innerHTML = payload.connectors.map(connector => `<tr><td>${escapeHtml(connector.name)}</td><td>${escapeHtml(connector.transport)}</td><td><label class="connector-url-field" aria-label="${escapeHtml(connector.name)} ingest URL"><input type="url" data-connector-url="${escapeHtml(connector.id)}" value="${escapeHtml(savedIngestUrl(connector))}"></label></td><td>${Number(connector.eventCount || 0).toLocaleString()}</td><td>${escapeHtml(displayTime(connector.lastReceivedAt))}</td><td><button type="button" class="xd-link" data-connector-copy-url="${escapeHtml(connector.id)}">Copy URL</button><button type="button" class="xd-link" data-connector-rotate="${escapeHtml(connector.id)}">Rotate token</button><button type="button" class="xd-link" data-connector-delete="${escapeHtml(connector.id)}" aria-label="Revoke ${escapeHtml(connector.name)} connector">Revoke</button></td></tr>`).join("") || `<tr><td colspan="6">No custom event integrations configured.</td></tr>`;
            connectedConnectorFeeds.innerHTML = payload.connectors.map(connector => {
                const enabled = connectorEnabled(connector);
                const readiness = Number(connector.eventCount || 0) > 0
                    ? `${Number(connector.eventCount).toLocaleString()} events received · last ${escapeHtml(displayTime(connector.lastReceivedAt))}`
                    : "Enabled endpoint · awaiting first event";
                return `<div class="connected-connector-row"><div><strong>${escapeHtml(connector.name)} · ${escapeHtml(connector.transport)}</strong><span class="muted">${readiness}</span></div><span class="ifc-status ${enabled ? "ok" : "uncfg"}">${enabled ? "Ingestion enabled" : "Ingestion disabled"}</span><button type="button" class="feed-toggle connector-feed-toggle" data-connector-feed-toggle="${escapeHtml(connector.id)}" role="switch" aria-checked="${enabled}" aria-label="${enabled ? "Disable" : "Enable"} ${escapeHtml(connector.name)} ingestion">${enabled ? "On" : "Off"}</button></div>`;
            }).join("") || `<div class="connected-tool-note muted">No inbound event connectors are configured.</div>`;
        } catch (error) {
            rows.innerHTML = `<tr><td colspan="6">${escapeHtml(error.message)}</td></tr>`;
            connectedConnectorFeeds.innerHTML = `<div class="muted">Connector readiness unavailable: ${escapeHtml(error.message)}</div>`;
        }
    }

    function showCreated(connector) {
        currentConnector = connector;
        created.hidden = false;
        created.innerHTML = `<div><strong>${escapeHtml(connector.name)} endpoint created</strong><p>Copy the bearer token now. The server stores only its hash, so it cannot be shown again after leaving this page.</p><label>Ingest URL<code>${escapeHtml(location.origin + connector.endpoint)}</code></label><label>Bearer token<code id="connectorTokenValue">${escapeHtml(connector.token)}</code></label><div class="connector-actions"><button type="button" class="ifc-btn save" id="connectorCopyToken">Copy token</button><button type="button" class="ifc-btn test" id="connectorTestIngest">Send test event</button></div><pre id="connectorExample"></pre><div id="connectorTestResult" role="status" aria-live="polite"></div></div>`;
        const auth = `Authorization: Bearer ${connector.token}`;
        const urlLabel = created.querySelector("label");
        const endpointInput = document.createElement("input");
        endpointInput.type = "url";
        endpointInput.id = "connectorEndpointValue";
        endpointInput.value = savedIngestUrl(connector);
        endpointInput.autocomplete = "off";
        endpointInput.spellcheck = false;
        endpointInput.addEventListener("input", () => {
            try {
                localStorage.setItem(connectorUrlKey(connector.id), endpointInput.value);
            } catch {
                status.textContent = "URL edits will be lost when this page closes because browser storage is unavailable.";
            }
            const example = document.getElementById("connectorExample");
            if (example) {
                const lines = example.textContent.split("\n");
                lines[0] = `POST ${endpointInput.value}`;
                example.textContent = lines.join("\n");
            }
        });
        urlLabel.querySelector("code").replaceWith(endpointInput);
        const copyUrlButton = document.createElement("button");
        copyUrlButton.type = "button";
        copyUrlButton.className = "ifc-btn save";
        copyUrlButton.id = "connectorCopyUrl";
        copyUrlButton.textContent = "Copy URL";
        created.querySelector(".connector-actions").prepend(copyUrlButton);
        const urlNote = document.createElement("p");
        urlNote.textContent = "Editing this URL changes only the value shown/copied for your sender configuration; the test event always targets this local dashboard.";
        created.querySelector(".connector-actions").after(urlNote);
        const sample = connector.transport === "syslog"
            ? `<134>1 ${new Date().toISOString()} local-test connector-manager 1 TEST - Connector test event`
            : connector.transport === "wazuh"
                ? JSON.stringify({ timestamp: new Date().toISOString(), rule: { id: "110011", level: 12, description: "Wrong signature or invalid signer certificate", groups: ["idnomic", "pki"] }, agent: { id: "local-test", name: "test-device", ip: "192.0.2.10" }, data: { username: "test-user" } }, null, 2)
                : connector.transport === "idnomic"
                    ? JSON.stringify({ "event.action": "Credential Enrollment Failure", "event.code": "110011", "Date UTC": new Date().toISOString(), "System User ID": "test-user", "System User Realm": "SYS_USER", "Device Holder ID": "test-holder", "Device Serial Number": "TOKENIZED", "Device Unique ID": "test-device", "Device Status": "enrollment_pending", "Device Management Profile": "test-profile", "Remote host": "192.0.2.10", "URI": "/cms/enroll", "Application Version": "test", "DNS Name": "test.example", "Process identifier": "123", "Wrong Signature": "true", "CMS error reference": `test-${crypto.randomUUID()}` }, null, 2)
            : connector.transport === "rubrik"
                ? JSON.stringify({ event_action: "trigger", payload: { summary: "Rubrik webhook test event", severity: "warning", source: "Rubrik Security Cloud", timestamp: new Date().toISOString(), custom_details: { object_name: "local-test-object", operation: "backup", status: "test" } } }, null, 2)
            : JSON.stringify({ event_type: "integration.test", event_time: new Date().toISOString(), source: { system: connector.name }, outcome: "success", details: { message: "Connector test event" } }, null, 2);
        document.getElementById("connectorExample").textContent = connector.transport === "syslog"
            ? `POST ${location.origin + connector.endpoint}\nAuthorization: Bearer <token>\nContent-Type: text/plain\n\n${sample}`
            : `POST ${location.origin + connector.endpoint}\n${auth}\nContent-Type: application/json\n\n${sample}`;
        document.getElementById("connectorCopyToken").addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(connector.token);
                status.textContent = "Bearer token copied.";
            } catch {
                status.textContent = "Clipboard unavailable. Select and copy the token above.";
            }
        });
        document.getElementById("connectorCopyUrl").addEventListener("click", async () => {
            const input = document.getElementById("connectorEndpointValue");
            if (!input.reportValidity() || !validIngestUrl(input.value)) {
                status.textContent = "Enter a valid HTTP or HTTPS ingest URL.";
                return;
            }
            try {
                await navigator.clipboard.writeText(input.value);
                status.textContent = "Ingest URL copied.";
            } catch {
                status.textContent = "Clipboard unavailable. Select and copy the ingest URL above.";
            }
        });
        document.getElementById("connectorTestIngest").addEventListener("click", testIngest);
    }

    async function testIngest() {
        if (!currentConnector) return;
        const result = document.getElementById("connectorTestResult");
        const button = document.getElementById("connectorTestIngest");
        button.disabled = true;
        result.textContent = "Sending test event…";
        const isSyslog = currentConnector.transport === "syslog";
        const body = isSyslog
            ? `<134>1 ${new Date().toISOString()} local-test connector-manager 1 TEST - Connector test event`
            : currentConnector.transport === "wazuh"
                ? JSON.stringify({ timestamp: new Date().toISOString(), rule: { id: "110011", level: 12, description: "Wrong signature or invalid signer certificate", groups: ["idnomic", "pki"] }, agent: { id: "local-test", name: "test-device", ip: "192.0.2.10" }, data: { username: "test-user" } })
                : currentConnector.transport === "idnomic"
                    ? JSON.stringify({ "event.action": "Credential Enrollment Failure", "event.code": "110011", "Date UTC": new Date().toISOString(), "System User ID": "test-user", "System User Realm": "SYS_USER", "Device Holder ID": "test-holder", "Device Serial Number": "TOKENIZED", "Device Unique ID": "test-device", "Device Status": "enrollment_pending", "Device Management Profile": "test-profile", "Remote host": "192.0.2.10", "URI": "/cms/enroll", "Application Version": "test", "DNS Name": "test.example", "Process identifier": "123", "Wrong Signature": "true", "CMS error reference": `test-${crypto.randomUUID()}` })
            : currentConnector.transport === "rubrik"
                ? JSON.stringify({ event_action: "trigger", payload: { summary: "Rubrik webhook test event", severity: "warning", source: "Rubrik Security Cloud", timestamp: new Date().toISOString(), custom_details: { object_name: "local-test-object", operation: "backup", status: "test" } } })
            : JSON.stringify({ event_type: "integration.test", event_time: new Date().toISOString(), source: { system: currentConnector.name }, outcome: "success", details: { message: "Connector test event" } });
        try {
            const response = await fetch(currentConnector.endpoint, {
                method: "POST",
                headers: { Authorization: `Bearer ${currentConnector.token}`, "Content-Type": isSyslog ? "text/plain" : "application/json" },
                body
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || `Ingest failed (${response.status})`);
            result.textContent = `Connected · ${payload.acceptedCount} event accepted into the local audit log.`;
            await load();
        } catch (error) {
            result.textContent = `Test failed: ${error.message}`;
        } finally {
            button.disabled = false;
        }
    }

    form?.addEventListener("submit", async event => {
        event.preventDefault();
        const submit = form.querySelector('[type="submit"]');
        submit.disabled = true;
        status.textContent = "Creating endpoint…";
        try {
            const response = await fetch("/api/integrations/connectors", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: document.getElementById("connectorName").value.trim(), transport: document.getElementById("connectorTransport").value })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not create connector");
            status.textContent = "Endpoint created. The bearer token is displayed once below.";
            showCreated(payload);
            form.reset();
            await load();
        } catch (error) {
            status.textContent = error.message;
        } finally {
            submit.disabled = false;
        }
    });

    rows?.addEventListener("input", event => {
        const input = event.target.closest("[data-connector-url]");
        if (!input) return;
        try {
            localStorage.setItem(connectorUrlKey(input.dataset.connectorUrl), input.value);
        } catch {
            status.textContent = "URL edits will be lost when this page closes because browser storage is unavailable.";
        }
    });

    rows?.addEventListener("click", async event => {
        const copyUrlButton = event.target.closest("[data-connector-copy-url]");
        if (copyUrlButton) {
            const input = rows.querySelector(`[data-connector-url="${CSS.escape(copyUrlButton.dataset.connectorCopyUrl)}"]`);
            if (!input.reportValidity() || !validIngestUrl(input.value)) {
                status.textContent = "Enter a valid HTTP or HTTPS ingest URL.";
                return;
            }
            try {
                await navigator.clipboard.writeText(input.value);
                status.textContent = "Ingest URL copied.";
            } catch {
                status.textContent = "Clipboard unavailable. Select and copy the ingest URL.";
            }
            return;
        }

        const rotateButton = event.target.closest("[data-connector-rotate]");
        if (rotateButton) {
            const connectorId = rotateButton.dataset.connectorRotate;
            if (!window.confirm("Rotate this token? The current token will stop working immediately. Update the sender with the new token.")) return;
            rotateButton.disabled = true;
            status.textContent = "Rotating connector token…";
            try {
                const response = await fetch(`/api/integrations/connectors/${encodeURIComponent(connectorId)}/rotate-token`, { method: "POST" });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.error || "Could not rotate connector token");
                currentConnector = payload;
                showCreated(payload);
                status.textContent = "Token rotated. Copy the new token now; it is shown once.";
                await load();
            } catch (error) {
                status.textContent = error.message;
                rotateButton.disabled = false;
            }
            return;
        }

        const button = event.target.closest("[data-connector-delete]");
        if (!button) return;
        button.disabled = true;
        status.textContent = "Revoking connector token…";
        try {
            const response = await fetch(`/api/integrations/connectors/${encodeURIComponent(button.dataset.connectorDelete)}`, { method: "DELETE" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not revoke connector");
            if (currentConnector?.id === button.dataset.connectorDelete) {
                currentConnector = null;
                created.hidden = true;
                created.replaceChildren();
            }
            status.textContent = "Connector revoked.";
            await load();
        } catch (error) {
            status.textContent = error.message;
            button.disabled = false;
        }
    });

    rubrikFeedToggle?.addEventListener("click", async () => {
        try { await setRubrikFeedEnabled(!rubrikFeedEnabled); } catch { /* Status is shown in the Settings panel. */ }
    });

    connectedConnectorFeeds?.addEventListener("click", async event => {
        const button = event.target.closest("[data-connector-feed-toggle]");
        if (!button) return;
        const connectorId = button.dataset.connectorFeedToggle;
        const enabled = button.getAttribute("aria-checked") !== "true";
        button.disabled = true;
        try {
            const response = await fetch(`/api/integrations/connectors/${encodeURIComponent(connectorId)}/enabled`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not update connector state");
            connectedToolsStatus.textContent = `${payload.connector.name} ingestion ${enabled ? "enabled" : "disabled"}.`;
            await load();
        } catch (error) {
            connectedToolsStatus.textContent = error.message;
            button.disabled = false;
        }
    });

    document.getElementById("enableAllFeeds")?.addEventListener("click", async event => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
            const response = await fetch("/api/integrations/connectors", { cache: "no-store" });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "Could not load connector list");
            await setRubrikFeedEnabled(true);
            for (const connector of payload.connectors || []) {
                if (connectorEnabled(connector)) continue;
                const update = await fetch(`/api/integrations/connectors/${encodeURIComponent(connector.id)}/enabled`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ enabled: true })
                });
                const result = await update.json();
                if (!update.ok) throw new Error(result.error || `Could not enable ${connector.name}`);
            }
            connectedToolsStatus.textContent = "Rubrik polling and inbound connectors are enabled. Read-only provider API feeds remain manual; sync them from the SIEM Workbench.";
            await load();
        } catch (error) {
            connectedToolsStatus.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });

    document.getElementById("rubrikLiveRefresh")?.addEventListener("click", loadRubrikActivities);
    document.getElementById("rubrikLiveLoadMore")?.addEventListener("click", loadMoreRubrikActivities);
    document.getElementById("integrationEventRefresh")?.addEventListener("click", loadIntegrationEvents);
    document.querySelector('.nav-item[data-section="integrations"]')?.addEventListener("click", () => {
        window.setTimeout(() => {
            loadFeedSettings();
            load();
            loadRubrikActivities();
            loadIntegrationEvents();
        }, 0);
    });
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
            loadFeedSettings();
            loadRubrikActivities();
            loadIntegrationEvents();
        }
    });
    window.setInterval(() => {
        loadRubrikActivities();
        loadIntegrationEvents();
    }, 60 * 1000);
    loadFeedSettings();
    loadRubrikActivities();
    loadIntegrationEvents();

    load();
    return { load };
})();