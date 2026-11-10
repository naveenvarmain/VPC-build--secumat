/* ==================================================================
   Incident layer — builds real incidents from loaded xDome alerts,
   joined to events (events.alert_id -> alerts.id) and to the device
   inventory. Replaces the previously hardcoded incident mocks.
   ================================================================== */
window.XDIncidents = (function() {
    "use strict";

    const SLA_MINUTES = { Critical: 60, High: 240, Medium: 480, Low: 1440 };

    function feed(name) {
        return window.ClarotyAPI ? ClarotyAPI.feedState(name) : { data: [], source: "pending", complete: false };
    }

    function text(value) {
        return String(value == null ? "" : value).trim();
    }

    function ipList(value) {
        if (Array.isArray(value)) return value.map(text).filter(Boolean);
        return text(value).split(/[,;\s]+/).filter(Boolean);
    }

    /* xDome reports a 0-100 risk score; map it to the dashboard severity bands. */
    function riskBand(score) {
        const value = Number(score);
        if (!Number.isFinite(value)) return "Unknown";
        if (value >= 80) return "Critical";
        if (value >= 60) return "High";
        if (value >= 40) return "Medium";
        return "Low";
    }

    /* Alert severity: xDome does not expose a single severity field, so derive it
       from the worst affected device, falling back to alert class/type keywords. */
    function alertSeverity(alert, devices) {
        const worst = devices.reduce((top, device) => Math.max(top, Number(device.risk_score) || 0), 0);
        if (worst) return riskBand(worst);
        const blob = `${alert.alert_class || ""} ${alert.alert_type_name || ""} ${alert.category || ""}`.toLowerCase();
        if (/critical|ransom|malware|exploit/.test(blob)) return "Critical";
        if (/high|lateral|credential|c2|command/.test(blob)) return "High";
        if (/medium|policy|config/.test(blob)) return "Medium";
        return "Low";
    }

    function mitreList(alert) {
        const pair = (ids, names) => {
            const idList = Array.isArray(ids) ? ids : ipList(ids);
            const nameList = Array.isArray(names) ? names : ipList(names);
            return idList.map((id, index) => ({ id: text(id), name: text(nameList[index]) || "" })).filter(item => item.id);
        };
        return [
            ...pair(alert.mitre_technique_ics_ids, alert.mitre_technique_ics_names).map(item => ({ ...item, domain: "ICS" })),
            ...pair(alert.mitre_technique_enterprise_ids, alert.mitre_technique_enterprise_names).map(item => ({ ...item, domain: "Enterprise" }))
        ];
    }

    function minutesSince(value) {
        const when = Date.parse(value);
        if (!Number.isFinite(when)) return null;
        return Math.max(0, Math.round((Date.now() - when) / 60000));
    }

    /* Build the incident set. One incident per xDome alert, enriched with the
       devices and events that actually reference it. */
    function build() {
        const alerts = feed("alerts").data || [];
        const events = feed("events").data || [];
        const devices = feed("devices").data || [];

        const eventsByAlert = new Map();
        events.forEach(event => {
            const key = text(event.alert_id);
            if (!key) return;
            if (!eventsByAlert.has(key)) eventsByAlert.set(key, []);
            eventsByAlert.get(key).push(event);
        });

        /* Index devices by every identifier an event might reference. */
        const deviceIndex = new Map();
        devices.forEach(device => {
            [device.device_name, device.uid, ...ipList(device.ip_list)].forEach(key => {
                const normalized = text(key).toLowerCase();
                if (normalized && !deviceIndex.has(normalized)) deviceIndex.set(normalized, device);
            });
        });

        return alerts.map(alert => {
            const alertId = text(alert.id);
            const linkedEvents = eventsByAlert.get(alertId) || [];

            const identities = new Set();
            linkedEvents.forEach(event => {
                [event.side_a_name, event.side_a_ip, event.side_b_name, event.side_b_ip]
                    .map(value => text(value).toLowerCase()).filter(Boolean)
                    .forEach(value => identities.add(value));
            });

            const matched = [];
            const seen = new Set();
            identities.forEach(key => {
                const device = deviceIndex.get(key);
                if (device && !seen.has(device.uid)) { seen.add(device.uid); matched.push(device); }
            });

            /* Events can name a peer that is not in the loaded inventory; keep it
               rather than silently dropping the only host identity we have. */
            const unmatched = [];
            linkedEvents.forEach(event => {
                [[event.side_a_name, event.side_a_ip, event.side_a_site_name, event.side_a_risk_score],
                 [event.side_b_name, event.side_b_ip, event.side_b_site_name, event.side_b_risk_score]]
                .forEach(([name, ip, site, risk]) => {
                    const key = text(name).toLowerCase() || text(ip).toLowerCase();
                    if (!key || deviceIndex.has(key) || seen.has(key)) return;
                    seen.add(key);
                    unmatched.push({ device_name: text(name) || text(ip), ip_list: ip ? [text(ip)] : [], site_name: text(site), risk_score: risk, _fromEvent: true });
                });
            });

            const allDevices = [...matched, ...unmatched];
            const severity = alertSeverity(alert, allDevices);
            const openedMinsAgo = minutesSince(alert.detected_time);
            const slaMins = SLA_MINUTES[severity] || 480;
            const remainMins = openedMinsAgo == null ? null : slaMins - openedMinsAgo;

            return {
                id: `XD-${alertId}`,
                alertId,
                title: text(alert.alert_name) || text(alert.alert_type_name) || `Alert ${alertId}`,
                severity,
                category: text(alert.alert_type_name) || text(alert.category) || "Uncategorised",
                alertClass: text(alert.alert_class),
                status: text(alert.status) || "Unknown",
                detectedTime: alert.detected_time,
                updatedTime: alert.updated_time,
                description: text(alert.description),
                devicesCount: Number(alert.devices_count) || allDevices.length,
                unresolvedDevicesCount: Number(alert.unresolved_devices_count) || 0,
                otCount: Number(alert.ot_devices_count) || 0,
                itCount: Number(alert.it_devices_count) || 0,
                iotCount: Number(alert.iot_devices_count) || 0,
                mitre: mitreList(alert),
                devices: allDevices.map(device => ({
                    name: text(device.device_name) || text(device.uid) || "Unknown device",
                    uid: text(device.uid),
                    ip: ipList(device.ip_list).join(", "),
                    site: text(device.site_name),
                    manufacturer: text(device.manufacturer),
                    type: text(device.device_type) || text(device.device_category),
                    risk: riskBand(device.risk_score),
                    riskScore: Number(device.risk_score) || null,
                    online: device.is_online == null ? null : Boolean(device.is_online),
                    fromEvent: Boolean(device._fromEvent)
                })),
                events: linkedEvents,
                openedMinsAgo,
                slaMins,
                remainMins,
                state: remainMins == null ? "unknown" : remainMins < 0 ? "breached" : remainMins < 120 ? "atrisk" : "ontrack"
            };
        }).sort((a, b) => (Date.parse(b.detectedTime) || 0) - (Date.parse(a.detectedTime) || 0));
    }

    /* Similarity: shared MITRE techniques, category, and shared devices.
       Weighted so a shared technique counts for more than a shared category. */
    function similarTo(incident, pool) {
        const mitreIds = new Set(incident.mitre.map(item => item.id));
        const deviceKeys = new Set(incident.devices.map(device => device.name.toLowerCase()));
        return pool
            .filter(candidate => candidate.id !== incident.id)
            .map(candidate => {
                const sharedMitre = candidate.mitre.filter(item => mitreIds.has(item.id));
                const sharedDevices = candidate.devices.filter(device => deviceKeys.has(device.name.toLowerCase()));
                const sameCategory = candidate.category === incident.category;
                const sameSeverity = candidate.severity === incident.severity;
                const mitreScore = mitreIds.size ? (sharedMitre.length / mitreIds.size) * 55 : 0;
                const deviceScore = deviceKeys.size ? (sharedDevices.length / deviceKeys.size) * 30 : 0;
                const score = Math.round(mitreScore + deviceScore + (sameCategory ? 10 : 0) + (sameSeverity ? 5 : 0));
                return { ...candidate, score, sharedMitre, sharedDevices, sameCategory };
            })
            .filter(candidate => candidate.score > 0)
            .sort((a, b) => b.score - a.score);
    }

    /* Attack story from the real MITRE techniques and linked event timeline.
       No invented stages: only techniques xDome actually reported are shown. */
    const TACTIC_ORDER = [
        { key: "initial", match: /initial access|phishing|drive-by|exploit public/i, icon: "📧", color: "#f59e0b", label: "Initial Access" },
        { key: "execution", match: /execution|command and scripting|user execution/i, icon: "⚡", color: "#ef4444", label: "Execution" },
        { key: "persistence", match: /persistence|scheduled task|registry run/i, icon: "📌", color: "#fb923c", label: "Persistence" },
        { key: "privilege", match: /privilege escalation|valid accounts/i, icon: "⬆", color: "#a78bfa", label: "Privilege Escalation" },
        { key: "credential", match: /credential|lsass|password|hash/i, icon: "🔑", color: "#e879f9", label: "Credential Access" },
        { key: "discovery", match: /discovery|scanning|enumeration/i, icon: "🔍", color: "#06b6d4", label: "Discovery" },
        { key: "lateral", match: /lateral|remote services|pass the/i, icon: "🔀", color: "#464feb", label: "Lateral Movement" },
        { key: "collection", match: /collection|data from/i, icon: "📦", color: "#22d3ee", label: "Collection" },
        { key: "c2", match: /command and control|c2|beacon|web protocols/i, icon: "📡", color: "#06b6d4", label: "Command & Control" },
        { key: "exfil", match: /exfiltration/i, icon: "📤", color: "#f87171", label: "Exfiltration" },
        { key: "impact", match: /impact|encrypted for impact|denial|inhibit|manipulat/i, icon: "🛑", color: "#dc2626", label: "Impact" }
    ];

    function attackStory(incident) {
        const start = Date.parse(incident.detectedTime);
        const steps = [];
        TACTIC_ORDER.forEach(tactic => {
            const techniques = incident.mitre.filter(item => tactic.match.test(`${item.name} ${item.id}`));
            if (!techniques.length) return;
            steps.push({
                icon: tactic.icon,
                color: tactic.color,
                title: tactic.label,
                techniques,
                desc: techniques.map(item => `${item.id}${item.name ? ` — ${item.name}` : ""} (${item.domain})`).join("; ")
            });
        });

        /* Anything xDome reported that did not map to a known tactic bucket. */
        const used = new Set(steps.flatMap(step => step.techniques.map(item => item.id)));
        const leftover = incident.mitre.filter(item => !used.has(item.id));
        if (leftover.length) {
            steps.push({
                icon: "🎯", color: "#94a3b8", title: "Other reported techniques",
                techniques: leftover,
                desc: leftover.map(item => `${item.id}${item.name ? ` — ${item.name}` : ""} (${item.domain})`).join("; ")
            });
        }

        const sortedEvents = [...incident.events].sort((a, b) => (Date.parse(a.timestamp) || 0) - (Date.parse(b.timestamp) || 0));
        return {
            steps,
            start: incident.detectedTime,
            events: sortedEvents,
            offsetFor(value) {
                const when = Date.parse(value);
                if (!Number.isFinite(when) || !Number.isFinite(start)) return "";
                const mins = Math.round((when - start) / 60000);
                const sign = mins < 0 ? "-" : "+";
                const abs = Math.abs(mins);
                return `T${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
            }
        };
    }

    function readiness() {
        const alerts = feed("alerts");
        const events = feed("events");
        const devices = feed("devices");
        return {
            ready: Boolean((alerts.data || []).length),
            alerts: (alerts.data || []).length,
            events: (events.data || []).length,
            devices: (devices.data || []).length,
            source: alerts.source,
            complete: alerts.complete,
            message: (alerts.data || []).length
                ? `${(alerts.data || []).length.toLocaleString()} xDome alerts · ${(events.data || []).length.toLocaleString()} events · ${(devices.data || []).length.toLocaleString()} devices loaded`
                : alerts.source === "error"
                    ? `Alert feed failed: ${alerts.error || "unknown error"}`
                    : "xDome alert feed has not loaded yet."
        };
    }

    return { build, similarTo, attackStory, readiness, riskBand, SLA_MINUTES };
})();
