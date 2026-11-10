/* =====================================================================
    integrations.js — API Integration & Secrets Manager
     Vendor credentials are stored encrypted by the local backend. The browser
     receives only saved-field metadata; saved settings are not verified connections.
   ===================================================================== */

const INTEGRATIONS = (() => {
    const STORE_KEY = "soc-integrations";
    const COPILOT_ENDPOINT_KEY = "soc-copilot-studio-token-endpoint-v1";
    const HIDDEN_TOOLS_KEY = "soc-hidden-integration-tools-v1";
    let clarotyBackendStatus = null;
    let serverCredentialTools = {};
    let serverCredentialsLoaded = false;
    let serverCredentialsPromise = null;
    const integrationView = { query: "", category: "all", hideUnconfigured: false, showHidden: false };

    async function loadServerCredentialStatus(force = false) {
        if (serverCredentialsPromise && !force) return serverCredentialsPromise;
        if (serverCredentialsLoaded && !force) return serverCredentialTools;
        serverCredentialsPromise = (async () => {
            try {
                const response = await fetch("/api/integrations/credentials", { cache: "no-store" });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.error || "Credential status unavailable");
                serverCredentialTools = payload.tools || {};
                serverCredentialsLoaded = true;
            } catch {
                serverCredentialTools = {};
                serverCredentialsLoaded = true;
                return serverCredentialTools;
            }
            const legacy = load();
            let migrated = false;
            for (const [toolId, config] of Object.entries(legacy)) {
                if (toolId === "claroty" || !INTEGRATION_TOOL_IDS.has(toolId)) continue;
                if (serverCredentialTools[toolId]?.configured) {
                    delete legacy[toolId];
                    migrated = true;
                    continue;
                }
                if (!config || typeof config !== "object" || !Object.keys(config).length) continue;
                try {
                    const saveResponse = await fetch("/api/integrations/credentials", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ toolId, config })
                    });
                    if (saveResponse.ok) {
                        delete legacy[toolId];
                        migrated = true;
                    }
                } catch { /* Keep this legacy entry until migration succeeds. */ }
            }
            if (migrated) {
                saveAll(legacy);
                try {
                    const refreshed = await fetch("/api/integrations/credentials", { cache: "no-store" }).then(response => response.json());
                    serverCredentialTools = refreshed.tools || serverCredentialTools;
                } catch { /* Server saved the entries; the next status refresh will pick them up. */ }
            }
            return serverCredentialTools;
        })();
        try { return await serverCredentialsPromise; }
        finally { serverCredentialsPromise = null; }
    }

    async function saveServerConfig(toolId, config) {
        const response = await fetch("/api/integrations/credentials", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ toolId, config })
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Could not save encrypted integration settings");
        serverCredentialTools[toolId] = payload.status;
        const legacy = load();
        delete legacy[toolId];
        saveAll(legacy);
        return payload;
    }

    async function deleteServerConfig(toolId) {
        const response = await fetch(`/api/integrations/credentials/${encodeURIComponent(toolId)}`, { method: "DELETE" });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Could not clear encrypted integration settings");
        delete serverCredentialTools[toolId];
        const legacy = load();
        delete legacy[toolId];
        saveAll(legacy);
        return payload;
    }

    const INTEGRATION_TOOL_IDS = new Set([
        "swimlane", "crowdstrike", "trellix", "sentinel", "splunk", "defender", "entra", "servicenow",
        "paloalto", "m365", "qradar", "virustotal", "abuseipdb", "greynoise", "tenable", "claroty", "elastic",
        "rubrik", "netapp", "nasuni", "wazuh", "bmc", "sentinelone", "mcafee-epo",
        "defender-cloud-apps", "wiz", "prismacloud", "cato", "dc2cloud",
        "opensearch", "misp", "keycloak", "trivy", "github", "gitlab"
    ]);

    function copilotEndpointValid(value) {
        try {
            const endpoint = new URL(value);
            const microsoftHost = /(^|\.)api\.powerplatform\.(com|us|de|cn)$/i.test(endpoint.hostname);
            const sensitiveQuery = [...endpoint.searchParams.keys()].some(key => /secret|token|password|key|sig/i.test(key));
            return endpoint.protocol === "https:" && microsoftHost && endpoint.pathname.includes("/powervirtualagents/") && !endpoint.username && !endpoint.password && !sensitiveQuery;
        } catch {
            return false;
        }
    }

    function renderCopilotStudioCard() {
        let endpoint = "";
        try { endpoint = localStorage.getItem(COPILOT_ENDPOINT_KEY) || ""; } catch { /* storage may be unavailable */ }
        const configured = copilotEndpointValid(endpoint);
        return `<div class="integ-section"><div class="integ-section-title">AI Assistant</div><div class="integ-forms-grid"><div class="integ-form-card" id="ifc-copilot-studio"><div class="ifc-head"><div class="ifc-logo" style="background:#0078d4">MS</div><div class="ifc-info"><div class="ifc-name">Microsoft Copilot Studio</div><div class="ifc-cat">Generative AI</div></div><span class="ifc-status ${configured ? "ok" : "uncfg"}" id="copilot-studio-status">${configured ? "● Endpoint saved" : "○ Not connected"}</span></div><div class="ifc-desc">Connect a published Copilot Studio agent to the Search conversation. The browser exchanges the endpoint for a short-lived chat token; never enter a Direct Line secret.</div><div class="ifc-fields"><div class="ifc-field-row"><label class="ifc-label" for="copilot-studio-endpoint">Published agent token endpoint</label><input class="ifc-input" id="copilot-studio-endpoint" type="url" placeholder="https://…api.powerplatform.com/powervirtualagents/…/directline/token?api-version=…" value="${endpoint.replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char])}" autocomplete="off" spellcheck="false"></div></div><div class="ifc-actions"><button type="button" class="ifc-btn save" data-copilot-action="save">Save</button><button type="button" class="ifc-btn test" data-copilot-action="test">Test connection</button><button type="button" class="ifc-btn clear" data-copilot-action="clear">Clear</button><button type="button" class="ifc-btn docs" data-copilot-action="open-search">Open Search</button><a class="ifc-btn docs" href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/publication-connect-bot-to-web-channels" target="_blank" rel="noopener noreferrer">Docs</a></div><div class="ifc-result" id="copilot-studio-result" role="status">${configured ? "Endpoint is saved on this device; test it to verify the published agent." : "Configure the published agent token endpoint to enable Copilot chat."}</div></div></div></div>`;
    }

    async function testCopilotEndpoint(endpoint) {
        if (!copilotEndpointValid(endpoint)) throw new Error("Enter a valid HTTPS Copilot Studio token endpoint. Do not use a Direct Line secret.");
        const tokenUrl = new URL(endpoint);
        const marker = "/powervirtualagents";
        const environmentEndpoint = tokenUrl.href.slice(0, tokenUrl.href.indexOf(marker));
        const apiVersion = tokenUrl.searchParams.get("api-version");
        if (!environmentEndpoint || !apiVersion) throw new Error("The endpoint must include the Copilot Studio api-version parameter.");
        const regionalUrl = `${environmentEndpoint}${marker}/regionalchannelsettings?api-version=${encodeURIComponent(apiVersion)}`;
        const [regionalResponse, tokenResponse] = await Promise.all([fetch(regionalUrl, { cache: "no-store" }), fetch(endpoint, { cache: "no-store" })]);
        const regional = await regionalResponse.json();
        const token = await tokenResponse.json();
        if (!regionalResponse.ok || !regional.channelUrlsById?.directline) throw new Error("Could not retrieve Copilot Studio Direct Line settings.");
        if (!tokenResponse.ok || !token.token) throw new Error("Copilot Studio did not issue a conversation token.");
        return "Connected: Direct Line settings loaded and a short-lived conversation token was issued.";
    }

    const TOOLS = [
        {
            id: "swimlane", name: "Swimlane SOAR", category: "SOAR",
            logo: "SL", color: "#464feb",
            desc: "Security orchestration, automation & response — core incident management platform",
            docs: "https://swimlane.com/docs/",
            fields: [
                { key: "baseUrl",  label: "Instance URL",            placeholder: "https://your-instance.swimlane.com", type: "url" },
                { key: "pat",      label: "Personal Access Token",   placeholder: "User PAT from Account › API Tokens", type: "password" },
                { key: "appId",    label: "Incident App ID",         placeholder: "App tracking ID from App Settings",  type: "text" }
            ]
        },
        {
            id: "crowdstrike", name: "CrowdStrike Falcon", category: "EDR",
            logo: "CS", color: "#e10600",
            desc: "Endpoint detection, response and threat intelligence platform. Supports host isolation, process kill, forensic collection and real-time RTR sessions.",
            docs: "https://developer.crowdstrike.com/",
            fields: [
                { key: "clientId",     label: "OAuth2 Client ID",     placeholder: "Falcon API Client ID (Settings › API Clients)",    type: "text" },
                { key: "clientSecret", label: "OAuth2 Client Secret", placeholder: "Falcon API Client Secret (copy at creation time)", type: "password" },
                { key: "baseUrl",      label: "API Base URL",         placeholder: "https://api.crowdstrike.com",                      type: "url" },
                { key: "cid",          label: "Customer CID",         placeholder: "Your Falcon CID (optional)",                       type: "text" }
            ]
        },
        {
            id: "trellix", name: "Trellix XDR (McAfee/FireEye)", category: "EDR",
            logo: "TX", color: "#d9272e",
            desc: "Extended detection & response platform — formerly McAfee Enterprise + FireEye. Covers endpoint, network, email and cloud threat detection.",
            docs: "https://docs.trellix.com/",
            fields: [
                { key: "baseUrl",      label: "API Base URL",         placeholder: "https://api.manage.trellix.com",                type: "url" },
                { key: "clientId",     label: "Client ID",            placeholder: "Trellix IAM Client ID",                         type: "text" },
                { key: "clientSecret", label: "Client Secret",        placeholder: "Trellix IAM Client Secret",                     type: "password" },
                { key: "tenantId",     label: "Tenant ID",            placeholder: "Trellix Tenant / Account ID",                   type: "text" },
                { key: "region",       label: "Region",               placeholder: "US / EU / AP (default: US)",                    type: "text" }
            ]
        },
        {
            id: "sentinelone", name: "SentinelOne Singularity", category: "EDR",
            logo: "S1", color: "#6d36c7",
            desc: "Read-only polling of recent SentinelOne threats. Sync is manual and bounded to 100 records; response actions are not enabled.",
            docs: "https://developer.sentinelone.com/",
            fields: [
                { key: "baseUrl", label: "Management API URL", placeholder: "https://usea1.sentinelone.net", type: "url" },
                { key: "apiToken", label: "API Token", placeholder: "SentinelOne API token", type: "password" },
                { key: "accountId", label: "Account ID (optional)", placeholder: "SentinelOne account ID", type: "text" },
                { key: "siteId", label: "Site ID (optional)", placeholder: "SentinelOne site ID", type: "text" }
            ]
        },
        {
            id: "mcafee-epo", name: "McAfee ePolicy Orchestrator", category: "EDR",
            logo: "Mc", color: "#c62828",
            desc: "Configure McAfee ePO REST access for endpoint and threat-management events. A live server connector is not yet implemented.",
            docs: "https://docs.trellix.com/",
            fields: [
                { key: "baseUrl", label: "ePO Server URL", placeholder: "https://epo.example.com", type: "url" },
                { key: "username", label: "API Username", placeholder: "ePO API service account", type: "text" },
                { key: "password", label: "API Password", placeholder: "ePO API password", type: "password" }
            ]
        },
        {
            id: "sentinel", name: "Microsoft Sentinel", category: "SIEM",
            logo: "MS", color: "#0078d4",
            desc: "Azure-native cloud SIEM and SOAR solution",
            docs: "https://docs.microsoft.com/azure/sentinel/",
            fields: [
                { key: "tenantId",     label: "Tenant ID",        placeholder: "Azure AD Tenant GUID",        type: "text" },
                { key: "clientId",     label: "App (Client) ID",  placeholder: "Azure App Registration ID",   type: "text" },
                { key: "clientSecret", label: "Client Secret",    placeholder: "Azure App Secret value",      type: "password" },
                { key: "workspaceId",  label: "Workspace ID",     placeholder: "Log Analytics Workspace ID",  type: "text" },
                { key: "subId",        label: "Subscription ID",  placeholder: "Azure Subscription GUID",     type: "text" }
            ]
        },
        {
            id: "wazuh", name: "Wazuh (Open Source SIEM/XDR)", category: "Open Source",
            logo: "WZ", color: "#1c6e8c",
            desc: "Read-only Wazuh Indexer alert polling when an Indexer URL and read account are configured; Manager credentials alone do not enable alert polling.",
            docs: "https://documentation.wazuh.com/",
            fields: [
                { key: "baseUrl", label: "Wazuh Manager API URL", placeholder: "https://wazuh-manager.example:55000", type: "url" },
                { key: "username", label: "API Username", placeholder: "Wazuh API service account", type: "text" },
                { key: "password", label: "API Password", placeholder: "Wazuh API password", type: "password" },
                { key: "indexerUrl", label: "Indexer URL (optional)", placeholder: "https://wazuh-indexer.example:9200", type: "url" }
            ]
        },
        {
            id: "opensearch", name: "OpenSearch (Open Source)", category: "Open Source",
            logo: "OS", color: "#005eb8",
            desc: "Read-only OpenSearch security-event polling from the configured index or pattern. Sync is manual and bounded to 100 records.",
            docs: "https://opensearch.org/docs/latest/api-reference/",
            fields: [
                { key: "baseUrl", label: "OpenSearch URL", placeholder: "https://opensearch.example:9200", type: "url" },
                { key: "username", label: "Username (optional)", placeholder: "OpenSearch service account", type: "text" },
                { key: "password", label: "Password (optional)", placeholder: "OpenSearch password", type: "password" },
                { key: "apiKey", label: "API Key (optional)", placeholder: "Use instead of username/password", type: "password" },
                { key: "index", label: "Index or pattern (optional)", placeholder: "security-events-*", type: "text" }
            ]
        },
        {
            id: "github", name: "GitHub Security", category: "Code / Repository Security",
            logo: "GH", color: "#24292f",
            desc: "Read organization audit events and repository security alerts; receive signed organization webhooks. API polling and webhook delivery are cloud-hosted only.",
            docs: "https://docs.github.com/en/rest",
            fields: [
                { key: "organization", label: "Organization", placeholder: "GitHub organization login", type: "text" },
                { key: "token", label: "Fine-grained or classic token", placeholder: "Organization audit and security read access", type: "password" },
                { key: "webhookSecret", label: "Organization Webhook Secret", placeholder: "Secret configured on the GitHub organization webhook", type: "password" }
            ]
        },
        {
            id: "gitlab", name: "GitLab Security", category: "Code / Repository Security",
            logo: "GL", color: "#fc6d26",
            desc: "Read group audit events and vulnerability findings; receive authenticated group or project webhooks. API polling and webhook delivery are GitLab.com only.",
            docs: "https://docs.gitlab.com/api/",
            fields: [
                { key: "groupId", label: "Group ID or path", placeholder: "Group ID or URL-encoded group path", type: "text" },
                { key: "token", label: "Access Token", placeholder: "Group audit and security read access", type: "password" },
                { key: "webhookSecret", label: "Webhook Secret Token", placeholder: "Secret configured on the GitLab group webhook", type: "password" }
            ]
        },
        {
            id: "misp", name: "MISP (Open Source Threat Intel)", category: "Open Source",
            logo: "MI", color: "#2d6ca2",
            desc: "Read-only MISP attribute polling into local IOC evidence. Sync is manual and bounded to 100 attributes.",
            docs: "https://www.misp-project.org/documentation/",
            fields: [
                { key: "baseUrl", label: "MISP URL", placeholder: "https://misp.example", type: "url" },
                { key: "apiKey", label: "Automation API Key", placeholder: "MISP automation key", type: "password" }
            ]
        },
        {
            id: "keycloak", name: "Keycloak (Open Source IAM)", category: "Open Source",
            logo: "KC", color: "#4d4d4d",
            desc: "Read-only Keycloak realm and admin event polling using client credentials. The service account needs permission to view events.",
            docs: "https://www.keycloak.org/documentation",
            fields: [
                { key: "baseUrl", label: "Keycloak URL", placeholder: "https://keycloak.example", type: "url" },
                { key: "realm", label: "Realm", placeholder: "ot-platform", type: "text" },
                { key: "clientId", label: "Client ID", placeholder: "Confidential client ID", type: "text" },
                { key: "clientSecret", label: "Client Secret", placeholder: "Client secret", type: "password" }
            ]
        },
        {
            id: "trivy", name: "Trivy (Open Source Scanner)", category: "Open Source",
            logo: "TR", color: "#1904da",
            desc: "Configure Trivy server access for vulnerability, image and IaC scan results. Credentials are stored encrypted; a live server connector is not yet implemented.",
            docs: "https://trivy.dev/latest/docs/",
            fields: [
                { key: "baseUrl", label: "Trivy Server URL", placeholder: "http://trivy-server.example:4954", type: "url" },
                { key: "token", label: "Server Token (optional)", placeholder: "Trivy server token", type: "password" }
            ]
        },
        {
            id: "splunk", name: "Splunk Enterprise Security", category: "SIEM",
            logo: "SP", color: "#65a637",
            desc: "Security information and event management (SIEM)",
            docs: "https://dev.splunk.com/enterprise/docs/",
            fields: [
                { key: "baseUrl", label: "Splunk URL",  placeholder: "https://splunk.company.com:8089", type: "url" },
                { key: "token",   label: "Auth Token",  placeholder: "HEC or REST API token",           type: "password" },
                { key: "index",   label: "Default Index", placeholder: "main",                          type: "text" }
            ]
        },
        {
            id: "defender", name: "Microsoft Defender XDR", category: "EDR",
            logo: "DE", color: "#00b4d8",
            desc: "Extended detection and response across Microsoft 365",
            docs: "https://docs.microsoft.com/microsoft-365/security/",
            fields: [
                { key: "tenantId",     label: "Tenant ID",       placeholder: "Azure AD Tenant GUID",      type: "text" },
                { key: "clientId",     label: "App (Client) ID", placeholder: "Azure App Registration ID", type: "text" },
                { key: "clientSecret", label: "Client Secret",   placeholder: "Azure App Secret value",    type: "password" }
            ]
        },
        {
            id: "entra", name: "Microsoft Entra ID", category: "IAM",
            logo: "EI", color: "#0078d4",
            desc: "Identity & access management, MFA, conditional access, SSPR",
            docs: "https://docs.microsoft.com/azure/active-directory/",
            fields: [
                { key: "tenantId",     label: "Tenant ID",       placeholder: "Azure AD Tenant GUID",       type: "text" },
                { key: "clientId",     label: "App ID",          placeholder: "Azure App Registration ID",  type: "text" },
                { key: "clientSecret", label: "Secret",          placeholder: "Azure App Secret value",     type: "password" }
            ]
        },
        {
            id: "servicenow", name: "ServiceNow ITSM", category: "ITSM",
            logo: "SN", color: "#62d84e",
            desc: "IT service management, incident ticketing and CMDB integration",
            docs: "https://developer.servicenow.com/",
            fields: [
                { key: "instance",  label: "Instance",  placeholder: "company.service-now.com",  type: "text" },
                { key: "user",      label: "Username",  placeholder: "API integration user",      type: "text" },
                { key: "password",  label: "Password",  placeholder: "User password or API key",  type: "password" }
            ]
        },
        {
            id: "bmc", name: "BMC Helix ITSM", category: "ITSM",
            logo: "BMC", color: "#ec8b00",
            desc: "Configure BMC Helix ITSM ticketing and incident API settings. A live server-side ticket connector is not yet implemented.",
            docs: "https://docs.bmc.com/",
            fields: [
                { key: "baseUrl", label: "Helix API URL", placeholder: "https://company.onbmc.com", type: "url" },
                { key: "clientId", label: "OAuth Client ID (optional)", placeholder: "BMC OAuth client ID", type: "text" },
                { key: "clientSecret", label: "OAuth Client Secret", placeholder: "BMC OAuth client secret", type: "password" },
                { key: "username", label: "API Username (optional)", placeholder: "BMC integration user", type: "text" },
                { key: "password", label: "API Password (optional)", placeholder: "BMC integration password", type: "password" },
                { key: "tenantId", label: "Tenant ID (optional)", placeholder: "BMC tenant or account ID", type: "text" }
            ]
        },
        {
            id: "paloalto", name: "Palo Alto NGFW / Panorama", category: "Firewall",
            logo: "PA", color: "#fa582d",
            desc: "Next-generation firewall policy management and threat prevention",
            docs: "https://docs.paloaltonetworks.com/",
            fields: [
                { key: "hostname",  label: "Firewall IP / Host",  placeholder: "192.168.1.1",                     type: "text" },
                { key: "apiKey",    label: "API Key",             placeholder: "PAN-OS API key",                  type: "password" },
                { key: "panorama",  label: "Panorama URL",        placeholder: "https://panorama.company.com",    type: "url" }
            ]
        },
        {
            id: "m365", name: "Microsoft 365 / Exchange", category: "Email",
            logo: "M3", color: "#d83b01",
            desc: "Email security, Exchange Online, and Microsoft 365 threat protection",
            docs: "https://docs.microsoft.com/exchange/",
            fields: [
                { key: "tenantId",     label: "Tenant ID",       placeholder: "Azure AD Tenant GUID",       type: "text" },
                { key: "clientId",     label: "App ID",          placeholder: "Azure App Registration ID",  type: "text" },
                { key: "clientSecret", label: "Secret",          placeholder: "Azure App Secret value",     type: "password" }
            ]
        },
        {
            id: "defender-cloud-apps", name: "Microsoft Defender for Cloud Apps", category: "Cloud Security",
            logo: "CA", color: "#16838f",
            desc: "Read-only Microsoft Graph alert polling filtered to Defender for Cloud Apps. Requires the SecurityAlert.Read.All application permission.",
            docs: "https://learn.microsoft.com/defender-cloud-apps/",
            fields: [
                { key: "baseUrl", label: "API URL (optional)", placeholder: "https://api.security.microsoft.com", type: "url" },
                { key: "tenantId", label: "Tenant ID", placeholder: "Microsoft Entra tenant GUID", type: "text" },
                { key: "clientId", label: "Application ID", placeholder: "App registration client ID", type: "text" },
                { key: "clientSecret", label: "Client Secret", placeholder: "App registration secret", type: "password" }
            ]
        },
        {
            id: "wiz", name: "Wiz Cloud Security", category: "Cloud Security",
            logo: "WZ", color: "#4563eb",
            desc: "Configure Wiz GraphQL API service-account credentials for cloud security posture and workload findings. A live server connector is not yet implemented.",
            docs: "https://docs.wiz.io/",
            fields: [
                { key: "baseUrl", label: "GraphQL API URL", placeholder: "https://api.usX.app.wiz.io/graphql", type: "url" },
                { key: "clientId", label: "Service Account Client ID", placeholder: "Wiz service account client ID", type: "text" },
                { key: "clientSecret", label: "Service Account Secret", placeholder: "Wiz service account secret", type: "password" },
                { key: "tenantId", label: "Project / Tenant ID (optional)", placeholder: "Wiz project or tenant ID", type: "text" }
            ]
        },
        {
            id: "prismacloud", name: "Palo Alto Prisma Cloud", category: "Cloud Security",
            logo: "PC", color: "#f15b2a",
            desc: "Read-only Prisma Cloud alert polling. Sync is manual and uses a short-lived API token; no policy or response action is issued.",
            docs: "https://pan.dev/prisma-cloud/",
            fields: [
                { key: "baseUrl", label: "API URL", placeholder: "https://api.prismacloud.io", type: "url" },
                { key: "accessKey", label: "Access Key", placeholder: "Prisma Cloud access key", type: "text" },
                { key: "secretKey", label: "Secret Key", placeholder: "Prisma Cloud secret key", type: "password" },
                { key: "tenantId", label: "Account / Tenant ID (optional)", placeholder: "Prisma Cloud account ID", type: "text" }
            ]
        },
        {
            id: "cato", name: "Cato Networks SASE", category: "SASE",
            logo: "CA", color: "#1c4c96",
            desc: "Read-only Cato auditFeed GraphQL polling for the configured account and previous 24 hours. Policy enforcement and response actions are not enabled.",
            docs: "https://support.catonetworks.com/",
            fields: [
                { key: "baseUrl", label: "GraphQL API URL", placeholder: "https://api.catonetworks.com/api/v1/graphql2", type: "url", defaultValue: "https://api.catonetworks.com/api/v1/graphql2" },
                { key: "apiKey", label: "API Key", placeholder: "Cato API key", type: "password" },
                { key: "accountId", label: "Account ID", placeholder: "Cato account ID", type: "text" }
            ]
        },
        {
            id: "dc2cloud", name: "DC2Cloud Security", category: "Cloud Transformation",
            logo: "D2", color: "#246f86",
            desc: "Configure the DC2Cloud tenant API endpoint and credentials. The API contract and live connector must be confirmed with your DC2Cloud provider before telemetry or policy actions can be enabled.",
            docs: null,
            fields: [
                { key: "baseUrl", label: "Provider API Base URL", placeholder: "https://provider.example/api", type: "url" },
                { key: "tenantId", label: "Tenant / Environment ID", placeholder: "DC2Cloud tenant or environment", type: "text" },
                { key: "clientId", label: "API Client ID (optional)", placeholder: "Provider-issued API client ID", type: "text" },
                { key: "clientSecret", label: "API Client Secret / Token", placeholder: "Provider-issued API secret or token", type: "password" }
            ]
        },
        {
            id: "qradar", name: "IBM QRadar", category: "SIEM",
            logo: "QR", color: "#1f70c1",
            desc: "Security intelligence and offense management platform",
            docs: "https://www.ibm.com/docs/en/qradar-on-cloud",
            fields: [
                { key: "baseUrl", label: "QRadar URL",  placeholder: "https://qradar.company.com",  type: "url" },
                { key: "token",   label: "SEC Token",   placeholder: "QRadar REST API SEC token",    type: "password" }
            ]
        },
        {
            id: "virustotal", name: "VirusTotal", category: "Threat Intel",
            logo: "VT", color: "#394eff",
            desc: "Multi-engine file, URL, IP address, and domain analysis",
            docs: "https://developers.virustotal.com/",
            fields: [
                { key: "apiKey", label: "API Key", placeholder: "Free or Premium VT API key", type: "password" }
            ]
        },
        {
            id: "abuseipdb", name: "AbuseIPDB", category: "Threat Intel",
            logo: "AB", color: "#ff4d4d",
            desc: "IP address abuse reporting database and reputation lookup",
            docs: "https://www.abuseipdb.com/api",
            fields: [
                { key: "apiKey", label: "API Key", placeholder: "AbuseIPDB v2 API key", type: "password" }
            ]
        },
        {
            id: "greynoise", name: "GreyNoise", category: "Threat Intel",
            logo: "GN", color: "#00c2cb",
            desc: "Internet scanner noise intelligence and context enrichment",
            docs: "https://docs.greynoise.io/",
            fields: [
                { key: "apiKey", label: "API Key", placeholder: "GreyNoise Community or Enterprise key", type: "password" }
            ]
        },
        {
            id: "tenable", name: "Tenable.io / Nessus", category: "Vulnerability",
            logo: "TE", color: "#00c176",
            desc: "Vulnerability assessment, scanning, and remediation tracking",
            docs: "https://developer.tenable.com/",
            fields: [
                { key: "baseUrl",   label: "API URL",    placeholder: "https://cloud.tenable.com",  type: "url" },
                { key: "accessKey", label: "Access Key", placeholder: "Tenable access key",         type: "text" },
                { key: "secretKey", label: "Secret Key", placeholder: "Tenable secret key",         type: "password" }
            ]
        },
        {
            id: "claroty", name: "Claroty xDome (OT/ICS)", category: "OT/ICS",
            logo: "CL", color: "#5c2d91",
            desc: "OT/IoT asset visibility, vulnerabilities &amp; network segmentation. Uses an API token only against the v1 device_vulnerability_relations endpoint. Loads are one-time/manual. Leave ZF Proxy blank to connect directly when your egress does not use the cloud proxy.",
            docs: "https://claroty.com/",
            fields: [
                { key: "baseUrl",  label: "Claroty Base URL", placeholder: "https://eu.api.claroty.com", type: "url", defaultValue: "https://eu.api.claroty.com" },
                { key: "apiKey",   label: "API Token",        placeholder: "API token for device_vulnerability_relations endpoint", type: "password" },
                { key: "proxyUrl", label: "ZF Proxy",         placeholder: "Blank = direct connection", type: "url", defaultValue: "http://cloudproxy.zf-world.com:8080" }
            ]
        },
        {
            id: "elastic", name: "Elastic Security (SIEM)", category: "SIEM",
            logo: "ES", color: "#00bfb3",
            desc: "Elastic Stack security with endpoint and threat hunting capabilities",
            docs: "https://www.elastic.co/guide/en/security/",
            fields: [
                { key: "kibanaUrl", label: "Kibana URL",  placeholder: "https://elastic.company.com:5601", type: "url" },
                { key: "apiKey",    label: "API Key",     placeholder: "Elastic base64 API key",           type: "password" },
                { key: "index",     label: "Data Index",  placeholder: ".siem-signals-*",                  type: "text" }
            ]
        },
        {
            id: "rubrik", name: "Rubrik Security Cloud", category: "Backup & Recovery",
            logo: "RB", color: "#d44b3e",
            desc: "Configure the Rubrik service account name, token URI, client ID, and client secret for the read-only live activity panel. Incoming PD-CEF alerts can also use the Rubrik transport in Inbound Event Integrations.",
            docs: "https://docs.rubrik.com/",
            fields: [
                { key: "name", label: "Service Account Name", placeholder: "Security_OT_SEC", type: "text" },
                { key: "access_token_uri", label: "Access Token URI", placeholder: "https://your-tenant.my.rubrik.com/api/client_token", type: "url" },
                { key: "client_id", label: "Service Account Client ID", placeholder: "Rubrik service account client ID", type: "text" },
                { key: "client_secret", label: "Service Account Secret", placeholder: "Enter the client secret in this field", type: "password" }
            ]
        },
        {
            id: "netapp", name: "NetApp ONTAP", category: "Storage",
            logo: "NA", color: "#0067c5",
            desc: "Read-only polling of recent ONTAP security audit messages. Sync is manual and bounded to 100 records.",
            docs: "https://docs.netapp.com/us-en/ontap-automation/",
            fields: [
                { key: "baseUrl", label: "Cluster Management URL", placeholder: "https://cluster.example.com", type: "url" },
                { key: "username", label: "API User", placeholder: "ONTAP API user", type: "text" },
                { key: "password", label: "API Password", placeholder: "ONTAP API password", type: "password" },
                { key: "svm", label: "SVM (optional)", placeholder: "Storage virtual machine", type: "text" }
            ]
        },
        {
            id: "nasuni", name: "Nasuni", category: "Storage",
            logo: "NS", color: "#0b806b",
            desc: "Configure Nasuni management API access for edge appliances and file-service events. Saved settings are encrypted; a live connector is not yet implemented.",
            docs: "https://docs.nasuni.com/",
            fields: [
                { key: "baseUrl", label: "Management API URL", placeholder: "https://management.example.com/api", type: "url" },
                { key: "clientId", label: "API Client ID", placeholder: "Nasuni API client ID", type: "text" },
                { key: "clientSecret", label: "API Client Secret", placeholder: "Nasuni API client secret", type: "password" },
                { key: "organizationId", label: "Organization ID (optional)", placeholder: "Nasuni organization or account ID", type: "text" }
            ]
        }
    ];

    function hiddenToolIds() {
        try {
            const stored = JSON.parse(localStorage.getItem(HIDDEN_TOOLS_KEY) || "[]");
            return new Set(Array.isArray(stored) ? stored.filter(id => TOOLS.some(tool => tool.id === id)) : []);
        } catch {
            return new Set();
        }
    }

    function applyIntegrationFilters(container) {
        const query = integrationView.query.trim().toLowerCase();
        const hidden = hiddenToolIds();
        let visibleCount = 0;
        container.querySelectorAll("[data-integration-card]").forEach(card => {
            const toolId = card.dataset.toolId;
            const isHidden = hidden.has(toolId);
            const matchesQuery = !query || `${card.dataset.name} ${card.dataset.category} ${card.textContent}`.toLowerCase().includes(query);
            const matchesCategory = integrationView.category === "all" || card.dataset.category === integrationView.category;
            const matchesConfigured = !integrationView.hideUnconfigured || card.dataset.configured === "true";
            card.hidden = !matchesQuery || !matchesCategory || !matchesConfigured || isHidden && !integrationView.showHidden;
            card.classList.toggle("integ-form-card-hidden", isHidden && integrationView.showHidden);
            const hideButton = card.querySelector("[data-integration-visibility]");
            if (hideButton) {
                hideButton.textContent = isHidden ? "Show" : "Hide";
                hideButton.setAttribute("aria-label", `${isHidden ? "Show" : "Hide"} ${card.dataset.name}`);
            }
            if (!card.hidden) visibleCount += 1;
        });
        container.querySelectorAll(".integ-section[data-integration-category]").forEach(section => {
            section.hidden = !section.querySelector("[data-integration-card]:not([hidden])");
        });
        const status = container.querySelector("[data-integration-filter-status]");
        if (status) status.textContent = `${visibleCount} integration cards shown · hiding a card does not clear its saved settings`;
        const search = container.querySelector("[data-integration-search]");
        const category = container.querySelector("[data-integration-category-filter]");
        const hideUnconfigured = container.querySelector("[data-integration-hide-unconfigured]");
        const showHidden = container.querySelector("[data-integration-show-hidden]");
        if (search) search.value = integrationView.query;
        if (category) category.value = integrationView.category;
        if (hideUnconfigured) hideUnconfigured.checked = integrationView.hideUnconfigured;
        if (showHidden) showHidden.checked = integrationView.showHidden;
    }

    /* ---- localStorage CRUD ---- */
    function load() {
        try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}"); } catch { return {}; }
    }
    function saveAll(data) {
        try { localStorage.setItem(STORE_KEY, JSON.stringify(data)); } catch { /* ignore */ }
    }
    function getConfig(toolId) {
        if (toolId === "claroty" && clarotyBackendStatus?.configured) {
            return { baseUrl: clarotyBackendStatus.baseUrl, proxyUrl: clarotyBackendStatus.proxyUrl, apiKey: "••••••••" };
        }
        const config = serverCredentialTools[toolId]?.safeConfig || {};
        if (toolId === "rubrik") {
            return {
                ...config,
                access_token_uri: config.access_token_uri || config.baseUrl || "",
                client_id: config.client_id || config.clientId || "",
                client_secret: config.client_secret || config.clientSecret || ""
            };
        }
        return config;
    }
    async function saveConfig(toolId, config) { return saveServerConfig(toolId, config); }
    async function clearConfig(toolId) { return deleteServerConfig(toolId); }
    function isConfigured(toolId) {
        if (toolId === "claroty" && clarotyBackendStatus?.configured) return true;
        if (serverCredentialTools[toolId]?.configured) return true;
        return !!serverCredentialTools[toolId]?.configured;
    }
    function configuredCount() { return TOOLS.filter(t => isConfigured(t.id)).length; }

    /* ---- Connection test ---- */
    async function testConnection(toolId) {
        const cfg = getConfig(toolId);
        const tool = TOOLS.find(t => t.id === toolId);
        const hasKey = serverCredentialTools[toolId]?.configured || tool && tool.fields.some(f => cfg[f.key] && cfg[f.key].length > 2);
        if (!hasKey) return { ok: false, msg: "No credentials configured — fill in the fields above first" };
        if (toolId === "swimlane") {
            try {
                const started = performance.now();
                await SwimlaneAPI.validateConnection();
                return { ok: true, msg: `Connected successfully · Response ${Math.round(performance.now() - started)}ms · Auth validated` };
            } catch (err) {
                return { ok: false, msg: `Connection failed · ${err.message}` };
            }
        }
        if (toolId === "claroty" && typeof ClarotyAPI !== "undefined") {
            const started = performance.now();
            const result = await ClarotyAPI.validateConnection();
            const ms = Math.round(performance.now() - started);
            return result.ok
                ? { ok: true, msg: `${result.msg} · ${ms}ms` }
                : { ok: false, msg: result.msg };
        }
        return await serverIntegrationTest(toolId);
    }

    async function serverIntegrationTest(toolId) {
        try {
            const response = await fetch("/api/integrations/test", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ toolId })
            });
            const payload = await response.json();
            if (!response.ok) return { ok: false, msg: payload.error || `Test failed (${response.status})` };
            const parts = [payload.message];
            if (payload.latencyMs != null) parts.push(`${payload.latencyMs}ms`);
            if (!payload.authTested && payload.ok) parts.push("reachability only — credential not verified");
            return { ok: Boolean(payload.ok), msg: parts.filter(Boolean).join(" · ") };
        } catch (error) {
            return { ok: false, msg: `Test request failed: ${error.message}` };
        }
    }

    /* ---- Render integration settings panel ---- */
    function render(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        const needsServerStatus = !serverCredentialsLoaded;

        const categories = [...new Set(TOOLS.map(t => t.category))];
        const hiddenIds = hiddenToolIds();
        if (!container.dataset.integrationControlsBound) {
            container.dataset.integrationControlsBound = "true";
            container.addEventListener("input", event => {
                if (event.target.matches("[data-integration-search]")) {
                    integrationView.query = event.target.value;
                    applyIntegrationFilters(container);
                }
            });
            container.addEventListener("change", event => {
                if (event.target.matches("[data-integration-category-filter]")) integrationView.category = event.target.value;
                if (event.target.matches("[data-integration-hide-unconfigured]")) integrationView.hideUnconfigured = event.target.checked;
                if (event.target.matches("[data-integration-show-hidden]")) integrationView.showHidden = event.target.checked;
                applyIntegrationFilters(container);
            });
            container.addEventListener("click", event => {
                const button = event.target.closest("[data-integration-visibility]");
                if (!button) return;
                const toolId = button.dataset.integrationVisibility;
                const next = hiddenToolIds();
                if (next.has(toolId)) next.delete(toolId);
                else next.add(toolId);
                try { localStorage.setItem(HIDDEN_TOOLS_KEY, JSON.stringify([...next])); } catch { /* storage may be unavailable */ }
                applyIntegrationFilters(container);
            });
        }

        container.innerHTML = `<div class="integ-manager-controls" role="search">
            <label class="integ-filter-search"><span>Find integration</span><input type="search" data-integration-search placeholder="Search tools, categories, or capabilities" aria-label="Search integrations" /></label>
            <label class="integ-filter-category"><span>Category</span><select data-integration-category-filter aria-label="Filter integration category"><option value="all">All categories</option>${categories.map(category => `<option value="${category}">${category}</option>`).join("")}</select></label>
            <label class="integ-visibility-option"><input type="checkbox" data-integration-hide-unconfigured /> Hide unconfigured</label>
            <label class="integ-visibility-option"><input type="checkbox" data-integration-show-hidden /> Show hidden cards</label>
            <span class="integ-filter-status" data-integration-filter-status role="status"></span>
        </div>` + categories.map(cat => {
            const tools = TOOLS.filter(t => t.category === cat);
            return `
            <div class="integ-section" data-integration-category="${cat}">
                <div class="integ-section-title">${cat}</div>
                <div class="integ-forms-grid">
                ${tools.map(tool => {
                    const cfg = getConfig(tool.id);
                    const configured = isConfigured(tool.id);
                    const savedFields = serverCredentialTools[tool.id]?.fields || [];
                    const hasSavedField = key => savedFields.includes(key) || tool.id === "rubrik" && (
                        key === "access_token_uri" && savedFields.includes("baseUrl")
                        || key === "client_id" && savedFields.includes("clientId")
                        || key === "client_secret" && savedFields.includes("clientSecret")
                    );
                    const clarotyLive = tool.id === "claroty" && window.ClarotyAPI?.feedState("devices").source === "live";
                    const extraActions = tool.id === "claroty"
                        ? `<a class="ifc-btn docs" href="claroty-demo.html" target="_blank" rel="noopener">📊 Data Loader</a>`
                        : "";
                    return `
                    <div class="integ-form-card" id="ifc-${tool.id}" data-integration-card data-tool-id="${tool.id}" data-name="${tool.name}" data-category="${tool.category}" data-configured="${configured}">
                        <div class="ifc-head">
                            <div class="ifc-logo" style="background:${tool.color}">${tool.logo}</div>
                            <div class="ifc-info">
                                <div class="ifc-name">${tool.name}</div>
                                <div class="ifc-cat">${tool.category}</div>
                            </div>
                            <span class="ifc-status ${clarotyLive ? "ok" : "uncfg"}">${clarotyLive ? "● Live connection" : configured ? "● Settings saved · unverified" : "○ Not set"}</span>
                        </div>
                        <div class="ifc-desc">${tool.desc}</div>
                        <div class="ifc-fields">
                            ${tool.fields.map(f => `
                            <div class="ifc-field-row">
                                <label class="ifc-label">${f.label}</label>
                                <input class="ifc-input" type="${f.type}"
                                    id="ifc-${tool.id}-${f.key}"
                                    placeholder="${hasSavedField(f.key) && f.type === "password" ? "Saved encrypted · enter new value to replace" : f.placeholder}"
                                    value="${f.type !== "password" ? (cfg[f.key] ?? f.defaultValue ?? "") : (cfg[f.key] || hasSavedField(f.key) ? "••••••••" : "")}" 
                                    autocomplete="off" spellcheck="false" />
                            </div>`).join("")}
                        </div>
                        <div class="ifc-actions">
                            <button class="ifc-btn save" onclick="INTEGRATIONS.saveForm('${tool.id}')">💾 Save</button>
                            <button class="ifc-btn test" id="ifc-test-${tool.id}" onclick="INTEGRATIONS.runTest('${tool.id}')">⚡ Test</button>
                            <button class="ifc-btn clear" onclick="INTEGRATIONS.clearForm('${tool.id}')">🗑 Clear</button>
                            <button type="button" class="ifc-btn integ-visibility-toggle" data-integration-visibility="${tool.id}" aria-label="${hiddenIds.has(tool.id) ? "Show" : "Hide"} ${tool.name}">${hiddenIds.has(tool.id) ? "Show" : "Hide"}</button>
                            ${extraActions}
                            ${tool.docs ? `<a class="ifc-btn docs" href="${tool.docs}" target="_blank" rel="noopener noreferrer">📖 Docs</a>` : ""}
                        </div>
                        <div class="ifc-result" id="ifc-result-${tool.id}"></div>
                    </div>`;
                }).join("")}
                </div>
            </div>`;
        }).join("") + renderCopilotStudioCard();
        applyIntegrationFilters(container);
        container.querySelector("#ifc-copilot-studio")?.addEventListener("click", async event => {
            const button = event.target.closest("[data-copilot-action]");
            if (!button) return;
            const action = button.dataset.copilotAction;
            const input = container.querySelector("#copilot-studio-endpoint");
            const result = container.querySelector("#copilot-studio-result");
            const status = container.querySelector("#copilot-studio-status");
            if (action === "open-search") {
                document.getElementById("createAiBtn")?.click();
                return;
            }
            if (action === "clear") {
                try { localStorage.removeItem(COPILOT_ENDPOINT_KEY); } catch { /* storage may be unavailable */ }
                input.value = "";
                status.className = "ifc-status uncfg";
                status.textContent = "○ Not connected";
                result.className = "ifc-result info";
                result.textContent = "Endpoint cleared from this device.";
                return;
            }
            const endpoint = input.value.trim();
            if (!copilotEndpointValid(endpoint)) {
                result.className = "ifc-result err";
                result.textContent = "Enter a valid HTTPS Copilot Studio token endpoint. Direct Line secrets are not accepted.";
                return;
            }
            if (action === "save") {
                try { localStorage.setItem(COPILOT_ENDPOINT_KEY, endpoint); }
                catch { result.className = "ifc-result err"; result.textContent = "Could not save the endpoint in this browser."; return; }
                status.className = "ifc-status ok";
                status.textContent = "● Endpoint saved";
                result.className = "ifc-result info";
                result.textContent = "Endpoint saved on this device. Test connection to verify the agent.";
                return;
            }
            button.disabled = true;
            result.className = "ifc-result loading";
            result.textContent = "Testing Copilot Studio connection…";
            try {
                result.textContent = await testCopilotEndpoint(endpoint);
                result.className = "ifc-result ok";
                status.className = "ifc-status ok";
                status.textContent = "● Connected";
            } catch (error) {
                result.className = "ifc-result err";
                result.textContent = error.message;
            } finally {
                button.disabled = false;
            }
        });
        refreshClarotyBackendStatus();
        if (needsServerStatus) loadServerCredentialStatus().then(() => {
            if (!container.isConnected) return;
            render(containerId);
            updateConfiguredCount();
        });
    }

    async function refreshClarotyBackendStatus() {
        if (typeof ClarotyAPI === "undefined") return;
        clarotyBackendStatus = await ClarotyAPI.migrateLocalCredentialsToBackend();
        const cfg = getConfig("claroty");
        ["baseUrl", "proxyUrl"].forEach(key => {
            const input = document.getElementById(`ifc-claroty-${key}`);
            if (input && cfg[key] != null) input.value = cfg[key];
        });
        const apiKey = document.getElementById("ifc-claroty-apiKey");
        if (apiKey && clarotyBackendStatus?.configured) apiKey.value = "••••••••";
        updateToolStatus("claroty");
        updateConfiguredCount();
    }

    function updateToolStatus(toolId) {
        const card = document.getElementById(`ifc-${toolId}`);
        const status = card && card.querySelector(".ifc-status");
        if (!status) return;
        const ok = isConfigured(toolId);
        const live = toolId === "claroty" && window.ClarotyAPI?.feedState("devices").source === "live";
        status.className = `ifc-status ${ok ? "ok" : "uncfg"}`;
        status.textContent = live ? "● Live connection" : ok ? "● Settings saved · unverified" : "○ Not set";
    }

    async function saveForm(toolId) {
        const tool = TOOLS.find(t => t.id === toolId);
        if (!tool) return;
        const cfg = toolId === "claroty" ? {} : { ...getConfig(toolId) };
        tool.fields.forEach(f => {
            const el = document.getElementById(`ifc-${toolId}-${f.key}`);
            if (el) {
                const val = el.value.trim();
                if (val && val !== "••••••••") cfg[f.key] = val;
                else if (f.type !== "password") cfg[f.key] = val;
                else if (!val) delete cfg[f.key];
            }
        });
        if (toolId === "claroty") {
            try {
                if (typeof ClarotyAPI === "undefined") throw new Error("ClarotyAPI is not loaded");
                clarotyBackendStatus = await ClarotyAPI.saveBackendCredentials(cfg);
                try {
                    const all = load();
                    delete all.claroty;
                    saveAll(all);
                } catch { /* ignore */ }
                updateToolStatus(toolId);
                showResult(toolId, { ok: true, msg: "✓ Claroty credentials encrypted and saved in backend storage" }, "save");
                updateConfiguredCount();
            } catch (error) {
                showResult(toolId, { ok: false, msg: `✗ ${error.message}` }, "err");
            }
            return;
        }
        try {
            await saveServerConfig(toolId, cfg);
            updateToolStatus(toolId);
            showResult(toolId, { ok: true, msg: "✓ Settings encrypted and saved on this server · connection unverified" }, "save");
            updateConfiguredCount();
            if (toolId === "swimlane") await window.SwimlaneAPI?.loadServerCredentials(true);
        } catch (error) {
            showResult(toolId, { ok: false, msg: `✗ ${error.message}` }, "err");
        }
    }

    async function runTest(toolId) {
        const btn = document.getElementById(`ifc-test-${toolId}`);
        if (btn) { btn.disabled = true; btn.textContent = "⏳ Testing…"; }
        showResult(toolId, { ok: null, msg: "Connecting…" }, "loading");
        const result = await testConnection(toolId);
        showResult(toolId, result, result.ok ? "ok" : "err");
        if (btn) { btn.disabled = false; btn.textContent = "⚡ Test"; }
    }

    async function clearForm(toolId) {
        const tool = TOOLS.find(t => t.id === toolId);
        if (!tool) return;
        if (toolId === "claroty" && typeof ClarotyAPI !== "undefined") {
            try {
                clarotyBackendStatus = await ClarotyAPI.clearBackendCredentials();
                const legacy = load();
                delete legacy.claroty;
                saveAll(legacy);
            } catch (error) {
                showResult(toolId, { ok: false, msg: `✗ ${error.message}` }, "err");
                return;
            }
        } else {
            try { await deleteServerConfig(toolId); }
            catch (error) {
                showResult(toolId, { ok: false, msg: `✗ ${error.message}` }, "err");
                return;
            }
        }
        tool.fields.forEach(f => {
            const el = document.getElementById(`ifc-${toolId}-${f.key}`);
            if (el) el.value = "";
        });
        updateToolStatus(toolId);
        showResult(toolId, { ok: null, msg: "Credentials cleared" }, "info");
        updateConfiguredCount();
    }

    function showResult(toolId, result, type) {
        const el = document.getElementById(`ifc-result-${toolId}`);
        if (!el) return;
        el.className = `ifc-result ${type}`;
        el.textContent = result.msg;
    }

    function updateConfiguredCount() {
        const el = document.getElementById("integ-configured-count");
        if (el) el.textContent = `${configuredCount()} / ${TOOLS.length} settings saved · connections unverified unless tested`;
    }

    return { TOOLS, getConfig, saveConfig, clearConfig, isConfigured, configuredCount,
             testConnection, render, saveForm, runTest, clearForm, updateConfiguredCount, loadServerCredentialStatus };
})();
