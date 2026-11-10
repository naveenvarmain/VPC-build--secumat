# OT Platform — Security Operations Dashboard

A single-page OT Platform covering Claroty xDome device coverage, vulnerability
analytics, risk management, threat intel enrichment, automation ROI, integrations,
playbooks, an executive scorecard, a live alert feed, a geo threat map, SLA tracking,
OT optimization, Settings - Integrations, User Management, and an incident graph
explorer.

Claroty xDome is the primary live OT data source. The Python backend (`server.py`)
serves the static site, stores Claroty credentials encrypted with Fernet, proxies
Claroty live-data calls, and provides supporting JSON APIs for alerts and public
threat-intel feed aggregation (CISA KEV, NVD, MSRC, URLhaus).

The Home, Devices Covered, Vulnerabilities, Risk & Exposures, Alerts & Threats,
and Network sections load xDome data automatically from the configured encrypted credential. Counts
show how many records are loaded and identify partial pages. Other SOC modules
are retained as sample analytics and marked as such in the app; the Claroty
API does not provide their incident, analyst, playbook, or SLA records.

An in-app **Documentation** tab (sidebar → 📘 Documentation) mirrors this file with
clickable section links.

## Quick Start

```powershell
py server.py
```

Then open **http://127.0.0.1:8080/** in a browser.

- Health check: `GET /api/health`
- Install prerequisites once with `py -m pip install -r requirements.txt`.
- The app is static HTML/CSS/JS served by `server.py`; Claroty credential encryption
  uses Python `cryptography`.

## File Structure

```
index.html              Layout, sidebar nav, all panel markup
styles.css               Dark/light cyber theme, all component styles
config.js                Swimlane connection config (demo-mode by default)
api.js                   Supporting alert/feed client
reports.js               CSV parsing + incident classification engine
integrations.js          API credential forms; Claroty saves encrypted backend credentials
xdome-modules.js         Claroty xDome device coverage and vulnerability tab renderers
xdome-portal.js          Live xDome Home, Risk, Alerts, Network, and export views
production-risk.js       Risk Management tab (exec risk, correlation, MTTR/SLA, heatmap, tool status)
app.js                   Navigation, charts, drill-downs, AI modal, notifications, exports
server.py                Python stdlib HTTP server + JSON API (alerts, incidents, public feeds)
%LOCALAPPDATA%/OTPlatform/    Encrypted Claroty and vendor integration credentials
```

## Tabs Reference

| Tab | What it shows |
|---|---|
| Home / Overview | Live xDome estate, risk, alert, CVE and event previews; incident activity heatmap filters from 2 to 52 weeks and drills into the selected week |
| OT Operations | Analyst productivity, false-positive reduction, closure rate, correlation timeline |
| Devices Covered | Live paged xDome device inventory, connectivity, risk, filters and device details |
| Vulnerabilities | Live paged xDome findings and severity mix; sample MITRE and aging charts are labeled |
| Threat Intel | Public CVE/KEV feeds, universal IOC enrichment search, Snort rule archive catalog, source catalog |

| Insider Threat | UBA risk KPIs, behavioral anomalies, exfiltration signals |
| Automation | Playbook execution success, hours saved by use case |
| Automation ROI | Interactive ROI calculator, cumulative cost avoidance, targets table |
| SIEM Integrations | Alert reduction funnel, events processed by platform |
| SIEM Workbench | Local event/source summaries, audit evidence, ATT&CK catalogue coverage, feed health, detection-engine readiness, and allowlisted local event search |
| OSINT Navigator | Investigation technique catalogue organised by the evidence you start with, plus an observable pivot that runs this platform's own indicator, known-exploited, and stored-sighting checks |
| Playbooks | Phishing response workflow diagram, use-case playbook table |
| Exec Scorecard | OT maturity radar, KPI RAG scorecard, executive outcomes |
| Alerts & Threats | Live xDome alerts; the separate SOC incident ticker needs another connector |
| Network | Live paged xDome network/OT activity events, observed-IP inventory, and local whitelist/blacklist controls |
| Threat Map | Geo threat origin bubbles, attack type by region, volume timeline |
| SLA Tracker | Breach/at-risk/on-track KPIs with AI-assisted investigation |
| OT Optimization | Maturity radar, benchmark comparison, prioritised recommendations, roadmap |
| Risk & Exposures | Live xDome device risk and an explicitly derived CVE exposure matrix; separate CAB analytics are sample data |
| SOC Studio | AnySIEM report drafts (38 templates), Sentinel adoption planning, coverage-disclosing ShiftGuard rosters, 21-section handbook, SOC learning path, 14 vendor-neutral dashboards, ATT&CK-mapped ELK detection starters, response playbooks, and local IOC analysis |
| Settings - Integrations | Encrypted credential forms including GitHub and GitLab, hide/show and category filters, security-tool inventory and User Management |
| Incident Graph | Force-directed entity graph, attack story, similar incidents |
| Documentation | This reference, rendered in-app |

Snort 3 Community rules are checked at server startup and refreshed every 24 hours when Snort.org is reachable. Use **Check for rule updates** for an immediate check. Import account-authorized `.tar.gz` packages to include Registered or Subscriber rules; these require the appropriate Snort account and license. The catalog indexes `.rules` files for search and inspection but does not run Snort or deploy rules to a sensor. Rule archives and UTF-8 IP/CIDR lists stay in the current user's local application data. Binary `.blf` files are not parsed; export them as text before importing. The Network page's whitelist and blacklist classify observed IPs, but do not enforce firewall policy.

The Integrations page's **Snort 3 Engine** card checks for `snort` on the server `PATH` or at `SNORT_ENGINE_PATH` and reports the local rule-catalog count. It does not start the engine or validate traffic detections. Use `snort -T` on the sensor host to test its configured engine and rule set.

## Key Formulas

```
Production Risk Score = CVSS×0.25 + Criticality×0.25 + Impact×0.20 + Exploitability×0.10 + Aging×0.10 + Exposure×0.10
Detection Confidence  = (Tools that detected CVE ÷ Total tools compared) × 100
MTTR                   = SUM(Resolution Days) ÷ COUNT(Closed Tickets)
SLA Breach %           = Breached Incidents ÷ Total Incidents × 100
Hours Saved            = (Incidents × Manual min − Incidents × Processing min) ÷ 60
FTE Savings            = Hours Saved × 12 ÷ (160 × 12)  →  Cost Avoidance = FTE × Annual Analyst Cost
```

## Server API (`server.py`)

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Liveness check |
| `/api/claroty/credentials` | GET/POST/DELETE | Encrypted Claroty credential status, save and clear |
| `/api/claroty/device-vulnerability-relations` | POST | Backend Claroty live-data proxy using the encrypted credential |
| `/api/claroty/feed` | POST | Paginated, allowlisted live devices, relations, alerts, CVEs, and events |
| `/api/claroty/diagnostics` | POST | Read-only connectivity checks for the five supported feeds |
| `/api/integrations/credentials` | GET/POST | Encrypted vendor setting status and save; secret values are never returned |
| `/api/integrations/credentials/{toolId}` | DELETE | Delete one encrypted vendor credential set |
| `/api/integrations/feed-state` | GET/POST | Read or toggle implemented Rubrik API polling |
| `/api/integrations/api-feeds/refresh` | POST | Manually poll configured read-only GitHub, GitLab, MISP, Keycloak, OpenSearch, Wazuh Indexer, SentinelOne, Defender for Cloud Apps, Prisma Cloud, ONTAP, and Cato audit feeds; routes normalized records to local evidence |
| `/api/integrations/connectors/{id}/enabled` | POST | Enable/pause an inbound connector; disabled endpoints reject new events |
| `/api/integrations/git/refresh` | POST | On-demand read-only GitHub/GitLab cloud API polling; routes normalized audit, alert and vulnerability records into local SIEM evidence |
| `/api/integrations/webhooks/github` | POST | Receive GitHub events authenticated with `X-Hub-Signature-256` using the saved webhook secret |
| `/api/integrations/webhooks/gitlab` | POST | Receive GitLab events authenticated with `X-Gitlab-Token` using the saved webhook secret |
| `/api/threat-intel/feeds` | GET | Local status, counts and refresh timestamps for indexed public indicators |
| `/api/threat-intel/feeds/refresh` | POST | Refresh configured public IP/domain/hash sources into the local index |
| `/api/threat-intel/lookup` | GET | Exact-match an IP, domain, MD5, SHA-1 or SHA-256 value against the local index |
| `/api/zero-trust/program` | GET/POST | Persist validated UDP maturity, governance, roadmap, control and AI-control profile; rejects credential fields |
| `/api/zero-trust/integrations` | GET | Provider and event-receiver readiness; configured does not mean connected |
| `/api/zero-trust/analytics` | GET | Metrics over canonical local audit events; missing telemetry is reported as unavailable |
| `/api/zero-trust/events` | GET/POST | Read/write validated local security events |
| `/api/zero-trust/detections` | GET | Evaluate local event rules, including malicious indicator-feed matches, over a bounded lookback window |
| `/api/zero-trust/policy/decision` | POST | Simulated policy evaluation; does not enforce access |
| `/api/zero-trust/risk/score` | POST | Deterministic five-factor risk score; not machine learning or enforcement |
| `/api/modules` | GET | Allowlisted modules available in the local record store |
| `/api/modules/{module}` | GET/POST | Search/list or create records for an allowlisted module; audit workflow collections are read-only here |
| `/api/modules/soc_studio` | GET/POST/PUT/DELETE | Persist locally saved SOC Studio reports, plans, rosters, handbook sections, learning progress, dashboard designs, detection drafts, playbooks, and IOC analyses; writes require the local session and same-origin request |
| `/api/soc-studio/summary` | GET | Local record counts and connector configuration readiness; configured credentials are not treated as verified connections |
| `/api/soc-studio/analyze` | POST | Aggregate up to 5,000 normalized records by source, severity, status, ATT&CK technique, and day; raw records are not stored or returned |
| `/api/modules/{module}/{id}` | GET/PUT/DELETE | Read, update, or delete one persisted module record; workflow-owned audit records cannot be changed through generic CRUD |
| `/api/analytics/modules` | GET | Aggregated counts and status/severity summaries from saved local module records |
| `/api/analytics/threats` | GET | Local threat, event, alert, vulnerability, indicator, and Snort-catalog counts; not a live-feed substitute |
| `/api/siem/dashboard` | GET | SIEM counts and trends from canonical local events, saved modules, audit assignments, threat feeds, and detection-engine readiness |
| `/api/siem/events` | GET | Search local event records with free text and allowlisted `source`, `severity`, `event_type`, `device`, and `ioc` filters; returns at most 200 rows |
| `/api/osint/framework` | GET | OSINT discipline catalogue: categories, subcategories, techniques, accepted input types, and access tiers |
| `/api/osint/search` | GET | Filter OSINT techniques by `q`, `category`, `input`, and `access`; unknown filter values are rejected with 400 |
| `/api/osint/pivot` | POST | Classify an observable and run the local indicator, known-exploited, and stored-sighting checks that apply to it |
| `/api/modules/osint_workspace` | GET/POST/PUT/DELETE | Persist OSINT bookmarks and investigation notes locally |
| `/api/automation/playbooks` | GET | Local dry-run playbook catalog and recent run history |
| `/api/automation/run` | POST | Record an automation dry-run from current local records; executes no vendor action |
| `/api/automation/runs` | GET | Recent local automation dry-runs |
| `/api/secumat_workspace` | GET | SECUMAT options, local audits, assignments, uploads, and custom questionnaires |
| `/api/secumat_templates` | GET | Templates discovered in `Audit Templates & Question Bank` |
| `/api/audit/workbooks?source={filename}` | GET | Audit draft/submission history for a spreadsheet template, including version and editor session |
| `/api/audit/workbooks/versions/{id}` | GET | Restore an immutable workbook revision with edited cells and row ratings/evidence |
| `/api/audit/workbooks` | POST | Save a draft, Save As a separate audit, or submit a locked version; rejects stale versions |
| `/api/secumat_audits` | GET/POST | Create and list persisted SECUMAT audit profiles |
| `/api/secumat_audits/{id}` | GET/PUT/DELETE | Read, update, or delete an audit profile |
| `/api/audit_assignments` | GET/POST | Create and list audit assignments |
| `/api/audit_assignments/{id}` | GET/PUT/DELETE | Read, update, or delete an assignment and its responses |
| `/api/audit_assignment_responses` | GET/POST | Save assignment responses and calculate progress/compliance scores |
| `/api/audit_results/{id}` | GET | Calculated assignment report, status counts, and response details |
| `/api/audit_results/{id}/download` | GET | Download an assignment response CSV |
| `/api/audit_results/analytics` | GET | Status, completion, pending, reviewed score, framework and dated activity metrics from local audit records |
| `/api/audit_results/analytics.csv` | GET | Download all assignment outcomes and reviewer details as CSV |
| `/api/audit_results/{id}/review` | POST | Submit auditor score and comments after assignee submission; rejects premature or repeat reviews |
| `/upload/compliance` | POST | Store and preview CSV/XLSX/XLSM questionnaires locally |
| `/api/compliance_audit` | GET | Latest upload or assignment compliance summary |
| `/api/compliance_audit/{id}/preview` | GET | Bounded worksheet preview from a stored upload |
| `/api/swimlane/request` | POST | Allowlisted Swimlane authorize/record-search calls using the encrypted server PAT |
| `/api/alerts` | GET | Simulated SOC alert queue; not Claroty alerts |
| `/api/alerts/{id}/actions` | POST | Acknowledge / own / escalate an alert (`{"action": "..."}`) |
| `/api/public-feeds` | GET | Aggregates CISA KEV, NVD, MSRC, Feodo Tracker, FIRST EPSS, and CIRCL CVE-Search (15-minute cache) |
| `/api/snort/rules` | GET/POST | Lists merged rule archives or imports a `.tar.gz` package |
| `/api/snort/engine-status` | GET | Reports whether a local Snort executable is discoverable and summarizes the rule catalog; does not run Snort |
| `/api/snort/update` | POST | Checks/downloads the public Snort 3 Community package |
| `/api/snort/blacklist` | GET/POST | Searches or imports a UTF-8 IP/CIDR list |
| `/api/network/ip-lists` | GET/POST | Lists, classifies, adds, and removes local whitelist/blacklist IPs or CIDRs |

All local module and SECUMAT API routes require a valid local browser session; write routes also reject untrusted origins. The session token is held in server memory and is issued only on non-API responses, so a server restart or an expired token would otherwise leave an already-open tab polling `/api/*` and receiving 401 forever. `session-recovery.js` (loaded first on both the main dashboard and the SECUMAT page) wraps `fetch`, and on a 401 from a same-origin `/api/` call it re-requests `/` once to obtain a fresh cookie and retries the call a single time. Retrying is safe because a 401 is returned before any request handling, so no side effect occurs. Tabs opened before this script was added still need one manual reload. The module registry marks audit assignments, responses, and workbook versions read-only; dedicated audit APIs control their transitions. Static Python source, secret-file extensions, hidden paths, and directory listings are denied for GET and HEAD. The local session is not authenticated user or auditor identity and should not be treated as multi-user authorization. Module records and dry-run history are stored atomically under `%LOCALAPPDATA%/OTPlatform` (or the platform’s per-user data directory). SECUMAT upload files are stored under that directory, not in the web root. Vendor settings do not imply live API connectivity. Claroty and public-feed data still require outbound network access; automation endpoints only record dry-runs until a specific vendor connector is implemented and verified.

### GitHub and GitLab security feeds

In **Settings - Integrations**, save a GitHub organization name and a token authorized to read organization audit logs, Dependabot alerts and secret-scanning alerts, or a GitLab.com group ID/path and token authorized to read group audit events and vulnerability findings. Exact permissions and licensing depend on the provider and organization; each source reports authorization/availability errors separately. In **SIEM Workbench**, select **Sync Git sources** to fetch up to 100 recent records per source, route them into local audit/alert/vulnerability evidence, and update the GitHub/GitLab KPI counts. Polling is on demand, not a background subscription or exhaustive import. Only the public cloud API hosts are contacted; self-managed GitLab requires a separately reviewed host policy.

For push events, set a distinct organization webhook secret in the GitHub integration or group/project webhook secret token in the GitLab integration. Configure the provider webhook URL as `https://YOUR-INGRESS/api/integrations/webhooks/github` or `https://YOUR-INGRESS/api/integrations/webhooks/gitlab`, respectively. The default `127.0.0.1:8080` server cannot receive cloud webhooks directly; deploy behind an authenticated, publicly reachable HTTPS ingress with appropriate rate limits before enabling push delivery. Webhooks verify the provider signature/token and store only selected event fields, not the raw payload. The SIEM metrics represent evidence actually received or fetched, not a verified absence of findings when a source is unconfigured or unavailable.

The SIEM dashboard and local event search use the same most-recent 5,000-record window for each contributing module, in addition to the local canonical event log. Search is a local query feature, not remote KQL execution. Feed or provider errors are reported as unavailable evidence and do not imply successful monitoring or enforcement.

The OSINT Navigator is a technique catalogue organised by the evidence an investigation starts with, not a directory of third-party sites. Each technique records the inputs it consumes, the outputs it produces, the access tier normally required, and whether this platform can perform the step. `/api/osint/pivot` classifies a submitted observable as an IP address, domain, file hash, CVE, email address, URL, crypto address, username, or person, then runs only the local checks that apply: the indexed indicator partitions, the known-exploited catalogue, and stored local sightings. Every other technique is returned as a recorded next step and is explicitly not performed; a "no hit" result means the observable is absent from local evidence, not that it is safe.

The SECUMAT template dropdown lists every file in the Audit Templates & Question Bank. Spreadsheet templates can be loaded, opened in a separate editor window, opened as Excel files, or assigned to a person/team. Workbook assignments derive question totals from the source file; saving rated rows updates completion percentage, pending items, editor session, and pending/in-progress/submitted status. The assignment table can reopen the latest assigned revision. The workbook editor loads all worksheets and cell values, including blank rows within the Excel used range. It pages the grid and stores only changed cells plus per-row ratings/evidence in immutable local audit revisions, visible on the Audit History tab. Older browser-only reviews are recovered as unsaved drafts. Save Draft appends a version, Save As creates a separate draft, and Submit locks the current audit; historical versions are read-only but may be branched with Save As. "Edited by" identifies the local browser session, not an authenticated user account. Export writes a new reviewed XLSX without changing the library template; Excel formatting, merged-cell layout, and formula editing are not represented by the value grid. Revision records have a 256 KB per-version limit; large bulk edits must be divided into smaller workbooks.

Audit Results includes pending and submitted assignments, actual workbook ratings/evidence, a dated assignment/submission/review trend, status and framework breakdowns, and a downloadable assignment CSV. Reviewer score averages appear only after an auditor submits a result. Auditor names are self-entered in the local app, not verified identities; the local session cookie is the only access control.

## Client Data Layer

- **ClarotyAPI** (`claroty.js`) — paginates the five supported xDome feeds
  through the encrypted backend and caches loaded pages until refresh. The
  dashboard refreshes while open every five minutes.
- **Reports** (`reports.js`) — parses an imported CSV, classifies each row into
  category/severity/automation via regex rules, and produces the same aggregate shape
  the charts expect.
- **INTEGRATIONS** (`integrations.js`) — stores vendor credentials encrypted in the
  local backend app-data directory. The browser receives safe field metadata only;
  saved settings are not verified connections.

## Create with AI and Copilot Studio

Create with AI includes local application chat, documentation search, quick help,
the indexed application knowledge base, and xDome draft generation. Local chat
searches the app guide and Claroty setup/troubleshooting documents; it is retrieval
from documentation, not a generative model.

To enable Microsoft Copilot chat:

1. Create and publish an agent in Microsoft Copilot Studio. Add this application's
  README and the relevant Claroty integration/troubleshooting files as agent
  knowledge sources if the agent should answer application-specific questions.
2. Configure the agent's web channel and trusted origins for the website hosting
  this dashboard. The trusted origin should match the dashboard's exact origin.
3. Copy the agent's **token endpoint** from its custom website/Web Chat setup. In
  Create with AI → Chat, paste that HTTPS token endpoint and select **Save endpoint**.
  Do not paste a Direct Line secret or API key.
4. Select **Start Copilot chat**. The browser obtains a short-lived conversation
  token from the configured agent endpoint and loads Microsoft's Web Chat client.

The token endpoint is saved in this browser's local storage. The Direct Line secret
must remain in Microsoft; it is never stored by this application. Copilot chat sends
the messages you type to your configured agent. xDome records are not automatically
sent to it. Local application KB chat and search remain available without Copilot.
See Microsoft's [Copilot Studio website publishing guide](https://learn.microsoft.com/en-us/microsoft-copilot-studio/publication-connect-bot-to-web-channels)
and [Direct Line authentication guide](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-direct-line-3-0-authentication?view=azure-bot-service-4.0).

## Integrations

29 tools are configurable under **Settings - Integrations**, including Swimlane,
CrowdStrike, Trellix, McAfee ePO, Wazuh, SentinelOne, BMC Helix ITSM, Microsoft
Sentinel, Splunk, Defender XDR, Defender for Cloud Apps, Wiz, Prisma Cloud, Entra ID,
ServiceNow, Palo Alto, M365, QRadar, VirusTotal, AbuseIPDB, GreyNoise, Tenable/Nessus,
Claroty, Elastic, Rubrik Security Cloud, NetApp ONTAP, Nasuni, Cato Networks SASE,
DC2Cloud, SentinelOne, McAfee ePO, Wazuh, BMC Helix, Defender for Cloud Apps,
Wiz and Prisma Cloud. Cards can be
searched, filtered by category, hidden individually, and restored without deleting
saved credentials.
Integration credentials are encrypted by the local backend with Fernet and stored
under the current user's application data directory. The browser receives only
configured-field metadata; secrets are not returned to JavaScript. Saved settings
do not prove a live connection. Swimlane uses a constrained backend proxy. Read-only
GitHub, GitLab, MISP, Keycloak, OpenSearch, Wazuh Indexer, SentinelOne, Defender
for Cloud Apps, Prisma Cloud, NetApp ONTAP, and Cato audit feeds are polled on demand; OpenSearch and Wazuh require an index
pattern or Indexer URL respectively. Keycloak requires a service account permitted
to view realm and admin events. Defender for Cloud Apps requires the Graph
`SecurityAlert.Read.All` application permission. Cato uses the vendor `auditFeed`
GraphQL operation with `x-api-key`, account ID, and a fixed 24-hour time frame;
pagination is bounded and does not issue policy or response mutations. Other
vendor API cards remain settings-only until their server-side connectors are implemented
and tested. Cato and DC2Cloud are listed in Zero Trust readiness but do not imply
live telemetry or policy enforcement. The Inbound Event Integrations panel provides webhook, REST JSON, and
an HTTP bridge accepting RFC 5424/3164 syslog text. Create a **Rubrik Security Cloud (PD-CEF webhook)**
receiver to map Rubrik trigger/resolve/acknowledge notifications into canonical local events. The adapter
retains only a small allowlist of `custom_details` fields and never stores the PD-CEF routing key.
Configure Rubrik to send `Authorization: Bearer <receiver token>` to the generated endpoint; the token
is shown once. The dashboard listens on localhost only, so remote Rubrik senders require a secured
reachable collector or reverse proxy. The Rubrik API credential card accepts `name`, `access_token_uri`,
`client_id`, and `client_secret`; the secret is encrypted in backend storage and never returned to the
browser. Existing camelCase Rubrik settings are migrated when saved. The API credential remains
enabled for a read-only live activity and audit-events panel: the dashboard obtains short-lived tokens from
`/api/client_token` using the OAuth2 client-credentials form and queries `/api/graphql` with Rubrik's
documented `activitySeriesConnection` and `userAuditConnection` queries. The panel fetches 50 workload
activities and 50 audit events per request from the last 24 hours, then exposes cursor-based **Load more**
pages until both streams are exhausted. The initial page refreshes every 60 seconds while visible. Each
request is bounded to one GraphQL page so a large result set does not hold a single dashboard request open.
It performs no GraphQL mutations and
does not treat local webhook tests as vendor data. Push-based alert notifications still require Rubrik
webhook delivery. Claroty also includes a one-time Data Loader from its settings card.

The **Connected tool feeds** card in Settings controls the Rubrik API poller and
each inbound event connector. Disabling Rubrik prevents API polling; disabling an
inbound connector rejects new deliveries until it is enabled again. **Enable all
available feeds** enables those toggle-controlled paths only. The read-only GitHub,
GitLab, MISP, Keycloak, OpenSearch, Wazuh Indexer, SentinelOne, Defender for Cloud
Apps, Prisma Cloud, and NetApp ONTAP API feeds are manually synced from the SIEM
Workbench and are not enabled by that toggle.
Successful Rubrik API polls are upserted into the `integrations` module using stable
event IDs. Accepted inbound events are stored in the canonical local event log and
the `integrations` module. Explicit threat/security-alert events are also mapped to
`alerts`; explicit vulnerability events or CVE-bearing findings are mapped to
`vulnerabilities`. Other records remain in `integrations`.

Audit events are retained as integration evidence and are not automatically written
into audit assignments, audit results, or reports. Those records represent reviewed
compliance state and must not be changed by an unverified external event. The Settings
log tables show source, device/resource, path, indicators/IOCs, module routing, and
the full normalized event when provided. Fields absent from a vendor event (for
example, Rubrik API events do not provide a network path or IOC) are explicitly shown
as not reported rather than inferred.

The Threat Intel page also maintains a local SQLite index of the user-requested
public malicious IP, domain, MD5, SHA-1 and SHA-256 list partitions. IP partitions
refresh every 12 hours; domain and hash partitions refresh daily. It supports manual
refresh and exact lookup; a failed partition refresh keeps
its previous indexed data and reports the error. This separate index avoids flooding
the existing 25,000-record threat-intel module limit. Explicit indicator values in
incoming canonical events are checked against the index; URLs are checked using their
hostname against the malicious-domain partitions, while IP and file-hash observables
are matched by type. Confirmed local matches are annotated with feed provenance,
elevated to high severity (critical remains critical), assigned the local
`local-threat-feed-match` detection rule, and routed to Alerts alongside the original
Integration Events record. The local detections endpoint and SIEM KPIs include these
matches. This is read-only threat intelligence: it does not block addresses, execute
Snort rules, change policies, or run external response actions. The Snort/Suricata
ruleset is a local catalogue only unless an engine is installed and separately
validated. Feed data is stored locally and is not copied from the linked repositories'
source code.

The connector table has an editable ingest URL field for configuring an external sender; this browser-only URL override is stored locally and does not change the dashboard's receiver or redirect test events. Use **Rotate token** to invalidate an exposed or lost bearer token and issue a replacement, which is shown once. Update the external sender immediately after rotation.

## Unified Defense Platform

The UDP / Zero Trust workspace combines the domain readiness matrix, local canonical-event analytics, detection rules, policy simulation, and audited playbook dry runs. Its server-persisted program profile tracks accountable owner, review date, self-assessed maturity and targets, implementation phases, cross-domain controls, and AI-agent/LLM safeguards. Profile data contains no credentials. Maturity and control completion are self-attested, not independently certified.

Cato SASE and DC2Cloud are represented in the Network and Applications/Workloads readiness domains. Their saved credentials do not enable polling or policy enforcement. Cato/DC2Cloud telemetry can be normalized through the local webhook/REST event receiver; a vendor-specific API connector and schema mapping are still required for live collection. The policy engine remains simulation-only.

## Risk Management

Under **Risk Management**:

- **Executive Risk** — risk score, critical assets, coverage, MTTR, SLA breaches,
  compliance score, trend/severity/tool charts, revenue-at-risk, top risk assets.
- **Correlation Matrix** — CVE × tool detection grid (Claroty vs Nessus, BMC,
  Trellix, CrowdStrike, PITS) with confidence badges.
- **MTTR & SLA** — MTTR trend (all vs critical OT), MTTR-vs-SLA-target chart,
  remediation ticket table.
- **Risk Heatmap** — plant × production-line risk grid with revenue/risk-by-plant
  charts.
- **Tool Integrations** — status cards for all 11 OT/IT security tools (Claroty,
  Swimlane, CrowdStrike, Defender, Azure, Wiz, Sentinel, Nessus, Trellix, BMC, PITS)
  plus an ingestion volume chart.

Claroty live data is loaded through the encrypted backend route; additional vendor
connectors can be wired behind the same Settings - Integrations surface.

Claroty egress is selected by the **ZF Proxy** field on the Claroty settings card.
Leave it blank to connect directly when the host already reaches the internet
through another path, such as a SASE agent. The backend only accepts the default
cloud proxy, a direct connection, or a value listed in `CLAROTY_APPROVED_PROXY_URLS`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Blank charts on a tab | Chart.js needs a visible canvas — charts render/resize on first tab activation; switch tabs once |
| Claroty live data not loading | Open Settings - Integrations and confirm Claroty credentials are configured on this backend |
| All five Claroty feeds fail with `Remote end closed connection without response` | The configured **ZF Proxy** is not usable from this host. Confirm with `/api/claroty/diagnostics`; if the proxy also fails for unrelated destinations, clear the ZF Proxy field to connect directly. A successful TCP test to the proxy port does not prove it answers `CONNECT` |
| Claroty returns `405 Method Not Allowed` | Expected for a `GET`; the v1 endpoint requires `POST`. It indicates the API is reachable, not a fault |
| Import fails | Ensure the CSV has `Tracking Id`, `Case Status`, `BMC Incident Title` columns |
| Public feeds show errors | Requires outbound internet access to CISA/NVD/MSRC/URLhaus; failures are caught per-source and shown individually |
| Port already in use | Stop the other process on 8080 or edit `PORT` in `server.py` |

## Security Notes

- Vendor credentials are encrypted with Fernet and stored under the current user's
  application data directory. The key is outside the project tree. Legacy Claroty
  credentials are migrated from `data/` on the next backend load.
- The Copilot Studio token endpoint is stored in browser `localStorage`; it is an
  endpoint, not a secret. Direct Line secrets must never be pasted into the app.
- `server.py` binds to `127.0.0.1` and restricts browser origins and the Claroty
  proxy target. It still has no user authentication; keep it local and do not expose
  it through a reverse proxy or shared network without adding authentication,
  authorization, and deployment-grade CSRF protections.
- Most vendor integration cards store encrypted settings but do not implement a
  live connector. Only successful tests or received events should count as evidence
  of connectivity.
