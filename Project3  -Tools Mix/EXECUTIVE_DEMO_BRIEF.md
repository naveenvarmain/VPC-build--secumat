# OT Platform | Executive Demo Brief

## Purpose
A single operations workspace for connecting OT asset visibility, vulnerability and threat context, audit evidence, and operational risk. The platform is designed to help leadership and security teams see what is known, where evidence comes from, and which work still needs a verified connector or human decision.

## Why It Matters
OT security evidence is often split across asset tools, SIEMs, vulnerability systems, ticketing platforms, and spreadsheets. That fragmentation slows triage and makes it difficult to explain risk in operational terms. This platform brings supported data into a common view, marks data provenance, and gives teams local workflows for investigation, reporting, and audit preparation.

**Management outcomes:**
- See OT asset coverage, exposed vulnerabilities, alerts, and risk in one place.
- Move from an alert or observable to related local evidence and next investigation steps.
- Track audit assignments, workbook reviews, evidence, and outcomes with version history.
- Separate verified live data from sample analytics, configured credentials, and unavailable feeds.

## Suggested 5-Minute Demo
1. **Start at Overview:** show the estate and risk summary, source labels, and how live xDome counts reflect records actually loaded.
2. **Open Devices and Vulnerabilities:** filter the OT inventory, inspect a device, then show related vulnerability context and severity.
3. **Pivot an observable:** use the Threat Intel or OSINT view to check local indicators, known-exploited data, and stored sightings; explain that a no-hit result is not proof of safety.
4. **Show SIEM Workbench:** sync configured read-only feeds, inspect normalized event evidence and source status, then use local filters to find related events.
5. **Close on Risk and Audit:** show risk prioritization, an audit workbook/assignment history, and a dry-run playbook or ROI view.

## Topics Covered
OT asset inventory and connectivity; vulnerability and CVE exposure; public threat intelligence; alert and event triage; risk, MTTR/SLA, and operational impact; audit workbooks and assignments; SIEM evidence and ATT&CK coverage; integrations; Zero Trust readiness; playbooks and automation ROI.

## Integrations and Data Sources
- **Primary OT source:** Claroty xDome live feeds for devices, vulnerabilities, alerts, and events when encrypted credentials and network access are configured.
- **Read-only manual API sync:** GitHub, GitLab, MISP, Keycloak, OpenSearch, Wazuh Indexer, SentinelOne, Microsoft Defender for Cloud Apps, Prisma Cloud, NetApp ONTAP, and Cato auditFeed. Each requires provider credentials and permissions; feed errors and unavailable sources remain visible.
- **Rubrik:** read-only API activity and audit polling, plus an inbound PD-CEF webhook option.
- **Other ingestion:** configurable webhook, REST JSON, and syslog HTTP-bridge connectors can receive normalized events. Most remaining integration cards store encrypted settings only and do not yet poll a vendor API.

## What Can Be Automated
The platform can refresh configured supported feeds, normalize and route events into local evidence, match incoming indicators against its local threat index, generate local reports and exports, maintain audit workbook revisions, and record automation playbook dry-runs. These steps reduce repetitive collection and evidence assembly.

## Important Boundaries
This is an operational visibility and workflow tool, not an autonomous response system. Playbooks are dry-runs; Zero Trust decisions are simulations; local IP lists classify but do not enforce firewall rules; Snort rules are catalogued but not deployed or executed. Some modules are sample analytics, and saved credentials do not prove connectivity. Do not present sample or unconfigured data as verified monitoring coverage. Vendor response actions and policy enforcement are not enabled.
