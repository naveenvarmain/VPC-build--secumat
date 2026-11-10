/* =====================================================================
    Swimlane connection defaults
    ---------------------------------------------------------------------
    Live credentials are entered in Settings → Integrations and stored by
    the backend. Keep PAT empty; never place a real credential in this file.
    The backend proxy controls whether live Swimlane requests are enabled.
   ===================================================================== */

window.SWIMLANE_CONFIG = {
    // Live mode is enabled only by complete server-side integration settings.
    USE_LIVE: false,

    // Base URL of your Swimlane instance (no trailing slash).
    BASE_URL: "https://frd-ngxswl01.secops.zf-world.com",

    // Must remain empty. PATs are stored encrypted on the server.
    PAT: "",

    // Application IDs (Swimlane app tracking IDs) that back each feed.
    // Find these under Application Settings > General.
    APPS: {
        incidents: "",      // Incident / case app
        alerts: "",         // Alert ingestion app
        vulnerabilities: "",// Vulnerability tracking app
        insiderThreat: "",  // Insider threat / UBA app
        automation: ""      // Playbook execution log app
    },

    // Optional: saved Report IDs for pre-aggregated widgets.
    REPORTS: {
        mttdMttrTrend: "",
        severityBreakdown: "",
        mitreCoverage: ""
    },

    // Field mapping — map dashboard concepts to the field keys/names in your
    // Swimlane Incident application. Update the right-hand values to match
    // your app's tracking field keys (Application Settings > Fields).
    FIELDS: {
        createdAt:   "created-date",   // when the incident record was created
        detectedAt:  "detected-time",  // when the threat was first detected
        respondedAt: "responded-time", // when response/containment began
        closedAt:    "closed-date",    // when the incident was closed
        severity:    "severity",       // Critical / High / Medium / Low
        status:      "status"          // Open / Closed / ...
    },

    // Request timeout (ms) before falling back to mock data.
    TIMEOUT_MS: 8000
};
