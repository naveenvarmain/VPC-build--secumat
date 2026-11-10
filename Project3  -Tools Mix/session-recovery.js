/* =====================================================================
    Local session recovery
    The dashboard session token is held in server memory, so a server
    restart or an expired token leaves already-open tabs sending a stale
    cookie. Those tabs would otherwise poll /api/* forever and receive
    401 responses until someone reloads them manually.

    Any same-origin /api/ request that returns 401 triggers one attempt to
    re-obtain the session cookie from a non-API path, followed by a single
    retry. A 401 is rejected before the handler runs, so retrying is safe
    for reads and writes alike.
   ===================================================================== */

(function () {
    if (window.__localSessionRecoveryInstalled) return;
    window.__localSessionRecoveryInstalled = true;

    const originalFetch = window.fetch.bind(window);
    const SESSION_ISSUING_PATH = "/";
    let pendingRenewal = null;

    function isLocalApiRequest(input) {
        try {
            const raw = typeof input === "string" ? input : (input && input.url) || "";
            const url = new URL(raw, window.location.href);
            return url.origin === window.location.origin && url.pathname.startsWith("/api/");
        } catch {
            return false;
        }
    }

    function renewLocalSession() {
        if (!pendingRenewal) {
            pendingRenewal = originalFetch(SESSION_ISSUING_PATH, { credentials: "same-origin", cache: "no-store" })
                .then(response => response.ok)
                .catch(() => false)
                .finally(() => { pendingRenewal = null; });
        }
        return pendingRenewal;
    }

    window.fetch = async function (input, init) {
        const response = await originalFetch(input, init);
        if (response.status !== 401 || (init && init.localSessionRetry) || !isLocalApiRequest(input)) {
            return response;
        }
        if (!(await renewLocalSession())) return response;
        try {
            return await originalFetch(input, { ...(init || {}), localSessionRetry: true });
        } catch {
            return response;
        }
    };
})();
