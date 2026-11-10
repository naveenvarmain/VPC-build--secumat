import csv
import io
import json
import threading
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

import server
from cryptography.fernet import Fernet


class IntegrationProviderPollerTests(unittest.TestCase):
    def test_provider_api_request_rejects_cleartext_base_urls(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            server.integration_provider_api_request({"baseUrl": "http://misp.example"}, "/attributes/restSearch")

    def test_misp_poller_bounds_and_normalizes_attribute_events(self):
        attributes = [
            {
                "id": str(index),
                "uuid": f"attribute-{index}",
                "timestamp": "1793270000",
                "type": "ip-dst",
                "value": f"192.0.2.{index % 254 + 1}",
                "category": "Network activity",
                "comment": "Indicator from MISP",
                "to_ids": True,
                "Event": {"id": "event-1", "info": "Test event"},
            }
            for index in range(101)
        ]
        with patch.object(server, "integration_provider_api_request", return_value={"response": {"Attribute": attributes}}) as request:
            events, sources = server.poll_misp_provider({"baseUrl": "https://misp.example", "apiKey": "test-key"})

        self.assertEqual(len(events), server.INTEGRATION_PROVIDER_PAGE_SIZE)
        self.assertEqual(sources, [{"source": "attributes", "status": "live", "count": 100}])
        request.assert_called_once()
        args, kwargs = request.call_args
        self.assertEqual(args[1], "/attributes/restSearch")
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(json.loads(kwargs["body"])["limit"], 100)
        self.assertEqual(kwargs["headers"]["Authorization"], "test-key")
        self.assertEqual(events[0]["event_type"], "misp.indicator.observed")
        self.assertEqual(events[0]["indicators"], [{"type": "ip-dst", "value": "192.0.2.1"}])
        self.assertEqual(events[0]["source"], {"system": "MISP", "transport": "api"})
        self.assertEqual(events[0]["outcome"], "to_ids")

    def test_keycloak_poller_reads_bounded_audit_and_user_events(self):
        responses = [
            {"access_token": "short-lived-token"},
            [{"id": "admin-1", "time": 1793270000000, "operationType": "UPDATE", "resourceType": "USER", "resourcePath": "users/1", "authDetails": {"userId": "actor-1", "ipAddress": "192.0.2.10"}}],
            [{"id": "event-1", "time": 1793270000001, "type": "LOGIN_ERROR", "clientId": "dashboard", "userId": "user-1", "ipAddress": "192.0.2.11", "error": "invalid_user_credentials", "details": {"secret": "must-not-be-copied"}}],
        ]
        with patch.object(server, "integration_provider_api_request", side_effect=responses) as request:
            events, sources = server.poll_keycloak_provider({
                "baseUrl": "https://identity.example",
                "realm": "ot realm",
                "clientId": "client",
                "clientSecret": "secret",
            })

        self.assertEqual(len(events), 2)
        self.assertEqual([item["status"] for item in sources], ["live", "live"])
        self.assertEqual(events[0]["event_type"], "keycloak.admin.audit")
        self.assertEqual(events[1]["event_type"], "keycloak.security.alert")
        self.assertEqual(events[1]["outcome"], "failure")
        self.assertNotIn("must-not-be-copied", json.dumps(events))
        self.assertEqual(request.call_count, 3)
        self.assertIn("/admin/realms/ot%20realm/admin-events?first=0&max=100", request.call_args_list[1].args[1])

    def test_opensearch_and_wazuh_pollers_use_configured_index_urls(self):
        search_payload = {"hits": {"hits": [{
            "_id": "alert-1",
            "_source": {
                "@timestamp": "2026-10-29T10:00:00Z",
                "message": "Suspicious event",
                "event": {"action": "process-start", "category": ["process"], "outcome": "failure"},
                "host": {"name": "ot-host-1"},
                "rule": {"id": "100001", "name": "Test alert", "severity": "high"},
                "source": {"ip": "192.0.2.20"},
            },
        }]}}
        with patch.object(server, "integration_provider_api_request", return_value=search_payload) as request:
            events, sources = server.poll_opensearch_provider({
                "baseUrl": "https://search.example:9200",
                "index": "security-events-*",
                "apiKey": "encoded-key",
            })
        self.assertEqual(events[0]["event_type"], "opensearch.security.alert")
        self.assertEqual(events[0]["indicators"], [{"type": "ip", "value": "192.0.2.20"}])
        self.assertEqual(sources[0]["count"], 1)
        self.assertEqual(request.call_args.args[0]["baseUrl"], "https://search.example:9200")
        self.assertEqual(request.call_args.kwargs["headers"]["Authorization"], "ApiKey encoded-key")

        with patch.object(server, "integration_provider_api_request", return_value=search_payload) as request:
            server.poll_wazuh_provider({
                "baseUrl": "https://manager.example:55000",
                "indexerUrl": "https://indexer.example:9200",
                "username": "reader",
                "password": "password",
            })
        self.assertEqual(request.call_args.args[0]["baseUrl"], "https://indexer.example:9200")
        self.assertEqual(request.call_args.args[1], "/wazuh-alerts-*/_search")

    def test_opensearch_api_key_connection_test_uses_api_key_auth(self):
        config = {"baseUrl": "https://search.example:9200", "apiKey": "encoded-key", "index": "security-events-*"}
        with patch.object(server, "load_integration_credential_store", return_value={"opensearch": config}), \
                patch.object(server, "perform_integration_probe", return_value={"status": 200, "ms": 12}) as probe:
            result = server.integration_connection_test("opensearch")
        self.assertTrue(result["ok"])
        self.assertTrue(result["authTested"])
        self.assertEqual(probe.call_args.args[1]["Authorization"], "ApiKey encoded-key")

    def test_sentinelone_poller_uses_read_only_threats_endpoint(self):
        response = {"data": [{
            "id": "threat-1",
            "createdAt": "2026-10-29T10:00:00Z",
            "status": "active",
            "agentId": "agent-1",
            "threatInfo": {
                "threatName": "Example threat",
                "classification": "Trojan",
                "detectionType": "static",
                "mitigationStatus": "not_mitigated",
                "confidenceLevel": "high",
            },
            "agentDetectionInfo": {"agentName": "ot-host-1"},
        }]}
        with patch.object(server, "integration_provider_api_request", return_value=response) as request:
            events, sources = server.poll_sentinelone_provider({
                "baseUrl": "https://sentinelone.example",
                "apiToken": "read-token",
            })
        self.assertEqual(events[0]["event_type"], "sentinelone.security.alert")
        self.assertEqual(events[0]["details"]["agent_name"], "ot-host-1")
        self.assertEqual(events[0]["severity"], "high")
        self.assertEqual(sources[0]["count"], 1)
        self.assertIn("/web/api/v2.1/threats?limit=100", request.call_args.args[1])
        self.assertEqual(request.call_args.kwargs["headers"]["Authorization"], "ApiToken read-token")

    def test_defender_cloud_apps_poller_uses_graph_read_permission_scope(self):
        response = {"value": [{
            "id": "alert-1",
            "providerAlertId": "provider-alert-1",
            "incidentId": "incident-1",
            "createdDateTime": "2026-10-29T10:00:00Z",
            "title": "Cloud app alert",
            "severity": "high",
            "status": "new",
            "serviceSource": "microsoftDefenderForCloudApps",
            "detectionSource": "cloudAppSecurity",
            "alertWebUrl": "https://security.microsoft.com/alerts/alert-1",
        }]}
        with patch.object(server, "integration_provider_api_request", side_effect=[{"access_token": "graph-token"}, response]) as request:
            events, sources = server.poll_defender_cloud_apps_provider({
                "tenantId": "tenant-1",
                "clientId": "client-1",
                "clientSecret": "secret",
            })
        self.assertEqual(events[0]["event_type"], "defender-cloud-apps.security.alert")
        self.assertEqual(events[0]["severity"], "high")
        self.assertEqual(events[0]["source"]["system"], "Microsoft Defender for Cloud Apps")
        self.assertEqual(sources[0]["count"], 1)
        self.assertIn("/oauth2/v2.0/token", request.call_args_list[0].args[1])
        self.assertIn("serviceSource%20eq%20'microsoftDefenderForCloudApps'", request.call_args_list[1].args[1])
        self.assertEqual(request.call_args_list[1].kwargs["headers"]["Authorization"], "Bearer graph-token")

    def test_prisma_cloud_poller_reads_alerts_without_vendor_actions(self):
        alert_response = {"items": [{
            "id": "prisma-alert-1",
            "firstSeen": "2026-10-29T10:00:00Z",
            "status": "open",
            "policy": {"name": "Public storage", "policyType": "config", "severity": "high"},
            "resource": {"name": "storage-1", "resourceType": "Storage", "cloudType": "aws"},
        }]}
        with patch.object(server, "integration_provider_api_request", side_effect=[{"token": "short-lived-token"}, alert_response]) as request:
            events, sources = server.poll_prisma_cloud_provider({
                "baseUrl": "https://api.prismacloud.example",
                "accessKey": "access-key",
                "secretKey": "secret-key",
            })
        self.assertEqual(events[0]["event_type"], "prismacloud.security.alert")
        self.assertEqual(events[0]["details"]["resource_name"], "storage-1")
        self.assertEqual(events[0]["severity"], "high")
        self.assertEqual(sources[0]["count"], 1)
        self.assertEqual(request.call_args_list[0].args[1], "/login")
        self.assertEqual(json.loads(request.call_args_list[0].kwargs["body"])["username"], "access-key")
        self.assertIn("/alert?timeRange=24h", request.call_args_list[1].args[1])
        self.assertEqual(request.call_args_list[1].kwargs["headers"]["x-redlock-auth"], "short-lived-token")

    def test_netapp_poller_reads_bounded_audit_messages(self):
        response = {"records": [{
            "uuid": "audit-1",
            "timestamp": "2026-10-29T10:00:00Z",
            "action": "volume.create",
            "application": "http",
            "user": "storage-reader",
            "address": "192.0.2.30",
            "state": "success",
            "message": "Volume created",
        }]}
        with patch.object(server, "integration_provider_api_request", return_value=response) as request:
            events, sources = server.poll_netapp_provider({
                "baseUrl": "https://ontap.example",
                "username": "reader",
                "password": "password",
            })
        self.assertEqual(events[0]["event_type"], "netapp.audit.event")
        self.assertEqual(events[0]["source"]["system"], "NetApp ONTAP")
        self.assertEqual(sources[0]["count"], 1)
        self.assertIn("/api/security/audit/messages?max_records=100", request.call_args.args[1])
        self.assertTrue(request.call_args.kwargs["headers"]["Authorization"].startswith("Basic "))

    def test_cato_poller_uses_parameterized_audit_feed_and_deduplicates_pages(self):
        duplicate = {"time": "2026-10-29T10:00:00Z", "fieldsMap": {"change_type": "UPDATED", "actor": "analyst"}}
        new_record = {"time": "2026-10-29T10:01:00Z", "fieldsMap": {"change_type": "CREATED", "actor": "operator"}}
        pages = [
            {"data": {"auditFeed": {"marker": "marker-1", "hasMore": True, "accounts": [{"id": "account-1", "records": [duplicate]}]}}},
            {"data": {"auditFeed": {"marker": "marker-2", "hasMore": False, "accounts": [{"id": "account-1", "records": [duplicate, new_record]}]}}},
        ]
        with patch.object(server, "integration_provider_api_request", side_effect=pages) as request:
            events, sources = server.poll_cato_provider({"apiKey": "cato-key", "accountId": "account-1"})
        self.assertEqual(len(events), 2)
        self.assertEqual(sources, [{"source": "auditFeed", "status": "live", "count": 2}])
        self.assertEqual(events[0]["event_type"], "cato.audit.event")
        self.assertEqual(events[0]["details"]["actor"], "analyst")
        self.assertEqual(request.call_count, 2)
        first_request = json.loads(request.call_args_list[0].kwargs["body"])
        self.assertEqual(first_request["operationName"], "auditFeed")
        self.assertEqual(first_request["variables"]["accountIDs"], ["account-1"])
        self.assertEqual(first_request["variables"]["timeFrame"], "last.P1D")
        self.assertEqual(request.call_args_list[0].kwargs["headers"]["x-api-key"], "cato-key")

    def test_cato_connection_test_uses_read_only_audit_feed(self):
        config = {"apiKey": "cato-key", "accountId": "account-1"}
        with patch.object(server, "load_integration_credential_store", return_value={"cato": config}), \
                patch.object(server, "poll_cato_provider", return_value=([{"event_id": "one"}], [])) as poller:
            result = server.integration_connection_test("cato")
        self.assertTrue(result["ok"])
        self.assertTrue(result["authTested"])
        self.assertIn("1 record(s)", result["message"])
        poller.assert_called_once_with(config)


class ClarotyProxyPolicyTests(unittest.TestCase):
    def test_allows_https_claroty_v1_endpoint(self):
        self.assertTrue(server.is_allowed_claroty_target("https://eu.api.claroty.com/api/v1/devices/"))
        self.assertTrue(server.is_allowed_claroty_target("https://tenant.api.claroty.com/api/v1/alerts/?limit=10"))

    def test_rejects_non_claroty_or_unsafe_target(self):
        targets = (
            "http://eu.api.claroty.com/api/v1/devices/",
            "https://127.0.0.1/api/v1/devices/",
            "https://example.com/api/v1/devices/",
            "https://eu.api.claroty.com/api/v2/devices/",
            "https://user:password@eu.api.claroty.com/api/v1/devices/",
            "https://eu.api.claroty.com:444/api/v1/devices/",
        )
        for target in targets:
            with self.subTest(target=target):
                self.assertFalse(server.is_allowed_claroty_target(target))

    def test_upstream_proxy_must_be_approved(self):
        self.assertTrue(server.allowed_claroty_upstream_proxy(""))
        self.assertTrue(server.allowed_claroty_upstream_proxy(server.CLAROTY_DEFAULT_PROXY_URL))
        self.assertFalse(server.allowed_claroty_upstream_proxy("http://127.0.0.1:8080"))

    def test_claroty_base_url_must_be_https_api_origin(self):
        self.assertTrue(server.is_allowed_claroty_base_url("https://eu.api.claroty.com"))
        self.assertFalse(server.is_allowed_claroty_base_url("http://eu.api.claroty.com"))
        self.assertFalse(server.is_allowed_claroty_base_url("https://127.0.0.1"))
        self.assertFalse(server.is_allowed_claroty_base_url("https://api.claroty.com.attacker.example"))

    def test_rejects_arbitrary_claroty_base_and_proxy_when_saving(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "CLAROTY_CREDENTIALS_FILE", state_dir / "claroty.enc"), \
                    patch.object(server, "LEGACY_CLAROTY_CREDENTIALS_FILE", root / "legacy.enc"):
                with self.assertRaises(ValueError):
                    server.save_claroty_credentials({"apiKey": "secret", "baseUrl": "http://127.0.0.1:8080"})
                with self.assertRaises(ValueError):
                    server.save_claroty_credentials({"apiKey": "secret", "proxyUrl": "http://127.0.0.1:8080"})

    def test_explicit_empty_proxy_selects_direct_connection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "CLAROTY_CREDENTIALS_FILE", state_dir / "claroty.enc"), \
                    patch.object(server, "LEGACY_CLAROTY_CREDENTIALS_FILE", root / "legacy.enc"):
                saved = server.save_claroty_credentials({"apiKey": "secret"})
                self.assertEqual(saved["proxyUrl"], server.CLAROTY_DEFAULT_PROXY_URL)

                direct = server.save_claroty_credentials({"proxyUrl": ""})
                self.assertEqual(direct["proxyUrl"], "")
                self.assertEqual(server.claroty_credentials_status()["proxyUrl"], "")

                unchanged = server.save_claroty_credentials({"baseUrl": "https://eu.api.claroty.com"})
                self.assertEqual(unchanged["proxyUrl"], "")


class ClarotyFeedResponseTests(unittest.TestCase):
    def test_unwraps_common_claroty_list_envelopes(self):
        records = [{"uid": "asset-1"}]
        for payload in (
            {"devices": records},
            {"items": records},
            {"data": records},
            {"data": {"results": records}},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(server.claroty_feed_records(payload, "devices"), records)

    def test_preserves_empty_feeds_and_rejects_unknown_shapes(self):
        self.assertEqual(server.claroty_feed_records({"items": []}, "devices"), [])
        self.assertIsNone(server.claroty_feed_records({"unexpected": "shape"}, "devices"))


class LocalOriginPolicyTests(unittest.TestCase):
    def test_allows_only_local_dashboard_origins(self):
        self.assertTrue(server.is_trusted_local_origin(None))
        for origin in server.LOCAL_BROWSER_ORIGINS:
            with self.subTest(origin=origin):
                self.assertTrue(server.is_trusted_local_origin(origin))
        self.assertFalse(server.is_trusted_local_origin("https://attacker.example"))

    def test_allows_matching_same_origin_loopback_port_only(self):
        self.assertTrue(server.is_trusted_local_origin("http://127.0.0.1:8081", "127.0.0.1:8081"))
        self.assertTrue(server.is_trusted_local_origin("http://localhost:9000", "localhost:9000"))
        self.assertFalse(server.is_trusted_local_origin("http://127.0.0.1:8081", "127.0.0.1:8080"))
        self.assertFalse(server.is_trusted_local_origin("http://attacker.example:8081", "attacker.example:8081"))
        self.assertFalse(server.is_trusted_local_origin("https://127.0.0.1:8081", "127.0.0.1:8081"))


class DashboardHttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        state_dir = root / "state"
        state_dir.mkdir()
        self.patchers = [
            patch.object(server, "APP_STATE_DIR", state_dir),
            patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"),
            patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"),
            patch.object(server, "CLAROTY_CREDENTIALS_FILE", state_dir / "claroty.enc"),
            patch.object(server, "LEGACY_CLAROTY_CREDENTIALS_FILE", root / "legacy.enc"),
            patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"),
            patch.object(server, "ZERO_TRUST_PROGRAM_FILE", state_dir / "zero-trust-program.json"),
            patch.object(server, "MODULE_DATA_FILE", state_dir / "module-data.json"),
            patch.object(server, "AUTOMATION_RUNS_FILE", state_dir / "automation-runs.json"),
            patch.object(server, "ASSESSMENT_REQUESTS_FILE", state_dir / "assessment-testing-requests.json"),
            patch.object(server, "SECUMAT_UPLOAD_DIR", state_dir / "secumat-uploads"),
            patch.object(server, "INTEGRATION_CONNECTORS_FILE", state_dir / "integration-connectors.json"),
            patch.object(server, "INTEGRATION_FEED_STATE_FILE", state_dir / "integration-feed-state.json"),
            patch.object(server, "ZERO_TRUST_EVENT_FILE", state_dir / "zero-trust-events.jsonl"),
        ]
        for item in self.patchers:
            item.start()
        self.httpd = server.ThreadingHTTPServer((server.HOST, 0), server.DashboardHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://{server.HOST}:{self.httpd.server_address[1]}"

    def browser_cookie(self):
        with urllib.request.urlopen(f"{self.base_url}/", timeout=3) as response:
            header = response.headers.get("Set-Cookie", "")
        return header.split(";", 1)[0]

    def test_static_sources_and_directory_listings_are_blocked(self):
        blocked = ("/server.py", "/data/", "/tests/test_server_security.py", "/.env", "/project%20-old/shared/app.py")
        for method in ("GET", "HEAD"):
            for path in blocked:
                with self.subTest(method=method, path=path), self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(urllib.request.Request(f"{self.base_url}{path}", method=method), timeout=3)
                self.assertEqual(denied.exception.code, 403)
                denied.exception.close()
            for path in ("/", "/project%20-old/secumat/dashboard.html", "/Audit%20Templates%20%26%20Question%20Bank/Audit%20Questions%20for%20companies.xlsx"):
                with self.subTest(method=method, path=path), urllib.request.urlopen(urllib.request.Request(f"{self.base_url}{path}", method=method), timeout=3) as response:
                    self.assertEqual(response.status, 200)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        for item in reversed(self.patchers):
            item.stop()
        self.temp_dir.cleanup()

    def test_foreign_origin_cannot_write_credentials(self):
        request = urllib.request.Request(
            f"{self.base_url}/api/integrations/credentials",
            data=b'{"toolId":"swimlane","config":{"pat":"blocked"}}',
            headers={"Content-Type": "application/json", "Origin": "https://attacker.example"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(error.exception.code, 403)
        error.exception.close()

    def test_git_provider_credentials_are_encrypted_and_secrets_are_redacted(self):
        for tool_id, config in (
            ("github", {"organization": "example-org", "token": "github-token", "webhookSecret": "github-secret"}),
            ("gitlab", {"groupId": "example-group", "token": "gitlab-token", "webhookSecret": "gitlab-secret"}),
        ):
            with self.subTest(tool_id=tool_id):
                server.save_integration_credentials({"toolId": tool_id, "config": config})
                public_status = server.public_integration_credential_status()["tools"][tool_id]
                self.assertTrue(public_status["configured"])
                self.assertEqual(public_status["safeConfig"], {key: value for key, value in config.items() if key not in {"token", "webhookSecret"}})

    def test_git_provider_pollers_normalize_audit_and_finding_records(self):
        github_records = [
            [{"@id": "audit-1", "@timestamp": 1793270000000, "action": "repo.access", "actor": "analyst", "repo": "example/app"}],
            [{"number": 4, "created_at": "2026-10-29T10:00:00Z", "state": "open", "security_advisory": {"summary": "Dependency advisory", "severity": "high"}, "security_vulnerability": {"package": {"name": "example-lib"}}, "repository": {"full_name": "example/app"}}],
            [{"number": 5, "created_at": "2026-10-29T10:01:00Z", "state": "open", "secret_type": "generic_api_key", "repository": {"full_name": "example/app"}}],
            [{"number": 6, "created_at": "2026-10-29T10:02:00Z", "state": "open", "rule": {"description": "SQL injection", "security_severity_level": "critical"}, "repository": {"full_name": "example/app"}}],
        ]
        with patch.object(server, "git_provider_api_request", side_effect=github_records):
            github_events, github_sources = server.poll_github_provider({"organization": "example", "token": "test"})
        self.assertEqual(len(github_events), 4)
        self.assertEqual([item["status"] for item in github_sources], ["live", "live", "live", "live"])
        self.assertEqual(github_events[2]["severity"], "high")
        self.assertEqual(github_events[3]["severity"], "critical")
        self.assertEqual(github_events[0]["event_type"], "github.audit.event")
        self.assertEqual(github_events[1]["event_type"], "github.vulnerability.finding")

        gitlab_records = [
            [{"id": 8, "created_at": "2026-10-29T10:00:00Z", "event_type": "group_access", "author": {"name": "analyst"}}],
            {"vulnerabilities": [{"id": "vuln-1", "created_at": "2026-10-29T10:01:00Z", "title": "Dependency issue", "severity": "high", "state": "detected"}]},
        ]
        with patch.object(server, "git_provider_api_request", side_effect=gitlab_records):
            gitlab_events, gitlab_sources = server.poll_gitlab_provider({"groupId": "example", "token": "test"})
        self.assertEqual(len(gitlab_events), 2)
        self.assertEqual([item["status"] for item in gitlab_sources], ["live", "live"])
        self.assertEqual(gitlab_events[0]["event_type"], "gitlab.audit.event")
        self.assertEqual(gitlab_events[1]["event_type"], "gitlab.vulnerability.finding")

    def test_git_provider_webhooks_require_valid_provider_authentication(self):
        github_secret = "github-webhook-secret"
        gitlab_secret = "gitlab-webhook-secret"
        server.save_integration_credentials({"toolId": "github", "config": {"webhookSecret": github_secret}})
        server.save_integration_credentials({"toolId": "gitlab", "config": {"webhookSecret": gitlab_secret}})
        body = b'{"action":"created","repository":{"full_name":"example/app"},"alert":{"number":4,"state":"open","severity":"high"}}'
        signature = "sha256=" + server.hmac.new(github_secret.encode(), body, server.hashlib.sha256).hexdigest()
        server.authenticate_git_webhook("github", {"X-Hub-Signature-256": signature}, body)
        with self.assertRaises(PermissionError):
            server.authenticate_git_webhook("github", {"X-Hub-Signature-256": "sha256=invalid"}, body)
        server.authenticate_git_webhook("gitlab", {"X-Gitlab-Token": gitlab_secret}, body)
        with self.assertRaises(PermissionError):
            server.authenticate_git_webhook("gitlab", {"X-Gitlab-Token": "invalid"}, body)

    def test_git_provider_settings_test_uses_fixed_cloud_api_hosts(self):
        for tool_id, config, expected_url in (
            ("github", {"organization": "example-org", "token": "github-token"}, "https://api.github.com/orgs/example-org"),
            ("gitlab", {"groupId": "example/group", "token": "gitlab-token"}, "https://gitlab.com/api/v4/groups/example%2Fgroup"),
        ):
            with self.subTest(tool_id=tool_id):
                server.save_integration_credentials({"toolId": tool_id, "config": config})
                with patch.object(server, "git_provider_api_request", return_value={"id": 1}) as provider_request:
                    result = server.integration_connection_test(tool_id)
                self.assertTrue(result["ok"])
                self.assertTrue(result["authTested"])
                provider_request.assert_called_once_with(tool_id, expected_url, config["token"])

    def test_github_webhook_ingest_routes_authenticated_security_alert(self):
        secret = "github-webhook-secret"
        server.save_integration_credentials({"toolId": "github", "config": {"webhookSecret": secret}})
        body = json.dumps({
            "action": "created",
            "repository": {"full_name": "example/app"},
            "alert": {"number": 4, "state": "open", "severity": "high", "summary": "Dependency alert"},
        }).encode()
        signature = "sha256=" + server.hmac.new(secret.encode(), body, server.hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            f"{self.base_url}/api/integrations/webhooks/github",
            data=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": signature, "X-GitHub-Event": "dependabot_alert", "X-GitHub-Delivery": "delivery-1"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            self.assertEqual(response.status, 202)
            payload = json.loads(response.read())
        self.assertEqual(payload["provider"], "github")
        self.assertEqual(payload["routing"]["category"], "vulnerability")
        self.assertEqual(len(server.module_store_payload()["modules"]["vulnerabilities"]), 1)

    def test_git_provider_refresh_requires_browser_session(self):
        request = urllib.request.Request(f"{self.base_url}/api/integrations/git/refresh", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(denied.exception.code, 401)
        denied.exception.close()
        cookie = self.browser_cookie()
        with patch.object(server, "git_provider_api_request", side_effect=AssertionError("Unconfigured providers must not call external APIs")):
            request.add_header("Cookie", cookie)
            request.add_header("Origin", self.base_url)
            with urllib.request.urlopen(request, timeout=3) as response:
                result = json.loads(response.read())
        self.assertEqual([item["status"] for item in result["providers"]], ["not_configured", "not_configured"])

    def test_api_feed_refresh_requires_session_and_skips_unconfigured_providers(self):
        request = urllib.request.Request(
            f"{self.base_url}/api/integrations/api-feeds/refresh",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(denied.exception.code, 401)
        denied.exception.close()

        cookie = self.browser_cookie()
        request.add_header("Cookie", cookie)
        request.add_header("Origin", self.base_url)
        with patch.object(server, "load_integration_credential_store", return_value={}), \
                patch.object(server, "integration_provider_api_request", side_effect=AssertionError("Unconfigured providers must not call external APIs")):
            with urllib.request.urlopen(request, timeout=3) as response:
                payload = json.loads(response.read())
        self.assertEqual(payload["source"], "read-only-provider-api")
        self.assertEqual([item["status"] for item in payload["providers"]], ["not_configured"] * 11)

    def test_gitlab_webhook_rejects_bad_token_and_routes_valid_audit(self):
        secret = "gitlab-webhook-secret"
        server.save_integration_credentials({"toolId": "gitlab", "config": {"webhookSecret": secret}})
        body = json.dumps({
            "object_kind": "audit_event",
            "event_uuid": "gitlab-1",
            "object_attributes": {"id": 9, "action": "member_added", "created_at": "2026-10-29T10:00:00Z"},
            "project": {"path_with_namespace": "example/app"},
        }).encode()
        def request(token):
            return urllib.request.Request(
                f"{self.base_url}/api/integrations/webhooks/gitlab",
                data=body,
                headers={"Content-Type": "application/json", "X-Gitlab-Token": token, "X-Gitlab-Event": "audit_event"},
                method="POST",
            )
        with self.assertRaises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request("wrong-token"), timeout=3)
        self.assertEqual(denied.exception.code, 401)
        denied.exception.close()
        with urllib.request.urlopen(request(secret), timeout=3) as response:
            self.assertEqual(response.status, 202)
        self.assertEqual(len(server.module_store_payload()["modules"]["integrations"]), 1)

    def test_rubrik_pd_cef_ingest_accepts_bearer_without_browser_session(self):
        connector = server.create_integration_connector({
            "name": "Rubrik Security Cloud",
            "transport": "rubrik",
        })
        body = json.dumps({
            "event_action": "trigger",
            "routing_key": "must-not-be-stored",
            "payload": {
                "summary": "Backup failure on VM",
                "severity": "critical",
                "source": "Rubrik Security Cloud",
                "timestamp": "2026-10-26T08:00:00Z",
                "custom_details": {"object_name": "vm-1", "status": "FAILURE"},
            },
        }).encode()
        request = urllib.request.Request(
            f"{self.base_url}{connector['endpoint']}",
            data=body,
            headers={
                "Authorization": f"Bearer {connector['token']}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            result = json.loads(response.read())
        self.assertEqual(response.status, 202)
        self.assertEqual(result["acceptedCount"], 1)
        event = server.read_zero_trust_events(1)[0]
        self.assertEqual(event["source"]["system"], "Rubrik Security Cloud")
        self.assertEqual(event["event_type"], "rubrik.alert.trigger")
        self.assertNotIn("must-not-be-stored", json.dumps(event))
        self.assertNotIn("routing_key", json.dumps(event))
        self.assertEqual(server.load_integration_connectors()[0]["eventCount"], 1)

    def test_feed_and_connector_toggles_control_real_ingestion(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        feed_state_request = urllib.request.Request(f"{self.base_url}/api/integrations/feed-state", headers={"Cookie": cookie})
        with urllib.request.urlopen(feed_state_request, timeout=3) as response:
            self.assertTrue(json.loads(response.read())["rubrikApiEnabled"])

        disable_rubrik = urllib.request.Request(
            f"{self.base_url}/api/integrations/feed-state",
            data=b'{"rubrikApiEnabled":false}',
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(disable_rubrik, timeout=3) as response:
            self.assertFalse(json.loads(response.read())["rubrikApiEnabled"])
        disabled_feed_request = urllib.request.Request(
            f"{self.base_url}/api/integrations/rubrik/events",
            headers={"Cookie": cookie},
        )
        with self.assertRaises(urllib.error.HTTPError) as disabled_feed:
            urllib.request.urlopen(disabled_feed_request, timeout=3)
        self.assertEqual(disabled_feed.exception.code, 409)
        disabled_feed.exception.close()

        connector = server.create_integration_connector({"name": "Toggle test", "transport": "webhook"})
        disable_connector = urllib.request.Request(
            f"{self.base_url}/api/integrations/connectors/{connector['id']}/enabled",
            data=b'{"enabled":false}',
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(disable_connector, timeout=3) as response:
            self.assertFalse(json.loads(response.read())["connector"]["enabled"])
        ingest = urllib.request.Request(
            f"{self.base_url}{connector['endpoint']}",
            data=b'{"event_type":"security.alert","event_time":"2026-10-26T08:00:00Z","source":{"system":"test"}}',
            headers={"Authorization": f"Bearer {connector['token']}", "Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as disabled_connector:
            urllib.request.urlopen(ingest, timeout=3)
        self.assertEqual(disabled_connector.exception.code, 409)
        disabled_connector.exception.close()

    def test_assessment_routes_require_session_and_keep_requests_unverified(self):
        root = "/api/v1/security-assessment"
        with self.assertRaises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(f"{self.base_url}{root}/summary", timeout=3)
        self.assertEqual(denied.exception.code, 401)
        denied.exception.close()

        cookie = self.browser_cookie()
        with patch.object(server, "load_integration_credential_store", return_value={}), \
             patch.object(server, "claroty_credentials_status", return_value={"configured": False}), \
             patch.object(server, "snort_attack_coverage",
                          return_value={"totalRules": 14, "tacticsCovered": 2, "tacticsTotal": 14}), \
             patch.object(server, "current_openappid_catalog", return_value=None):
            def get(path):
                request = urllib.request.Request(f"{self.base_url}{root}{path}", headers={"Cookie": cookie})
                with urllib.request.urlopen(request, timeout=3) as response:
                    return json.load(response)

            summary = get("/summary")
            self.assertEqual(summary["domainsValidated"], 0)
            self.assertEqual(summary["domainsPending"], 7)
            self.assertIsNone(summary["deferredKpis"][0]["value"])
            self.assertEqual(get("/domains")["total"], 10)
            domain = get("/domains/identity-ad")
            self.assertEqual(domain["validation"]["status"], "PENDING")
            self.assertEqual(domain["testingRequests"], [])
            with self.assertRaises(urllib.error.HTTPError) as missing:
                get("/domains/not-a-domain")
            self.assertEqual(missing.exception.code, 404)
            missing.exception.close()

            body = json.dumps({
                "testType": "AUTHORIZED_ACTIVE_TEST", "scope": "Identity authentication",
                "authorizationReference": "CHG00012345", "requestedBy": "security-team",
                "scheduledStart": "2026-10-28T08:00:00Z",
            }).encode()
            url = f"{self.base_url}{root}/domains/identity-ad/testing"
            with self.assertRaises(urllib.error.HTTPError) as forbidden:
                urllib.request.urlopen(urllib.request.Request(
                    url, data=body, headers={"Cookie": cookie, "Origin": "https://evil.example"},
                    method="POST"), timeout=3)
            self.assertEqual(forbidden.exception.code, 403)
            forbidden.exception.close()
            with urllib.request.urlopen(urllib.request.Request(
                url, data=body, headers={"Cookie": cookie, "Content-Type": "application/json"},
                method="POST"), timeout=3) as response:
                self.assertEqual(response.status, 201)
                self.assertEqual(json.load(response)["status"], "REQUESTED")
            self.assertEqual(get("/domains/identity-ad")["testingRequests"][0]["authorizationVerified"], False)
            self.assertEqual(get("/summary")["domainsValidated"], 0)

    def test_proxy_rejects_non_claroty_destination(self):
        cookie = self.browser_cookie()
        request = urllib.request.Request(
            f"{self.base_url}/api/proxy?target=https%3A%2F%2Fexample.com%2Fsecret",
            data=b"{}",
            headers={"Content-Type": "application/json", "Origin": f"http://{server.HOST}:{self.httpd.server_address[1]}", "Cookie": cookie},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(error.exception.code, 403)
        error.exception.close()

    def test_local_api_requires_browser_session(self):
        request = urllib.request.Request(f"{self.base_url}/api/integrations/credentials")
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        cookie = self.browser_cookie()
        authenticated = urllib.request.Request(f"{self.base_url}/api/integrations/credentials", headers={"Cookie": cookie})
        with urllib.request.urlopen(authenticated, timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())['tools'], {})

    def test_stale_browser_session_can_be_recovered_from_non_api_path(self):
        stale = urllib.request.Request(
            f"{self.base_url}/api/integrations/credentials",
            headers={"Cookie": "OTPlatformSession=stale-token-not-in-memory"},
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(stale, timeout=3)
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        recovered = self.browser_cookie()
        self.assertNotIn("stale-token-not-in-memory", recovered)
        retried = urllib.request.Request(
            f"{self.base_url}/api/integrations/credentials", headers={"Cookie": recovered}
        )
        with urllib.request.urlopen(retried, timeout=3) as response:
            self.assertEqual(response.status, 200)

    def test_udp_program_api_persists_valid_profile_and_rejects_secrets(self):
        cookie = self.browser_cookie()
        origin = {"Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Cookie": cookie}
        profile = {
            "owner": "Cybersecurity & Trust",
            "executive_sponsor": "Security Office",
            "review_date": "2026-12-31",
            "maturity": {"identity": 2, "network": 1},
            "targets": {"identity": 4, "network": 4},
            "phases": {"assessment": "in_progress"},
            "controls": {"identity_mfa": True},
            "ai_controls": {"ai_inventory": True},
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/zero-trust/program",
            data=json.dumps(profile).encode("utf-8"),
            headers={**origin, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            saved = json.loads(response.read())
            self.assertEqual(response.status, 201)
        self.assertEqual(saved["profile"]["maturity"]["identity"], 2)
        self.assertEqual(saved["profile"]["maturity"]["device"], None)
        get_request = urllib.request.Request(f"{self.base_url}/api/zero-trust/program", headers={"Cookie": cookie})
        with urllib.request.urlopen(get_request, timeout=3) as response:
            self.assertEqual(json.loads(response.read())["profile"]["phases"]["assessment"], "in_progress")

        invalid = {"owner": "Test", "apiKey": "must-not-persist"}
        invalid_request = urllib.request.Request(
            f"{self.base_url}/api/zero-trust/program",
            data=json.dumps(invalid).encode("utf-8"),
            headers={**origin, "Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(invalid_request, timeout=3)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

    def test_alert_feed_is_labeled_sample_and_has_device_identity(self):
        cookie = self.browser_cookie()
        request = urllib.request.Request(f"{self.base_url}/api/alerts", headers={"Cookie": cookie})
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["source"], "sample")
        self.assertTrue(payload["alerts"])
        self.assertTrue(all(alert["data_source"] == "sample" for alert in payload["alerts"]))
        self.assertTrue(all(alert["device_name"] in server.SAMPLE_ALERT_DEVICES for alert in payload["alerts"]))

    def test_module_crud_is_persisted_and_rejects_secrets(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        registry_request = urllib.request.Request(f"{self.base_url}/api/modules", headers={"Cookie": cookie})
        with urllib.request.urlopen(registry_request, timeout=3) as response:
            registry = {item["id"]: item for item in json.loads(response.read())["modules"]}
        self.assertTrue(registry["vulnerabilities"]["writable"])
        self.assertTrue(registry["soc_studio"]["writable"])
        for module in ("audit_assignments", "audit_responses", "audit_workbook_versions"):
            self.assertFalse(registry[module]["writable"])
        studio_request = urllib.request.Request(
            f"{self.base_url}/api/modules/soc_studio",
            data=json.dumps({"artifact_type": "report_draft", "title": "SOC weekly report", "content": "Draft"}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(studio_request, timeout=3) as response:
            studio_artifact = json.loads(response.read())["record"]
            self.assertEqual(response.status, 201)
        self.assertEqual(server.get_module_record("soc_studio", studio_artifact["id"])["title"], "SOC weekly report")
        studio_update = urllib.request.Request(
            f"{self.base_url}/api/modules/soc_studio/{studio_artifact['id']}",
            data=json.dumps({**studio_artifact, "content": "Updated draft"}).encode(),
            headers=headers,
            method="PUT",
        )
        with urllib.request.urlopen(studio_update, timeout=3) as response:
            self.assertEqual(json.loads(response.read())["record"]["content"], "Updated draft")
        request = urllib.request.Request(
            f"{self.base_url}/api/modules/vulnerabilities",
            data=json.dumps({"cve": "CVE-TEST-1", "severity": "high", "status": "open"}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            created = json.loads(response.read())["record"]
            self.assertEqual(response.status, 201)
        record_id = created["id"]
        self.assertEqual(server.get_module_record("vulnerabilities", record_id)["cve"], "CVE-TEST-1")

        analytics_request = urllib.request.Request(f"{self.base_url}/api/analytics/modules", headers={"Cookie": cookie})
        with urllib.request.urlopen(analytics_request, timeout=3) as response:
            analytics = json.loads(response.read())
        self.assertEqual(analytics["totals"]["vulnerabilities"], 1)
        self.assertEqual(analytics["source"], "local-module-store")

        threat_request = urllib.request.Request(f"{self.base_url}/api/analytics/threats", headers={"Cookie": cookie})
        with urllib.request.urlopen(threat_request, timeout=3) as response:
            threats = json.loads(response.read())
        self.assertEqual(threats["counts"]["vulnerabilities"], 1)
        self.assertEqual(threats["live_sources"]["vendor_connectors"], "not_connected")

        update = urllib.request.Request(
            f"{self.base_url}/api/modules/vulnerabilities/{record_id}",
            data=json.dumps({"status": "in_progress"}).encode(),
            headers=headers,
            method="PUT",
        )
        with urllib.request.urlopen(update, timeout=3) as response:
            self.assertEqual(json.loads(response.read())["record"]["status"], "in_progress")

        invalid = urllib.request.Request(
            f"{self.base_url}/api/modules/alerts",
            data=json.dumps({"title": "bad", "apiToken": "must-not-store"}).encode(),
            headers=headers,
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(invalid, timeout=3)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

        delete = urllib.request.Request(f"{self.base_url}/api/modules/vulnerabilities/{record_id}", headers=headers, method="DELETE")
        with urllib.request.urlopen(delete, timeout=3) as response:
            self.assertTrue(json.loads(response.read())["deleted"])

    def test_soc_studio_live_analysis_api_is_aggregate_only(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        summary_request = urllib.request.Request(f"{self.base_url}/api/soc-studio/summary", headers={"Cookie": cookie})
        with patch.object(server, "claroty_credentials_status", return_value={"configured": True}):
            with urllib.request.urlopen(summary_request, timeout=3) as response:
                summary = json.loads(response.read())
        self.assertEqual(summary["source"], "local-configuration")
        self.assertIn("swimlane", summary["connectors"])
        self.assertEqual(summary["connectors"]["claroty"], "configured_not_verified")
        self.assertIn("m365", summary["connectors"])

        request = urllib.request.Request(
            f"{self.base_url}/api/soc-studio/analyze",
            data=json.dumps({"sources": [
                {"name": "Swimlane", "source": "live", "records": [
                    {"id": "private-1", "title": "private title", "severity": "critical", "status": "open", "created": "2026-10-26T09:00:00Z", "mitre": "T1059.001"},
                    {"severity": "high", "status": "closed", "created": "2026-10-25T09:00:00Z", "mitre": "T1059.001"},
                ]},
                {"name": "Claroty events", "source": "pending", "complete": False, "record_count": 0, "records": []},
            ]}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            result = json.loads(response.read())
        self.assertEqual(result["source"], "local-backend-analysis")
        self.assertEqual(result["sources"][0]["severity"], {"Critical": 1, "High": 1})
        self.assertEqual(result["sources"][0]["mitre_techniques"], {"T1059.001": 2})
        self.assertEqual(result["sources"][1]["source"], "pending")
        self.assertFalse(result["sources"][1]["complete"])
        self.assertNotIn("private title", json.dumps(result))
        self.assertNotIn("private-1", json.dumps(result))

    def test_secumat_audit_assignment_and_dry_run_apis(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        audit_request = urllib.request.Request(
            f"{self.base_url}/api/secumat_audits",
            data=json.dumps({"audit_name": "OT baseline", "framework": "NIST"}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(audit_request, timeout=3) as response:
            audit = json.loads(response.read())["audit"]
            self.assertEqual(response.status, 201)
        self.assertEqual(audit["audit_name"], "OT baseline")

        assignment_request = urllib.request.Request(
            f"{self.base_url}/api/audit_assignments",
            data=json.dumps({"questionnaire_name": "OT Security", "audit_profile_id": audit["id"], "question_count": 2}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(assignment_request, timeout=3) as response:
            assignment = json.loads(response.read())["assignment"]
        self.assertEqual(assignment["question_count"], 2)
        tamper_request = urllib.request.Request(
            f"{self.base_url}/api/audit_assignments/{assignment['id']}", data=b'{"status":"completed","reviewed_by":"Forged"}', headers=headers, method="PUT",
        )
        with self.assertRaises(urllib.error.HTTPError) as tamper:
            urllib.request.urlopen(tamper_request, timeout=3)
        self.assertEqual(tamper.exception.code, 403)
        tamper.exception.close()

        response_request = urllib.request.Request(
            f"{self.base_url}/api/audit_assignment_responses",
            data=json.dumps({"assignment_id": assignment["id"], "finalize": True, "responses": [
                {"question_id": "Q1", "response_status": "compliant", "evidence": "Control tested"},
                {"question_id": "Q2", "response_status": "partial", "comments": "Gap recorded"},
            ]}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(response_request, timeout=3) as response:
            result = json.loads(response.read())
        self.assertEqual(result["progress_percent"], 100)
        self.assertEqual(result["compliance_score"], 75)
        self.assertEqual(len(result["responses"]), 2)
        with self.assertRaises(urllib.error.HTTPError) as finalized:
            urllib.request.urlopen(response_request, timeout=3)
        self.assertEqual(finalized.exception.code, 409)
        finalized.exception.close()

        automation_request = urllib.request.Request(
            f"{self.base_url}/api/automation/run",
            data=json.dumps({"module": "audit_followup"}).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(automation_request, timeout=3) as response:
            run = json.loads(response.read())
        self.assertEqual(run["mode"], "dry-run")
        self.assertFalse(run["external_actions_executed"])
        self.assertGreaterEqual(len(server.automation_catalog_payload()["runs"]), 1)
        dashboard_request = urllib.request.Request(f"{self.base_url}/api/v1/automation/dashboard", headers={"Cookie": cookie})
        with urllib.request.urlopen(dashboard_request, timeout=3) as response:
            automation_dashboard = json.loads(response.read())
        self.assertEqual(automation_dashboard["source"], "local-dry-run-store")
        self.assertIn("kpis", automation_dashboard)
        self.assertIn("charts", automation_dashboard)
        self.assertFalse(automation_dashboard["external_actions_enabled"])

    def test_secumat_custom_templates_are_listed_in_workspace(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        template_payload = {
            "name": "OT audit template",
            "framework": "NIST",
            "version": "1.0",
            "description": "Local test template",
            "questions": [{"question": "Are OT assets inventoried?", "control_id": "OT-1"}],
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/custom_questionnaire_templates",
            data=json.dumps(template_payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            template = json.loads(response.read())["template"]
            self.assertEqual(response.status, 201)
        self.assertEqual(template["question_count"], 1)
        detail = urllib.request.Request(f"{self.base_url}/api/custom_templates/{template['id']}/questions", headers={"Cookie": cookie})
        with urllib.request.urlopen(detail, timeout=3) as response:
            self.assertEqual(json.loads(response.read())["questions"][0]["control_id"], "OT-1")
        workspace = urllib.request.Request(f"{self.base_url}/api/secumat_workspace", headers={"Cookie": cookie})
        with urllib.request.urlopen(workspace, timeout=3) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["questionnaires"][0]["name"], "OT audit template")
        self.assertTrue(payload["templates"])
        zf_questionnaire = next(item for item in payload["questionnaires"] if item["id"] == "zf-security-requirements")
        database_questionnaire = next(item for item in payload["questionnaires"] if item["id"] == "database-security-audit")
        zf_rows = [item for item in payload["questionnaire_library"] if item["framework"] == "ZF Security Requirements" and not item.get("template_resource")]
        database_rows = [item for item in payload["questionnaire_library"] if item["framework"] == "Database Security" and not item.get("template_resource")]
        template_rows = [item for item in payload["questionnaire_library"] if item.get("template_resource")]
        self.assertEqual(zf_questionnaire["question_count"], len(zf_rows))
        self.assertEqual(zf_questionnaire["question_count"], 221)
        self.assertTrue(any(item["question"] == "Privileged access workstation" for item in zf_rows))
        self.assertTrue(any(item["question"] == "Single Sign-On" for item in zf_rows))
        self.assertTrue(any(item["control_id"] == "TSI 01 - 501" and item["question"] == "Establish and maintain a penetration testing program" for item in zf_rows))
        self.assertEqual(database_questionnaire["question_count"], 37)
        self.assertEqual(len(database_rows), 37)
        self.assertEqual(len(template_rows), len(payload["templates"]))
        self.assertTrue(any(item["category"] == "Compliance and Audit Evidence" for item in payload["guidance"]))
        self.assertTrue(any(item["name"] == "Database Security Audit Controls.csv" for item in payload["templates"]))

        update = urllib.request.Request(
            f"{self.base_url}/api/custom_templates/{template['id']}",
            data=json.dumps({"description": "Updated local test template"}).encode(),
            headers=headers,
            method="PUT",
        )
        with urllib.request.urlopen(update, timeout=3) as response:
            self.assertEqual(json.loads(response.read())["template"]["description"], "Updated local test template")
        delete = urllib.request.Request(f"{self.base_url}/api/custom_questionnaire_templates/{template['id']}", headers=headers, method="DELETE")
        with urllib.request.urlopen(delete, timeout=3) as response:
            self.assertTrue(json.loads(response.read())["deleted"])

    def test_secumat_sample_form_and_disclaimer_are_hidden(self):
        filename = "IC-ISO-27001-Sample-Form-10838.xlsx"
        source = server.ROOT / "Audit Templates & Question Bank" / filename
        preview = server.parse_secumat_workbook(filename, source.read_bytes())
        self.assertNotIn(filename, {item["name"] for item in server.secumat_template_files()})
        self.assertNotIn("- Disclaimer -", {sheet["sheet_name"] for sheet in preview["sheets"]})

    def test_secumat_csv_upload_persists_previewable_sheet(self):
        cookie = self.browser_cookie()
        boundary = "----OTPlatformTestBoundary"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audit.csv\"\r\n"
            "Content-Type: text/csv\r\n\r\n"
            "Control,Question,Response\r\nAC-1,Are access controls reviewed?,Compliant\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"framework\"\r\n\r\nNIST\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"upload_name\"\r\n\r\nOT Baseline\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/upload/compliance",
            data=body,
            headers={"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            upload = json.loads(response.read())
            self.assertEqual(response.status, 201)
        upload_id = upload["upload_id"]
        self.assertEqual(upload["upload"]["total_questions"], 1)
        preview_request = urllib.request.Request(f"{self.base_url}/api/compliance_audit/{upload_id}/preview", headers={"Cookie": cookie})
        with urllib.request.urlopen(preview_request, timeout=3) as response:
            preview = json.loads(response.read())
        self.assertEqual(preview["sheets"][0]["sheet_name"], "audit")
        self.assertEqual(preview["sheets"][0]["rows"][1]["cells"][1], "Are access controls reviewed?")

    def test_audit_workbook_draft_history_and_submission(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        with patch.object(server, "secumat_template_files", return_value=[{"name": "test.xlsx", "extension": "xlsx"}]):
            payload = {"source": "test.xlsx", "name": "Site audit", "status": "draft", "expectedVersion": 0,
                       "changes": {"Controls": {"B2": "Reviewed"}}, "ratings": {"Controls": {"2": {"rating": "partial", "evidence": "Ticket 42"}}}}

            def save(body):
                request = urllib.request.Request(f"{self.base_url}/api/audit/workbooks", data=json.dumps(body).encode(), headers=headers, method="POST")
                with urllib.request.urlopen(request, timeout=3) as response:
                    return json.loads(response.read())["revision"]

            draft = save(payload)
            self.assertEqual(draft["version"], 1)
            self.assertTrue(draft["edited_by"].startswith("Local session "))
            history_request = urllib.request.Request(f"{self.base_url}/api/audit/workbooks?source=test.xlsx", headers={"Cookie": cookie})
            with urllib.request.urlopen(history_request, timeout=3) as response:
                self.assertEqual(len(json.loads(response.read())["history"]), 1)
            detail_request = urllib.request.Request(f"{self.base_url}/api/audit/workbooks/versions/{draft['id']}", headers={"Cookie": cookie})
            with urllib.request.urlopen(detail_request, timeout=3) as response:
                self.assertEqual(json.loads(response.read())["revision"]["changes"]["Controls"]["B2"], "Reviewed")
            with self.assertRaises(urllib.error.HTTPError) as stale:
                save({**payload, "auditId": draft["audit_id"]})
            self.assertEqual(stale.exception.code, 400)
            stale.exception.close()
            for malformed in ({"status": []}, {"expectedVersion": []}, {"ratings": {"Controls": {"2": {"rating": [], "evidence": "Ticket 42"}}}}):
                with self.subTest(malformed=malformed), self.assertRaises(urllib.error.HTTPError) as rejected:
                    save({**payload, **malformed})
                self.assertEqual(rejected.exception.code, 400)
                rejected.exception.close()
            submitted = save({**payload, "auditId": draft["audit_id"], "expectedVersion": 1, "status": "submitted"})
            self.assertEqual(submitted["version"], 2)
            with self.assertRaises(urllib.error.HTTPError) as locked:
                save({**payload, "auditId": draft["audit_id"], "expectedVersion": 2})
            self.assertEqual(locked.exception.code, 400)
            locked.exception.close()
            with self.assertRaises(urllib.error.HTTPError) as bypass:
                request = urllib.request.Request(f"{self.base_url}/api/modules/audit_workbook_versions/{submitted['id']}", data=b'{}', headers=headers, method="PUT")
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(bypass.exception.code, 403)
            bypass.exception.close()

    def test_assigned_workbook_progress_and_pending_items(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}
        source = "Audit Questions for companies.xlsx"

        def post(path, payload):
            request = urllib.request.Request(f"{self.base_url}{path}", data=json.dumps(payload).encode(), headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=8) as response:
                return json.loads(response.read())

        assignment = post("/api/audit_assignments", {"template_file": source, "assessment_name": "Plant review", "assigned_to": "OT Team",
                                                       "status": "completed", "reviewed_at": "2026-10-01T00:00:00Z", "reviewer_score": 100})["assignment"]
        self.assertEqual(assignment["status"], "pending")
        self.assertNotIn("reviewed_at", assignment)
        for module in ("audit_assignments", "audit_responses"):
            with self.subTest(module=module), self.assertRaises(urllib.error.HTTPError) as forged:
                post(f"/api/modules/{module}", {"status": "completed"})
            self.assertEqual(forged.exception.code, 403)
            forged.exception.close()
        self.assertGreater(assignment["question_count"], 2)
        self.assertEqual(assignment["pending_items"], assignment["question_count"])
        draft = post("/api/audit/workbooks", {"source": source, "name": "Plant review", "status": "draft", "expectedVersion": 0,
                  "assignmentId": assignment["id"], "changes": {"Auditor Summary": {"A2": "Reviewed"}},
                  "ratings": {"Auditor Summary": {"2": {"rating": "partial", "evidence": "Ticket 42"}}}})["revision"]
        detail_request = urllib.request.Request(f"{self.base_url}/api/audit_assignments/{assignment['id']}", headers={"Cookie": cookie})
        with urllib.request.urlopen(detail_request, timeout=3) as response:
            detail = json.loads(response.read())
        self.assertEqual(detail["completed_responses"], 1)
        self.assertEqual(detail["pending_items"], assignment["question_count"] - 1)
        self.assertEqual(detail["status"], "in_progress")
        self.assertTrue(detail["edited_by"].startswith("Local session "))
        with self.assertRaises(urllib.error.HTTPError) as wrong_endpoint:
            post("/api/audit_assignment_responses", {"assignment_id": assignment["id"], "responses": [{"question_id": "1", "response_status": "compliant"}]})
        self.assertEqual(wrong_endpoint.exception.code, 409)
        wrong_endpoint.exception.close()
        for path in (f"/api/audit_assignments/{assignment['id']}", f"/api/modules/audit_assignments/{assignment['id']}"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as tamper:
                request = urllib.request.Request(f"{self.base_url}{path}", data=json.dumps({"status": "submitted", "reviewer_score": 100}).encode(), headers=headers, method="PUT")
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(tamper.exception.code, 403)
            tamper.exception.close()
        edit_request = urllib.request.Request(f"{self.base_url}/api/audit_assignments/{assignment['id']}", data=json.dumps({"assigned_to": "Updated OT Team"}).encode(), headers=headers, method="PUT")
        with urllib.request.urlopen(edit_request, timeout=3) as response:
            self.assertEqual(json.loads(response.read())["assignment"]["assigned_to"], "Updated OT Team")
        with self.assertRaises(urllib.error.HTTPError) as premature_review:
            post(f"/api/audit_results/{assignment['id']}/review", {"reviewer_score": 75, "reviewed_by": "Auditor"})
        self.assertEqual(premature_review.exception.code, 409)
        premature_review.exception.close()
        other_assignment = post("/api/audit_assignments", {"template_file": source, "assessment_name": "Other plant", "assigned_to": "Other Team"})["assignment"]
        with self.assertRaises(urllib.error.HTTPError) as mismatch:
            post("/api/audit/workbooks", {"source": source, "name": "Plant review", "status": "draft", "expectedVersion": 1,
                  "auditId": draft["audit_id"], "assignmentId": other_assignment["id"]})
        self.assertEqual(mismatch.exception.code, 400)
        mismatch.exception.close()
        post("/api/audit/workbooks", {"source": source, "name": "Plant review", "status": "submitted", "expectedVersion": 1,
             "auditId": draft["audit_id"], "assignmentId": assignment["id"], "ratings": {"Auditor Summary": {"2": {"rating": "partial", "evidence": "Ticket 42"}}}})
        with urllib.request.urlopen(detail_request, timeout=3) as response:
            submitted = json.loads(response.read())
        self.assertEqual(submitted["status"], "submitted")
        self.assertEqual(submitted["pending_items"], assignment["question_count"] - 1)
        report_request = urllib.request.Request(f"{self.base_url}/api/audit_results/{assignment['id']}", headers={"Cookie": cookie})
        with urllib.request.urlopen(report_request, timeout=5) as response:
            report = json.loads(response.read())
        self.assertEqual(report["report"]["compliance_score"], 50)
        self.assertEqual(report["report"]["status_breakdown"]["partial"], 1)
        self.assertEqual(report["responses"][0]["question_id"], "Auditor Summary!2")
        self.assertEqual(report["responses"][0]["evidence"], "Ticket 42")
        download_request = urllib.request.Request(f"{self.base_url}/api/audit_results/{assignment['id']}/download", headers={"Cookie": cookie})
        with urllib.request.urlopen(download_request, timeout=5) as response:
            self.assertIn("Ticket 42", response.read().decode())
        analytics_request = urllib.request.Request(f"{self.base_url}/api/audit_results/analytics", headers={"Cookie": cookie})
        with urllib.request.urlopen(analytics_request, timeout=5) as response:
            analytics = json.loads(response.read())
        self.assertEqual(analytics["summary"]["total"], 2)
        self.assertEqual(analytics["summary"]["awaitingReview"], 1)
        self.assertEqual(analytics["summary"]["pendingItems"], assignment["question_count"] * 2 - 1)
        self.assertIsNone(analytics["summary"]["averageReviewedScore"])
        self.assertEqual(analytics["findings"]["partial"], 1)
        self.assertEqual(sum(item["submitted"] for item in analytics["trends"]), 1)
        summary_csv_request = urllib.request.Request(f"{self.base_url}/api/audit_results/analytics.csv", headers={"Cookie": cookie})
        with urllib.request.urlopen(summary_csv_request, timeout=5) as response:
            summary_rows = list(csv.DictReader(io.StringIO(response.read().decode("utf-8-sig"))))
        self.assertEqual(len(summary_rows), 2)
        self.assertEqual(next(row for row in summary_rows if row["status"] == "submitted")["pending"], str(assignment["question_count"] - 1))
        reviewed = post(f"/api/audit_results/{assignment['id']}/review", {"reviewer_score": 75, "reviewed_by": "Auditor", "reviewer_comments": "Evidence checked"})["assignment"]
        self.assertEqual(reviewed["status"], "completed")
        self.assertEqual(reviewed["reviewed_by"], "Auditor")
        with self.assertRaises(urllib.error.HTTPError) as after_review:
            post("/api/audit_assignment_responses", {"assignment_id": assignment["id"], "responses": [{"question_id": "1", "response_status": "compliant"}]})
        self.assertEqual(after_review.exception.code, 409)
        after_review.exception.close()
        with urllib.request.urlopen(analytics_request, timeout=5) as response:
            final_analytics = json.loads(response.read())
        self.assertEqual(final_analytics["summary"]["awaitingReview"], 0)
        self.assertEqual(final_analytics["summary"]["reviewed"], 1)
        self.assertEqual(final_analytics["summary"]["averageReviewedScore"], 75)
        self.assertEqual(sum(day["reviewed"] for day in final_analytics["trends"]), 1)

    def test_duplicate_workbook_assignment_starts_independent(self):
        cookie = self.browser_cookie()
        headers = {"Cookie": cookie, "Origin": next(iter(server.LOCAL_BROWSER_ORIGINS)), "Content-Type": "application/json"}

        def post(path, payload):
            request = urllib.request.Request(f"{self.base_url}{path}", data=json.dumps(payload).encode(), headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=8) as response:
                return json.loads(response.read())

        source = "Audit Questions for companies.xlsx"
        original = post("/api/audit_assignments", {"template_file": source, "assigned_to": "OT Team"})["assignment"]
        post("/api/audit/workbooks", {"source": source, "name": "Original", "status": "draft", "expectedVersion": 0,
             "assignmentId": original["id"], "ratings": {"Auditor Summary": {"2": {"rating": "partial", "evidence": "Checked"}}}})
        copy = post(f"/api/audit_assignments/{original['id']}/duplicate", {})["assignment"]
        self.assertEqual(copy["status"], "pending")
        self.assertEqual(copy["pending_items"], copy["question_count"])
        self.assertNotIn("workbook_audit_id", copy)
        self.assertNotIn("edited_by", copy)
        self.assertNotIn("reviewed_at", copy)
        revision = post("/api/audit/workbooks", {"source": source, "name": "Copy", "status": "draft", "expectedVersion": 0,
                    "assignmentId": copy["id"], "ratings": {"Auditor Summary": {"2": {"rating": "compliant", "evidence": "Separate"}}}})["revision"]
        self.assertEqual(str(revision["assignment_id"]), str(copy["id"]))


class EncryptedCredentialStoreTests(unittest.TestCase):
    def test_integration_secrets_are_encrypted_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"):
                server.save_integration_credentials({
                    "toolId": "swimlane",
                    "config": {"baseUrl": "https://swimlane.example", "pat": "unit-test-secret", "appId": "incident-app"},
                })
                status = server.public_integration_credential_status()["tools"]["swimlane"]
                self.assertTrue(status["configured"])
                self.assertEqual(status["safeConfig"]["baseUrl"], "https://swimlane.example")
                self.assertNotIn("pat", status["safeConfig"])
                self.assertNotIn(b"unit-test-secret", (state_dir / "integrations.enc").read_bytes())
                self.assertEqual(server.load_integration_credential_store()["swimlane"]["pat"], "unit-test-secret")

    def test_new_vendor_credentials_are_encrypted_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"):
                configs = {
                    "rubrik": {"baseUrl": "https://rubrik.example", "clientId": "rubrik-client", "clientSecret": "rubrik-secret"},
                    "netapp": {"baseUrl": "https://ontap.example", "username": "ontap-user", "password": "ontap-secret"},
                    "nasuni": {"baseUrl": "https://nasuni.example/api", "clientId": "nasuni-client", "clientSecret": "nasuni-secret"},
                    "wazuh": {"baseUrl": "https://wazuh.example", "username": "wazuh-user", "password": "wazuh-secret"},
                    "bmc": {"baseUrl": "https://bmc.example", "clientId": "bmc-client", "clientSecret": "bmc-secret"},
                    "sentinelone": {"baseUrl": "https://sentinelone.example", "apiToken": "sentinelone-token"},
                    "mcafee-epo": {"baseUrl": "https://epo.example", "username": "epo-user", "password": "epo-secret"},
                    "defender-cloud-apps": {"tenantId": "cloud-tenant", "clientId": "cloud-client", "clientSecret": "cloud-secret"},
                    "wiz": {"baseUrl": "https://wiz.example/graphql", "clientId": "wiz-client", "clientSecret": "wiz-secret"},
                    "prismacloud": {"baseUrl": "https://prisma.example", "accessKey": "prisma-access", "secretKey": "prisma-secret"},
                    "cato": {"baseUrl": "https://cato.example/graphql", "apiKey": "cato-api-token", "accountId": "cato-account"},
                    "dc2cloud": {"baseUrl": "https://dc2cloud.example/api", "tenantId": "dc2cloud-tenant", "clientId": "dc2cloud-client", "clientSecret": "dc2cloud-secret"},
                }
                for tool_id, config in configs.items():
                    server.save_integration_credentials({"toolId": tool_id, "config": config})
                encrypted = (state_dir / "integrations.enc").read_bytes()
                public = server.public_integration_credential_status()["tools"]
                self.assertEqual(public["rubrik"]["safeConfig"]["access_token_uri"], "https://rubrik.example")
                self.assertIn("client_id", public["rubrik"]["fields"])
                self.assertIn("client_secret", public["rubrik"]["fields"])
                self.assertNotIn("clientSecret", public["rubrik"]["fields"])
                for tool_id, config in configs.items():
                    with self.subTest(tool=tool_id):
                        self.assertTrue(public[tool_id]["configured"])
                        for field in ("clientSecret", "password", "apiToken", "secretKey", "accessKey"):
                            self.assertNotIn(field, public[tool_id]["safeConfig"])
                        for value in config.values():
                            self.assertNotIn(value.encode("utf-8"), encrypted)

    def test_rubrik_snake_case_fields_preserve_legacy_secret_encrypted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"):
                server.save_integration_credentials({
                    "toolId": "rubrik",
                    "config": {
                        "baseUrl": "https://old-rubrik.example",
                        "clientId": "old-client",
                        "clientSecret": "preserved-rubrik-secret",
                    },
                })
                server.save_integration_credentials({
                    "toolId": "rubrik",
                    "config": {
                        "name": "Security_OT_SEC",
                        "access_token_uri": "https://zf-prod.my.rubrik.com/api/client_token",
                        "client_id": "new-client",
                    },
                })

                config = server.load_integration_credential_store()["rubrik"]
                status = server.public_integration_credential_status()["tools"]["rubrik"]
                encrypted = (state_dir / "integrations.enc").read_bytes()

                self.assertEqual(config["name"], "Security_OT_SEC")
                self.assertEqual(config["access_token_uri"], "https://zf-prod.my.rubrik.com/api/client_token")
                self.assertEqual(config["client_id"], "new-client")
                self.assertEqual(config["client_secret"], "preserved-rubrik-secret")
                self.assertNotIn("clientSecret", config)
                self.assertNotIn("client_secret", status["safeConfig"])
                self.assertNotIn(b"preserved-rubrik-secret", encrypted)

    def test_cato_and_dc2cloud_zero_trust_readiness_is_not_live_enforcement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "CLAROTY_CREDENTIALS_FILE", state_dir / "claroty.enc"), \
                    patch.object(server, "LEGACY_CLAROTY_CREDENTIALS_FILE", root / "legacy.enc"), \
                    patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"), \
                    patch.object(server, "INTEGRATION_CONNECTORS_FILE", state_dir / "connectors.json"):
                server.save_integration_credentials({"toolId": "cato", "config": {"baseUrl": "https://cato.example/graphql", "apiKey": "cato-test-secret", "accountId": "cato-test-account"}})
                server.save_integration_credentials({"toolId": "dc2cloud", "config": {"baseUrl": "https://dc2cloud.example/api", "tenantId": "dc2cloud-test-tenant", "clientSecret": "dc2cloud-test-secret"}})
                payload = server.zero_trust_integrations_payload()
                statuses = {item.get("tool_id"): item["status"] for item in payload["connectors"] if item.get("tool_id")}
                self.assertEqual(statuses["cato"], "credentials_configured")
                self.assertEqual(statuses["dc2cloud"], "credentials_configured")
                self.assertEqual(payload["policyEnforcement"], "not_connected")
                self.assertNotIn("cato-test-secret", json.dumps(payload))
                self.assertNotIn("dc2cloud-test-secret", json.dumps(payload))

    def test_open_source_engine_readiness_requires_observed_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            timestamp = server.datetime.now(server.timezone.utc).isoformat()
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "CLAROTY_CREDENTIALS_FILE", state_dir / "claroty.enc"), \
                    patch.object(server, "LEGACY_CLAROTY_CREDENTIALS_FILE", root / "legacy.enc"), \
                    patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"), \
                    patch.object(server, "INTEGRATION_CONNECTORS_FILE", state_dir / "connectors.json"), \
                    patch.object(server, "ZERO_TRUST_EVENT_FILE", state_dir / "events.jsonl"):
                server.write_json_store(server.INTEGRATION_CONNECTORS_FILE, [{
                    "id": "receiver-1", "name": "Wazuh", "transport": "webhook",
                    "eventCount": 1, "lastReceivedAt": timestamp,
                }])
                server.append_zero_trust_event({
                    "event_id": "wazuh-event-1", "event_type": "security.alert", "event_time": timestamp,
                    "source": {"system": "Wazuh"}, "outcome": "observed",
                })
                payload = server.zero_trust_integrations_payload()
                engines = {engine["id"]: engine for engine in payload["openSourceEngines"]}
                self.assertEqual(engines["wazuh"]["status"], "telemetry_received")
                self.assertEqual(engines["wazuh"]["eventCount"], 1)
                self.assertEqual(engines["suricata"]["status"], "candidate_not_connected")
                self.assertFalse(engines["suricata"]["externalActionsEnabled"])
                self.assertEqual(payload["policyEnforcement"], "not_connected")

    def test_udp_analytics_counts_sase_dc2cloud_and_ai_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            event_file = Path(temp_dir) / "zero-trust-events.jsonl"
            with patch.object(server, "ZERO_TRUST_EVENT_FILE", event_file):
                timestamp = server.datetime.now(server.timezone.utc).isoformat()
                events = [
                    {"event_id": "sase-test", "event_type": "sase.access.session", "event_time": timestamp, "source": {"system": "Cato SASE"}, "outcome": "denied"},
                    {"event_id": "dc-test", "event_type": "cloud.workload.finding", "event_time": timestamp, "source": {"system": "DC2Cloud"}, "outcome": "observed"},
                    {"event_id": "ai-test", "event_type": "ai.agent.activity", "event_time": timestamp, "source": {"system": "UDP AI Guard"}, "outcome": "observed"},
                ]
                for event in events:
                    server.append_zero_trust_event(event)
                metrics = server.zero_trust_analytics_payload(24)["metrics"]
                self.assertEqual(metrics["sase_access_sessions"]["value"], 1)
                self.assertEqual(metrics["sase_denials"]["value"], 1)
                self.assertEqual(metrics["dc2cloud_security_events"]["value"], 1)
                self.assertEqual(metrics["ai_security_events"]["value"], 1)

    def test_legacy_claroty_credentials_move_to_user_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            legacy_dir = root / "project-data"
            state_dir.mkdir()
            legacy_dir.mkdir()
            legacy_key_path = legacy_dir / ".claroty_fernet.key"
            legacy_file_path = legacy_dir / "claroty_credentials.enc"
            legacy_key = Fernet.generate_key()
            legacy_key_path.write_bytes(legacy_key)
            legacy_config = {"apiKey": "legacy-test-token", "baseUrl": "https://eu.api.claroty.com"}
            legacy_file_path.write_bytes(Fernet(legacy_key).encrypt(json.dumps(legacy_config).encode("utf-8")))
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", legacy_key_path), \
                    patch.object(server, "CLAROTY_CREDENTIALS_FILE", state_dir / "claroty_credentials.enc"), \
                    patch.object(server, "LEGACY_CLAROTY_CREDENTIALS_FILE", legacy_file_path):
                self.assertEqual(server.load_claroty_credentials(), legacy_config)
                self.assertTrue((state_dir / "credentials.key").exists())
                self.assertTrue((state_dir / "claroty_credentials.enc").exists())
                self.assertFalse(legacy_key_path.exists())
                self.assertFalse(legacy_file_path.exists())
                self.assertNotIn(b"legacy-test-token", (state_dir / "claroty_credentials.enc").read_bytes())

    def test_swimlane_proxy_uses_backend_pat_and_allowlists_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_dir = root / "state"
            with patch.object(server, "APP_STATE_DIR", state_dir), \
                    patch.object(server, "CLAROTY_KEY_FILE", state_dir / "credentials.key"), \
                    patch.object(server, "LEGACY_CLAROTY_KEY_FILE", root / "legacy.key"), \
                    patch.object(server, "INTEGRATION_CREDENTIALS_FILE", state_dir / "integrations.enc"):
                server.save_integration_credentials({
                    "toolId": "swimlane",
                    "config": {"baseUrl": "https://swimlane.example", "pat": "server-only-pat", "appId": "incident_app"},
                })
                captured = {}

                class FakeResponse:
                    def __enter__(self):
                        return self

                    def __exit__(self, *_args):
                        return False

                    def read(self, _limit=-1):
                        return b'{"records":[]}'

                def fake_urlopen(request, timeout):
                    captured["url"] = request.full_url
                    captured["pat"] = request.get_header("Private-token")
                    captured["timeout"] = timeout
                    return FakeResponse()

                with patch("server.urllib.request.urlopen", side_effect=fake_urlopen):
                    result = server.swimlane_request({
                        "path": "/api/app/incident_app/record/search",
                        "method": "POST",
                        "body": {"filters": []},
                    })
                self.assertEqual(result, {"records": []})
                self.assertEqual(captured["url"], "https://swimlane.example/api/app/incident_app/record/search")
                self.assertEqual(captured["pat"], "server-only-pat")
                self.assertNotIn("server-only-pat", json.dumps(result))
                with self.assertRaises(ValueError):
                    server.swimlane_request({"path": "http://127.0.0.1/private", "method": "GET"})


if __name__ == "__main__":
    unittest.main()
class IntegrationBaseUrlNormalizationTests(unittest.TestCase):
    def test_strips_quotes_and_duplicated_token_path(self):
        self.assertEqual(
            server.normalize_base_url('https://tenant.my.rubrik.com/api/client_token"', "/api/client_token"),
            "https://tenant.my.rubrik.com",
        )

    def test_adds_scheme_and_trims_trailing_slash(self):
        self.assertEqual(server.normalize_base_url("tenant.my.rubrik.com/", "/api/client_token"), "https://tenant.my.rubrik.com")

    def test_keeps_unrelated_path(self):
        self.assertEqual(server.normalize_base_url("https://host/base", "/api/client_token"), "https://host/base")

    def test_blank_value_returns_empty_string(self):
        self.assertEqual(server.normalize_base_url('  ""  '), "")

    def test_rubrik_client_id_strips_json_punctuation(self):
        self.assertEqual(server.normalize_rubrik_client_id('"client|55c3abe2-eb39-4ac1-8030-20859b181d0c",'), "client|55c3abe2-eb39-4ac1-8030-20859b181d0c")

    def test_rubrik_token_probe_uses_normalized_client_id(self):
        captured = {}

        def fake_probe(url, headers=None, data=None, method="GET"):
            captured.update({"url": url, "headers": headers, "payload": urllib.parse.parse_qs(data.decode("utf-8"))})
            return {"status": 200, "ms": 1}

        config = {"baseUrl": 'https://rubrik.example/api/client_token"', "clientId": '"client|account-id",', "clientSecret": "secret"}
        with patch.object(server, "load_integration_credential_store", return_value={"rubrik": config}), \
                patch.object(server, "perform_integration_probe", side_effect=fake_probe):
            result = server.integration_connection_test("rubrik")
        self.assertTrue(result["ok"])
        self.assertEqual(captured["url"], "https://rubrik.example/api/client_token")
        self.assertEqual(captured["payload"]["client_id"], ["client|account-id"])
        self.assertEqual(captured["headers"]["Content-Type"], "application/x-www-form-urlencoded")

    def test_rubrik_snake_case_fields_and_full_token_uri(self):
        captured = {}

        def fake_probe(url, headers=None, data=None, method="GET"):
            captured.update({"url": url, "headers": headers, "payload": urllib.parse.parse_qs(data.decode("utf-8"))})
            return {"status": 200, "ms": 1}

        config = {
            "name": "Security_OT_SEC",
            "access_token_uri": "https://zf-prod.my.rubrik.com/api/client_token",
            "client_id": "client|account-id",
            "client_secret": "test-secret",
        }
        with patch.object(server, "load_integration_credential_store", return_value={"rubrik": config}), \
                patch.object(server, "perform_integration_probe", side_effect=fake_probe):
            result = server.integration_connection_test("rubrik")
        self.assertTrue(result["ok"])
        self.assertEqual(captured["url"], "https://zf-prod.my.rubrik.com/api/client_token")
        self.assertEqual(captured["payload"]["client_id"], ["client|account-id"])
        self.assertEqual(captured["payload"]["client_secret"], ["test-secret"])
        self.assertEqual(captured["headers"]["Content-Type"], "application/x-www-form-urlencoded")

    def test_rubrik_api_origin_requires_official_https_tenant_domain(self):
        self.assertEqual(
            server.rubrik_api_origin({"access_token_uri": "https://zf-prod.my.rubrik.com/api/client_token"}),
            "https://zf-prod.my.rubrik.com",
        )
        for uri in (
            "http://zf-prod.my.rubrik.com/api/client_token",
            "https://example.com/api/client_token",
            "https://zf-prod.my.rubrik.com:8443/api/client_token",
        ):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                server.rubrik_api_origin({"access_token_uri": uri})

    def test_rubrik_recent_activities_are_mapped_to_safe_dashboard_fields(self):
        config = {"client_id": "rubrik-client", "client_secret": "do-not-return"}
        response = {
            "activitySeriesConnection": {
                "nodes": [{
                    "activitySeriesId": "activity-1",
                    "lastActivityStatus": "FAILURE",
                    "lastActivityType": "BACKUP",
                    "lastActivityMessage": "Snapshot failed",
                    "lastUpdated": "2026-10-26T08:30:00Z",
                    "lastEventAddedAt": "2026-10-26T08:29:00Z",
                    "startTime": "2026-10-26T08:00:00Z",
                    "objectId": "object-1",
                    "objectName": "server-1",
                    "objectType": "VMWARE_VM",
                    "orgName": "Production",
                    "clusterName": "cluster-1",
                    "severity": "CRITICAL",
                    "failureReason": "Snapshot failure",
                    "causeErrorCode": "SNAPSHOT_FAILED",
                    "client_secret": "should-not-be-forwarded",
                }],
                "pageInfo": {"hasNextPage": True, "endCursor": "cursor"},
            },
            "userAuditConnection": {
                "nodes": [{
                    "actorType": "USER",
                    "auditType": "SLA_MODIFICATION",
                    "id": "audit-1",
                    "message": "SLA settings updated",
                    "objectId": "sla-1",
                    "objectName": "Gold SLA",
                    "objectType": "SLA_DOMAIN",
                    "orgName": "Production",
                    "severity": "INFO",
                    "status": "SUCCESS",
                    "time": "2026-10-26T08:31:00Z",
                    "userName": "operator",
                }],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            },
        }
        second_page = {
            "activitySeriesConnection": {
                "nodes": [{
                    "activitySeriesId": "activity-2",
                    "lastActivityType": "BACKUP",
                    "lastActivityMessage": "Snapshot completed",
                    "lastUpdated": "2026-10-26T08:32:00Z",
                }],
                "pageInfo": {"hasNextPage": False, "endCursor": "cursor-2"},
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server, "load_integration_credential_store", return_value={"rubrik": config}), \
                patch.object(server, "rubrik_graphql_query", side_effect=[response, second_page]) as query:
            first_result = server.rubrik_recent_activity_payload("60")
            result = server.rubrik_recent_activity_payload(
                "60", activity_after=first_result["nextActivityCursor"], audit_done=True,
            )
            self.assertEqual(len(server.list_module_records("integrations")["records"]), 3)

        self.assertEqual(query.call_count, 2)
        self.assertEqual(query.call_args_list[0].args[1], server.RUBRIK_ACTIVITY_QUERY)
        self.assertEqual(first_result["count"], 2)
        self.assertEqual(first_result["activityCount"], 1)
        self.assertEqual(first_result["auditCount"], 1)
        self.assertTrue(first_result["partial"])
        self.assertEqual(first_result["nextActivityCursor"], "cursor")
        self.assertFalse(first_result["hasMoreAuditEvents"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["activityCount"], 1)
        self.assertEqual(result["auditCount"], 0)
        self.assertFalse(result["hasMoreActivities"])
        self.assertFalse(result["hasMoreAuditEvents"])
        self.assertFalse(result["partial"])
        activity_event = next(item for item in first_result["events"] if item["eventClass"] == "Workload activity")
        audit_event = next(item for item in first_result["events"] if item["eventClass"] == "Audit event")
        self.assertEqual(activity_event["title"], "Snapshot failed")
        self.assertEqual(activity_event["severity"], "CRITICAL")
        self.assertEqual(activity_event["path"], "")
        self.assertEqual(activity_event["indicators"], [])
        self.assertEqual(activity_event["routedModules"], ["integrations"])
        self.assertEqual(audit_event["actor"], "operator")
        self.assertEqual(audit_event["routedModules"], ["integrations"])
        self.assertNotIn("client_secret", json.dumps([first_result, result]))
        first_variables = query.call_args_list[0].args[2]
        second_variables = query.call_args_list[1].args[2]
        self.assertEqual(first_variables["first"], server.RUBRIK_PAGE_SIZE)
        self.assertIn("lastUpdatedTimeGt", first_variables["activityFilters"])
        self.assertIn("timeGt", first_variables["auditFilters"])
        self.assertEqual(second_variables["activityAfter"], "cursor")
        self.assertFalse(second_variables["includeAudit"])


class ConnectorTokenRotationTests(unittest.TestCase):
    def test_rotation_invalidates_old_bearer_and_returns_new_token_once(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(server, "INTEGRATION_CONNECTORS_FILE", Path(temp_dir) / "connectors.json"):
                created = server.create_integration_connector({"name": "Rotation test", "transport": "webhook"})
                rotated = server.rotate_integration_connector_token(created["id"])

                self.assertEqual(rotated["id"], created["id"])
                self.assertNotEqual(rotated["token"], created["token"])
                self.assertNotIn("tokenHash", rotated)
                self.assertIsNone(server.authenticate_integration_connector(
                    created["id"], f"Bearer {created['token']}"))
                self.assertEqual(
                    server.authenticate_integration_connector(created["id"], f"Bearer {rotated['token']}")["id"],
                    created["id"],
                )
                self.assertIsNone(server.rotate_integration_connector_token("missing-connector"))

    def test_disabled_connector_rejects_ingestion_until_reenabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(server, "INTEGRATION_CONNECTORS_FILE", Path(temp_dir) / "connectors.json"):
                created = server.create_integration_connector({"name": "Pause test", "transport": "webhook"})
                disabled = server.set_integration_connector_enabled(created["id"], False)
                self.assertFalse(disabled["enabled"])
                with self.assertRaisesRegex(PermissionError, "disabled"):
                    server.authenticate_integration_connector(created["id"], f"Bearer {created['token']}")
                enabled = server.set_integration_connector_enabled(created["id"], True)
                self.assertTrue(enabled["enabled"])
                self.assertEqual(
                    server.authenticate_integration_connector(created["id"], f"Bearer {created['token']}")["id"],
                    created["id"],
                )


class RubrikWebhookTests(unittest.TestCase):
    def test_maps_pd_cef_alert_and_excludes_routing_key_and_unapproved_details(self):
        event = server.connector_json_events({
            "event_action": "trigger",
            "routing_key": "must-not-be-stored",
            "payload": {
                "summary": "Backup failure on VM",
                "severity": "error",
                "source": "Rubrik Security Cloud",
                "timestamp": "2026-10-26T08:00:00Z",
                "custom_details": {
                    "object_name": "vm-1",
                    "operation": "backup",
                    "error_message": "Snapshot failed",
                    "access_token": "must-not-be-stored",
                    "extra": "not allowlisted",
                },
            },
        }, {"transport": "rubrik"})[0]

        self.assertEqual(event["event_type"], "rubrik.alert.trigger")
        self.assertEqual(event["source"]["system"], "Rubrik Security Cloud")
        self.assertEqual(event["source"]["transport"], "rubrik")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["details"]["object_name"], "vm-1")
        serialized = json.dumps(event)
        self.assertNotIn("must-not-be-stored", serialized)
        self.assertNotIn("access_token", serialized)
        self.assertNotIn("not allowlisted", serialized)

    def test_integration_event_routes_by_category_and_upserts_without_touching_audit_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"):
                attack = server.validate_zero_trust_event({
                    "event_id": "event-attack-1",
                    "event_type": "network.attack.detected",
                    "event_time": "2026-10-26T08:00:00Z",
                    "source": {"system": "Test SIEM"},
                    "device": {"device_name": "plc-01"},
                    "path": "/api/ot/command",
                    "indicators": [{"type": "ip", "value": "203.0.113.20"}],
                    "details": {"summary": "Suspicious control command"},
                })
                threat_route = server.save_integration_event(attack)
                server.save_integration_event(attack)
                self.assertEqual(threat_route["modules"], ["integrations", "alerts"])
                self.assertEqual(len(server.list_module_records("integrations")["records"]), 1)
                threat = server.get_module_record("alerts", threat_route["record_id"])
                self.assertEqual(threat["device"]["device_name"], "plc-01")
                self.assertEqual(threat["path"], "/api/ot/command")
                self.assertEqual(threat["indicators"][0]["value"], "203.0.113.20")

                vulnerability = server.validate_zero_trust_event({
                    "event_id": "event-vuln-1",
                    "event_type": "vulnerability.finding",
                    "event_time": "2026-10-26T08:01:00Z",
                    "source": {"system": "Scanner"},
                    "details": {"cve": "CVE-2026-12345", "summary": "Affected device"},
                })
                vulnerability_route = server.save_integration_event(vulnerability)
                self.assertEqual(vulnerability_route["modules"], ["integrations", "vulnerabilities"])
                record = server.get_module_record("vulnerabilities", vulnerability_route["record_id"])
                self.assertEqual(record["cve"], "CVE-2026-12345")

                audit = server.validate_zero_trust_event({
                    "event_id": "event-audit-1",
                    "event_type": "identity.audit.login",
                    "event_time": "2026-10-26T08:02:00Z",
                    "source": {"system": "Identity Provider"},
                    "details": {"summary": "User signed in"},
                })
                audit_route = server.save_integration_event(audit)
                self.assertEqual(audit_route["modules"], ["integrations"])
                self.assertEqual(server.list_module_records("audit_results")["total"], 0)

    def test_integration_event_batch_persists_all_module_records_with_one_store_write(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server, "write_json_store", wraps=server.write_json_store) as write_store:
            events = [
                server.validate_zero_trust_event({
                    "event_id": f"batch-{index}",
                    "event_type": "network.attack.detected",
                    "event_time": "2026-10-26T08:00:00Z",
                    "source": {"system": "Batch test"},
                    "details": {"summary": f"Suspicious event {index}"},
                })
                for index in range(3)
            ]
            routes = server.save_integration_events(events)

            self.assertEqual(len(routes), 3)
            self.assertEqual(write_store.call_count, 1)
            self.assertEqual(server.list_module_records("integrations")["total"], 3)
            self.assertEqual(server.list_module_records("alerts")["total"], 3)

    def test_rubrik_feed_state_defaults_enabled_and_persists_user_toggle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(server, "INTEGRATION_FEED_STATE_FILE", Path(temp_dir) / "feed-state.json"):
                self.assertTrue(server.load_integration_feed_state()["rubrikApiEnabled"])
                self.assertEqual(server.save_integration_feed_state({"rubrikApiEnabled": False}), {"rubrikApiEnabled": False})
                self.assertFalse(server.load_integration_feed_state()["rubrikApiEnabled"])

    def test_maps_resolved_notifications_and_rejects_missing_summary(self):
        resolved = server.connector_json_events({
            "event_action": "resolve",
            "payload": {"summary": "Backup recovered", "timestamp": "2026-10-26T08:00:00Z"},
        }, {"transport": "rubrik"})[0]
        self.assertEqual(resolved["event_type"], "rubrik.alert.resolve")
        self.assertEqual(resolved["outcome"], "observed")

        with self.assertRaisesRegex(ValueError, "payload.summary is required"):
            server.connector_json_events({"payload": {}}, {"transport": "rubrik"})

    def test_rubrik_receiver_is_reported_in_resilience_readiness(self):
        with patch.object(server, "claroty_credentials_status", return_value={"configured": False}), \
             patch.object(server, "load_integration_connectors", return_value=[{
                 "id": "rubrik-receiver", "name": "Rubrik Security Cloud", "transport": "rubrik",
                 "eventCount": 2, "lastReceivedAt": "2026-10-26T08:00:00+00:00",
             }]), \
             patch.object(server, "load_integration_credential_store", return_value={}), \
             patch.object(server, "read_zero_trust_events", return_value=[]), \
             patch.object(server, "openappid_status_payload", return_value={"configured": False}):
            payload = server.zero_trust_integrations_payload()

        resilience = next(item for item in payload["connectors"] if item["pillar"] == "Risk & Resilience")
        self.assertEqual(resilience["status"], "telemetry_received")
        self.assertEqual(resilience["eventReceiver"]["transport"], "rubrik")
        self.assertEqual(resilience["eventReceiver"]["eventCount"], 2)


class ThreatFeedIndexTests(unittest.TestCase):
    def test_feed_parser_normalizes_supported_indicators_and_skips_invalid_rows(self):
        self.assertEqual(server.parse_threat_feed("# comment\n203.0.113.10\nnot-an-ip\n", "ip"), ["203.0.113.10"])
        self.assertEqual(server.parse_threat_feed("EXAMPLE.COM\ninvalid domain\n", "domain"), ["example.com"])
        self.assertEqual(server.parse_threat_feed("D41D8CD98F00B204E9800998ECF8427E\n123\n", "md5"), ["d41d8cd98f00b204e9800998ecf8427e"])

    def test_ingested_url_hash_and_ip_correlate_and_generate_a_high_alert(self):
        indicators = [
            ("domain", "bad.example", "Malicious domains"),
            ("sha256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "Malicious hashes"),
            ("ip", "203.0.113.10", "Malicious IPs"),
        ]
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "THREAT_FEED_DB_FILE", Path(temp_dir) / "feeds.sqlite3"), \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"):
            connection = server.threat_feed_database()
            try:
                connection.executemany(
                    "INSERT INTO indicators(feed_id, feed_name, indicator_type, value, refreshed_at) VALUES (?, ?, ?, ?, ?)",
                    [
                        (f"feed-{kind}", name, kind, value, "2026-10-27T00:00:00+00:00")
                        for kind, value, name in indicators
                    ],
                )
                connection.commit()
            finally:
                connection.close()

            self.assertTrue(server.lookup_threat_indicators("bad.example/payload", "url")["matched"])

            event = server.validate_zero_trust_event({
                "event_id": "multi-ioc-event",
                "event_type": "network.connection",
                "event_time": "2026-10-27T08:00:00Z",
                "source": {"system": "New inbound security tool"},
                "indicators": [
                    {"type": "url", "value": "https://bad.example/payload"},
                    {"type": "sha256", "value": indicators[1][1]},
                    {"type": "ip", "value": "203.0.113.10"},
                ],
                "details": {"severity": "low"},
            })
            routing = server.save_integration_event(event)

            self.assertEqual(routing["category"], "threat")
            self.assertEqual(routing["modules"], ["integrations", "alerts"])
            alert = server.get_module_record("alerts", routing["record_id"])
            self.assertEqual(alert["severity"], "high")
            self.assertEqual(alert["detection_rule_id"], "local-threat-feed-match")
            matches = alert["event"]["threat_feed_matches"]
            self.assertEqual({(item["type"], item["indicator"]) for item in matches}, {
                ("domain", "bad.example"),
                ("sha256", indicators[1][1]),
                ("ip", "203.0.113.10"),
            })
            self.assertTrue(any(item.get("observedIndicator") == "https://bad.example/payload" for item in matches))

    def test_feed_match_is_in_local_detection_rules_and_siem_kpis(self):
        now = server.datetime.now(server.timezone.utc).isoformat()
        event = {
            "event_id": "feed-detection-event",
            "event_type": "network.connection",
            "event_time": now,
            "source": {"system": "new-connector"},
            "threat_feed_matches": [{
                "type": "domain",
                "indicator": "bad.example",
                "sources": [{"id": "test-feed", "name": "Test feed"}],
            }],
        }
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server, "read_zero_trust_events", return_value=[event]):
            detections = server.zero_trust_detections_payload()["detections"]
            feed_detection = next(item for item in detections if item["rule_id"] == "local-threat-feed-match")
            self.assertEqual(feed_detection["severity"], "high")
            self.assertEqual(feed_detection["matched_count"], 1)

            server.save_module_record("alerts", {
                "id": "feed-alert",
                "event": event,
                "severity": "high",
                "event_time": now,
            })
            siem = server.siem_dashboard_payload()
            self.assertEqual(siem["counts"]["feedMatchedAlerts"], 1)
            self.assertEqual(siem["counts"]["feedMatchedIndicators"], 1)

    def test_refresh_indexes_all_partitions_and_routes_feed_matches(self):
        body_by_type = {
            "ip": b"203.0.113.10\n",
            "domain": b"malicious.example\n",
            "md5": b"d41d8cd98f00b204e9800998ecf8427e\n",
            "sha1": b"0123456789abcdef0123456789abcdef01234567\n",
            "sha256": b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        }

        class FeedResponse:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, _limit):
                return self.body

        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "THREAT_FEED_DB_FILE", Path(temp_dir) / "feeds.sqlite3"), \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server.urllib.request, "urlopen", side_effect=lambda request, timeout: FeedResponse(
                    body_by_type[next(feed["type"] for feed in server.THREAT_INDICATOR_FEEDS if feed["url"] == request.full_url)]
                )):
            refreshed = server.refresh_threat_indicator_feeds()
            self.assertEqual(refreshed["failedFeedCount"], 0)
            self.assertEqual(refreshed["feedCount"], 10)
            self.assertEqual(refreshed["indicatorCount"], 5)
            self.assertTrue(server.lookup_threat_indicators("MALICIOUS.EXAMPLE")["matched"])
            self.assertEqual(len(server.lookup_threat_indicators("d41d8cd98f00b204e9800998ecf8427e")["sources"]), 2)

            event = server.validate_zero_trust_event({
                "event_id": "feed-match-1",
                "event_type": "network.connection",
                "event_time": "2026-10-26T08:00:00Z",
                "source": {"system": "Test firewall"},
                "indicators": [{"type": "domain", "value": "malicious.example"}],
                "device": {"device_name": "ot-workstation-1"},
            })
            routing = server.save_integration_event(event)
            self.assertEqual(routing["category"], "threat")
            self.assertEqual(routing["modules"], ["integrations", "alerts"])
            alert = server.get_module_record("alerts", routing["record_id"])
            self.assertEqual(alert["device"]["device_name"], "ot-workstation-1")
            self.assertEqual(alert["event"]["threat_feed_matches"][0]["indicator"], "malicious.example")

            with patch.object(server.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")):
                failed_refresh = server.refresh_threat_indicator_feeds()
            self.assertEqual(failed_refresh["failedFeedCount"], 10)
            self.assertEqual(failed_refresh["indicatorCount"], 5)
            self.assertTrue(server.lookup_threat_indicators("malicious.example")["matched"])


class OsintNavigatorTests(unittest.TestCase):
    def test_catalogue_is_internally_consistent(self):
        payload = server.osint_framework_payload()
        self.assertEqual(payload["summary"]["techniques"], len(server.OSINT_TECHNIQUES))
        self.assertEqual(payload["summary"]["categories"], len(server.OSINT_CATEGORIES))
        self.assertEqual(
            payload["summary"]["runsLocally"] + payload["summary"]["manualProcedures"],
            payload["summary"]["techniques"],
        )
        identifiers = [technique["id"] for technique in payload["techniques"]]
        self.assertEqual(len(identifiers), len(set(identifiers)), "technique ids must be unique")
        for technique in server.OSINT_TECHNIQUES:
            self.assertIn(technique["category"], server.OSINT_CATEGORY_IDS)
            self.assertIn(technique["access"], server.OSINT_ACCESS_TIERS)
            for input_type in technique["inputs"]:
                self.assertIn(input_type, server.OSINT_INPUT_TYPES)
        self.assertEqual(
            sum(category["techniqueCount"] for category in payload["categories"]),
            payload["summary"]["techniques"],
        )

    def test_catalogue_carries_no_external_references(self):
        serialised = json.dumps(server.osint_framework_payload())
        for forbidden in ("http://", "https://", "www.", ".com", "github"):
            self.assertNotIn(forbidden, serialised.casefold())

    def test_observable_classification_covers_supported_types(self):
        cases = {
            "203.0.113.10": "ip",
            "plant.example.com": "domain",
            "d41d8cd98f00b204e9800998ecf8427e": "hash",
            "CVE-2024-21412": "cve",
            "operator@example.com": "email",
            "https://example.com/path": "url",
            "0x52908400098527886E0F7030069857D2E4169EE7": "crypto_address",
            "plant-operator": "username",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(server.detect_osint_input_type(value)[0], expected)
        with self.assertRaises(ValueError):
            server.detect_osint_input_type("")
        with self.assertRaises(ValueError):
            server.detect_osint_input_type("x" * 513)

    def test_search_filters_are_validated_and_applied(self):
        by_category = server.osint_search_payload(category="email-investigation")
        self.assertTrue(by_category["count"])
        self.assertTrue(all(item["category"] == "email-investigation" for item in by_category["techniques"]))

        by_input = server.osint_search_payload(input_type="cve")
        self.assertTrue(all("cve" in item["inputs"] for item in by_input["techniques"]))

        by_access = server.osint_search_payload(access="local")
        self.assertTrue(by_access["count"])
        self.assertTrue(all(item["runsLocally"] for item in by_access["techniques"]))

        self.assertLessEqual(
            server.osint_search_payload(query_text="certificate")["count"],
            server.osint_search_payload()["count"],
        )
        for bad in ({"category": "nope"}, {"input_type": "nope"}, {"access": "nope"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                server.osint_search_payload(**bad)

    def test_pivot_runs_only_local_checks_and_reports_feed_hits(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server, "THREAT_FEED_DB_FILE", Path(temp_dir) / "feeds.sqlite3"), \
                patch.object(server, "read_zero_trust_events", return_value=[]):
            connection = server.threat_feed_database()
            try:
                connection.execute(
                    "INSERT OR REPLACE INTO indicators (feed_id, feed_name, indicator_type, value, refreshed_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    ("test-feed", "Test feed", "ip", "203.0.113.10", "2026-10-27T00:00:00Z"),
                )
                connection.commit()
            finally:
                connection.close()

            hit = server.osint_pivot_payload({"value": "203.0.113.10"})
            self.assertEqual(hit["inputType"], "ip")
            feed_check = next(item for item in hit["enrichment"] if item["technique"] == "indicator-feed-correlation")
            self.assertTrue(feed_check["matched"])
            self.assertEqual(feed_check["sources"][0]["name"], "Test feed")
            self.assertTrue(all(technique["runsLocally"] or technique["access"] != "local" for technique in hit["techniques"]))
            self.assertEqual(hit["summary"]["localChecksRun"], len(hit["enrichment"]))

            miss = server.osint_pivot_payload({"value": "198.51.100.7"})
            miss_check = next(item for item in miss["enrichment"] if item["technique"] == "indicator-feed-correlation")
            self.assertFalse(miss_check["matched"])

            self.assertTrue(all(input_type in technique["inputs"] for technique in hit["techniques"] for input_type in ["ip"]))

        with self.assertRaises(ValueError):
            server.osint_pivot_payload({"value": ""})
        with self.assertRaises(ValueError):
            server.osint_pivot_payload("not-an-object")


class SiemEventIntegrationTests(unittest.TestCase):
    def test_dashboard_and_search_use_the_same_module_event_window(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server, "read_zero_trust_events", return_value=[]), \
                patch.object(server, "snort_attack_coverage", return_value={
                    "tactics": [], "tacticsCovered": 0, "tacticsTotal": 0,
                    "totalRules": 0, "explicitTechniqueRules": [], "method": "test",
                }), \
                patch.object(server, "get_threat_feed_status", return_value={
                    "indicatorCount": 0, "feedCount": 0, "lastSuccess": None, "feeds": [],
                }), \
                patch.object(server, "public_feed_payload", return_value={"sources": []}), \
                patch.object(server, "snort_engine_status_payload", return_value={"status": "not_installed"}), \
                patch.object(server, "load_integration_connectors", return_value=[]), \
                patch.object(server, "load_integration_feed_state", return_value={"rubrikApiEnabled": False}):
            server.write_json_store(server.MODULE_DATA_FILE, {
                "schema_version": 1,
                "modules": {
                    "integrations": [
                        {"id": f"event-{index}", "event_type": "network.connection"}
                        for index in range(1001)
                    ],
                },
            })

            dashboard = server.siem_dashboard_payload()
            search = server.siem_event_search_payload()

        self.assertEqual(dashboard["counts"]["events"], 1001)
        self.assertEqual(search["count"], dashboard["counts"]["events"])
        self.assertEqual(len(search["records"]), 100)

    def test_event_search_applies_source_severity_device_ioc_and_type_filters(self):
        records = [
            {
                "id": "attack-event",
                "event_type": "network.attack.detected",
                "source": {"system": "Sensor A"},
                "severity": "high",
                "routing": {"category": "threat", "modules": ["integrations", "alerts"]},
                "device": {"device_name": "plc-01"},
                "indicators": [{"type": "ip", "value": "203.0.113.20"}],
                "details": {"summary": "Suspicious connection"},
            },
            {
                "id": "routine-event",
                "event_type": "network.connection",
                "source": {"system": "Sensor B"},
                "severity": "low",
                "routing": {"category": "operational", "modules": ["integrations"]},
                "device": {"device_name": "plc-02"},
                "indicators": [{"type": "ip", "value": "203.0.113.21"}],
                "details": {"summary": "Routine connection"},
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(server, "MODULE_DATA_FILE", Path(temp_dir) / "modules.json"), \
                patch.object(server, "read_zero_trust_events", return_value=[]):
            server.write_json_store(server.MODULE_DATA_FILE, {
                "schema_version": 1,
                "modules": {"integrations": records},
            })
            result = server.siem_event_search_payload(
                'source:"Sensor A" severity:high device:plc-01 '
                'ioc:203.0.113.20 event_type:network.attack category:threat'
            )
            second_page = server.siem_event_search_payload("", limit=1, offset=1)

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["records"][0]["id"], "attack-event")
        self.assertEqual(result["filters"]["source"], "sensor a")
        self.assertEqual(result["records"][0]["category"], "threat")
        self.assertEqual(result["sourceOptions"], ["Rubrik Security Cloud", "Sensor A", "Sensor B"])
        self.assertEqual(second_page["records"][0]["id"], "routine-event")


class IntelCorrelationTests(unittest.TestCase):
    INDEX = {
        "kev": {"CVE-2021-44228": {"cve": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j2",
                                   "name": "Log4Shell", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                                   "knownRansomware": True}},
        "c2": {"198.51.100.7": {"ip": "198.51.100.7", "malware": "Emotet", "port": 8080,
                                 "firstSeen": None, "lastOnline": None, "status": "online"}},
        "errors": {},
        "builtAt": "2026-01-01T00:00:00+00:00",
    }

    def test_matches_kev_and_c2_and_ignores_invalid_input(self):
        with patch.object(server, "build_intel_match_index", return_value=self.INDEX), \
             patch.object(server, "fetch_epss_scores", return_value={"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}}):
            result = server.intel_correlation_payload({
                "cves": ["CVE-2021-44228", "CVE-2000-1111", "not-a-cve", ""],
                "ips": ["198.51.100.7", "8.8.8.8", "not-an-ip"],
            })
        self.assertEqual(result["submitted"], {"cves": 2, "ips": 2})
        self.assertEqual(result["summary"]["kevMatches"], 1)
        self.assertEqual(result["summary"]["ransomwareLinked"], 1)
        self.assertEqual(result["summary"]["c2Matches"], 1)
        self.assertEqual(result["kevMatches"][0]["epss"], 0.97)
        self.assertEqual(result["c2Matches"][0]["malware"], "Emotet")

    def test_rejects_non_list_and_oversized_payloads(self):
        with self.assertRaises(ValueError):
            server.intel_correlation_payload({"cves": "CVE-2021-44228", "ips": []})
        with self.assertRaises(ValueError):
            server.intel_correlation_payload({"cves": ["CVE-2021-44228"] * (server.MAX_CORRELATE_ITEMS + 1), "ips": []})
        with self.assertRaises(ValueError):
            server.intel_correlation_payload("nope")


class SnortAttackCoverageTests(unittest.TestCase):
    CATALOG = {"records": [
        {"sid": 1, "enabled": True, "message": "SERVER-WEBAPP Apache Log4j RCE attempt",
         "rule": 'alert tcp any any -> any any (msg:"SERVER-WEBAPP Log4j"; classtype:attempted-admin; sid:1;)'},
        {"sid": 2, "enabled": True, "message": "MALWARE-CNC Emotet outbound beacon",
         "rule": 'alert tcp any any -> any any (msg:"MALWARE-CNC Emotet"; classtype:trojan-activity; sid:2;)'},
        {"sid": 3, "enabled": False, "message": "MALWARE-CNC disabled beacon",
         "rule": 'alert tcp any any -> any any (msg:"MALWARE-CNC old"; classtype:trojan-activity; sid:3;)'},
        {"sid": 4, "enabled": True, "message": "Brute force login T1110 observed",
         "rule": 'alert tcp any any -> any any (msg:"T1110 brute force"; classtype:attempted-recon; sid:4;)'},
        {"sid": 5, "enabled": True, "message": "totally unclassifiable marketing banner",
         "rule": 'alert tcp any any -> any any (msg:"nothing"; sid:5;)'},
    ]}

    def setUp(self):
        server.attack_coverage_cache.update({"fingerprint": None, "payload": None})

    def tearDown(self):
        server.attack_coverage_cache.update({"fingerprint": None, "payload": None})

    def test_maps_categories_classtypes_and_explicit_techniques(self):
        with patch.object(server, "current_snort_catalog", return_value=self.CATALOG):
            coverage = server.snort_attack_coverage()
        self.assertEqual(coverage["totalRules"], 5)
        self.assertIn("T1110", coverage["explicitTechniqueRules"])
        self.assertEqual(coverage["tacticsTotal"], len(server.ATTACK_TACTICS))
        by_id = {row["tacticId"]: row for row in coverage["tactics"]}
        self.assertTrue(by_id["TA0001"]["covered"])
        self.assertTrue(by_id["TA0011"]["covered"])
        self.assertEqual(by_id["TA0011"]["enabledCount"], 1)
        self.assertEqual(by_id["TA0011"]["ruleCount"], 2)
        self.assertGreaterEqual(coverage["unmappedRules"], 1)

    def test_handles_list_catalog_and_missing_catalog(self):
        with patch.object(server, "current_snort_catalog", return_value=self.CATALOG["records"]):
            self.assertEqual(server.snort_attack_coverage()["totalRules"], 5)
        server.attack_coverage_cache.update({"fingerprint": None, "payload": None})
        with patch.object(server, "current_snort_catalog", side_effect=RuntimeError("no catalogue")):
            empty = server.snort_attack_coverage()
        self.assertEqual(empty["totalRules"], 0)
        self.assertEqual(empty["tacticsCovered"], 0)


class OffsecAttackPathTests(unittest.TestCase):
    INDEX = {
        "kev": {
            "CVE-2021-44228": {"cve": "CVE-2021-44228", "name": "Log4Shell", "knownRansomware": True},
            "CVE-2020-0796": {"cve": "CVE-2020-0796", "name": "SMBGhost", "knownRansomware": False},
        },
        "c2": {"198.51.100.7": {"ip": "198.51.100.7", "malware": "Emotet", "port": 8080}},
        "errors": {}, "builtAt": "2026-01-01T00:00:00+00:00",
    }
    EPSS = {"CVE-2021-44228": {"epss": 1.0, "percentile": 0.99}, "CVE-2020-0796": {"epss": 0.5, "percentile": 0.9}}

    def _run(self, assets):
        with patch.object(server, "build_intel_match_index", return_value=self.INDEX), \
             patch.object(server, "fetch_epss_scores", return_value=self.EPSS):
            return server.offsec_attack_paths_payload({"assets": assets})

    def test_scores_reachable_ransomware_asset_above_offline_asset(self):
        result = self._run([
            {"id": "hmi-1", "name": "HMI Line 3", "online": True, "riskScore": 100,
             "cves": ["CVE-2021-44228", "CVE-2020-0796"], "ips": ["198.51.100.7"]},
            {"id": "plc-1", "name": "PLC West", "online": False, "riskScore": 10,
             "cves": ["CVE-2020-0796"], "ips": []},
        ])
        self.assertEqual(result["assetsSubmitted"], 2)
        self.assertEqual(result["assetsWithPath"], 2)
        hmi, plc = result["paths"][0], result["paths"][1]
        self.assertEqual(hmi["assetId"], "hmi-1")
        self.assertEqual(hmi["band"], "Critical")
        self.assertEqual(hmi["ransomwareCves"], ["CVE-2021-44228"])
        self.assertEqual(hmi["c2Addresses"], ["198.51.100.7"])
        self.assertGreater(hmi["score"], plc["score"])
        self.assertEqual(plc["scoring"]["reachability"], 0)
        self.assertEqual(plc["scoring"]["ransomware"], 0)
        self.assertEqual(result["kpis"]["ransomwareExposedAssets"], 1)
        self.assertEqual(result["kpis"]["c2LinkedAssets"], 1)
        self.assertIn("TA0040", [stage["tacticId"] for stage in hmi["stages"]])

    def test_excludes_assets_without_kev_and_rejects_bad_payloads(self):
        result = self._run([
            {"id": "printer", "name": "Printer", "online": True, "cves": ["CVE-1999-9999", "junk"], "ips": ["bad-ip"]},
        ])
        self.assertEqual(result["assetsSubmitted"], 1)
        self.assertEqual(result["assetsWithPath"], 0)
        self.assertEqual(result["kpis"]["maxScore"], 0)
        with self.assertRaises(ValueError):
            server.offsec_attack_paths_payload({"assets": "nope"})
        with self.assertRaises(ValueError):
            server.offsec_attack_paths_payload({"assets": [{}] * (server.MAX_CORRELATE_ITEMS + 1)})
        with self.assertRaises(ValueError):
            server.offsec_attack_paths_payload("nope")


class OffsecPurpleTeamTests(unittest.TestCase):
    COVERAGE = {
        "totalRules": 4, "unmappedRules": 0, "explicitTechniqueRules": ["T1110"],
        "tacticsCovered": 2, "tacticsTotal": 2, "coveragePercent": 100.0,
        "tactics": [
            {"tacticId": "TA0001", "tactic": "Initial Access", "ruleCount": 3, "enabledCount": 3,
             "techniqueIds": [], "covered": True, "sampleRules": []},
            {"tacticId": "TA0006", "tactic": "Credential Access", "ruleCount": 1, "enabledCount": 1,
             "techniqueIds": ["T1110"], "covered": True, "sampleRules": []},
        ],
        "method": "test",
    }

    def _run(self, techniques):
        with patch.object(server, "snort_attack_coverage", return_value=self.COVERAGE):
            return server.offsec_purple_team_payload({"techniques": techniques})

    def test_separates_technique_rules_tactic_rules_and_gaps(self):
        result = self._run(["T1110", "T1190", "T1190", "T9999"])
        self.assertEqual(result["techniquesObserved"], 3)
        rows = {row["techniqueId"]: row for row in result["techniques"]}
        self.assertEqual(rows["T1110"]["status"], "technique_rule")
        self.assertEqual(rows["T1190"]["status"], "tactic_rules")
        self.assertEqual(rows["T1190"]["occurrences"], 2)
        self.assertEqual(rows["T9999"]["status"], "unmapped")
        self.assertEqual(result["kpis"]["techniqueLevelCoverage"], 1)
        self.assertEqual(result["kpis"]["tacticLevelCoverage"], 1)
        self.assertEqual(result["kpis"]["detectionGaps"], 1)

    def test_rejects_bad_payloads(self):
        with self.assertRaises(ValueError):
            server.offsec_purple_team_payload({"techniques": "T1110"})
        with self.assertRaises(ValueError):
            server.offsec_purple_team_payload({"techniques": ["T1110"] * (server.MAX_CORRELATE_ITEMS + 1)})
        with self.assertRaises(ValueError):
            server.offsec_purple_team_payload("nope")


class SecurityAssessmentTests(unittest.TestCase):
    COVERAGE = {
        "totalRules": 14, "tacticsCovered": 2, "tacticsTotal": 14,
    }

    def methodology(self, configured):
        with patch.object(server, "load_integration_credential_store", return_value=configured), \
             patch.object(server, "claroty_credentials_status", return_value={"configured": True}), \
             patch.object(server, "snort_attack_coverage", return_value=self.COVERAGE), \
             patch.object(server, "current_openappid_catalog", return_value=None):
            return server.offsec_methodology_payload()

    def test_connector_is_not_evidence_and_validation_is_not_inferred(self):
        result = self.methodology({"rubrik": {"baseUrl": "configured"}})
        domains = {item["domainId"]: item for item in result["domains"]}
        supply = domains["supply-chain"]
        self.assertIn("rubrik", supply["connectorsConfigured"])
        self.assertEqual(supply["evidenceStatus"], "NO_LOCAL_EVIDENCE")
        self.assertIsNone(supply["evidenceCount"])
        self.assertIsNone(supply["lastEvidenceAt"])
        self.assertEqual(supply["validationStatus"], "PENDING")
        self.assertEqual(domains["identity-ad"]["assessmentStatus"], "ASSESSMENT_PENDING")
        self.assertEqual(domains["network-security"]["evidenceStatus"], "PARTIALLY_EVIDENCED")
        self.assertEqual(domains["network-security"]["evidenceCount"], 14)
        self.assertEqual(domains["network-security"]["validationStatus"], "NOT_VALIDATED")
        self.assertEqual(result["kpis"]["domainsWithEvidence"], 3)
        summary = server.security_assessment_summary(result)
        self.assertEqual(summary["domainsPending"], 7)
        self.assertEqual(summary["domainsValidated"], 0)
        self.assertEqual(summary["domainsPassiveOnly"], 3)
        self.assertIsNone(summary["activeTestingCoveragePercentage"])
        self.assertEqual(len(summary["deferredKpis"]), 7)
        self.assertTrue(all(item["value"] is None and item["status"] == "DEFERRED"
                            for item in summary["deferredKpis"]))

    def test_missing_catalog_does_not_create_evidence(self):
        with patch.object(server, "load_integration_credential_store", return_value={}), \
             patch.object(server, "claroty_credentials_status", return_value={"configured": False}), \
             patch.object(server, "snort_attack_coverage", return_value={**self.COVERAGE, "totalRules": 0}), \
             patch.object(server, "current_openappid_catalog", return_value=None):
            result = server.offsec_methodology_payload()
        self.assertEqual(result["kpis"]["domainsWithEvidence"], 0)

    def test_testing_request_is_persistent_but_never_authorizes(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(server, "ASSESSMENT_REQUESTS_FILE", Path(temp) / "requests.json"):
                request = {
                    "testType": "AUTHORIZED_ACTIVE_TEST", "scope": "Identity authentication",
                    "authorizationReference": "CHG00012345", "requestedBy": "security-team",
                    "scheduledStart": "2026-10-28T08:00:00Z",
                }
                record = server.request_assessment_testing("identity-ad", request)
                self.assertEqual(record["status"], "REQUESTED")
                self.assertFalse(record["authorizationVerified"])
                self.assertEqual(record["validationStatus"], "PENDING")
                self.assertEqual(server.assessment_requests()[0]["id"], record["id"])
                domain = next(item for item in self.methodology({})["domains"]
                              if item["domainId"] == "identity-ad")
                detail = server.security_assessment_domain_detail(domain)
                self.assertEqual(detail["testingRequests"][0]["status"], "REQUESTED")
                self.assertEqual(detail["validation"]["status"], "PENDING")
                with self.assertRaises(ValueError):
                    server.request_assessment_testing("identity-ad", {**request, "status": "VALIDATED"})
                with self.assertRaises(ValueError):
                    server.request_assessment_testing("identity-ad", {**request, "scheduledStart": "tomorrow"})
                with self.assertRaises(ValueError):
                    server.request_assessment_testing("identity-ad", {**request, "scheduledStart": "2026-10-28T08:00:00"})
                with self.assertRaises(KeyError):
                    server.request_assessment_testing("unknown-domain", request)
                self.assertEqual(len(server.assessment_requests()), 1)
