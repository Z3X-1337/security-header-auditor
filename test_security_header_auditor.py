import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from security_header_auditor import (
    audit_headers,
    build_report,
    determine_exit_code,
    fetch_target,
    normalize_headers,
    parse_csp,
    validate_url,
)


class TestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A003
        return

    def do_HEAD(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/head-rejected":
            self.send_response(405)
            self.end_headers()
            return
        self._send_final()

    def do_GET(self):
        self._send_final()

    def _send_final(self):
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        self.end_headers()


class SecurityHeaderAuditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_normalize_headers_is_case_insensitive(self):
        headers = normalize_headers({"Strict-Transport-Security": " max-age=31536000 "})
        self.assertEqual(headers["strict-transport-security"], "max-age=31536000")

    def test_parse_csp_directives(self):
        directives = parse_csp("default-src 'self'; object-src 'none'")
        self.assertEqual(directives["default-src"], ["'self'"])
        self.assertEqual(directives["object-src"], ["'none'"])

    def test_audit_scores_strong_headers(self):
        report = audit_headers(
            {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )
        self.assertEqual(report["score"], 100)
        self.assertEqual(report["summary"]["strong"], 6)

    def test_missing_headers_are_reported(self):
        report = audit_headers({})
        self.assertEqual(report["score"], 0)
        self.assertEqual(report["summary"]["missing"], 6)

    def test_weak_hsts_is_marked_weak(self):
        report = audit_headers({"Strict-Transport-Security": "max-age=300"})
        hsts = next(finding for finding in report["findings"] if finding["header"] == "strict-transport-security")
        self.assertEqual(hsts["status"], "weak")

    def test_csp_unsafe_inline_requires_review(self):
        report = audit_headers(
            {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"}
        )
        csp = next(finding for finding in report["findings"] if finding["header"] == "content-security-policy")
        self.assertEqual(csp["status"], "review")
        self.assertIn("unsafe-inline", " ".join(csp["observations"]))

    def test_csp_without_default_or_script_source_is_weak(self):
        report = audit_headers({"Content-Security-Policy": "img-src 'self'"})
        csp = next(finding for finding in report["findings"] if finding["header"] == "content-security-policy")
        self.assertEqual(csp["status"], "weak")

    def test_referrer_policy_baseline_requires_review(self):
        report = audit_headers({"Referrer-Policy": "unsafe-url"})
        finding = next(item for item in report["findings"] if item["header"] == "referrer-policy")
        self.assertEqual(finding["status"], "review")

    def test_validate_url_rejects_missing_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("example.com")

    def test_validate_url_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            validate_url("https://user:pass@example.com")

    def test_redirect_chain_is_recorded(self):
        result = fetch_target(f"{self.base_url}/redirect")
        self.assertEqual(result.final_url, f"{self.base_url}/final")
        self.assertEqual(len(result.redirects), 1)
        self.assertEqual(result.redirects[0].status_code, 302)

    def test_head_rejection_falls_back_to_get(self):
        result = fetch_target(f"{self.base_url}/head-rejected")
        self.assertEqual(result.request_method, "GET")
        self.assertEqual(result.headers["X-Content-Type-Options"], "nosniff")

    def test_build_report_warns_for_http(self):
        report = build_report(fetch_target(f"{self.base_url}/final"))
        self.assertTrue(any("uses HTTP" in warning for warning in report["warnings"]))
        self.assertEqual(report["schema_version"], "1.1")

    def test_determine_exit_code_uses_score_threshold(self):
        report = {"score": 60}
        self.assertEqual(determine_exit_code(report, 60), 0)
        self.assertEqual(determine_exit_code(report, 61), 1)
        with self.assertRaises(ValueError):
            determine_exit_code(report, 101)

    def test_cli_help_exits_successfully(self):
        result = subprocess.run(
            [sys.executable, "security_header_auditor.py", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("Audit common HTTP security headers", result.stdout)
        self.assertIn("--fail-under", result.stdout)

    def test_audit_output_is_json_serializable(self):
        payload = audit_headers({"X-Content-Type-Options": "nosniff"})
        encoded = json.dumps(payload)
        self.assertIn("x-content-type-options", encoded)


if __name__ == "__main__":
    unittest.main()
