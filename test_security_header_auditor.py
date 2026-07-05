import json
import subprocess
import sys
import unittest

from security_header_auditor import audit_headers, normalize_headers, validate_url


class SecurityHeaderAuditorTests(unittest.TestCase):
    def test_normalize_headers_is_case_insensitive(self):
        headers = normalize_headers({"Strict-Transport-Security": " max-age=31536000 "})
        self.assertEqual(headers["strict-transport-security"], "max-age=31536000")

    def test_audit_scores_strong_headers(self):
        report = audit_headers(
            {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )

        self.assertEqual(report["score"], 100)
        self.assertEqual(report["summary"]["strong"], 6)
        self.assertTrue(all(finding["present"] for finding in report["findings"]))

    def test_missing_headers_are_reported(self):
        report = audit_headers({})
        self.assertEqual(report["score"], 0)
        self.assertEqual(report["summary"]["missing"], 6)
        self.assertEqual(report["findings"][0]["status"], "missing")

    def test_weak_hsts_is_marked_weak(self):
        report = audit_headers({"Strict-Transport-Security": "max-age=300"})
        hsts = next(finding for finding in report["findings"] if finding["header"] == "strict-transport-security")
        self.assertEqual(hsts["status"], "weak")

    def test_csp_unsafe_inline_requires_review(self):
        report = audit_headers({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"})
        csp = next(finding for finding in report["findings"] if finding["header"] == "content-security-policy")
        self.assertEqual(csp["status"], "review")

    def test_validate_url_rejects_missing_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("example.com")

    def test_cli_help_exits_successfully(self):
        result = subprocess.run(
            [sys.executable, "security_header_auditor.py", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("Audit common HTTP security headers", result.stdout)

    def test_audit_output_is_json_serializable(self):
        payload = audit_headers({"X-Content-Type-Options": "nosniff"})
        encoded = json.dumps(payload)
        self.assertIn("x-content-type-options", encoded)


if __name__ == "__main__":
    unittest.main()
