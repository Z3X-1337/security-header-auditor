import unittest

from security_header_auditor import audit_headers


class SecurityHeaderAuditorTests(unittest.TestCase):
    def test_audit_headers_scores_present_headers(self):
        report = audit_headers(
            {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
            }
        )
        self.assertEqual(report["score"], 2)
        self.assertTrue(report["results"]["strict-transport-security"]["present"])
        self.assertFalse(report["results"]["content-security-policy"]["present"])


if __name__ == "__main__":
    unittest.main()
