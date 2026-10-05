import unittest
import json
import os
from unittest.mock import MagicMock
from dynamic_analysis.rules import InsecureHttpSensitiveHeaderRule
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.rules import FindingSeverity, FindingCategory

class TestHttpSensitiveHeaderRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureHttpSensitiveHeaderRule()
        self.session = AnalysisSession(apk_path="test.apk")
        self.session.output_dir = "/tmp/test_session"

    def _create_http_evidence(self, url: str, headers: dict) -> EvidenceItem:
        content = {
            "url": url,
            "method": "GET",
            "request_headers": headers
        }
        return EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=1234567890.0,
            serial="test_serial"
        )

    def test_sensitive_headers_over_http(self):
        # 1-6. Authorization, Proxy-Authorization, X-API-Key, X-Auth-Token, X-Access-Token, X-Client-Secret
        test_headers = [
            ("Authorization", "Bearer abc123456789"),
            ("Proxy-Authorization", "Basic xyz987654321"),
            ("X-API-Key", "apikey_123"),
            ("X-Auth-Token", "token_123"),
            ("X-Access-Token", "access_123"),
            ("X-Client-Secret", "secret_123")
        ]

        for header_name, header_val in test_headers:
            with self.subTest(header=header_name):
                ev = self._create_http_evidence(
                    url="http://example.com/api",
                    headers={header_name: header_val, "Host": "example.com"}
                )
                result = self.rule.evaluate(self.session, [ev])
                self.assertTrue(result.triggered)
                self.assertEqual(len(result.findings), 1)
                finding = result.findings[0]
                self.assertEqual(finding.severity, FindingSeverity.HIGH)
                self.assertEqual(finding.category, FindingCategory.NETWORK)
                self.assertIn(header_name.lower(), finding.description)
                # 17. Redaction check
                self.assertIn(f"{header_val[:3]}...<redacted>", finding.description)
                self.assertNotIn(header_val, finding.description)
                self.assertIn("example.com", finding.description)

    def test_https_evidence_no_finding(self):
        # 7. HTTPS evidence -> no finding
        content = {
            "url": "https://example.com/api",
            "method": "GET",
            "request_headers": {"Authorization": "Bearer abc123456789"}
        }
        ev = EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=1234567890.0,
            serial="test_serial"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_generic_token_text_no_finding(self):
        # 8. Generic "token" text -> no finding
        ev = self._create_http_evidence(
            url="http://example.com/api",
            headers={"Custom-Token": "abc", "Some-Authorization-Field": "123"}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_empty_header_value(self):
        # 9. Empty header value -> no finding
        ev = self._create_http_evidence(
            url="http://example.com/api",
            headers={"Authorization": "", "X-API-Key": "   "}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_missing_request_headers(self):
        # 10. Missing request headers -> no finding
        content = {
            "url": "http://example.com/api",
            "method": "GET"
        }
        ev = EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=1234567890.0,
            serial="test_serial"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_malformed_json(self):
        # 11. Malformed JSON -> no finding
        ev = EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content="NOT JSON",
            timestamp=1234567890.0,
            serial="test_serial"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_case_insensitive_header_names(self):
        # 12. Case-insensitive header names
        ev = self._create_http_evidence(
            url="http://example.com/api",
            headers={"aUtHoRiZaTiOn": "Bearer abc123456789"}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_multiple_sensitive_headers(self):
        # 13. Multiple sensitive headers
        ev = self._create_http_evidence(
            url="http://example.com/api",
            headers={
                "Authorization": "Bearer abc",
                "X-API-Key": "xyz"
            }
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        descriptions = [f.description for f in result.findings]
        self.assertTrue(any("authorization" in d for d in descriptions))
        self.assertTrue(any("x-api-key" in d for d in descriptions))

    def test_duplicate_evidence_deduplication(self):
        # 15. Duplicate evidence deduplication
        ev1 = self._create_http_evidence(
            url="http://example.com/api/1",
            headers={"Authorization": "Bearer abc"}
        )
        ev2 = self._create_http_evidence(
            url="http://example.com/api/2",
            headers={"Authorization": "Bearer def"}
        )
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        # Should deduplicate on (host, header_name) -> ("example.com", "authorization")
        self.assertEqual(len(result.findings), 1)

    def test_evidence_references_preserved(self):
        # 18. Evidence references are preserved
        ev = self._create_http_evidence(
            url="http://example.com/api",
            headers={"Authorization": "Bearer abc"}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertIn("evidence_1234567890.0_mitmproxy", result.evidence_references)
        self.assertIn("evidence_1234567890.0_mitmproxy", result.findings[0].evidence_references)

if __name__ == '__main__':
    unittest.main()
