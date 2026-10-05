import unittest
import json
import time
from dynamic_analysis.rules import InsecureHttpBasicAuthRule
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestInsecureHttpBasicAuthRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureHttpBasicAuthRule()
        self.session = AnalysisSession(apk_path="test.apk")

    def _create_http_evidence(self, url: str, request_headers: dict) -> EvidenceItem:
        content = {
            "url": url,
            "method": "GET",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "request_headers": request_headers
            }
        }
        return EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=time.time(),
            serial="test_serial"
        )
        
    def _create_https_evidence(self, url: str, request_headers: dict) -> EvidenceItem:
        content = {
            "url": url,
            "method": "GET",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "request_headers": request_headers
            }
        }
        return EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=time.time(),
            serial="test_serial"
        )

    def test_http_basic_auth(self):
        ev = self._create_http_evidence("http://example.com", {"Authorization": "Basic dGVzdDp0ZXN0"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)
        finding = res.findings[0]
        self.assertEqual(finding.severity.value, "CRITICAL")
        self.assertIn("Basic Authentication credentials sent over unencrypted HTTP", finding.description)
        self.assertIn("Payload: Basic <redacted>", finding.description)
        self.assertNotIn("dGVzdDp0ZXN0", finding.description)

    def test_https_basic_auth(self):
        ev = self._create_https_evidence("https://example.com", {"Authorization": "Basic dGVzdDp0ZXN0"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_case_insensitive_header_name(self):
        ev = self._create_http_evidence("http://example.com", {"aUtHoRiZaTiOn": "Basic dGVzdDp0ZXN0"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)

    def test_case_insensitive_header_value(self):
        ev = self._create_http_evidence("http://example.com", {"Authorization": "bAsIc dGVzdDp0ZXN0"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)

    def test_bearer_auth(self):
        ev = self._create_http_evidence("http://example.com", {"Authorization": "Bearer token123"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_missing_authorization(self):
        ev = self._create_http_evidence("http://example.com", {"Host": "example.com"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_empty_authorization(self):
        ev = self._create_http_evidence("http://example.com", {"Authorization": ""})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_multiple_authorization_headers(self):
        ev = self._create_http_evidence("http://example.com", {"Authorization": ["Bearer token", "Basic dGVzdDp0ZXN0"]})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)

    def test_deduplication(self):
        ev1 = self._create_http_evidence("http://example.com/a", {"Authorization": "Basic dGVzdDp0ZXN0"})
        ev2 = self._create_http_evidence("http://example.com/b", {"Authorization": "Basic dGVzdDp0ZXN0"})
        res = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)

    def test_malformed_json(self):
        ev = EvidenceItem(source="mitmproxy", evidence_type=EvidenceType.HTTP_TRAFFIC.value, content="{malformed", timestamp=time.time(), serial="test")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_missing_request_headers(self):
        content = {
            "url": "http://example.com",
            "raw_metadata": {}
        }
        ev = EvidenceItem(source="mitmproxy", evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content), timestamp=time.time(), serial="test")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

if __name__ == '__main__':
    unittest.main()
