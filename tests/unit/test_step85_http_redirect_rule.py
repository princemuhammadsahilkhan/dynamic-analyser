import unittest
import json
import time
from dynamic_analysis.rules import InsecureHttpRedirectRule
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestHttpRedirectRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureHttpRedirectRule()
        self.session = AnalysisSession(apk_path="test.apk")

    def _create_http_evidence(self, url: str, response_headers: dict) -> EvidenceItem:
        content = {
            "url": url,
            "method": "GET",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "response_headers": response_headers
            }
        }
        return EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=time.time(),
            serial="test_serial"
        )
        
    def _create_https_evidence(self, url: str, response_headers: dict) -> EvidenceItem:
        content = {
            "url": url,
            "method": "GET",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "response_headers": response_headers
            }
        }
        return EvidenceItem(
            source="mitmproxy",
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=time.time(),
            serial="test_serial"
        )

    def test_https_redirects_to_http(self):
        ev = self._create_https_evidence("https://example.com", {"Location": "http://example.com/login"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)
        finding = res.findings[0]
        self.assertEqual(finding.severity.value, "HIGH")
        self.assertIn("http://example.com/login", finding.description)
        self.assertIn("Destination Host: example.com", finding.description)

    def test_http_redirects_to_http(self):
        ev = self._create_http_evidence("http://example.com", {"Location": "http://example.com/login"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)

    def test_https_redirects_to_https(self):
        ev = self._create_https_evidence("https://example.com", {"Location": "https://example.com/login"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_missing_location(self):
        ev = self._create_http_evidence("http://example.com", {"X-Custom": "http://test.com"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_empty_location(self):
        ev = self._create_http_evidence("http://example.com", {"Location": ""})
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_missing_response_headers(self):
        content = {
            "url": "http://example.com",
            "raw_metadata": {}
        }
        ev = EvidenceItem(source="mitmproxy", evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content), timestamp=time.time(), serial="test")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_null_response_headers(self):
        content = {
            "url": "http://example.com",
            "raw_metadata": {"response_headers": None}
        }
        ev = EvidenceItem(source="mitmproxy", evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content), timestamp=time.time(), serial="test")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_malformed_json(self):
        ev = EvidenceItem(source="mitmproxy", evidence_type=EvidenceType.HTTP_TRAFFIC.value, content="{malformed", timestamp=time.time(), serial="test")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_case_insensitive_location(self):
        ev = self._create_http_evidence("http://example.com", {"lOcAtIoN": "http://example.com/abc"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)

    def test_multiple_location_values(self):
        ev = self._create_http_evidence("http://example.com", {"Location": ["https://example.com", "http://insecure.com"]})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        self.assertIn("insecure.com", res.findings[0].description)

    def test_deduplication(self):
        ev1 = self._create_http_evidence("http://example.com", {"Location": "http://example.com/login"})
        ev2 = self._create_http_evidence("http://example.com/a", {"Location": "http://example.com/login2"})
        res = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)

    def test_query_string_redaction(self):
        ev = self._create_http_evidence("http://example.com", {"Location": "http://example.com/login?token=secret123&foo=bar"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        finding = res.findings[0]
        self.assertIn("http://example.com/login?<redacted>", finding.description)
        self.assertNotIn("secret123", finding.description)
        
    def test_fragment_redaction(self):
        ev = self._create_http_evidence("http://example.com", {"Location": "http://example.com/login#token=secret123"})
        res = self.rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        finding = res.findings[0]
        self.assertIn("http://example.com/login?<redacted>", finding.description)
        self.assertNotIn("secret123", finding.description)

    def test_generic_url_without_location(self):
        content = {
            "url": "http://example.com",
            "request_headers": {"Location": "http://example.com"},
            "raw_metadata": {"response_headers": {"Host": "example.com"}}
        }
        ev = EvidenceItem(source="mitmproxy", evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content), timestamp=time.time(), serial="test")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)

    def test_malformed_location_value(self):
        # Even with malformed, urlparse will not raise exception but scheme will likely not be 'http'
        # if it is malformed in a way that urlparse doesn't see 'http://'
        ev = self._create_http_evidence("http://example.com", {"Location": "http://[invalid_host_here"})
        res = self.rule.evaluate(self.session, [ev])
        # Depending on urlparse, it might say scheme is http. 
        # But we don't care if it's malformed as long as it parses out http or not.
        # So we just ensure it doesn't crash.

if __name__ == '__main__':
    unittest.main()
