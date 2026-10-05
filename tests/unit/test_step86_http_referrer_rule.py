import unittest
import json
from unittest.mock import MagicMock
from dynamic_analysis.rules import InsecureHttpReferrerRule
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.finding import FindingSeverity, FindingCategory

class TestInsecureHttpReferrerRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureHttpReferrerRule()
        self.session = MagicMock()
        self.session.analysis_id = "test-session-123"

    def _create_evidence(self, referer_value, evidence_type=EvidenceType.HTTP_TRAFFIC, host="example.com", missing_headers=False, malformed_json=False):
        if malformed_json:
            content = "{ malformed "
        else:
            raw_metadata = {}
            if not missing_headers:
                if referer_value is not None:
                    raw_metadata["request_headers"] = {"Referer": referer_value}
                else:
                    raw_metadata["request_headers"] = {}

            data = {
                "host": host,
                "raw_metadata": raw_metadata
            }
            content = json.dumps(data)

        return EvidenceItem(
            evidence_type=evidence_type.value,
            content=content,
            source="mitmproxy",
            timestamp="1234567890.0",
            serial="test_serial"
        )
        
    def _create_custom_evidence(self, req_headers, evidence_type=EvidenceType.HTTP_TRAFFIC, host="example.com"):
        data = {
            "host": host,
            "raw_metadata": {
                "request_headers": req_headers
            }
        }
        content = json.dumps(data)
        return EvidenceItem(
            evidence_type=evidence_type.value,
            content=content,
            source="mitmproxy",
            timestamp="1234567890.0",
            serial="test_serial"
        )

    def test_sensitive_token_in_referer_http(self):
        ev = self._create_evidence("http://example.com/page?token=supersecret123")
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "Insecure HTTP Referrer Information Observed")
        self.assertIn("Host: example.com", finding.description)
        self.assertIn("Parameter: token", finding.description)
        self.assertIn("Value: <redacted>", finding.description)
        self.assertNotIn("supersecret123", finding.description)

    def test_password_in_referer_http(self):
        ev = self._create_evidence("http://example.com/page?password=mypassword")
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertIn("Parameter: password", finding.description)
        self.assertIn("Value: <redacted>", finding.description)
        self.assertNotIn("mypassword", finding.description)

    def test_api_key_in_referer(self):
        ev = self._create_evidence("http://example.com/page?api_key=apikey123")
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertIn("Parameter: api_key", finding.description)

    def test_multiple_sensitive_parameters(self):
        ev = self._create_evidence("http://example.com/page?token=tok&password=pass")
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        params = [f.description for f in result.findings]
        self.assertTrue(any("Parameter: token" in p for p in params))
        self.assertTrue(any("Parameter: password" in p for p in params))

    def test_https_evidence_no_finding(self):
        ev = self._create_evidence("http://example.com/page?token=secret", evidence_type=EvidenceType.HTTPS_TRAFFIC)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_normal_referer_url(self):
        ev = self._create_evidence("http://example.com/page?id=123&sort=asc")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_missing_referer(self):
        ev = self._create_evidence(None)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_empty_referer(self):
        ev = self._create_evidence("   ")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_missing_request_headers(self):
        ev = self._create_evidence("http://example.com/page?token=123", missing_headers=True)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_malformed_json(self):
        ev = self._create_evidence("http://example.com/page?token=123", malformed_json=True)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_case_insensitive_referer_header(self):
        ev = self._create_custom_evidence({"reFeReR": "http://example.com/page?token=secret"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_case_insensitive_sensitive_parameter_names(self):
        ev = self._create_evidence("http://example.com/page?ToKeN=secret")
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_empty_sensitive_parameter_value(self):
        ev = self._create_evidence("http://example.com/page?token=  ")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_deterministic_deduplication(self):
        ev1 = self._create_evidence("http://example.com/page?token=secret1")
        ev2 = self._create_evidence("http://example.com/page?token=secret2")
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.evidence_references), 1)

    def test_sensitive_value_redacted_and_never_in_description(self):
        ev = self._create_evidence("http://example.com/page?api_key=my_super_secret_key_12345")
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        finding = result.findings[0]
        self.assertIn("<redacted>", finding.description)
        self.assertNotIn("my_super_secret_key_12345", finding.description)

if __name__ == '__main__':
    unittest.main()
