import json
import unittest
from dynamic_analysis.rules import (
    InsecureHttpCookieTransmissionRule,
    EvidenceItem,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    FindingConfidence,
    AnalysisSession
)

class TestStep80HttpCookieRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="fake.apk",
            base_output_dir="/tmp/fake",
            package_name="com.example.app"
        )
        self.rule = InsecureHttpCookieTransmissionRule()

    def create_network_evidence(self, content: str, protocol: str = "HTTP") -> EvidenceItem:
        ev_type = EvidenceType.HTTP_TRAFFIC.value if protocol == "HTTP" else EvidenceType.HTTPS_TRAFFIC.value
        return EvidenceItem(
            evidence_type=ev_type,
            content=content,
            timestamp=12345.0,
            source="proxy",
            serial="test_serial"
        )

    def test_cookie_header_over_http(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Cookie": "sessionid=abc123456"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("sessionid", result.findings[0].title)
        self.assertIn("abc...<redacted>", result.findings[0].description)
        self.assertEqual(result.findings[0].severity, FindingSeverity.HIGH)
        self.assertEqual(result.findings[0].category, FindingCategory.NETWORK)

    def test_multiple_cookies_in_header(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Cookie": "sessionid=abc123456; auth_token=def789"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        finding_titles = [f.title for f in result.findings]
        self.assertTrue(any("sessionid" in t for t in finding_titles))
        self.assertTrue(any("auth_token" in t for t in finding_titles))

    def test_https_cookie_header_no_finding(self):
        flow_json = '{"url": "https://example.com", "request_headers": {"Cookie": "sessionid=abc123456"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTPS")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_generic_word_cookie_without_data_no_finding(self):
        flow_json = '{"url": "http://example.com/cookie_policy.html", "request_headers": {}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_missing_request_headers_no_finding(self):
        flow_json = '{"url": "http://example.com"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_malformed_json_safely_ignored_but_finds_regex(self):
        ev = self.create_network_evidence("invalid json\r\nCookie: sessionid=12345\r\n", protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("sessionid", result.findings[0].title)

    def test_malformed_json_no_cookie(self):
        ev = self.create_network_evidence("invalid json data here", protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_empty_cookie_header_no_finding(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Cookie": ""}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_case_insensitive_cookie_header(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"cOoKiE": "token=XYZ"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("token", result.findings[0].title)

    def test_duplicate_observations_deduplication(self):
        flow_json1 = '{"url": "http://example.com/api", "request_headers": {"Cookie": "sessionid=abc123456"}}'
        flow_json2 = '{"url": "http://example.com/checkout", "request_headers": {"Cookie": "sessionid=abc123456"}}'
        
        ev1 = self.create_network_evidence(flow_json1, protocol="HTTP")
        ev2 = self.create_network_evidence(flow_json2, protocol="HTTP")
        
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1) # Should deduplicate to 1 finding for host + sessionid

    def test_deterministic_finding_id(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Cookie": "sessionid=abc123456"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result1 = self.rule.evaluate(self.session, [ev])
        result2 = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(result1.findings[0].finding_id, result2.findings[0].finding_id)

    def test_evidence_reference_preserved(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Cookie": "sessionid=abc123456"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(len(result.evidence_references), 1)
        self.assertEqual(result.evidence_references[0], "evidence_12345.0_proxy")
        self.assertEqual(result.findings[0].evidence_references, ["evidence_12345.0_proxy"])

    def test_complete_cookie_value_never_exposed(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Cookie": "sessionid=SuperSecretTokenValue123!"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertNotIn("SuperSecretTokenValue123!", result.findings[0].description)
        self.assertIn("Sup...<redacted>", result.findings[0].description)

if __name__ == "__main__":
    unittest.main()
