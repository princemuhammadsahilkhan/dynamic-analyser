import json
import unittest
from dynamic_analysis.rules import (
    InsecureHttpAuthRule,
    EvidenceItem,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    FindingConfidence,
    AnalysisSession
)

class TestStep78HttpAuthRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="fake.apk",
            base_output_dir="/tmp/fake",
            package_name="com.example.app"
        )
        self.rule = InsecureHttpAuthRule()

    def create_network_evidence(self, content: str, protocol: str = "HTTP") -> EvidenceItem:
        ev_type = EvidenceType.HTTP_TRAFFIC.value if protocol == "HTTP" else EvidenceType.HTTPS_TRAFFIC.value
        return EvidenceItem(
            evidence_type=ev_type,
            content=content,
            timestamp=12345.0,
            source="proxy",
            serial="test_serial"
        )

    def test_http_basic_authorization(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Authorization Header", result.findings[0].title)
        self.assertIn("dXN...<redacted>", result.findings[0].description)
        self.assertEqual(result.findings[0].severity, FindingSeverity.HIGH)

    def test_http_bearer_authorization(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Authorization": "Bearer supersecret1234567890"}}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Authorization Header", result.findings[0].title)

    def test_http_password_parameter(self):
        flow_json = '{"url": "http://example.com/login", "request_content": "password=MySuperSecretPassword123"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        
    def test_http_api_key(self):
        flow_json = '{"url": "http://example.com?api_key=AIzaSyB1234567890abcdefghijklmnopqrstuv"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        
    def test_http_access_token(self):
        flow_json = '{"url": "http://example.com?access_token=supersecret1234567890"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_https_credentials_do_not_trigger(self):
        flow_json = '{"url": "https://example.com/login", "request_content": "username=admin&password=MySuperSecretPassword123"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTPS")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_generic_password_text_no_finding(self):
        flow_json = '{"url": "http://example.com", "response_content": "Please enter your password here."}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_generic_token_text_no_finding(self):
        flow_json = '{"url": "http://example.com", "response_content": "Your token has expired."}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_missing_request_headers_and_content(self):
        flow_json = '{"url": "http://example.com"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_malformed_json_safely_ignored(self):
        ev = self.create_network_evidence("invalid json", protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_null_evidence_safely_ignored(self):
        ev = self.create_network_evidence(None, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        
    def test_secret_redaction(self):
        flow_json = '{"url": "http://example.com?api_key=AIzaSyB1234567890abcdefghijklmnopqrstuv"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertIn("AIz...<redacted>", result.findings[0].description)
        self.assertNotIn("AIzaSyB", result.findings[0].description)

    def test_deterministic_finding_id(self):
        flow_json = '{"url": "http://example.com/login", "request_content": "password=MySuperSecretPassword123"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result1 = self.rule.evaluate(self.session, [ev])
        result2 = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(result1.findings[0].finding_id, result2.findings[0].finding_id)

    def test_duplicate_prevention(self):
        flow_json = '{"url": "http://example.com/login", "request_content": "password=MySuperSecretPassword123"}'
        ev1 = self.create_network_evidence(flow_json, protocol="HTTP")
        ev2 = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_correct_evidence_reference(self):
        flow_json = '{"url": "http://example.com/login", "request_content": "password=MySuperSecretPassword123"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(len(result.evidence_references), 1)
        self.assertEqual(result.evidence_references[0], "evidence_12345.0_proxy")
        self.assertEqual(result.findings[0].evidence_references, ["evidence_12345.0_proxy"])

    def test_rule_metadata(self):
        self.assertEqual(self.rule.rule_id, "RULE-021")
        self.assertEqual(self.rule.name, "Insecure HTTP Authentication Observed")
        self.assertEqual(self.rule.category, FindingCategory.NETWORK)
        self.assertEqual(self.rule.severity, FindingSeverity.HIGH)

if __name__ == "__main__":
    unittest.main()
