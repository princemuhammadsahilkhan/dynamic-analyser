import json
import unittest
from dynamic_analysis.rules import (
    SensitiveNetworkDataRule,
    EvidenceItem,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    FindingConfidence,
    AnalysisSession
)

class TestStep77SensitiveNetworkRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="fake.apk",
            base_output_dir="/tmp/fake",
            package_name="com.example.app"
        )
        self.rule = SensitiveNetworkDataRule()

    def create_network_evidence(self, content: str, protocol: str = "HTTP") -> EvidenceItem:
        ev_type = EvidenceType.HTTP_TRAFFIC.value if protocol == "HTTP" else EvidenceType.HTTPS_TRAFFIC.value
        return EvidenceItem(
            evidence_type=ev_type,
            content=content,
            timestamp=12345.0,
            source="proxy",
            serial="test_serial"
        )

    def test_explicit_authorization_header(self):
        flow_json = '{"url": "http://example.com", "request_headers": {"Authorization": "Bearer supersecret1234567890"}}'
        ev = self.create_network_evidence(flow_json)
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Authorization Header", result.findings[0].title)
        self.assertIn("sup...<redacted>", result.findings[0].description)
        self.assertNotIn("supersecret", result.findings[0].description)
        self.assertEqual(result.findings[0].severity, FindingSeverity.HIGH)

    def test_explicit_api_key(self):
        flow_json = '{"url": "http://example.com?api_key=AIzaSyB1234567890abcdefghijklmnopqrstuv"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTPS")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("API Key / Token", result.findings[0].title)
        self.assertIn("AIz...<redacted>", result.findings[0].description)
        self.assertNotIn("AIzaSyB", result.findings[0].description)

    def test_explicit_password_field(self):
        flow_json = '{"url": "http://example.com/login", "request_content": "username=admin&password=MySuperSecretPassword123"}'
        ev = self.create_network_evidence(flow_json)
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Password", result.findings[0].title)
        self.assertIn("MyS...<redacted>", result.findings[0].description)
        self.assertNotIn("MySuperSecret", result.findings[0].description)

    def test_generic_words_no_trigger(self):
        flow_json = '{"url": "http://example.com", "response_content": "Please enter your password and token."}'
        ev = self.create_network_evidence(flow_json)
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_missing_evidence(self):
        ev = EvidenceItem(evidence_type=EvidenceType.PROCESS_LIST.value, content="password=secret1234567890", timestamp=1.0, source="adb", serial="test")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_duplicate_findings_prevented(self):
        flow_json = '{"url": "http://example.com?api_key=AIzaSyB1234567890abcdefghijklmnopqrstuv"}'
        ev1 = self.create_network_evidence(flow_json, protocol="HTTP")
        ev2 = self.create_network_evidence(flow_json, protocol="HTTPS")
        
        result = self.rule.evaluate(self.session, [ev1, ev2])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_finding_id_is_deterministic(self):
        flow_json = '{"url": "http://example.com?api_key=AIzaSyB1234567890abcdefghijklmnopqrstuv"}'
        ev = self.create_network_evidence(flow_json)
        
        result1 = self.rule.evaluate(self.session, [ev])
        result2 = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(result1.findings[0].finding_id, result2.findings[0].finding_id)

    def test_evidence_reference_is_correct(self):
        flow_json = '{"url": "http://example.com?api_key=AIzaSyB1234567890abcdefghijklmnopqrstuv"}'
        ev = self.create_network_evidence(flow_json)
        
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(len(result.evidence_references), 1)
        self.assertEqual(result.evidence_references[0], "evidence_12345.0_proxy")
        self.assertEqual(result.findings[0].evidence_references, ["evidence_12345.0_proxy"])

    def test_malformed_json_safely_ignored(self):
        ev = self.create_network_evidence(None)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

if __name__ == "__main__":
    unittest.main()
