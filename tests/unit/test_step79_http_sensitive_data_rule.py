import json
import unittest
from dynamic_analysis.rules import (
    InsecureHttpSensitiveDataRule,
    EvidenceItem,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    FindingConfidence,
    AnalysisSession
)

class TestStep79HttpSensitiveDataRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="fake.apk",
            base_output_dir="/tmp/fake",
            package_name="com.example.app"
        )
        self.rule = InsecureHttpSensitiveDataRule()

    def create_network_evidence(self, content: str, protocol: str = "HTTP") -> EvidenceItem:
        ev_type = EvidenceType.HTTP_TRAFFIC.value if protocol == "HTTP" else EvidenceType.HTTPS_TRAFFIC.value
        return EvidenceItem(
            evidence_type=ev_type,
            content=content,
            timestamp=12345.0,
            source="proxy",
            serial="test_serial"
        )

    def test_explicit_email(self):
        flow_json = '{"url": "http://example.com/signup", "request_content": "email=user@example.com"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("email", result.findings[0].title)
        self.assertIn("use...<redacted>", result.findings[0].description)
        self.assertEqual(result.findings[0].severity, FindingSeverity.HIGH)

    def test_explicit_phone(self):
        flow_json = '{"url": "http://example.com/contact", "request_content": "phone=123456789"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("phone", result.findings[0].title)
        self.assertIn("123...<redacted>", result.findings[0].description)

    def test_explicit_credit_card(self):
        flow_json = '{"url": "http://example.com/checkout", "request_content": "credit_card=4111111111111111"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("credit_card", result.findings[0].title)
        
    def test_explicit_ssn(self):
        flow_json = '{"url": "http://example.com/apply", "request_content": "ssn=123-45-6789"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("ssn", result.findings[0].title)
        
    def test_explicit_cvv(self):
        flow_json = '{"url": "http://example.com/checkout", "request_content": "cvv=123"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("cvv", result.findings[0].title)

    def test_https_credentials_do_not_trigger(self):
        flow_json = '{"url": "https://example.com/signup", "request_content": "email=user@example.com"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTPS")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_generic_words_without_values_no_finding(self):
        flow_json = '{"url": "http://example.com", "response_content": "Please enter your email and phone."}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_empty_values_no_finding(self):
        flow_json = '{"url": "http://example.com/signup", "request_content": "email="}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertFalse(result.triggered)

    def test_missing_request_content(self):
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
        flow_json = '{"url": "http://example.com/checkout", "request_content": "credit_card=4111111111111111"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(result.triggered)
        self.assertIn("411...<redacted>", result.findings[0].description)
        self.assertNotIn("4111111111111111", result.findings[0].description)

    def test_deterministic_finding_id(self):
        flow_json = '{"url": "http://example.com/checkout", "request_content": "credit_card=4111111111111111"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result1 = self.rule.evaluate(self.session, [ev])
        result2 = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(result1.findings[0].finding_id, result2.findings[0].finding_id)

    def test_duplicate_prevention(self):
        flow_json = '{"url": "http://example.com/checkout", "request_content": "credit_card=4111111111111111"}'
        ev1 = self.create_network_evidence(flow_json, protocol="HTTP")
        ev2 = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_correct_evidence_reference(self):
        flow_json = '{"url": "http://example.com/checkout", "request_content": "credit_card=4111111111111111"}'
        ev = self.create_network_evidence(flow_json, protocol="HTTP")
        
        result = self.rule.evaluate(self.session, [ev])
        
        self.assertEqual(len(result.evidence_references), 1)
        self.assertEqual(result.evidence_references[0], "evidence_12345.0_proxy")
        self.assertEqual(result.findings[0].evidence_references, ["evidence_12345.0_proxy"])

    def test_rule_metadata(self):
        self.assertEqual(self.rule.rule_id, "RULE-022")
        self.assertEqual(self.rule.name, "Insecure HTTP Sensitive Data Observed")
        self.assertEqual(self.rule.category, FindingCategory.NETWORK)
        self.assertEqual(self.rule.severity, FindingSeverity.HIGH)

if __name__ == "__main__":
    unittest.main()
