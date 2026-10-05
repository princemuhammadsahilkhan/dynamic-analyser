import unittest
import json
import time
from typing import Dict, Any

from dynamic_analysis.rules import InsecureHttpQueryParameterRule
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestInsecureHttpQueryParameterRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureHttpQueryParameterRule()
        self.session = AnalysisSession(apk_path="test.apk")
        self.session.output_dir = "/tmp"

    def _create_http_evidence(self, content_str: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="proxy",
            content=content_str
        )

    def _create_https_evidence(self, content_str: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="proxy",
            content=content_str
        )

    def test_password_query_parameter_over_http(self):
        content = json.dumps({
            "url": "http://example.com/login?password=mysecretpassword",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity.value, "HIGH")
        self.assertEqual(finding.category.value, "NETWORK")
        self.assertIn("password", finding.title)
        self.assertIn("mys...<redacted>", finding.description)
        self.assertNotIn("mysecretpassword", finding.description)

    def test_multiple_sensitive_query_parameters(self):
        content = json.dumps({
            "url": "http://example.com/api?api_key=apikey123&access_token=token456",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        titles = [f.title for f in result.findings]
        self.assertTrue(any("api_key" in t for t in titles))
        self.assertTrue(any("access_token" in t for t in titles))

    def test_refresh_token_and_client_secret(self):
        content = json.dumps({
            "url": "http://example.com/oauth?refresh_token=rt123&client_secret=cs456",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)

    def test_ssn_and_credit_card(self):
        content = json.dumps({
            "url": "http://example.com/checkout?ssn=000000000&credit_card=1234567890123456",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)

    def test_https_traffic_ignored(self):
        content = json.dumps({
            "url": "https://example.com/login?password=mysecretpassword",
            "request_content": ""
        })
        evidence = self._create_https_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_url_without_query_parameters(self):
        content = json.dumps({
            "url": "http://example.com/login",
            "request_content": "password=mysecretpassword"
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_missing_url(self):
        content = json.dumps({
            "request_content": "password=mysecretpassword"
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_malformed_evidence(self):
        evidence = self._create_http_evidence("not valid json")
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertFalse(result.triggered)

    def test_empty_sensitive_parameter(self):
        content = json.dumps({
            "url": "http://example.com/login?password=&api_key=",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertFalse(result.triggered)

    def test_generic_parameter(self):
        content = json.dumps({
            "url": "http://example.com/search?query=password",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertFalse(result.triggered)

    def test_case_insensitive_parameter_names(self):
        content = json.dumps({
            "url": "http://example.com/login?PaSsWoRd=mysecretpassword",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_url_encoded_sensitive_values(self):
        content = json.dumps({
            "url": "http://example.com/login?password=my%20secret",
            "request_content": ""
        })
        evidence = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence])
        
        self.assertTrue(result.triggered)
        finding = result.findings[0]
        # "my%20secret" -> "my secret" -> "my ...<redacted>"
        self.assertIn("my ...<redacted>", finding.description)

    def test_duplicate_observations(self):
        content = json.dumps({
            "url": "http://example.com/login?password=mysecretpassword",
            "request_content": ""
        })
        evidence1 = self._create_http_evidence(content)
        evidence2 = self._create_http_evidence(content)
        result = self.rule.evaluate(self.session, [evidence1, evidence2])
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

if __name__ == '__main__':
    unittest.main()
