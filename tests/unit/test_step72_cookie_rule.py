import json
import unittest

from dynamic_analysis.finding import FindingSeverity, FindingCategory
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.rules import InsecureCookieAttributeRule, RuleEngine
from dynamic_analysis.session import AnalysisSession


class TestStep72InsecureCookieAttributeRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureCookieAttributeRule()
        self.session = AnalysisSession(apk_path="fake.apk")
        self.session.id = self.session.analysis_id  # Mock alignment

    def _create_http_evidence(self, host: str, response_headers: dict) -> EvidenceItem:
        content = {
            "request": {"host": host},
            "host": host,
            "raw_metadata": {
                "response_headers": response_headers
            }
        }
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="proxy",
            content=json.dumps(content)
        )

    def test_missing_secure(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": ["session=123; HttpOnly; SameSite=Lax"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Missing Secure Cookie Attribute", result.findings[0].title)

    def test_missing_httponly(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": ["session=123; Secure; SameSite=Lax"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Missing HttpOnly Cookie Attribute", result.findings[0].title)

    def test_missing_samesite(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": ["session=123; Secure; HttpOnly"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Missing SameSite Cookie Attribute", result.findings[0].title)

    def test_all_secure(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": ["session=123; Secure; HttpOnly; SameSite=Strict"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_multiple_missing(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": ["session=123"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 3)
        titles = [f.title for f in result.findings]
        self.assertTrue(any("Missing Secure" in t for t in titles))
        self.assertTrue(any("Missing HttpOnly" in t for t in titles))
        self.assertTrue(any("Missing SameSite" in t for t in titles))

    def test_multiple_cookies_and_deduplication(self):
        evidence1 = self._create_http_evidence("example.com", {
            "set-cookie": ["session=123; HttpOnly"]
        })
        # same missing attrs for session cookie
        evidence2 = self._create_http_evidence("example.com", {
            "set-cookie": ["session=456; HttpOnly"]
        })
        result = self.rule.evaluate(self.session, [evidence1, evidence2])
        self.assertTrue(result.triggered)
        # Should deduplicate on host + cookie name (session) + missing attr (Secure, SameSite)
        self.assertEqual(len(result.findings), 2)
        
    def test_case_insensitive_header(self):
        evidence = self._create_http_evidence("example.com", {
            "Set-Cookie": ["session=123; SECURE; HTTPONLY; SAMESITE=lax"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)
        
    def test_string_instead_of_list(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": "session=123; Secure; HttpOnly; SameSite=lax"
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)
        
    def test_missing_response_headers(self):
        content = {
            "request": {"host": "example.com"},
            "raw_metadata": {}
        }
        evidence = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="proxy",
            content=json.dumps(content)
        )
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)

    def test_malformed_evidence(self):
        evidence = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="proxy",
            content="{"
        )
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)

    def test_no_cookie_values_in_findings(self):
        evidence = self._create_http_evidence("example.com", {
            "set-cookie": ["session=secretvalue12345"]
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)
        
        for f in result.findings:
            self.assertNotIn("secretvalue12345", f.title)
            self.assertNotIn("secretvalue12345", f.description)
            self.assertIn("session", f.description)
            
    def test_engine_integration(self):
        engine = RuleEngine()
        engine.register_rule(self.rule)
        
        evidence1 = self._create_http_evidence("example.com", {
            "set-cookie": ["auth=123"]
        })
        
        evidence2 = self._create_http_evidence("example.com", {
            "set-cookie": ["auth=123"]
        })
        
        results = engine.evaluate_all(self.session, [evidence1, evidence2])
        
        # Expect 1 result for our rule, triggered
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].triggered)
        
        # Deduplication in the rule should result in 3 findings (Secure, HttpOnly, SameSite)
        self.assertEqual(len(results[0].findings), 3)

if __name__ == '__main__':
    unittest.main()
