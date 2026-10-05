import json
import unittest
from typing import Dict, Any
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.rules import Rule008InsecureCookieAttributeRule
from dynamic_analysis.session import AnalysisSession

class TestStep65CookieRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="fake.apk", 
            package_name="com.example.fake", 
            base_output_dir="/tmp/fake"
        )
        self.rule = Rule008InsecureCookieAttributeRule()

    def create_evidence(self, ev_type: EvidenceType, response_headers: Dict[str, Any]) -> EvidenceItem:
        flow = {
            "raw_metadata": {
                "response_headers": response_headers
            }
        }
        return EvidenceItem(
            evidence_type=ev_type.value,
            timestamp=_get_utc_timestamp(),
            serial="emulator-5554",
            source="Test",
            content=json.dumps(flow),
            exit_code=0
        )

    def test_missing_secure(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": "session_id=123; HttpOnly; SameSite=Lax"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Missing Secure Cookie Attribute Observed")

    def test_missing_httponly(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": "session_id=123; Secure; SameSite=Strict"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Missing HttpOnly Cookie Attribute Observed")

    def test_missing_samesite(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": "session_id=123; Secure; HttpOnly"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Missing SameSite Cookie Attribute Observed")

    def test_missing_all(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": "session_id=123"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 3)

    def test_valid_cookie(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": "session_id=123; Secure; HttpOnly; SameSite=Strict"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_multiple_cookies_one_invalid(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": [
                "valid=1; Secure; HttpOnly; SameSite=None",
                "invalid=1; HttpOnly; SameSite=Lax"
            ]
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Missing Secure Cookie Attribute Observed")

    def test_case_insensitive_attributes(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "set-cookie": "session_id=123; sEcUrE; httponly; samesite=Lax"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        
    def test_no_response_headers(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="emulator-5554",
            source="Test",
            content=json.dumps({"raw_metadata": {}}),
            exit_code=0
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_no_set_cookie_header(self):
        ev = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, {
            "content-type": "application/json"
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

if __name__ == "__main__":
    unittest.main()
