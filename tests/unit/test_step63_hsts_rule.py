import unittest
import json
import time

from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.rules import MissingHSTSRule, RuleEngine

class TestStep63HSTSRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="test.apk")
        self.rule = MissingHSTSRule()

    def create_evidence(self, headers=None, is_https=True, malformed=False) -> EvidenceItem:
        ts = time.time()
        
        if not is_https:
            return EvidenceItem(
                evidence_type=EvidenceType.HTTP_TRAFFIC.value,
                content=json.dumps({"request": {"url": "http://example.com"}}),
                timestamp=ts,
                serial="test-serial",
                source="test"
            )
        if malformed:
            return EvidenceItem(
                evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
                content="invalid json",
                timestamp=ts,
                serial="test-serial",
                source="test"
            )
        
        flow = {"request": {"url": "https://example.com"}}
        if headers is not False: # False means no raw_metadata or missing response_headers
            flow["raw_metadata"] = {}
            if headers is not None:
                flow["raw_metadata"]["response_headers"] = headers
                
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(flow),
            timestamp=ts,
            serial="test-serial",
            source="test"
        )

    def test_missing_hsts_triggers(self):
        # Present headers but no HSTS
        ev = self.create_evidence(headers={"x-content-type-options": "nosniff"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Missing Strict-Transport-Security Header Observed")

    def test_present_hsts_no_trigger(self):
        # Present headers including HSTS
        ev = self.create_evidence(headers={"strict-transport-security": "max-age=31536000"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_no_headers_metadata_no_trigger(self):
        # Missing response_headers in raw_metadata should not trigger
        ev = self.create_evidence(headers=False)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(result.evaluation_details.get("reason"), "Missing response_headers metadata")

    def test_http_traffic_ignored(self):
        # Rule only applies to HTTPS
        ev = self.create_evidence(is_https=False)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_malformed_evidence_handled(self):
        ev = self.create_evidence(malformed=True)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

if __name__ == "__main__":
    unittest.main()
