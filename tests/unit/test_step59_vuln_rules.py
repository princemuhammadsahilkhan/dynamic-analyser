import unittest
import json
from dynamic_analysis.rules import (
    RuleEngine,
    CleartextTrafficRule,
)
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.finding import FindingCategory, FindingSeverity, FindingStatus, FindingConfidence

class TestCleartextTrafficRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="/fake.apk", package_name="com.example.mentorcraft2")
        self.rule = CleartextTrafficRule()
        self.engine = RuleEngine()
        self.engine.register_rule(self.rule)

    def _create_http_evidence(self, host: str, scheme: str = "http", ev_type: str = EvidenceType.HTTP_TRAFFIC.value) -> EvidenceItem:
        flow = {
            "host": host,
            "scheme": scheme,
            "port": 80,
            "path": "/",
        }
        return EvidenceItem(
            evidence_type=ev_type,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content=json.dumps(flow)
        )

    def test_external_cleartext_http_triggers(self):
        ev = self._create_http_evidence("example.com")
        res = self.rule.evaluate(self.session, [ev])
        
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)
        finding = res.findings[0]
        
        self.assertEqual(finding.title, "Cleartext HTTP Traffic Observed")
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.category, FindingCategory.NETWORK)
        self.assertEqual(finding.status, FindingStatus.VALIDATED)
        self.assertEqual(finding.confidence, FindingConfidence.CERTAIN)
        self.assertIn("example.com", res.evaluation_details["cleartext_hosts"])
        self.assertEqual(len(finding.evidence_references), 1)
        self.assertTrue(finding.evidence_references[0].startswith(EvidenceType.HTTP_TRAFFIC.value))
        self.assertIsNotNone(finding.finding_id)

    def test_https_evidence_does_not_trigger(self):
        ev = self._create_http_evidence("example.com", scheme="https", ev_type=EvidenceType.HTTPS_TRAFFIC.value)
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)

    def test_localhost_does_not_trigger(self):
        ev = self._create_http_evidence("localhost")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)

    def test_127_0_0_1_does_not_trigger(self):
        ev = self._create_http_evidence("127.0.0.1")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)

    def test_ipv6_loopback_does_not_trigger(self):
        ev = self._create_http_evidence("::1")
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)

    def test_missing_evidence_does_not_trigger(self):
        res = self.rule.evaluate(self.session, [])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)

    def test_malformed_evidence_safe_failure(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content="not a json string"
        )
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)
        
    def test_ambiguous_evidence(self):
        flow = {"some_other_key": "value"}
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content=json.dumps(flow)
        )
        res = self.rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        
    def test_rule_engine_integration(self):
        ev = self._create_http_evidence("api.example.com")
        results = self.engine.evaluate_all(self.session, [ev])
        
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].triggered)
        self.assertEqual(results[0].rule_id, "RULE-003")

if __name__ == "__main__":
    unittest.main()
