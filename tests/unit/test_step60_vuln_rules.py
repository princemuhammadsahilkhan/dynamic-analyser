import unittest
import json
from dynamic_analysis.rules import WeakTLSRule, RuleResult
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.finding import FindingSeverity, FindingCategory

class TestWeakTLSRule(unittest.TestCase):
    def setUp(self):
        self.rule = WeakTLSRule()
        self.session = AnalysisSession(
            apk_path="dummy.apk",
            package_name="com.example.dummy"
        )
        self.ts = "2023-10-01T12:00:00Z"

    def _create_https_evidence(self, metadata: dict) -> EvidenceItem:
        flow = {
            "scheme": "https",
            "host": "api.example.com",
            "raw_metadata": metadata
        }
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=self.ts,
            serial="emulator-5554",
            source="proxy",
            content=json.dumps(flow)
        )

    def test_weak_tls_1_0_triggers(self):
        evidence = [self._create_https_evidence({"tls_version": "TLSv1.0"})]
        result = self.rule.evaluate(self.session, evidence)
        
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.category, FindingCategory.NETWORK)
        self.assertEqual(finding.title, "Weak TLS Version Observed")
        self.assertIn(f"{EvidenceType.HTTPS_TRAFFIC.value}:{self.ts}", finding.evidence_references)

    def test_weak_tls_1_1_triggers(self):
        evidence = [self._create_https_evidence({"tls_version": "TLS 1.1"})]
        result = self.rule.evaluate(self.session, evidence)
        self.assertTrue(result.triggered)

    def test_strong_tls_1_2_no_trigger(self):
        evidence = [self._create_https_evidence({"tls_version": "TLSv1.2"})]
        result = self.rule.evaluate(self.session, evidence)
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_strong_tls_1_3_no_trigger(self):
        evidence = [self._create_https_evidence({"tls_version": "TLSv1.3"})]
        result = self.rule.evaluate(self.session, evidence)
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_missing_tls_version_safely_handles(self):
        evidence = [self._create_https_evidence({})]
        result = self.rule.evaluate(self.session, evidence)
        self.assertFalse(result.triggered)
        self.assertEqual(result.evaluation_details.get("reason"), "No weak TLS version evidence found or metadata missing.")

    def test_missing_https_evidence(self):
        item = EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=self.ts,
            serial="emulator-5554",
            source="proxy",
            content="{}"
        )
        result = self.rule.evaluate(self.session, [item])
        self.assertFalse(result.triggered)

    def test_malformed_json_safely_handled(self):
        item = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=self.ts,
            serial="emulator-5554",
            source="proxy",
            content="NOT JSON"
        )
        result = self.rule.evaluate(self.session, [item])
        self.assertFalse(result.triggered)

    def test_deterministic_finding_ids(self):
        evidence1 = [self._create_https_evidence({"tls_version": "TLSv1.0"})]
        result1 = self.rule.evaluate(self.session, evidence1)
        
        evidence2 = [self._create_https_evidence({"tls_version": "TLSv1.0"})]
        result2 = self.rule.evaluate(self.session, evidence2)
        
        self.assertEqual(result1.findings[0].finding_id, result2.findings[0].finding_id)

if __name__ == '__main__':
    unittest.main()
