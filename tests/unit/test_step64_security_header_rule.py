import json
import unittest
import uuid
from typing import List

from dynamic_analysis.finding import FindingCategory, FindingSeverity
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.rules import MissingXCTORule, RuleEngine, RuleResult
from dynamic_analysis.session import AnalysisSession


class TestMissingXCTORule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="test.apk",
            package_name="com.test.app"
        )
        self.rule = MissingXCTORule()

    def _create_https_evidence(self, metadata: dict) -> EvidenceItem:
        content = json.dumps({
            "host": "api.example.com",
            "raw_metadata": metadata
        })
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=content,
            timestamp="1234567890.0",
            serial="emulator-5554",
            source="test"
        )

    def test_secure_header_present(self):
        evidence = self._create_https_evidence({
            "response_headers": {
                "x-content-type-options": "nosniff",
                "content-type": "application/json"
            }
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)

    def test_header_absent_complete_evidence(self):
        evidence = self._create_https_evidence({
            "response_headers": {
                "content-type": "application/json"
            }
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "Missing X-Content-Type-Options Header Observed")
        self.assertEqual(finding.severity, FindingSeverity.MEDIUM)
        self.assertEqual(finding.category, FindingCategory.NETWORK)
        self.assertEqual(finding.evidence_references, ["HTTPS_TRAFFIC:1234567890.0"])

    def test_header_name_case_variations(self):
        cases = ["X-Content-Type-Options", "x-content-type-options", "X-CONTENT-TYPE-OPTIONS", "x-Content-type-Options"]
        for case in cases:
            with self.subTest(case=case):
                evidence = self._create_https_evidence({
                    "response_headers": {
                        case: "nosniff"
                    }
                })
                result = self.rule.evaluate(self.session, [evidence])
                self.assertFalse(result.triggered)

    def test_missing_response_headers_field(self):
        evidence = self._create_https_evidence({
            "tls_version": "TLSv1.3"
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)

    def test_empty_response_headers(self):
        evidence = self._create_https_evidence({
            "response_headers": {}
        })
        result = self.rule.evaluate(self.session, [evidence])
        self.assertTrue(result.triggered)

    def test_malformed_json_evidence(self):
        evidence = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content="not valid json",
            timestamp="1234567890.0",
            serial="emulator-5554",
            source="test"
        )
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)

    def test_non_https_evidence(self):
        content = json.dumps({
            "host": "api.example.com",
            "raw_metadata": {
                "response_headers": {
                    "content-type": "application/json"
                }
            }
        })
        evidence = EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=content,
            timestamp="1234567890.0",
            serial="emulator-5554",
            source="test"
        )
        result = self.rule.evaluate(self.session, [evidence])
        self.assertFalse(result.triggered)

    def test_deterministic_finding_id(self):
        evidence = self._create_https_evidence({
            "response_headers": {
                "content-type": "application/json"
            }
        })
        result1 = self.rule.evaluate(self.session, [evidence])
        result2 = self.rule.evaluate(self.session, [evidence])
        self.assertEqual(result1.findings[0].finding_id, result2.findings[0].finding_id)

    def test_rule_engine_integration(self):
        engine = RuleEngine()
        engine.register_rule(self.rule)
        evidence = self._create_https_evidence({
            "response_headers": {
                "content-type": "application/json"
            }
        })
        results = engine.evaluate_all(self.session, [evidence])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].triggered)
        
    def test_duplicate_finding_prevention(self):
        evidence1 = self._create_https_evidence({
            "response_headers": {
                "content-type": "application/json"
            }
        })
        evidence2 = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=evidence1.content,
            timestamp="1234567891.0",
            serial="emulator-5554",
            source="test"
        )
        result = self.rule.evaluate(self.session, [evidence1, evidence2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.evidence_references), 2)
        
    def test_json_serialization(self):
        evidence = self._create_https_evidence({
            "response_headers": {
                "content-type": "application/json"
            }
        })
        result = self.rule.evaluate(self.session, [evidence])
        f_dict = result.findings[0].to_dict()
        self.assertIsInstance(json.dumps(f_dict), str)


if __name__ == "__main__":
    unittest.main()
