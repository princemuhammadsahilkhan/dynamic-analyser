import json
import unittest
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.rules import MissingXFrameOptionsRule, RuleResult
from dynamic_analysis.session import AnalysisSession

class TestMissingXFrameOptionsRule(unittest.TestCase):
    def setUp(self):
        self.rule = MissingXFrameOptionsRule()
        self.session = AnalysisSession(apk_path="test.apk")

    def create_evidence(self, ev_type: EvidenceType, host: str, headers: dict) -> EvidenceItem:
        content = {
            "request": {"host": host},
            "host": host,
            "raw_metadata": {
                "response_headers": headers
            }
        }
        return EvidenceItem(
            evidence_type=ev_type.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="test_proxy",
            content=json.dumps(content)
        )

    def test_xfo_present_no_finding(self):
        ev = self.create_evidence(
            EvidenceType.HTTPS_TRAFFIC,
            "example.com",
            {"X-Frame-Options": "DENY"}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_xfo_case_insensitive_no_finding(self):
        ev = self.create_evidence(
            EvidenceType.HTTP_TRAFFIC,
            "example.com",
            {"x-fRaMe-OpTiOnS": "SAMEORIGIN"}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_xfo_absent_triggers_finding(self):
        ev = self.create_evidence(
            EvidenceType.HTTPS_TRAFFIC,
            "example.com",
            {"Content-Type": "text/html"}
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "[RULE-013] Missing X-Frame-Options Header Observed - example.com")
        self.assertEqual(finding.severity.value, "MEDIUM")
        self.assertEqual(finding.category.value, "NETWORK")

    def test_missing_response_headers_ignored(self):
        content = {
            "request": {"host": "example.com"},
            "host": "example.com",
            "raw_metadata": {
                # no response_headers
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="test_proxy",
            content=json.dumps(content)
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_malformed_response_headers_ignored(self):
        content = {
            "request": {"host": "example.com"},
            "host": "example.com",
            "raw_metadata": {
                "response_headers": "not_a_dict"
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="test_proxy",
            content=json.dumps(content)
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_multiple_flows_same_host_deduplicated(self):
        ev1 = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, "example.com", {"Server": "nginx"})
        ev2 = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, "example.com", {"Server": "nginx"})
        
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_multiple_flows_different_hosts(self):
        ev1 = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, "example1.com", {"Server": "nginx"})
        ev2 = self.create_evidence(EvidenceType.HTTPS_TRAFFIC, "example2.com", {"Server": "nginx"})
        
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        
    def test_missing_host_fallback(self):
        content = {
            # missing "request" with "host" and missing "host"
            "raw_metadata": {
                "response_headers": {"Server": "nginx"}
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="test_proxy",
            content=json.dumps(content)
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("unknown", result.findings[0].title)

if __name__ == '__main__':
    unittest.main()
