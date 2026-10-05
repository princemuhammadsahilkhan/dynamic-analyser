import unittest
import json
from dynamic_analysis.rules import MissingCacheControlRule
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.finding import FindingSeverity, FindingCategory

class TestMissingCacheControlRule(unittest.TestCase):
    def setUp(self):
        self.rule = MissingCacheControlRule()
        self.session = AnalysisSession(apk_path="dummy.apk")
        self.session.analysis_id = "test-session-123"

    def test_cache_control_present_no_finding(self):
        content = {
            "host": "example.com",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "response_headers": {
                    "cache-control": "no-store"
                }
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            source="proxy",
            serial="serial",
            timestamp="2023-01-01T00:00:00Z"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_cache_control_present_mixed_case(self):
        content = {
            "host": "example.com",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "response_headers": {
                    "Cache-Control": "no-cache"
                }
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            source="proxy",
            serial="serial",
            timestamp="2023-01-01T00:00:00Z"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_cache_control_absent_triggers_finding(self):
        content = {
            "host": "example.com",
            "request": {"host": "example.com"},
            "raw_metadata": {
                "response_headers": {
                    "content-type": "text/html"
                }
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            source="proxy",
            serial="serial",
            timestamp="2023-01-01T00:00:00Z"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "[RULE-016] Missing Cache-Control Header Observed - example.com")
        self.assertEqual(finding.severity.value, "LOW")
        self.assertEqual(finding.category.value, "NETWORK")

    def test_missing_response_headers_ignored(self):
        content = {
            "host": "example.com",
            "raw_metadata": {}
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            source="proxy",
            serial="serial",
            timestamp="2023-01-01T00:00:00Z"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_response_headers_none_ignored(self):
        content = {
            "host": "example.com",
            "raw_metadata": {
                "response_headers": None
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=json.dumps(content),
            source="proxy",
            serial="serial",
            timestamp="2023-01-01T00:00:00Z"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_deduplication(self):
        content1 = {
            "host": "example.com",
            "raw_metadata": {"response_headers": {"a": "b"}}
        }
        content2 = {
            "host": "example.com",
            "raw_metadata": {"response_headers": {"c": "d"}}
        }
        content3 = {
            "host": "other.com",
            "raw_metadata": {"response_headers": {"e": "f"}}
        }
        evs = [
            EvidenceItem(evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content1), source="proxy", serial="serial", timestamp="1"),
            EvidenceItem(evidence_type=EvidenceType.HTTPS_TRAFFIC.value, content=json.dumps(content2), source="proxy", serial="serial", timestamp="2"),
            EvidenceItem(evidence_type=EvidenceType.HTTPS_TRAFFIC.value, content=json.dumps(content3), source="proxy", serial="serial", timestamp="3"),
        ]
        result = self.rule.evaluate(self.session, evs)
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        titles = [f.title for f in result.findings]
        self.assertIn("[RULE-016] Missing Cache-Control Header Observed - example.com", titles)
        self.assertIn("[RULE-016] Missing Cache-Control Header Observed - other.com", titles)

    def test_malformed_json_ignored(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content="{malformed",
            source="proxy",
            serial="serial",
            timestamp="1"
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_missing_host(self):
        content1 = {
            "raw_metadata": {"response_headers": {"a": "b"}}
        }
        content2 = {
            "raw_metadata": {"response_headers": {"c": "d"}}
        }
        evs = [
            EvidenceItem(evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content1), source="proxy", serial="serial", timestamp="1"),
            EvidenceItem(evidence_type=EvidenceType.HTTP_TRAFFIC.value, content=json.dumps(content2), source="proxy", serial="serial", timestamp="2"),
        ]
        result = self.rule.evaluate(self.session, evs)
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

if __name__ == "__main__":
    unittest.main()
