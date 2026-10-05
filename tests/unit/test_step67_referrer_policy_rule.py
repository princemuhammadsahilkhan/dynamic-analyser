"""Unit tests for Step 67: RULE-010 — Missing Referrer-Policy Header Observed."""

import json
import unittest
from unittest.mock import MagicMock

from dynamic_analysis.finding import FindingCategory, FindingConfidence, FindingSeverity, FindingStatus
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.rules import MissingReferrerPolicyRule
from dynamic_analysis.session import AnalysisSession


def _make_session():
    """Create a minimal mock AnalysisSession for testing."""
    session = MagicMock(spec=AnalysisSession)
    session.analysis_id = "test-analysis-referrer"
    session.package_name = "com.example.test"
    return session


def _make_evidence(evidence_type, content_dict):
    """Create an EvidenceItem with a JSON-serialized content."""
    return EvidenceItem(
        evidence_type=evidence_type,
        timestamp="2026-09-28T12:00:00Z",
        serial="emulator-5554",
        source="test",
        content=json.dumps(content_dict) if isinstance(content_dict, dict) else content_dict,
        exit_code=0,
    )


def _make_https_evidence_with_headers(headers_dict, host="example.com", include_raw_metadata=True):
    """Create HTTPS traffic evidence with specified response headers."""
    flow = {
        "host": host,
        "scheme": "https",
        "port": 443,
        "method": "GET",
        "url": f"https://{host}/api/data",
    }
    if include_raw_metadata:
        if headers_dict is not None:
            flow["raw_metadata"] = {"response_headers": headers_dict}
        else:
            flow["raw_metadata"] = {}
            
    return _make_evidence(EvidenceType.HTTPS_TRAFFIC.value, flow)


class TestStep67ReferrerPolicyRule(unittest.TestCase):
    def setUp(self):
        self.rule = MissingReferrerPolicyRule()
        self.session = _make_session()

    def test_referrer_policy_present(self):
        """1. Referrer-Policy present -> no missing-header finding."""
        ev = _make_https_evidence_with_headers({"Referrer-Policy": "no-referrer"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_referrer_policy_missing_valid_headers(self):
        """2. Referrer-Policy missing with valid response headers -> finding."""
        ev = _make_https_evidence_with_headers({"Content-Type": "application/json"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, FindingSeverity.MEDIUM)

    def test_case_insensitive_header_matching(self):
        """3. Case-insensitive header matching."""
        ev1 = _make_https_evidence_with_headers({"referrer-policy": "strict-origin"})
        ev2 = _make_https_evidence_with_headers({"REFERRER-POLICY": "no-referrer"})
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertFalse(result.triggered)

    def test_different_valid_referrer_policy_values(self):
        """4. Different valid Referrer-Policy values."""
        ev = _make_https_evidence_with_headers({"Referrer-Policy": "unsafe-url"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        
    def test_missing_response_headers(self):
        """5. Missing response_headers -> no finding."""
        ev = _make_https_evidence_with_headers(None)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_missing_raw_metadata(self):
        """6. Missing raw_metadata -> no finding."""
        ev = _make_https_evidence_with_headers(None, include_raw_metadata=False)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        
    def test_malformed_json(self):
        """7. Malformed JSON -> no finding."""
        ev = _make_evidence(EvidenceType.HTTPS_TRAFFIC.value, "{malformed")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_invalid_header_structure(self):
        """8. Invalid header structure -> no finding."""
        flow = {"host": "example.com", "raw_metadata": {"response_headers": "not_a_dict"}}
        ev = _make_evidence(EvidenceType.HTTPS_TRAFFIC.value, flow)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        
    def test_multiple_response_headers(self):
        """9. Multiple response headers."""
        headers = {"X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000"}
        ev = _make_https_evidence_with_headers(headers)
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_duplicate_evidence(self):
        """10. Duplicate evidence."""
        ev1 = _make_https_evidence_with_headers({"Content-Type": "text/html"})
        ev2 = _make_https_evidence_with_headers({"Content-Type": "text/html"})
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_deterministic_finding_ids(self):
        """11. Deterministic finding IDs."""
        ev1 = _make_https_evidence_with_headers({"Content-Type": "text/html"})
        ev2 = _make_evidence(EvidenceType.HTTP_TRAFFIC.value, {
            "host": "example.com",
            "raw_metadata": {"response_headers": {"Content-Type": "text/html"}}
        })
        r1 = self.rule.evaluate(self.session, [ev1])
        r2 = self.rule.evaluate(self.session, [ev2])
        self.assertEqual(r1.findings[0].finding_id, r2.findings[0].finding_id)

    def test_evidence_references(self):
        """12. Evidence references."""
        ev = _make_https_evidence_with_headers({"Content-Type": "text/html"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertEqual(result.evidence_references, [f"{ev.evidence_type}:{ev.timestamp}"])
        self.assertEqual(result.findings[0].evidence_references, [f"{ev.evidence_type}:{ev.timestamp}"])

    def test_correct_properties(self):
        """13. Correct severity/category/status/confidence."""
        ev = _make_https_evidence_with_headers({"Content-Type": "text/html"})
        result = self.rule.evaluate(self.session, [ev])
        f = result.findings[0]
        self.assertEqual(f.severity, FindingSeverity.MEDIUM)
        self.assertEqual(f.category, FindingCategory.NETWORK)
        self.assertEqual(f.status, FindingStatus.VALIDATED)
        self.assertEqual(f.confidence, FindingConfidence.CERTAIN)

if __name__ == '__main__':
    unittest.main()
