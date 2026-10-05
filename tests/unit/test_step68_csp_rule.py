"""Unit tests for Step 68: RULE-011 — Missing Content-Security-Policy Header Observed."""

import json
import unittest
from unittest.mock import MagicMock

from dynamic_analysis.finding import FindingCategory, FindingConfidence, FindingSeverity, FindingStatus
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.rules import MissingCSPRule
from dynamic_analysis.session import AnalysisSession


def _make_session():
    """Create a minimal mock AnalysisSession for testing."""
    session = MagicMock(spec=AnalysisSession)
    session.id = "test-session-csp"
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


def _make_https_evidence_with_headers(headers_dict, host="example.com", include_raw_metadata=True, request_host=True):
    """Create HTTPS traffic evidence with specified response headers."""
    flow = {
        "scheme": "https",
        "port": 443,
        "method": "GET",
        "url": f"https://{host}/api/data",
    }
    if request_host:
        flow["request"] = {"host": host}
    else:
        flow["host"] = host
        
    if include_raw_metadata:
        if headers_dict is not None:
            flow["raw_metadata"] = {"response_headers": headers_dict}
        else:
            flow["raw_metadata"] = {}
            
    return _make_evidence(EvidenceType.HTTPS_TRAFFIC.value, flow)


class TestStep68CSPRule(unittest.TestCase):
    def setUp(self):
        self.rule = MissingCSPRule()
        self.session = _make_session()

    def test_csp_present(self):
        """1. CSP header present -> no finding."""
        ev = _make_https_evidence_with_headers({"Content-Security-Policy": "default-src 'self'"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_case_insensitive_header_matching(self):
        """2. CSP header present with different capitalization -> no finding."""
        ev1 = _make_https_evidence_with_headers({"content-security-policy": "default-src 'self'"})
        ev2 = _make_https_evidence_with_headers({"CONTENT-SECURITY-POLICY": "default-src 'self'"})
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_csp_missing_valid_headers(self):
        """3. Explicit response_headers without CSP -> finding."""
        ev = _make_https_evidence_with_headers({"Server": "nginx", "Content-Type": "text/html"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertIn("RULE-011", finding.title)
        self.assertIn("Missing Content-Security-Policy Header", finding.title)
        self.assertIn("example.com", finding.description)
        self.assertIn(f"Evidence from {ev.timestamp} (host: example.com)", finding.evidence_references)

    def test_missing_response_headers(self):
        """4. Missing response_headers -> no finding."""
        ev = _make_https_evidence_with_headers(None)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_missing_raw_metadata(self):
        """5. Missing raw_metadata -> no finding."""
        ev = _make_https_evidence_with_headers(None, include_raw_metadata=False)
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_malformed_json(self):
        """6. Malformed JSON -> no finding."""
        ev = _make_evidence(EvidenceType.HTTPS_TRAFFIC.value, "{invalid-json")
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_empty_response_headers(self):
        """7. Empty response_headers dictionary -> finding."""
        ev = _make_https_evidence_with_headers({})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_https_traffic_handling(self):
        """8. HTTPS traffic handling."""
        ev = _make_evidence(EvidenceType.HTTPS_TRAFFIC.value, {
            "request": {"host": "https-host.com"},
            "raw_metadata": {"response_headers": {"Server": "Apache"}}
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertTrue(result.findings[0].description.startswith("The observed HTTP response did not include a Content-Security-Policy header."))
        self.assertEqual(result.findings[0].title, "[RULE-011] Missing Content-Security-Policy Header Observed - https-host.com")

    def test_http_traffic_handling(self):
        """9. HTTP traffic handling."""
        ev = _make_evidence(EvidenceType.HTTP_TRAFFIC.value, {
            "request": {"host": "http-host.com"},
            "raw_metadata": {"response_headers": {"Server": "Apache"}}
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(result.findings[0].title, "[RULE-011] Missing Content-Security-Policy Header Observed - http-host.com")

    def test_multiple_response_headers(self):
        """10. Multiple evidence items."""
        ev1 = _make_https_evidence_with_headers({"Server": "nginx"}, host="host1.com")
        ev2 = _make_https_evidence_with_headers({"Content-Security-Policy": "default-src *"}, host="host2.com")
        ev3 = _make_https_evidence_with_headers({"X-Powered-By": "PHP"}, host="host3.com")
        
        result = self.rule.evaluate(self.session, [ev1, ev2, ev3])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        finding_titles = [f.title for f in result.findings]
        self.assertIn(f"[RULE-011] Missing Content-Security-Policy Header Observed - host1.com", finding_titles)
        self.assertIn(f"[RULE-011] Missing Content-Security-Policy Header Observed - host3.com", finding_titles)

    def test_duplicate_evidence(self):
        """11. Duplicate prevention."""
        ev1 = _make_https_evidence_with_headers({"Server": "nginx"}, host="samehost.com")
        ev2 = _make_https_evidence_with_headers({"X-Powered-By": "PHP"}, host="samehost.com")
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        # Should only trigger once per host
        self.assertEqual(len(result.findings), 1)

    def test_deterministic_finding_ids(self):
        """12. Deterministic finding ID."""
        ev = _make_https_evidence_with_headers({"Server": "nginx"}, host="deterministhost.com")
        result1 = self.rule.evaluate(self.session, [ev])
        self.rule.seen_hosts.clear() # Clear seen hosts
        result2 = self.rule.evaluate(self.session, [ev])
        self.assertEqual(result1.findings[0].title, result2.findings[0].title)

    def test_correct_properties(self):
        """13. Correct severity/category/status/confidence."""
        ev = _make_https_evidence_with_headers({"Server": "nginx"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        finding = result.findings[0]
        self.assertEqual(finding.severity, FindingSeverity.MEDIUM)
        self.assertEqual(finding.category, FindingCategory.NETWORK)

    def test_evidence_references(self):
        """14. Correct evidence reference."""
        ev = _make_https_evidence_with_headers({"Server": "nginx"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.evidence_references), 1)
        self.assertEqual(result.evidence_references[0], f"Evidence from {ev.timestamp} (host: example.com)")

    def test_rule_engine_integration(self):
        """15. RuleEngine integration."""
        from dynamic_analysis.rules import RuleEngine
        engine = RuleEngine()
        engine.register_rule(self.rule)
        
        ev = _make_https_evidence_with_headers({"Server": "nginx"}, host="engine-host.com")
        results = engine.evaluate_all(self.session, [ev])
        
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].triggered)
        self.assertEqual(len(results[0].findings), 1)

if __name__ == "__main__":
    unittest.main()
