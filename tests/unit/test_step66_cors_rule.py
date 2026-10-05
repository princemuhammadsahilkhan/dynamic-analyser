"""Unit tests for Step 66: RULE-009 — Insecure CORS Policy Observed."""

import json
import os
import unittest
from unittest.mock import MagicMock

from dynamic_analysis.finding import FindingCategory, FindingConfidence, FindingSeverity, FindingStatus
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.rules import (
    InsecureCORSRule,
    RuleEngine,
    TargetProcessObservedRule,
    ProxyConfiguredRule,
    CleartextTrafficRule,
    WeakTLSRule,
    WeakTLSCipherRule,
    MissingHSTSRule,
    MissingXCTORule,
    Rule008InsecureCookieAttributeRule,
)
from dynamic_analysis.session import AnalysisSession


def _make_session():
    """Create a minimal mock AnalysisSession for testing."""
    session = MagicMock(spec=AnalysisSession)
    session.analysis_id = "test-analysis-cors"
    session.package_name = "com.example.test"
    return session


def _make_evidence(evidence_type, content_dict):
    """Create an EvidenceItem with a JSON-serialized content."""
    return EvidenceItem(
        evidence_type=evidence_type,
        timestamp="2026-09-28T12:00:00Z",
        serial="emulator-5554",
        source="test",
        content=json.dumps(content_dict),
        exit_code=0,
    )


def _make_https_evidence_with_headers(headers_dict, host="example.com"):
    """Create HTTPS traffic evidence with specified response headers."""
    return _make_evidence(
        EvidenceType.HTTPS_TRAFFIC.value,
        {
            "host": host,
            "scheme": "https",
            "port": 443,
            "method": "GET",
            "url": f"https://{host}/api/data",
            "raw_metadata": {
                "response_headers": headers_dict,
            },
        },
    )


def _make_http_evidence_with_headers(headers_dict, host="example.com"):
    """Create HTTP traffic evidence with specified response headers."""
    return _make_evidence(
        EvidenceType.HTTP_TRAFFIC.value,
        {
            "host": host,
            "scheme": "http",
            "port": 80,
            "method": "GET",
            "url": f"http://{host}/api/data",
            "raw_metadata": {
                "response_headers": headers_dict,
            },
        },
    )


class TestInsecureCORSRule(unittest.TestCase):
    """Tests for InsecureCORSRule (RULE-009)."""

    def setUp(self):
        self.rule = InsecureCORSRule()
        self.session = _make_session()

    # --- Rule Identity ---

    def test_rule_identity(self):
        self.assertEqual(self.rule.rule_id, "RULE-009")
        self.assertEqual(self.rule.name, "Insecure CORS Policy Observed")
        self.assertEqual(self.rule.category, FindingCategory.NETWORK)

    # --- 1. No CORS headers → no finding ---

    def test_no_cors_headers_no_finding(self):
        ev = _make_https_evidence_with_headers({"content-type": "application/json"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    # --- 2. Wildcard origin → finding ---

    def test_wildcard_origin_generates_finding(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "Wildcard CORS Origin Observed")
        self.assertEqual(finding.severity, FindingSeverity.MEDIUM)
        self.assertEqual(finding.category, FindingCategory.NETWORK)
        self.assertEqual(finding.status, FindingStatus.VALIDATED)
        self.assertEqual(finding.confidence, FindingConfidence.CERTAIN)

    # --- 3. Wildcard origin + credentials → appropriate finding ---

    def test_wildcard_origin_with_credentials_generates_finding(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.title, "Wildcard CORS Origin With Credentials Observed")
        self.assertEqual(finding.severity, FindingSeverity.HIGH)

    def test_wildcard_origin_with_credentials_false_is_wildcard_only(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "false",
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Wildcard CORS Origin Observed")

    # --- 4. Specific origin → no automatic vulnerability ---

    def test_specific_origin_no_vulnerability(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": "https://trusted.example.com",
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_specific_origin_with_credentials_no_vulnerability(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": "https://trusted.example.com",
            "access-control-allow-credentials": "true",
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    # --- 5. Header-name case insensitivity ---

    def test_mixed_case_header_names(self):
        ev = _make_https_evidence_with_headers({
            "Access-Control-Allow-Origin": "*",
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    # --- 6. Missing response_headers ---

    def test_missing_response_headers_no_finding(self):
        ev = _make_evidence(
            EvidenceType.HTTPS_TRAFFIC.value,
            {"host": "example.com", "raw_metadata": {}},
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    # --- 7. Missing raw_metadata ---

    def test_missing_raw_metadata_no_finding(self):
        ev = _make_evidence(
            EvidenceType.HTTPS_TRAFFIC.value,
            {"host": "example.com"},
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    # --- 8. Malformed JSON ---

    def test_malformed_json_no_crash(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp="2026-09-28T12:00:00Z",
            serial="emulator-5554",
            source="test",
            content="NOT VALID JSON {{{",
            exit_code=0,
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    # --- 9. Non-dictionary headers ---

    def test_non_dict_headers_no_crash(self):
        ev = _make_evidence(
            EvidenceType.HTTPS_TRAFFIC.value,
            {"host": "example.com", "raw_metadata": {"response_headers": "not-a-dict"}},
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_list_headers_no_crash(self):
        ev = _make_evidence(
            EvidenceType.HTTPS_TRAFFIC.value,
            {"host": "example.com", "raw_metadata": {"response_headers": ["a", "b"]}},
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    # --- 10. Multiple response-header representations (string vs list) ---

    def test_acao_as_list_value(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": ["*"],
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_acao_as_list_with_credentials_list(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": ["*"],
            "access-control-allow-credentials": ["true"],
        })
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(result.findings[0].title, "Wildcard CORS Origin With Credentials Observed")

    # --- 11. Duplicate evidence (deduplication) ---

    def test_duplicate_evidence_deduplicated(self):
        ev1 = _make_https_evidence_with_headers(
            {"access-control-allow-origin": "*"}, host="api.example.com"
        )
        ev2 = _make_https_evidence_with_headers(
            {"access-control-allow-origin": "*"}, host="api.example.com"
        )
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        # Same host should deduplicate to 1 finding
        self.assertEqual(len(result.findings), 1)

    def test_different_hosts_produce_separate_findings(self):
        ev1 = _make_https_evidence_with_headers(
            {"access-control-allow-origin": "*"}, host="api1.example.com"
        )
        ev2 = _make_https_evidence_with_headers(
            {"access-control-allow-origin": "*"}, host="api2.example.com"
        )
        result = self.rule.evaluate(self.session, [ev1, ev2])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)

    # --- 12. Deterministic finding IDs ---

    def test_deterministic_finding_ids(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        result1 = self.rule.evaluate(self.session, [ev])
        result2 = self.rule.evaluate(self.session, [ev])
        self.assertEqual(
            result1.findings[0].finding_id,
            result2.findings[0].finding_id,
        )

    # --- 13. Evidence references ---

    def test_evidence_references_populated(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertTrue(len(result.evidence_references) > 0)
        self.assertTrue(len(result.findings[0].evidence_references) > 0)

    # --- 14. Correct severity/category/status/confidence ---

    def test_wildcard_severity_medium(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        result = self.rule.evaluate(self.session, [ev])
        f = result.findings[0]
        self.assertEqual(f.severity, FindingSeverity.MEDIUM)
        self.assertEqual(f.category, FindingCategory.NETWORK)
        self.assertEqual(f.status, FindingStatus.VALIDATED)
        self.assertEqual(f.confidence, FindingConfidence.CERTAIN)

    def test_wildcard_with_creds_severity_high(self):
        ev = _make_https_evidence_with_headers({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        result = self.rule.evaluate(self.session, [ev])
        f = result.findings[0]
        self.assertEqual(f.severity, FindingSeverity.HIGH)

    # --- 15. RuleEngine integration ---

    def test_rule_engine_integration(self):
        engine = RuleEngine()
        engine.register_rule(InsecureCORSRule())
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        results = engine.evaluate_all(self.session, [ev])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].triggered)

    # --- 16. Existing rules remain unaffected ---

    def test_existing_rules_remain_unaffected(self):
        engine = RuleEngine()
        engine.register_rule(TargetProcessObservedRule())
        engine.register_rule(ProxyConfiguredRule())
        engine.register_rule(CleartextTrafficRule())
        engine.register_rule(WeakTLSRule())
        engine.register_rule(WeakTLSCipherRule())
        engine.register_rule(MissingHSTSRule())
        engine.register_rule(MissingXCTORule())
        engine.register_rule(Rule008InsecureCookieAttributeRule())
        engine.register_rule(InsecureCORSRule())

        results = engine.evaluate_all(self.session, [])
        self.assertEqual(len(results), 9)
        rule_ids = [r.rule_id for r in results]
        self.assertIn("RULE-001", rule_ids)
        self.assertIn("RULE-002", rule_ids)
        self.assertIn("RULE-003", rule_ids)
        self.assertIn("RULE-004", rule_ids)
        self.assertIn("RULE-005", rule_ids)
        self.assertIn("RULE-006", rule_ids)
        self.assertIn("RULE-007", rule_ids)
        self.assertIn("RULE-008", rule_ids)
        self.assertIn("RULE-009", rule_ids)

    # --- Additional edge cases ---

    def test_http_traffic_also_evaluated(self):
        ev = _make_http_evidence_with_headers({"access-control-allow-origin": "*"})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)

    def test_non_traffic_evidence_ignored(self):
        ev = _make_evidence(
            EvidenceType.PROCESS_LIST.value,
            {"host": "example.com", "raw_metadata": {"response_headers": {"access-control-allow-origin": "*"}}},
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_empty_evidence_list(self):
        result = self.rule.evaluate(self.session, [])
        self.assertFalse(result.triggered)

    def test_null_raw_metadata_value(self):
        ev = _make_evidence(
            EvidenceType.HTTPS_TRAFFIC.value,
            {"host": "example.com", "raw_metadata": None},
        )
        result = self.rule.evaluate(self.session, [ev])
        self.assertFalse(result.triggered)

    def test_wildcard_with_whitespace(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": " * "})
        result = self.rule.evaluate(self.session, [ev])
        self.assertTrue(result.triggered)

    def test_finding_json_serializable(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        result = self.rule.evaluate(self.session, [ev])
        for finding in result.findings:
            serialized = json.dumps(finding.to_dict())
            self.assertIsInstance(serialized, str)

    def test_result_json_serializable(self):
        ev = _make_https_evidence_with_headers({"access-control-allow-origin": "*"})
        result = self.rule.evaluate(self.session, [ev])
        serialized = result.to_json()
        self.assertIsInstance(serialized, str)
        parsed = json.loads(serialized)
        self.assertIn("rule_id", parsed)


if __name__ == "__main__":
    unittest.main()
