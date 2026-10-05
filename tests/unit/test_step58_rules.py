import unittest
import json
from dynamic_analysis.rules import (
    RuleEngine,
    RuleResult,
    TargetProcessObservedRule,
    ProxyConfiguredRule,
    RuleValidationError,
    Rule,
    RuleError
)
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.finding import FindingCategory

class DummyRule(Rule):
    @property
    def rule_id(self) -> str:
        return "RULE-DUMMY"
    @property
    def name(self) -> str:
        return "Dummy Rule"
    @property
    def description(self) -> str:
        return "A rule for testing"
    @property
    def category(self) -> FindingCategory:
        return FindingCategory.MISC
    def evaluate(self, session, evidence_items):
        return RuleResult(rule_id=self.rule_id, triggered=False)

class TestRules(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="/fake.apk", package_name="com.example.mentorcraft2")
        self.engine = RuleEngine()

    def test_engine_registration(self):
        rule = DummyRule()
        self.engine.register_rule(rule)
        with self.assertRaises(RuleValidationError):
            self.engine.register_rule(rule)
        with self.assertRaises(RuleValidationError):
            self.engine.register_rule("not a rule")

    def test_target_process_rule_triggered(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content="com.example.mentorcraft2"
        )
        rule = TargetProcessObservedRule()
        res = rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].title, "Target Package Process Detected")
        self.assertEqual(res.findings[0].evidence_references[0], f"{ev.evidence_type}:{ev.timestamp}")

    def test_target_process_rule_not_triggered(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content="com.example.other"
        )
        rule = TargetProcessObservedRule()
        res = rule.evaluate(self.session, [ev])
        self.assertFalse(res.triggered)
        self.assertEqual(len(res.findings), 0)

    def test_proxy_configured_rule_triggered(self):
        ev = EvidenceItem(
            evidence_type=EvidenceType.PROXY_LIFECYCLE.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content="proxy started"
        )
        rule = ProxyConfiguredRule()
        res = rule.evaluate(self.session, [ev])
        self.assertTrue(res.triggered)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].title, "Network Proxy Configured")

    def test_rule_result_serialization(self):
        res = RuleResult(rule_id="TEST", triggered=False)
        d = res.to_dict()
        self.assertEqual(d["rule_id"], "TEST")
        self.assertEqual(d["triggered"], False)
        j = res.to_json()
        self.assertIn('"rule_id": "TEST"', j)

    def test_engine_evaluate_all(self):
        self.engine.register_rule(TargetProcessObservedRule())
        self.engine.register_rule(ProxyConfiguredRule())
        
        ev1 = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content="com.example.mentorcraft2"
        )
        ev2 = EvidenceItem(
            evidence_type=EvidenceType.PROXY_LIFECYCLE.value,
            timestamp=_get_utc_timestamp(),
            serial="test",
            source="test",
            content="started"
        )
        results = self.engine.evaluate_all(self.session, [ev1, ev2])
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].triggered)
        self.assertTrue(results[1].triggered)

    def test_engine_error_handling(self):
        class ErrorRule(DummyRule):
            def evaluate(self, session, evidence_items):
                raise ValueError("Oops")
        
        self.engine.register_rule(ErrorRule())
        results = self.engine.evaluate_all(self.session, [])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].triggered)
        self.assertIn("Oops", results[0].evaluation_details["error"])

if __name__ == "__main__":
    unittest.main()
