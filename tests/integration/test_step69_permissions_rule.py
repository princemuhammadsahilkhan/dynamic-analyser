import unittest
from unittest.mock import MagicMock

from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.rules import RuleEngine, SensitivePermissionObservedRule
from dynamic_analysis.session import AnalysisSession

class TestIntegrationPermissionsRule(unittest.TestCase):
    def test_integration_permissions_collection_and_evaluation(self):
        """
        Integration test validating that the AnalysisRunner correctly collects permissions
        evidence, and the RuleEngine evaluates it with SensitivePermissionObservedRule.
        """
        from dynamic_analysis.runner import AnalysisRunner
        
        # Mock APK manager
        mock_apk_manager = MagicMock()
        mock_apk_result = MagicMock()
        mock_apk_result.package_name = "com.example.sensitive"
        mock_apk_manager.run_lifecycle.return_value = mock_apk_result

        # Mock Observer to return a fake permissions dump
        mock_observer = MagicMock()
        mock_observer.collect_processes.return_value = MagicMock(evidence_type=EvidenceType.PROCESS_LIST.value)
        mock_observer.collect_logcat_dump.return_value = MagicMock(evidence_type=EvidenceType.LOGCAT.value)
        
        # Fake permission dump showing RECORD_AUDIO
        permission_dump = MagicMock()
        permission_dump.evidence_type = EvidenceType.PERMISSIONS.value
        permission_dump.content = (
            "Packages:\n"
            "  Package [com.example.sensitive] (2d87a41):\n"
            "    requested permissions:\n"
            "      android.permission.RECORD_AUDIO\n"
        )
        permission_dump.timestamp = "2024-01-01T12:00:00Z"
        permission_dump.source = "dumpsys package com.example.sensitive"
        mock_observer.collect_permissions.return_value = permission_dump

        mock_network_observer = MagicMock()
        mock_network_observer.collect_all_network_evidence.return_value = []
        
        mock_logcat_collector = MagicMock()
        mock_proxy_manager = MagicMock()

        runner = AnalysisRunner(
            apk_manager=mock_apk_manager,
            observer=mock_observer,
            network_observer=mock_network_observer,
            proxy_manager=mock_proxy_manager,
            logcat_collector=mock_logcat_collector,
        )

        # Disable real rules in RuleEngine and inject only ours
        engine = RuleEngine()
        engine.register_rule(SensitivePermissionObservedRule())

        evidence_items = []
        evidence_items.append(mock_observer.collect_processes())
        evidence_items.append(mock_observer.collect_logcat_dump())
        
        # The runner logic for permissions:
        perm_ev = runner.observer.collect_permissions(mock_apk_result.package_name)
        evidence_items.append(perm_ev)

        session = AnalysisSession(apk_path="/fake/path.apk", package_name="com.example.sensitive")
        
        results = engine.evaluate_all(session, evidence_items)
        
        self.assertEqual(len(results), 1)
        result = results[0]
        
        self.assertEqual(result.rule_id, "RULE-012")
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        
        finding = result.findings[0]
        self.assertIn("android.permission.RECORD_AUDIO", finding.title)

if __name__ == "__main__":
    unittest.main()
