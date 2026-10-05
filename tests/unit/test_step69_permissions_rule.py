import unittest
from typing import List

from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.rules import (
    SensitivePermissionObservedRule,
    FindingSeverity,
    FindingCategory,
)
from dynamic_analysis.session import AnalysisSession


class TestSensitivePermissionObservedRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="/fake/path.apk", package_name="com.example.app")
        self.rule = SensitivePermissionObservedRule()

    def test_sensitive_permission_observed_declared(self):
        """Test that a declared sensitive permission is detected."""
        content = (
            "Packages:\n"
            "  Package [com.example.app] (2d87a41):\n"
            "    requested permissions:\n"
            "      android.permission.CAMERA\n"
            "      android.permission.INTERNET\n"
            "    install permissions:\n"
            "      android.permission.INTERNET: granted=true\n"
        )
        
        evidence = [
            EvidenceItem(
                evidence_type=EvidenceType.PERMISSIONS.value,
                timestamp="2024-01-01T12:00:00Z",
                serial="emulator-5554",
                source="dumpsys package com.example.app",
                content=content,
                exit_code=0
            )
        ]
        
        result = self.rule.evaluate(self.session, evidence)
        
        self.assertEqual(result.rule_id, "RULE-012")
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 1)
        
        finding = result.findings[0]
        self.assertEqual(finding.severity, FindingSeverity.INFO)
        self.assertEqual(finding.category, FindingCategory.AUTHENTICATION)
        self.assertIn("android.permission.CAMERA", finding.title)
        self.assertIn("declared/requested", finding.description)

    def test_sensitive_permission_observed_runtime(self):
        """Test that a runtime granted sensitive permission is detected."""
        content = (
            "Packages:\n"
            "  Package [com.example.app] (2d87a41):\n"
            "    requested permissions:\n"
            "      android.permission.ACCESS_FINE_LOCATION\n"
            "    runtime permissions:\n"
            "      android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ user_set ]\n"
        )
        
        evidence = [
            EvidenceItem(
                evidence_type=EvidenceType.PERMISSIONS.value,
                timestamp="2024-01-01T12:00:00Z",
                serial="emulator-5554",
                source="dumpsys package com.example.app",
                content=content,
                exit_code=0
            )
        ]
        
        result = self.rule.evaluate(self.session, evidence)
        
        self.assertEqual(result.rule_id, "RULE-012")
        self.assertTrue(result.triggered)
        self.assertEqual(len(result.findings), 2)
        
        descriptions = [f.description for f in result.findings]
        self.assertTrue(any("declared/requested" in desc for desc in descriptions))
        self.assertTrue(any("runtime-granted" in desc for desc in descriptions))

    def test_no_sensitive_permissions(self):
        """Test that rule does not trigger if no sensitive permissions exist."""
        content = (
            "Packages:\n"
            "  Package [com.example.app] (2d87a41):\n"
            "    requested permissions:\n"
            "      android.permission.INTERNET\n"
            "      android.permission.ACCESS_NETWORK_STATE\n"
        )
        
        evidence = [
            EvidenceItem(
                evidence_type=EvidenceType.PERMISSIONS.value,
                timestamp="2024-01-01T12:00:00Z",
                serial="emulator-5554",
                source="dumpsys package com.example.app",
                content=content,
                exit_code=0
            )
        ]
        
        result = self.rule.evaluate(self.session, evidence)
        
        self.assertEqual(result.rule_id, "RULE-012")
        self.assertFalse(result.triggered)
        self.assertEqual(len(result.findings), 0)

    def test_wrong_evidence_type(self):
        """Test that rule ignores non-permissions evidence."""
        evidence = [
            EvidenceItem(
                evidence_type=EvidenceType.HTTP_TRAFFIC.value,
                timestamp="2024-01-01T12:00:00Z",
                serial="proxy",
                source="mitmproxy",
                content='{"request": {"method": "GET"}, "response": {"status_code": 200}}',
                exit_code=0
            )
        ]
        
        result = self.rule.evaluate(self.session, evidence)
        
        self.assertEqual(result.rule_id, "RULE-012")
        self.assertFalse(result.triggered)

if __name__ == "__main__":
    unittest.main()
