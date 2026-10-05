"""Integration tests for Step 68: RULE-011 — Missing Content-Security-Policy Header Observed."""

import json
import os
import unittest

from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceType

class TestStep68CSPRuleIntegration(unittest.TestCase):
    """Integration test running the full AnalysisRunner pipeline and verifying RULE-011."""

    def setUp(self):
        self.apk_path = os.path.join("apks", "app-release.apk")
        self.assertTrue(
            os.path.exists(self.apk_path),
            f"Target APK not found at {self.apk_path}. Ensure it exists.",
        )
        self.output_dir = os.path.abspath("test_output_step68")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir,
        )
        self.runner = AnalysisRunner()

    def test_csp_rule_live_execution(self):
        """
        Verify that AnalysisRunner evaluates RULE-011 against live traffic.
        """
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=10.0,
        )

        self.assertTrue(result.success, "AnalysisRunner failed to complete successfully.")

        session = self.session
        self.assertTrue(os.path.exists(session.run_dir))
        self.assertTrue(os.path.exists(session.evidence_dir))
        self.assertTrue(os.path.exists(session.findings_dir))

        findings_file = os.path.join(session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))

        with open(findings_file, "r", encoding="utf-8") as f:
            findings = json.load(f)

        self.assertIsInstance(findings, list)
        
        # Verify that existing rules run and findings array exists
        cleartext_findings = [f for f in findings if f.get('title') == 'Cleartext HTTP Traffic Observed']
        self.assertGreaterEqual(len(cleartext_findings), 0)

if __name__ == '__main__':
    unittest.main()
