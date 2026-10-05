import os
import shutil
import unittest
from dynamic_analysis.session import AnalysisSession, SessionStatus
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.observation import EvidenceType

class TestStep59VulnRulesIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.abspath("apks/app-release.apk")
        self.output_dir = os.path.abspath("test_output_step59")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )
        self.runner = AnalysisRunner()

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

    def test_end_to_end_vuln_rule_evaluation(self):
        # Run the full analysis workflow with proxy enabled
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=5.0
        )

        self.assertTrue(result.success, f"Run failed: {result.error_message}")
        self.assertEqual(self.session.status, SessionStatus.COMPLETED)

        # 1. Verify proxy lifecycle evidence was collected
        proxy_evs = [ev for ev in result.evidence_items if ev.evidence_type == EvidenceType.PROXY_LIFECYCLE.value]
        self.assertGreater(len(proxy_evs), 0, "Proxy was not started/collected")

        # 2. Verify we generated at least the non-vuln finding for proxy configuration
        proxy_finding = next((f for f in result.findings if f.title == "Network Proxy Configured"), None)
        self.assertIsNotNone(proxy_finding, "Expected 'Network Proxy Configured' finding to trigger")

        # 3. Verify that the CleartextTrafficRule did NOT trigger
        cleartext_finding = next((f for f in result.findings if f.title == "Cleartext HTTP Traffic Observed"), None)
        self.assertIsNone(
            cleartext_finding, 
            "Cleartext HTTP Traffic rule triggered improperly. The app uses HTTPS, so this should not trigger."
        )

        # 4. We can optionally inspect the evaluation details of the session/result if we exposed them, 
        # but verifying the finding is absent is the primary goal for negative testing of vulnerability rules.
        
        # 5. Verify findings.json is persisted on disk
        findings_json_path = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_json_path), f"Findings JSON not found at {findings_json_path}")

if __name__ == "__main__":
    unittest.main()
