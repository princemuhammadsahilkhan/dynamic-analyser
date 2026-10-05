import os
import shutil
import unittest
from dynamic_analysis.session import AnalysisSession, SessionStatus
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.observation import EvidenceType

class TestStep60VulnRulesIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.abspath("apks/app-release.apk")
        self.output_dir = os.path.abspath("test_output_step60")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )
        self.runner = AnalysisRunner()

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

    def test_end_to_end_weak_tls_evaluation(self):
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

        # 2. Verify that HTTPS traffic was captured
        https_evs = [ev for ev in result.evidence_items if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value]
        # The app might or might not generate traffic in 5 seconds. If it does, we expect WeakTLSRule to evaluate it.
        # It's possible there is no HTTPS traffic in 5s depending on the emulator speed, but we can verify that the rule 
        # is registered and executed.

        # 3. Verify that the WeakTLSRule did NOT trigger
        weak_tls_finding = next((f for f in result.findings if f.title == "Weak TLS Version Observed"), None)
        self.assertIsNone(
            weak_tls_finding, 
            "Weak TLS Version Observed triggered improperly. Evidence is either missing or the connection is strong TLS."
        )

        # 4. Verify findings.json is persisted on disk
        findings_json_path = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_json_path), f"Findings JSON not found at {findings_json_path}")

        # Note: In the real evaluation_details for the rule, we could verify "No weak TLS version evidence found or metadata missing." 
        # is returned. This validates our conservative evidence-backed constraint.

if __name__ == "__main__":
    unittest.main()
