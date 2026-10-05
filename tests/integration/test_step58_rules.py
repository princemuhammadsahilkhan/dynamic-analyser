import os
import unittest
import json
import shutil
from typing import List, Dict, Any

from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession, SessionStatus
from dynamic_analysis.runtime import AndroidRuntimeConfig, AndroidRuntimeOrchestrator
from dynamic_analysis.observation import EvidenceType

class TestStep58RulesIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.abspath("apks/app-release.apk")
        self.output_dir = os.path.abspath("test_output_step58")
        
        # Ensure we have the target APK
        self.assertTrue(os.path.exists(self.apk_path), f"APK not found at {self.apk_path}")

        # Cleanup any previous output
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554
        )
        orchestrator = AndroidRuntimeOrchestrator(config)
        self.runner = AnalysisRunner(orchestrator=orchestrator)
        
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )

    def tearDown(self):
        # Guarantee orchestrator is shut down
        if self.runner.orchestrator.is_running():
            self.runner.orchestrator.shutdown()
        
        # Optional: Keep output for debugging, but normally we'd clean up
        # if os.path.exists(self.output_dir):
        #    shutil.rmtree(self.output_dir)
        pass

    def test_end_to_end_rule_engine(self):
        # Run analysis, expecting rules to trigger
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=5.0
        )
        
        self.assertTrue(result.success, f"Run failed: {result.error_message}")
        self.assertEqual(result.session.status, SessionStatus.COMPLETED)
        
        # 1. Verify findings exist in memory
        self.assertGreaterEqual(len(result.findings), 2, "Expected at least 2 findings (Process + Proxy)")
        
        titles = [f.title for f in result.findings]
        self.assertIn("Target Package Process Detected", titles)
        self.assertIn("Network Proxy Configured", titles)
        
        # 2. Verify PROCESS_LIST evidence is referenced properly
        process_finding = next(f for f in result.findings if f.title == "Target Package Process Detected")
        self.assertEqual(len(process_finding.evidence_references), 1)
        self.assertTrue(process_finding.evidence_references[0].startswith(EvidenceType.PROCESS_LIST.value))
        
        # 3. Verify Proxy configured finding references PROXY_LIFECYCLE
        proxy_finding = next(f for f in result.findings if f.title == "Network Proxy Configured")
        self.assertEqual(len(proxy_finding.evidence_references), 1)
        self.assertTrue(proxy_finding.evidence_references[0].startswith(EvidenceType.PROXY_LIFECYCLE.value))
        
        # 4. Verify findings.json is persisted on disk
        findings_json_path = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_json_path), "findings.json not created")
        
        with open(findings_json_path, "r", encoding="utf-8") as f:
            disk_findings = json.load(f)
            
        self.assertEqual(len(disk_findings), len(result.findings))
        disk_titles = [f["title"] for f in disk_findings]
        self.assertIn("Target Package Process Detected", disk_titles)
        self.assertIn("Network Proxy Configured", disk_titles)
        
        # 5. Verify cleanup
        self.assertFalse(self.runner.orchestrator.is_running())
        self.assertFalse(self.runner.proxy_manager.is_running())
        self.assertFalse(self.runner.logcat_collector.is_running())

if __name__ == "__main__":
    unittest.main()
