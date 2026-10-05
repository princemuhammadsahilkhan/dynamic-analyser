"""Real emulator integration test for Step 57 — Finding Generation Foundation."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator
from dynamic_analysis.session import AnalysisSession, SessionStatus
from dynamic_analysis.finding import FindingSeverity, FindingCategory, FindingStatus, FindingConfidence


APK_PATH = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "apks", "app-release.apk"
)
PACKAGE_NAME = "com.example.mentorcraft2"


class TestStep57FindingRunnerIntegration(unittest.TestCase):
    """Real integration test: AnalysisRunner with finding generation
    using analysis_baseline_api33 and the target APK."""

    def setUp(self) -> None:
        self.config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(self.config)
        self.runner = AnalysisRunner(orchestrator=self.orchestrator)
        self.temp_dir = tempfile.mkdtemp(prefix="step57_finding_")
        self.apk_path = os.path.abspath(APK_PATH)

    def tearDown(self) -> None:
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _check_no_orphan_processes(self) -> None:
        """Verify no orphan qemu/adb/mitmdump processes remain."""
        for pname in ("qemu-system-x86_64", "mitmdump"):
            result = subprocess.run(
                ["pgrep", "-f", pname],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode,
                1,
                f"Orphan {pname} process detected: {result.stdout.strip()}",
            )

    def test_finding_generation_lifecycle(self) -> None:
        """Verify Finding generation and persistence through a real APK analysis run."""
        print("\n--- Starting Step 57 Finding Runner Integration Test ---")

        # 1. Create an AnalysisSession
        session = AnalysisSession(
            apk_path=self.apk_path,
            package_name=PACKAGE_NAME,
            base_output_dir=self.temp_dir,
        )

        # 2. Run the analysis with the session
        result = self.runner.run(
            apk_path=self.apk_path,
            session=session,
            boot_timeout=120.0,
            observation_duration=5.0,
        )

        # 3. Verify run success
        self.assertTrue(result.success, f"Runner workflow failed: {result.error_message}")
        self.assertEqual(session.status, SessionStatus.COMPLETED)

        # 4. Verify we found the expected finding
        self.assertIsNotNone(result.findings)
        self.assertGreaterEqual(len(result.findings), 1, "Expected at least one finding to be generated")
        
        target_finding = None
        for f in result.findings:
            if f.title == "Target Package Process Detected":
                target_finding = f
                break
        
        self.assertIsNotNone(target_finding, "Expected 'Target Package Process Detected' finding was not generated")
        
        # 5. Verify the finding fields
        self.assertEqual(target_finding.severity, FindingSeverity.INFO)
        self.assertEqual(target_finding.category, FindingCategory.MISC)
        self.assertEqual(target_finding.status, FindingStatus.VALIDATED)
        self.assertEqual(target_finding.confidence, FindingConfidence.CERTAIN)
        self.assertEqual(target_finding.analysis_id, session.analysis_id)
        
        # 6. Verify evidence reference
        self.assertGreater(len(target_finding.evidence_references), 0)
        self.assertTrue(target_finding.evidence_references[0].startswith("PROCESS_LIST:"))
        print(f"Finding Evidence Reference: {target_finding.evidence_references[0]}")

        # 7. Verify persistence in findings.json
        findings_file = os.path.join(session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r") as f:
            persisted_data = json.load(f)
            
        self.assertIsInstance(persisted_data, list)
        self.assertGreaterEqual(len(persisted_data), 1)
        
        persisted_target = None
        for p in persisted_data:
            if p["title"] == "Target Package Process Detected":
                persisted_target = p
                break
                
        self.assertIsNotNone(persisted_target)
        self.assertEqual(persisted_target["severity"], "INFO")
        self.assertEqual(persisted_target["category"], "MISC")
        self.assertEqual(persisted_target["status"], "VALIDATED")
        self.assertEqual(persisted_target["confidence"], "CERTAIN")
        self.assertEqual(persisted_target["finding_id"], target_finding.finding_id)
        self.assertEqual(persisted_target["evidence_references"], target_finding.evidence_references)
        print(f"Findings persisted successfully to {findings_file}")

        # 8. Verify APK and basic runner functionality still works
        self.assertTrue(result.apk_result.installed)
        self.assertTrue(result.apk_result.launched)
        
        # 9. Verify cleanup
        self.assertFalse(self.orchestrator.is_running())
        self._check_no_orphan_processes()

        print("--- Step 57 Integration Test Completed Successfully ---")


if __name__ == "__main__":
    unittest.main()
