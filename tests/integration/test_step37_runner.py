"""Real emulator integration test for Step 37 AnalysisRunner workflow (without APK)."""

import os
import shutil
import tempfile
import unittest

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


class TestStep37RunnerIntegration(unittest.TestCase):
    """Real integration test for AnalysisRunner workflow using analysis_baseline_api33."""

    def setUp(self) -> None:
        self.config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(self.config)
        self.runner = AnalysisRunner(orchestrator=self.orchestrator)
        self.temp_dir = tempfile.mkdtemp(prefix="step37_runner_")

    def tearDown(self) -> None:
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_real_emulator_runner_workflow_without_apk(self) -> None:
        print("\n--- Starting Step 37 AnalysisRunner Integration Test ---")
        job = AnalysisJob(apk_path="")

        result = self.runner.run(
            job=job,
            output_dir=self.temp_dir,
            boot_timeout=120.0,
        )

        print(f"Workflow Success: {result.success}")
        print(f"Final Job State: {job.state}")
        print(f"Captured Evidence Count: {len(result.evidence_items)}")
        print(f"Saved Evidence File: {result.evidence_file_path}")
        print(f"Execution Duration: {result.execution_duration:.2f}s")

        self.assertTrue(result.success, f"Runner workflow failed: {result.error_message}")
        self.assertIsNone(result.error_message)
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertIsNotNone(result.evidence_file_path)
        self.assertTrue(os.path.exists(result.evidence_file_path))
        self.assertGreater(len(result.evidence_items), 0)

        # Verify system property content
        prop_items = [e for e in result.evidence_items if e.evidence_type == "SYSTEM_PROPERTY"]
        prop_map = {p.source: p.content for p in prop_items}
        print(f"Captured Properties: {prop_map}")
        self.assertEqual(prop_map.get("ro.build.version.sdk"), "33")
        self.assertEqual(prop_map.get("sys.boot_completed"), "1")

        # Verify emulator process was cleanly shut down
        self.assertFalse(self.orchestrator.is_running(), "Emulator should not be running after workflow completion")
        print("--- Step 37 Integration Test Completed Successfully ---")


if __name__ == "__main__":
    unittest.main()
