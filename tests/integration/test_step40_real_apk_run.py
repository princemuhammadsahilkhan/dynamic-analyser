"""Real integration test for Step 40: Real APK Installation, Package Verification, Launch, and Evidence Collection."""

import os
import shutil
import tempfile
import unittest

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


class TestStep40RealAPKRun(unittest.TestCase):
    """Real integration test for executing apks/app-release.apk against analysis_baseline_api33 AVD."""

    def setUp(self) -> None:
        self.apk_path = "apks/app-release.apk"
        self.config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(self.config)
        self.runner = AnalysisRunner(orchestrator=self.orchestrator)
        self.temp_dir = tempfile.mkdtemp(prefix="step40_apk_run_")

    def tearDown(self) -> None:
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_real_apk_installation_verification_launch_lifecycle(self) -> None:
        print("\n--- Starting Step 40 Real APK Dynamic Analysis Workflow ---")
        job = AnalysisJob(apk_path=self.apk_path)

        result = self.runner.run(
            job=job,
            output_dir=self.temp_dir,
            boot_timeout=120.0,
        )

        print(f"Workflow Success: {result.success}")
        print(f"Final Job State: {job.state}")
        print(f"Execution Duration: {result.execution_duration:.2f}s")
        print(f"Saved Evidence File: {result.evidence_file_path}")

        if not result.success:
            print(f"Error Message: {result.error_message}")

        self.assertTrue(result.success, f"Workflow execution failed: {result.error_message}")
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertIsNotNone(result.apk_result, "APK result should be populated")

        apk_res = result.apk_result
        print(f"\n--- APK Lifecycle Result ---")
        print(f"APK Path: {apk_res.apk_path}")
        print(f"Package Name: {apk_res.package_name}")
        print(f"Launchable Activity: {apk_res.launchable_activity}")
        print(f"Installed: {apk_res.installed}")
        print(f"Verified: {apk_res.verified}")
        print(f"Launched: {apk_res.launched}")
        print(f"Install Output: {apk_res.install_output}")
        print(f"Launch Output: {apk_res.launch_output}")

        self.assertEqual(apk_res.package_name, "com.example.mentorcraft2")
        self.assertEqual(apk_res.launchable_activity, "com.example.mentorcraft2.MainActivity")
        self.assertTrue(apk_res.installed, "APK installation should succeed")
        self.assertTrue(apk_res.verified, "Package pm verification should succeed")
        self.assertTrue(apk_res.launched, "Activity am start launch should succeed")

        # Verify evidence items
        self.assertGreater(len(result.evidence_items), 0, "Evidence items must not be empty")
        self.assertIsNotNone(result.evidence_file_path)
        self.assertTrue(os.path.exists(result.evidence_file_path))

        # Check process list for app process
        proc_items = [e for e in result.evidence_items if e.evidence_type == "PROCESS_LIST"]
        app_running = False
        for item in proc_items:
            if "com.example.mentorcraft2" in item.content:
                app_running = True
                break

        print(f"Target App Process Detected in Process List: {app_running}")

        # Verify emulator cleanup
        self.assertFalse(self.orchestrator.is_running(), "Emulator process should be shut down cleanly")
        print("--- Step 40 Real APK Dynamic Analysis Completed Successfully ---")


if __name__ == "__main__":
    unittest.main()
