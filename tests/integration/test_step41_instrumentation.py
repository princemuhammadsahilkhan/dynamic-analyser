"""Real integration test for Step 41: Controlled Dynamic Instrumentation Boundary."""

import os
import shutil
import tempfile
import unittest

from dynamic_analysis.apk import APKLifecycleManager
from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.instrumentation import InstrumentationManager, InstrumentationStatus
from dynamic_analysis.observation import LogcatCollector, RuntimeObserver, save_evidence_items
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


class TestStep41InstrumentationIntegration(unittest.TestCase):
    """Real integration test verifying InstrumentationManager against analysis_baseline_api33."""

    def setUp(self) -> None:
        self.apk_path = "apks/app-release.apk"
        self.package_name = "com.example.mentorcraft2"
        self.config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(self.config)
        self.apk_manager = APKLifecycleManager(self.orchestrator)
        self.logcat_collector = LogcatCollector(self.orchestrator)
        self.observer = RuntimeObserver(self.orchestrator)
        self.instrumentation_mgr = InstrumentationManager(self.orchestrator)
        self.temp_dir = tempfile.mkdtemp(prefix="step41_instrumentation_")

    def tearDown(self) -> None:
        if self.logcat_collector.is_running():
            try:
                self.logcat_collector.stop()
            except Exception:
                pass
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_real_emulator_instrumentation_boundary(self) -> None:
        print("\n--- Starting Step 41 Instrumentation Boundary Integration Test ---")

        # 1. Start emulator and wait for boot
        self.orchestrator.start()
        self.orchestrator.wait_for_boot(timeout=120.0)
        self.assertTrue(self.orchestrator.is_running())

        # 2. Start logcat stream collector
        self.logcat_collector.start(clear_buffer=True)

        # 3. Install and launch target APK
        apk_result = self.apk_manager.run_lifecycle(self.apk_path, launch=True)
        self.assertTrue(apk_result.installed)
        self.assertTrue(apk_result.verified)
        self.assertTrue(apk_result.launched)
        print(f"App Launched: {apk_result.package_name}/{apk_result.launchable_activity}")

        # 4. Attempt instrumentation connectivity check
        instr_result = self.instrumentation_mgr.attach(self.package_name, timeout=3.0)
        print(f"\n--- Instrumentation Boundary Status ---")
        print(f"Target Package: {instr_result.target_package}")
        print(f"Frida Client Version: {instr_result.frida_client_version or 'Not Installed in Host Python'}")
        print(f"Instrumentation Status: {instr_result.status}")
        print(f"Connected: {instr_result.connected}")
        print(f"Proof of Connectivity: {instr_result.proof_of_connectivity}")
        print(f"Detail Message: {instr_result.error_message}")

        # Convert result to evidence item
        instr_evidence = instr_result.to_evidence_item(serial=self.config.serial)

        # 5. Collect post-launch process and logcat evidence
        procs = self.observer.collect_processes()
        logcat_dump = self.observer.collect_logcat_dump()
        streamed_logcat = self.logcat_collector.stop()

        all_evidence = [instr_evidence, procs, logcat_dump, streamed_logcat]
        evidence_file = save_evidence_items(all_evidence, self.temp_dir, "step41_evidence.json")
        self.assertTrue(os.path.exists(evidence_file))
        print(f"Saved Evidence Artifact: {evidence_file}")

        # 6. Shutdown emulator
        self.orchestrator.shutdown()
        self.assertFalse(self.orchestrator.is_running())
        print("--- Step 41 Instrumentation Integration Test Completed ---")


if __name__ == "__main__":
    unittest.main()
