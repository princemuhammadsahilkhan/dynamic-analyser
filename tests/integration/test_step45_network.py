"""Real integration test for Step 45: Controlled Network Observation Foundation."""

import os
import shutil
import tempfile
import unittest

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.network import NetworkObserver
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


class TestStep45NetworkIntegration(unittest.TestCase):
    """Real integration test verifying NetworkObserver against analysis_baseline_api33 and apks/app-release.apk."""

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
        self.network_observer = NetworkObserver(self.orchestrator)
        self.temp_dir = tempfile.mkdtemp(prefix="step45_network_")

    def tearDown(self) -> None:
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_real_network_observation_foundation(self) -> None:
        print("\n--- Starting Step 45 Network Observation Integration Test ---")

        # Audit host proxy capability
        avail, version_info = self.network_observer.check_host_proxy_capability()
        print(f"Host Proxy Audited (mitmproxy): Available={avail}, Detail={version_info}")
        self.assertTrue(avail, "Host should have mitmproxy installed")

        # Execute AnalysisRunner workflow with target APK
        job = AnalysisJob(apk_path=self.apk_path)
        result = self.runner.run(
            job=job,
            output_dir=self.temp_dir,
            boot_timeout=120.0,
        )

        print(f"Workflow Success: {result.success}")
        print(f"Final Job State: {job.state}")
        print(f"Total Evidence Items: {len(result.evidence_items)}")
        print(f"Saved Evidence JSON: {result.evidence_file_path}")

        self.assertTrue(result.success, f"Workflow failed: {result.error_message}")
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertIsNotNone(result.evidence_file_path)
        self.assertTrue(os.path.exists(result.evidence_file_path))

        # Inspect network evidence items
        network_types = {
            "NETWORK_INTERFACE",
            "NETWORK_ROUTE",
            "NETWORK_DNS",
            "NETWORK_CONNECTIONS",
            "NETWORK_PROPERTIES",
            "NETWORK_DUMPSYS",
        }
        captured_types = {e.evidence_type for e in result.evidence_items}
        found_network = captured_types.intersection(network_types)

        print(f"Captured Network Evidence Types: {found_network}")
        self.assertGreater(len(found_network), 0, "Network evidence types must be captured")

        for item in result.evidence_items:
            if item.evidence_type in network_types:
                print(f"[{item.evidence_type}] Source: {item.source}, Length: {len(item.content)} bytes")

        # Confirm app launch
        self.assertIsNotNone(result.apk_result)
        self.assertTrue(result.apk_result.launched)
        print(f"App Successfully Launched: {result.apk_result.package_name}/{result.apk_result.launchable_activity}")

        # Clean shutdown check
        self.assertFalse(self.orchestrator.is_running(), "Emulator process should be shut down cleanly")
        print("--- Step 45 Network Observation Integration Test Completed ---")


if __name__ == "__main__":
    unittest.main()
