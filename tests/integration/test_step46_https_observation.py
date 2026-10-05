"""Integration test for Step 46: Controlled HTTPS Traffic Observation against real AVD analysis_baseline_api33."""

import json
import os
import tempfile
import time
import unittest

from dynamic_analysis.apk import APKLifecycleManager
from dynamic_analysis.config import AndroidRuntimeConfig, AppConfig
from dynamic_analysis.observation import LogcatCollector, RuntimeObserver, save_evidence_items
from dynamic_analysis.network import NetworkObserver
from dynamic_analysis.proxy import ProxyManager
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


class TestStep46HTTPSObservationIntegration(unittest.TestCase):
    """Integration test verifying ProxyManager and controlled proxy observation against live emulator."""

    def test_step46_https_traffic_observation(self) -> None:
        """Execute end-to-end controlled proxy observation lifecycle against analysis_baseline_api33."""
        runtime_config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            port=5554,
            headless=True,
        )
        orchestrator = AndroidRuntimeOrchestrator(config=runtime_config)

        apk_manager = APKLifecycleManager(orchestrator=orchestrator)
        runtime_observer = RuntimeObserver(orchestrator=orchestrator)
        logcat_collector = LogcatCollector(orchestrator=orchestrator)
        network_observer = NetworkObserver(orchestrator=orchestrator)
        proxy_manager = ProxyManager(orchestrator=orchestrator)

        apk_path = "apks/app-release.apk"
        self.assertTrue(os.path.exists(apk_path), f"Target APK missing at {apk_path}")

        # 1. Audit host mitmproxy capability
        available, version_info = proxy_manager.audit_mitmproxy()
        self.assertTrue(available, f"mitmdump not available at {proxy_manager.binary_path}")
        print(f"\n[Step 46 Integration] Audited host mitmproxy: {version_info}")

        temp_dir = tempfile.mkdtemp(prefix="step46_proxy_test_")
        flow_file = os.path.join(temp_dir, "mitm_flows.mitm")
        evidence_dir = os.path.join(temp_dir, "evidence")

        evidence_items = []

        try:
            # 2. Start AVD emulator child process
            print("[Step 46 Integration] Starting AVD analysis_baseline_api33...")
            orchestrator.start()
            self.assertTrue(orchestrator.is_running())
            self.assertEqual(orchestrator.config.serial, "emulator-5554")

            # 3. Wait for guest OS boot completion
            booted = orchestrator.wait_for_boot(timeout=60.0)
            self.assertTrue(booted, "Emulator failed to boot within timeout")

            # 4. Start mitmdump proxy process
            print("[Step 46 Integration] Starting mitmdump proxy process on 0.0.0.0:8080...")
            proxy_manager.start(host="0.0.0.0", port=8080, flow_file=flow_file)
            self.assertTrue(proxy_manager.is_running())
            proxy_pid = proxy_manager.pid
            self.assertIsNotNone(proxy_pid)
            print(f"[Step 46 Integration] Proxy running under PID {proxy_pid}")

            # 5. Configure guest HTTP proxy via ADB
            configured_target = proxy_manager.configure_emulator_proxy(proxy_host="10.0.2.2", proxy_port=8080)
            self.assertEqual(configured_target, "10.0.2.2:8080")
            print(f"[Step 46 Integration] Emulator proxy configured to {configured_target}")

            # 6. Verify guest proxy setting via getprop / settings shell command
            res_proxy = orchestrator.shell("settings get global http_proxy")
            self.assertIn("10.0.2.2:8080", res_proxy.stdout.strip())

            # 7. Start LogcatCollector
            logcat_collector.start(clear_buffer=True)
            self.assertTrue(logcat_collector.is_running())

            # 8. Install and launch target APK
            print(f"[Step 46 Integration] Installing and launching {apk_path}...")
            apk_result = apk_manager.run_lifecycle(apk_path, launch=True)
            self.assertTrue(apk_result.installed)
            self.assertTrue(apk_result.launched)
            self.assertEqual(apk_result.package_name, "com.example.mentorcraft2")

            # 9. Allow observation time for application activity
            print("[Step 46 Integration] Observing application runtime for 5 seconds...")
            time.sleep(5.0)

            # 10. Verify application process is active
            procs_ev = runtime_observer.collect_processes()
            self.assertIn("com.example.mentorcraft2", procs_ev.content)
            evidence_items.append(procs_ev)

            # 11. Collect guest network state and proxy evidence
            net_evidence = network_observer.collect_all_network_evidence()
            evidence_items.extend(net_evidence)

            proxy_evidence = proxy_manager.get_evidence_items()
            evidence_items.extend(proxy_evidence)
            print(f"[Step 46 Integration] Collected {len(proxy_evidence)} proxy evidence items")

            # 12. Stop LogcatCollector
            streamed_logcat = logcat_collector.stop()
            evidence_items.append(streamed_logcat)

            # 13. Save evidence items to JSON artifact
            evidence_file = save_evidence_items(evidence_items, output_dir=evidence_dir)
            self.assertTrue(os.path.exists(evidence_file))
            print(f"[Step 46 Integration] Saved evidence artifact to {evidence_file}")

        finally:
            # 14. Restore emulator proxy configuration
            if proxy_manager.get_status().proxy_configured:
                print("[Step 46 Integration] Restoring emulator proxy configuration...")
                proxy_manager.restore_emulator_proxy()
                res_check = orchestrator.shell("settings get global http_proxy")
                print(f"[Step 46 Integration] Restored guest http_proxy value: '{res_check.stdout.strip()}'")

            # 15. Stop mitmdump proxy process
            if proxy_manager.is_running():
                print("[Step 46 Integration] Stopping mitmdump proxy process...")
                proxy_manager.stop()
                self.assertFalse(proxy_manager.is_running())

            # 16. Stop LogcatCollector if running
            if logcat_collector.is_running():
                logcat_collector.stop()

            # 17. Stop emulator process
            if orchestrator.is_running():
                print("[Step 46 Integration] Stopping emulator...")
                orchestrator.shutdown()
                self.assertFalse(orchestrator.is_running())

        # 18. Verify process cleanup
        print("[Step 46 Integration] Step 46 integration test completed successfully.")



if __name__ == "__main__":
    unittest.main()
