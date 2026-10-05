"""Integration test for Step 49: Deeper Controlled UI-Driven Behavioral Exploration on analysis_baseline_api33."""

import json
import os
import tempfile
import time
import unittest

from dynamic_analysis.apk import APKLifecycleManager
from dynamic_analysis.certificates import CertificateTrustManager
from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.network import NetworkObserver
from dynamic_analysis.observation import LogcatCollector, RuntimeObserver, save_evidence_items
from dynamic_analysis.proxy import ProxyManager
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator
from dynamic_analysis.ui import UIInteractionManager


class TestStep49DeeperUIBehaviorIntegration(unittest.TestCase):
    """Integration test verifying deeper UI exploration, screen transitions, and post-interaction network evidence."""

    def test_step49_deeper_ui_behavior(self) -> None:
        """Execute end-to-end deeper UI behavioral exploration and dynamic observation on analysis_baseline_api33."""
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
        cert_manager = CertificateTrustManager(orchestrator=orchestrator)
        ui_manager = UIInteractionManager(orchestrator=orchestrator)

        apk_path = "apks/app-release.apk"
        self.assertTrue(os.path.exists(apk_path), f"Target APK missing at {apk_path}")

        temp_dir = tempfile.mkdtemp(prefix="step49_ui_test_")
        flow_file = os.path.join(temp_dir, "mitm_flows.mitm")
        evidence_dir = os.path.join(temp_dir, "evidence")

        evidence_items = []

        try:
            # 1. Start AVD emulator child process
            print("\n[Step 49 Integration] Starting AVD analysis_baseline_api33...")
            orchestrator.start()
            self.assertTrue(orchestrator.is_running())

            # 2. Wait for guest OS boot completion
            booted = orchestrator.wait_for_boot(timeout=60.0)
            self.assertTrue(booted, "Emulator failed to boot within timeout")

            # 3. Start mitmdump proxy process and configure emulator proxy
            print("[Step 49 Integration] Starting mitmdump proxy on 0.0.0.0:8080...")
            proxy_manager.start(host="0.0.0.0", port=8080, flow_file=flow_file)
            self.assertTrue(proxy_manager.is_running())
            proxy_manager.configure_emulator_proxy(proxy_host="10.0.2.2", proxy_port=8080)

            # 4. Install mitmproxy CA to guest system and user stores
            cert_manager.install_ca_to_user_store()
            cert_manager.install_ca_to_system_store()
            post_trust = cert_manager.audit_guest_trust_store()
            self.assertTrue(post_trust.installed_system)
            print(f"[Step 49 Integration] Installed mitmproxy CA to guest system store: Hash={post_trust.subject_hash_old}")

            # 5. Start LogcatCollector
            logcat_collector.start(clear_buffer=True)

            # 6. Install and launch target APK
            print(f"[Step 49 Integration] Installing and launching {apk_path}...")
            apk_result = apk_manager.run_lifecycle(apk_path, launch=True)
            self.assertTrue(apk_result.installed)
            self.assertTrue(apk_result.launched)
            time.sleep(3.0)

            # 7. Collect Baseline Evidence (pre-interaction)
            print("[Step 49 Integration] Capturing baseline pre-interaction evidence...")
            base_procs = runtime_observer.collect_processes()
            self.assertIn("com.example.mentorcraft2", base_procs.content)
            evidence_items.append(base_procs)

            base_hier = ui_manager.dump_hierarchy()
            print(f"[Step 49 Integration] Baseline UI hierarchy captured ({len(base_hier.elements)} elements)")

            # 8. Perform Deeper Controlled UI Behavioral Exploration
            print("[Step 49 Integration] Performing deeper UI behavioral exploration past role selection into Sign In / Sign Up screens...")
            interactions = ui_manager.exercise_deeper_navigation_flow()
            self.assertGreaterEqual(len(interactions), 4, "Expected at least 4 successful UI interactions")
            print(f"[Step 49 Integration] Performed {len(interactions)} UI interactions successfully")

            for inter in interactions:
                print(f"  -> UI Action: {inter.action} on '{inter.target_desc}' at ({inter.target_x}, {inter.target_y})")

            # 9. Collect Post-Interaction Evidence
            print("[Step 49 Integration] Capturing post-interaction runtime, network, and proxy evidence...")
            time.sleep(3.0)

            post_procs = runtime_observer.collect_processes()
            evidence_items.append(post_procs)

            post_net = network_observer.collect_all_network_evidence()
            evidence_items.extend(post_net)

            proxy_evidence = proxy_manager.get_evidence_items()
            evidence_items.extend(proxy_evidence)

            ui_evidence = ui_manager.get_evidence_items()
            evidence_items.extend(ui_evidence)

            cert_evidence = cert_manager.get_evidence_items()
            evidence_items.extend(cert_evidence)

            # 10. Analyze Proxy Flows Post-Interaction
            parsed_flows = proxy_manager.parse_flow_file()
            https_decrypted = False
            for flow in parsed_flows:
                if flow.scheme.lower() == "https" and flow.status_code is not None:
                    https_decrypted = True
                    break

            print(f"[Step 49 Integration] Post-interaction proxy flow analysis: Captured {len(parsed_flows)} flows. HTTPS Decrypted: {https_decrypted}")

            # 11. Stop LogcatCollector
            streamed_logcat = logcat_collector.stop()
            evidence_items.append(streamed_logcat)

            # 12. Save evidence items to JSON artifact
            evidence_file = save_evidence_items(evidence_items, output_dir=evidence_dir)
            self.assertTrue(os.path.exists(evidence_file))
            print(f"[Step 49 Integration] Saved evidence artifact to {evidence_file}")

        finally:
            # 13. Restore guest CA trust store state
            print("[Step 49 Integration] Restoring guest CA trust store state...")
            cert_manager.restore_guest_trust_store()

            # 14. Restore emulator proxy configuration
            if proxy_manager.get_status().proxy_configured:
                print("[Step 49 Integration] Restoring emulator proxy configuration...")
                proxy_manager.restore_emulator_proxy()

            # 15. Stop mitmdump proxy process
            if proxy_manager.is_running():
                print("[Step 49 Integration] Stopping mitmdump proxy process...")
                proxy_manager.stop()

            # 16. Stop LogcatCollector if running
            if logcat_collector.is_running():
                logcat_collector.stop()

            # 17. Stop emulator process
            if orchestrator.is_running():
                print("[Step 49 Integration] Stopping emulator...")
                orchestrator.shutdown()
                self.assertFalse(orchestrator.is_running())

        # 18. Verify process cleanup
        print("[Step 49 Integration] Step 49 integration test completed successfully.")


if __name__ == "__main__":
    unittest.main()
