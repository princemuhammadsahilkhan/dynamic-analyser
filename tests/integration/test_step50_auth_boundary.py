"""Integration test for Step 50: Controlled Authentication-Boundary Analysis on analysis_baseline_api33."""

import json
import os
import tempfile
import time
import unittest

from dynamic_analysis.apk import APKLifecycleManager
from dynamic_analysis.auth import AuthenticationBoundaryObserver
from dynamic_analysis.certificates import CertificateTrustManager
from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.network import NetworkObserver
from dynamic_analysis.observation import LogcatCollector, RuntimeObserver, save_evidence_items
from dynamic_analysis.proxy import ProxyManager
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator
from dynamic_analysis.ui import UIInteractionManager


class TestStep50AuthBoundaryIntegration(unittest.TestCase):
    """Integration test verifying controlled authentication-boundary inspection, local validation feedback, and boundary logging."""

    def test_step50_auth_boundary_analysis(self) -> None:
        """Execute end-to-end controlled authentication-boundary observation on analysis_baseline_api33."""
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
        auth_observer = AuthenticationBoundaryObserver(
            orchestrator=orchestrator,
            ui_manager=ui_manager,
            proxy_manager=proxy_manager,
        )

        apk_path = "apks/app-release.apk"
        self.assertTrue(os.path.exists(apk_path), f"Target APK missing at {apk_path}")

        temp_dir = tempfile.mkdtemp(prefix="step50_auth_test_")
        flow_file = os.path.join(temp_dir, "mitm_flows.mitm")
        evidence_dir = os.path.join(temp_dir, "evidence")

        evidence_items = []

        try:
            # 1. Start AVD emulator child process
            print("\n[Step 50 Integration] Starting AVD analysis_baseline_api33...")
            orchestrator.start()
            self.assertTrue(orchestrator.is_running())

            # 2. Wait for guest OS boot completion
            booted = orchestrator.wait_for_boot(timeout=60.0)
            self.assertTrue(booted, "Emulator failed to boot within timeout")

            # 3. Start mitmdump proxy process and configure emulator proxy
            print("[Step 50 Integration] Starting mitmdump proxy on 0.0.0.0:8080...")
            proxy_manager.start(host="0.0.0.0", port=8080, flow_file=flow_file)
            self.assertTrue(proxy_manager.is_running())
            proxy_manager.configure_emulator_proxy(proxy_host="10.0.2.2", proxy_port=8080)

            # 4. Install mitmproxy CA to guest system and user stores
            cert_manager.install_ca_to_user_store()
            cert_manager.install_ca_to_system_store()
            post_trust = cert_manager.audit_guest_trust_store()
            self.assertTrue(post_trust.installed_system)
            print(f"[Step 50 Integration] Installed mitmproxy CA to guest system store: Hash={post_trust.subject_hash_old}")

            # 5. Start LogcatCollector
            logcat_collector.start(clear_buffer=True)

            # 6. Install and launch target APK
            print(f"[Step 50 Integration] Installing and launching {apk_path}...")
            apk_result = apk_manager.run_lifecycle(apk_path, launch=True)
            self.assertTrue(apk_result.installed)
            self.assertTrue(apk_result.launched)
            time.sleep(3.0)

            # 7. Collect Baseline Evidence (pre-interaction)
            print("[Step 50 Integration] Capturing baseline pre-interaction evidence...")
            base_procs = runtime_observer.collect_processes()
            self.assertIn("com.example.mentorcraft2", base_procs.content)
            evidence_items.append(base_procs)

            base_hier = ui_manager.dump_hierarchy()
            print(f"[Step 50 Integration] Baseline UI hierarchy captured ({len(base_hier.elements)} elements)")

            # 8. Navigate through Onboarding & Role Selection to Sign In Screen
            print("[Step 50 Integration] Navigating to Sign In screen...")
            skip_btn = ui_manager.find_element(base_hier, content_desc="Skip")
            if skip_btn:
                ui_manager.tap_element(skip_btn)
                time.sleep(2.0)

            hier_role = ui_manager.dump_hierarchy()
            student_role = ui_manager.find_element(hier_role, content_desc="Student")
            if student_role:
                ui_manager.tap_element(student_role)
                time.sleep(2.0)

            # 9. Inspect Sign In Form Fields & Controls
            print("[Step 50 Integration] Cataloging Sign In screen input fields & buttons...")
            fields = auth_observer.inspect_signin_screen()
            self.assertTrue(len(fields) > 0, "Failed to observe Sign In form fields")
            print(f"[Step 50 Integration] Cataloged {len(fields)} form elements on Sign In screen")

            # 10. Exercise Non-Authenticated Empty Sign In Form Validation
            print("[Step 50 Integration] Exercising empty Sign In submission validation...")
            val_signin = auth_observer.exercise_signin_validation()
            self.assertTrue(val_signin.local_validation_only)
            self.assertFalse(val_signin.network_traffic_detected)
            self.assertIn("Please enter your email", val_signin.validation_messages)
            print(f"[Step 50 Integration] Sign In validation observed: {val_signin.validation_messages}")

            # 11. Exercise Non-Authenticated Empty Sign Up Form Validation
            print("[Step 50 Integration] Exercising empty Sign Up submission validation...")
            val_signup = auth_observer.exercise_signup_validation()
            self.assertTrue(val_signup.local_validation_only)
            self.assertFalse(val_signup.network_traffic_detected)
            self.assertIn("Please enter your full name", val_signup.validation_messages)
            print(f"[Step 50 Integration] Sign Up validation observed: {val_signup.validation_messages}")

            # 12. Document Explicit Authentication Boundary State
            print("[Step 50 Integration] Documenting explicit Authentication Boundary state...")
            boundary = auth_observer.record_authentication_boundary(
                screen_name="Sign In / Sign Up",
                reason="Target screen requires real user account credentials / registration. Halted to prevent unauthorized access attempt.",
            )
            self.assertTrue(boundary.blocked)

            # 13. Collect Post-Interaction Evidence
            print("[Step 50 Integration] Capturing post-interaction runtime, network, and proxy evidence...")
            time.sleep(3.0)

            post_procs = runtime_observer.collect_processes()
            evidence_items.append(post_procs)

            post_net = network_observer.collect_all_network_evidence()
            evidence_items.extend(post_net)

            proxy_evidence = proxy_manager.get_evidence_items()
            evidence_items.extend(proxy_evidence)

            ui_evidence = ui_manager.get_evidence_items()
            evidence_items.extend(ui_evidence)

            auth_evidence = auth_observer.get_evidence_items()
            evidence_items.extend(auth_evidence)

            cert_evidence = cert_manager.get_evidence_items()
            evidence_items.extend(cert_evidence)

            # 14. Analyze Proxy Flows Post-Interaction
            parsed_flows = proxy_manager.parse_flow_file()
            self.assertEqual(len(parsed_flows), 0, "Expected 0 network flows during auth boundary analysis")
            print(f"[Step 50 Integration] Post-interaction proxy flow analysis: Captured {len(parsed_flows)} flows.")

            # 15. Stop LogcatCollector
            streamed_logcat = logcat_collector.stop()
            evidence_items.append(streamed_logcat)

            # 16. Save evidence items to JSON artifact
            evidence_file = save_evidence_items(evidence_items, output_dir=evidence_dir)
            self.assertTrue(os.path.exists(evidence_file))
            print(f"[Step 50 Integration] Saved evidence artifact to {evidence_file}")

        finally:
            # 17. Restore guest CA trust store state
            print("[Step 50 Integration] Restoring guest CA trust store state...")
            cert_manager.restore_guest_trust_store()

            # 18. Restore emulator proxy configuration
            if proxy_manager.get_status().proxy_configured:
                print("[Step 50 Integration] Restoring emulator proxy configuration...")
                proxy_manager.restore_emulator_proxy()

            # 19. Stop mitmdump proxy process
            if proxy_manager.is_running():
                print("[Step 50 Integration] Stopping mitmdump proxy process...")
                proxy_manager.stop()

            # 20. Stop LogcatCollector if running
            if logcat_collector.is_running():
                logcat_collector.stop()

            # 21. Stop emulator process
            if orchestrator.is_running():
                print("[Step 50 Integration] Stopping emulator...")
                orchestrator.shutdown()
                self.assertFalse(orchestrator.is_running())

        # 22. Verify process cleanup
        print("[Step 50 Integration] Step 50 integration test completed successfully.")


if __name__ == "__main__":
    unittest.main()
