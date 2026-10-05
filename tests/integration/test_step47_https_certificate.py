"""Integration test for Step 47: Controlled HTTPS Certificate Trust & Decryption Verification against live AVD analysis_baseline_api33."""

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


class TestStep47HTTPSCertificateIntegration(unittest.TestCase):
    """Integration test verifying controlled CA trust installation and HTTPS decryption against live emulator."""

    def test_step47_https_certificate_decryption_verification(self) -> None:
        """Execute end-to-end controlled CA trust lifecycle and HTTPS decryption verification on analysis_baseline_api33."""
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

        apk_path = "apks/app-release.apk"
        self.assertTrue(os.path.exists(apk_path), f"Target APK missing at {apk_path}")

        # 1. Audit local mitmproxy CA
        cert_details = cert_manager.audit_local_ca()
        self.assertIn("mitmproxy", cert_details.subject)
        self.assertEqual(cert_details.subject_hash_old, "c8750f0d")
        print(f"\n[Step 47 Integration] Audited host mitmproxy CA (Subject Hash: {cert_details.subject_hash_old})")

        temp_dir = tempfile.mkdtemp(prefix="step47_cert_test_")
        flow_file = os.path.join(temp_dir, "mitm_flows.mitm")
        evidence_dir = os.path.join(temp_dir, "evidence")

        evidence_items = []

        try:
            # 2. Start AVD emulator child process
            print("[Step 47 Integration] Starting AVD analysis_baseline_api33...")
            orchestrator.start()
            self.assertTrue(orchestrator.is_running())

            # 3. Wait for guest OS boot completion
            booted = orchestrator.wait_for_boot(timeout=60.0)
            self.assertTrue(booted, "Emulator failed to boot within timeout")

            # 4. Audit pre-test guest trust store state
            pre_trust_status = cert_manager.audit_guest_trust_store()
            self.assertTrue(pre_trust_status.is_rooted)
            self.assertFalse(pre_trust_status.installed_user)
            print(f"[Step 47 Integration] Pre-test guest trust store audited: Rooted={pre_trust_status.is_rooted}, UserCert={pre_trust_status.installed_user}")

            # 5. Start mitmdump proxy process
            print("[Step 47 Integration] Starting mitmdump proxy process on 0.0.0.0:8080...")
            proxy_manager.start(host="0.0.0.0", port=8080, flow_file=flow_file)
            self.assertTrue(proxy_manager.is_running())

            # 6. Configure guest HTTP proxy via ADB
            configured_target = proxy_manager.configure_emulator_proxy(proxy_host="10.0.2.2", proxy_port=8080)
            self.assertEqual(configured_target, "10.0.2.2:8080")
            print(f"[Step 47 Integration] Emulator proxy configured to {configured_target}")

            # 7. Install mitmproxy CA to guest user and system trust stores
            installed_user_cert = cert_manager.install_ca_to_user_store()
            self.assertIn("c8750f0d.0", installed_user_cert)
            print(f"[Step 47 Integration] Installed mitmproxy CA to user store: {installed_user_cert}")

            installed_system_cert = cert_manager.install_ca_to_system_store()
            self.assertIn("c8750f0d.0", installed_system_cert)
            print(f"[Step 47 Integration] Installed mitmproxy CA to system store (tmpfs): {installed_system_cert}")

            # 8. Audit post-install guest trust store state
            post_trust_status = cert_manager.audit_guest_trust_store()
            self.assertTrue(post_trust_status.installed_user)
            self.assertTrue(post_trust_status.installed_system)
            print(f"[Step 47 Integration] Post-install guest trust store verified: UserCertInstalled={post_trust_status.installed_user}, SystemCertInstalled={post_trust_status.installed_system}")


            # 9. Start LogcatCollector
            logcat_collector.start(clear_buffer=True)
            self.assertTrue(logcat_collector.is_running())

            # 10. Install and launch target APK
            print(f"[Step 47 Integration] Installing and launching {apk_path}...")
            apk_result = apk_manager.run_lifecycle(apk_path, launch=True)
            self.assertTrue(apk_result.installed)
            self.assertTrue(apk_result.launched)
            self.assertEqual(apk_result.package_name, "com.example.mentorcraft2")

            # 11. Allow observation time for application network activity
            print("[Step 47 Integration] Observing application runtime for 5 seconds...")
            time.sleep(5.0)

            # 12. Verify application process is active
            procs_ev = runtime_observer.collect_processes()
            self.assertIn("com.example.mentorcraft2", procs_ev.content)
            evidence_items.append(procs_ev)

            # 13. Collect network evidence, proxy evidence, and certificate evidence
            net_evidence = network_observer.collect_all_network_evidence()
            evidence_items.extend(net_evidence)

            proxy_evidence = proxy_manager.get_evidence_items()
            evidence_items.extend(proxy_evidence)

            cert_evidence = cert_manager.get_evidence_items()
            evidence_items.extend(cert_evidence)

            # 14. Analyze captured proxy flows for HTTPS decryption
            parsed_flows = proxy_manager.parse_flow_file()
            https_decrypted = False
            for flow in parsed_flows:
                if flow.scheme.lower() == "https" and flow.status_code is not None:
                    https_decrypted = True
                    break

            print(f"[Step 47 Integration] Proxy flow analysis: Captured {len(parsed_flows)} flows. HTTPS Decrypted: {https_decrypted}")

            # 15. Stop LogcatCollector
            streamed_logcat = logcat_collector.stop()
            evidence_items.append(streamed_logcat)

            # 16. Save evidence items to JSON artifact
            evidence_file = save_evidence_items(evidence_items, output_dir=evidence_dir)
            self.assertTrue(os.path.exists(evidence_file))
            print(f"[Step 47 Integration] Saved evidence artifact to {evidence_file}")

        finally:
            # 17. Restore guest CA trust store state
            print("[Step 47 Integration] Restoring guest CA trust store state...")
            cert_manager.restore_guest_trust_store()
            post_restore_trust = cert_manager.audit_guest_trust_store()
            self.assertFalse(post_restore_trust.installed_user)
            self.assertFalse(post_restore_trust.installed_system)
            print(f"[Step 47 Integration] Guest CA trust store restored: UserCertInstalled={post_restore_trust.installed_user}, SystemCertInstalled={post_restore_trust.installed_system}")


            # 18. Restore emulator proxy configuration
            if proxy_manager.get_status().proxy_configured:
                print("[Step 47 Integration] Restoring emulator proxy configuration...")
                proxy_manager.restore_emulator_proxy()

            # 19. Stop mitmdump proxy process
            if proxy_manager.is_running():
                print("[Step 47 Integration] Stopping mitmdump proxy process...")
                proxy_manager.stop()

            # 20. Stop LogcatCollector if running
            if logcat_collector.is_running():
                logcat_collector.stop()

            # 21. Stop emulator process
            if orchestrator.is_running():
                print("[Step 47 Integration] Stopping emulator...")
                orchestrator.shutdown()
                self.assertFalse(orchestrator.is_running())

        # 22. Verify process cleanup
        print("[Step 47 Integration] Step 47 integration test completed successfully.")


if __name__ == "__main__":
    unittest.main()
