import unittest
import os
import time
import subprocess
import json
import shutil
from unittest.mock import patch

from dynamic_analysis.session import AnalysisSession, SessionStatus
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.rules import RuleEngine, RuleResult, FindingSeverity
from dynamic_analysis.observation import EvidenceType

class TestStep61TLSMetadataIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.abspath("apks/app-release.apk")
        self.output_dir = os.path.abspath("test_output_step61")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )
        self.runner = AnalysisRunner()

    def test_live_tls_extraction(self):
        # Give it a short run time.
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=10.0
        )
        
        self.assertTrue(result.success)
        session = self.session
        
        https_evidences = [ev for ev in result.evidence_items if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value]
        
        has_tls_metadata = False
        weak_tls_found = False
        tls_versions_found = set()
        
        for ev in https_evidences:
            try:
                flow = json.loads(ev.content)
                raw_meta = flow.get("raw_metadata", {})
                tls_ver = raw_meta.get("tls_version")
                if tls_ver:
                    has_tls_metadata = True
                    tls_versions_found.add(tls_ver)
                    if "TLSV1.0" in tls_ver.upper() or "TLSV1.1" in tls_ver.upper() or tls_ver in ("TLS 1.0", "TLS 1.1"):
                        weak_tls_found = True
            except Exception:
                pass
                
        print(f"\nCaptured {len(https_evidences)} HTTPS evidences.")
        print(f"TLS versions actually captured: {tls_versions_found}")
        
        findings_file = os.path.join(session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
            
        weak_tls_finding_present = any(f.get("title") == "Weak TLS Version Observed" for f in findings_data)
        
        self.assertEqual(weak_tls_found, weak_tls_finding_present)
        
        if not has_tls_metadata:
            self.assertFalse(weak_tls_finding_present)
            print("No TLS metadata observed, safely non-triggered.")

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        try:
            if self.runner.proxy_manager.is_running():
                self.runner.proxy_manager.stop()
        except Exception:
            pass
        try:
            if self.runner.orchestrator.is_running():
                self.runner.orchestrator.shutdown()
        except Exception:
            pass

if __name__ == "__main__":
    unittest.main()
