import unittest
import os
import shutil
import subprocess
import json
from unittest.mock import patch

from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.rules import RuleEngine, RuleResult, FindingSeverity
from dynamic_analysis.observation import EvidenceType

class TestStep62CipherRuleIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.abspath("apks/app-release.apk")
        self.output_dir = os.path.abspath("test_output_step62")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )
        self.runner = AnalysisRunner()

    def test_live_cipher_suite_evaluation(self):
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
        
        has_cipher_metadata = False
        weak_cipher_found = False
        ciphers_found = set()
        weak_patterns = ["NULL", "ANULL", "EXPORT", "RC4", "DES", "3DES"]
        
        for ev in https_evidences:
            try:
                flow = json.loads(ev.content)
                raw_meta = flow.get("raw_metadata", {})
                cipher_suite = raw_metadata.get("cipher_suite")
                if cipher_suite:
                    has_cipher_metadata = True
                    ciphers_found.add(cipher_suite)
                    cipher_upper = cipher_suite.upper()
                    
                    for pattern in weak_patterns:
                        if pattern == "DES" and "3DES" in cipher_upper:
                            continue
                        if pattern in cipher_upper:
                            weak_cipher_found = True
                            break
            except Exception:
                pass
                
        print(f"\nCaptured {len(https_evidences)} HTTPS evidences.")
        print(f"Cipher suites actually captured: {ciphers_found}")
        
        findings_file = os.path.join(session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
            
        weak_cipher_finding_present = any(f.get("title") == "Weak TLS Cipher Suite Observed" for f in findings_data)
        
        self.assertEqual(weak_cipher_found, weak_cipher_finding_present)
        
        if not has_cipher_metadata:
            self.assertFalse(weak_cipher_finding_present)
            print("No TLS cipher metadata observed, safely non-triggered.")

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
