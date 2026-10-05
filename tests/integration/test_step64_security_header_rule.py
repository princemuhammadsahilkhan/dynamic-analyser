import os
import unittest
import json
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.rules import MissingXCTORule


class TestStep64SecurityHeaderRuleIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.join("apks", "app-release.apk")
        self.assertTrue(
            os.path.exists(self.apk_path),
            f"Target APK not found at {self.apk_path}. Ensure it exists."
        )
        self.output_dir = os.path.abspath("test_output_step64")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )
        self.runner = AnalysisRunner()

    def test_missing_xcto_rule_live_execution(self):
        """
        Verify that AnalysisRunner successfully collects evidence and evaluates
        RULE-007 (Missing X-Content-Type-Options Header Observed) against live traffic.
        """
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=10.0
        )
        
        # 1. Verify runner execution success
        self.assertTrue(result.success, "AnalysisRunner failed to complete successfully.")
        
        # 2. Verify Session output directories
        session = self.session
        self.assertTrue(os.path.exists(session.run_dir))
        self.assertTrue(os.path.exists(session.evidence_dir))
        self.assertTrue(os.path.exists(session.findings_dir))
        
        # 3. Process Evidence
        https_evidences = [ev for ev in result.evidence_items if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value]
        
        has_headers_evidence = False
        missing_xcto = False
        
        for item in https_evidences:
            try:
                content = json.loads(item.content)
                raw_metadata = content.get("raw_metadata")
                if raw_metadata and isinstance(raw_metadata, dict):
                    headers = raw_metadata.get("response_headers")
                    if isinstance(headers, dict):
                        has_headers_evidence = True
                        
                        xcto_present = False
                        for key in headers.keys():
                            if key.lower() == "x-content-type-options":
                                xcto_present = True
                                break
                        
                        if not xcto_present:
                            missing_xcto = True
                            break
            except Exception:
                pass
                
        # 4. Load findings and verify rules executed
        findings_file = os.path.join(session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r", encoding="utf-8") as f:
            findings = json.load(f)
            
        # 5. Check if RULE-007 triggered
        xcto_findings = [
            f for f in findings 
            if f.get("title") == MissingXCTORule().name
        ]
        
        if https_evidences:
            if has_headers_evidence and missing_xcto:
                # We expect the rule to trigger
                self.assertGreater(len(xcto_findings), 0, "RULE-007 should have triggered but did not.")
                for finding in xcto_findings:
                    self.assertEqual(finding["category"], "NETWORK")
                    self.assertEqual(finding["severity"], "MEDIUM")
                    self.assertTrue(len(finding["evidence_references"]) > 0)
            elif has_headers_evidence and not missing_xcto:
                self.assertEqual(len(xcto_findings), 0, "RULE-007 triggered on secure traffic.")
            else:
                self.assertEqual(len(xcto_findings), 0, "RULE-007 triggered without response_headers evidence.")
        else:
            self.assertEqual(len(xcto_findings), 0, "RULE-007 triggered without any HTTPS evidence.")

if __name__ == "__main__":
    unittest.main()
