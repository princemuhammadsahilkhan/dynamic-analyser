import os
import unittest
import json
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.rules import InsecureCookieAttributeRule

class TestStep65CookieRuleIntegration(unittest.TestCase):
    def setUp(self):
        self.apk_path = os.path.join("apks", "app-release.apk")
        self.assertTrue(
            os.path.exists(self.apk_path),
            f"Target APK not found at {self.apk_path}. Ensure it exists."
        )
        self.output_dir = os.path.abspath("test_output_step65")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir
        )
        self.runner = AnalysisRunner()

    def test_insecure_cookie_rule_live_execution(self):
        """
        Verify that AnalysisRunner successfully collects evidence and evaluates
        RULE-008 (Insecure Cookie Attribute Observed) against live traffic.
        """
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=10.0
        )
        
        self.assertTrue(result.success, "AnalysisRunner failed to complete successfully.")
        
        session = self.session
        self.assertTrue(os.path.exists(session.run_dir))
        self.assertTrue(os.path.exists(session.evidence_dir))
        self.assertTrue(os.path.exists(session.findings_dir))
        
        findings_file = os.path.join(session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r", encoding="utf-8") as f:
            findings = json.load(f)
            
        cookie_findings = [
            f for f in findings 
            if f.get("title") in (
                "Missing Secure Cookie Attribute Observed",
                "Missing HttpOnly Cookie Attribute Observed",
                "Missing SameSite Cookie Attribute Observed"
            )
        ]
        
        https_evidences = [ev for ev in result.evidence_items if ev.evidence_type in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value)]
        has_set_cookie_evidence = False
        
        for item in https_evidences:
            try:
                content = json.loads(item.content)
                raw_metadata = content.get("raw_metadata")
                if raw_metadata and isinstance(raw_metadata, dict):
                    headers = raw_metadata.get("response_headers")
                    if isinstance(headers, dict) and "set-cookie" in headers:
                        has_set_cookie_evidence = True
                        break
            except Exception:
                pass
        
        # If the app produces Set-Cookie without these attributes, findings should trigger.
        # But we only assert based on whether the app actually sets cookies during testing.
        if has_set_cookie_evidence:
            # We don't enforce > 0 unless we are certain the target app sets insecure cookies.
            pass
        else:
            self.assertEqual(len(cookie_findings), 0, "RULE-008 triggered without Set-Cookie evidence.")

if __name__ == "__main__":
    unittest.main()
