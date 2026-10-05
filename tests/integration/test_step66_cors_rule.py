"""Integration tests for Step 66: RULE-009 — Insecure CORS Policy Observed."""

import json
import os
import unittest

from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceType


class TestStep66CORSRuleIntegration(unittest.TestCase):
    """Integration test running the full AnalysisRunner pipeline and verifying RULE-009."""

    def setUp(self):
        self.apk_path = os.path.join("apks", "app-release.apk")
        self.assertTrue(
            os.path.exists(self.apk_path),
            f"Target APK not found at {self.apk_path}. Ensure it exists.",
        )
        self.output_dir = os.path.abspath("test_output_step66")
        self.session = AnalysisSession(
            apk_path=self.apk_path,
            package_name="com.example.mentorcraft2",
            base_output_dir=self.output_dir,
        )
        self.runner = AnalysisRunner()

    def test_cors_rule_live_execution(self):
        """
        Verify that AnalysisRunner evaluates RULE-009 against live traffic.
        A CORS finding is generated only when concrete evidence supports it.
        """
        result = self.runner.run(
            session=self.session,
            launch_app=True,
            enable_proxy=True,
            observation_duration=10.0,
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

        cors_findings = [
            f
            for f in findings
            if f.get("title")
            in (
                "Wildcard CORS Origin Observed",
                "Wildcard CORS Origin With Credentials Observed",
            )
        ]

        # Check whether evidence contains CORS headers
        has_cors_evidence = False
        traffic_types = (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value)
        for item in result.evidence_items:
            if item.evidence_type in traffic_types:
                try:
                    content = json.loads(item.content)
                    raw_metadata = content.get("raw_metadata")
                    if raw_metadata and isinstance(raw_metadata, dict):
                        headers = raw_metadata.get("response_headers")
                        if isinstance(headers, dict) and "access-control-allow-origin" in headers:
                            acao_val = headers["access-control-allow-origin"]
                            if isinstance(acao_val, list):
                                acao_val = acao_val[0]
                            if acao_val.strip() == "*":
                                has_cors_evidence = True
                                break
                except Exception:
                    pass

        if has_cors_evidence:
            # If wildcard CORS evidence was observed, we expect at least one finding
            self.assertGreater(
                len(cors_findings),
                0,
                "Expected CORS finding when wildcard CORS evidence was observed.",
            )
        else:
            # If no wildcard CORS evidence was observed, there should be no CORS findings
            self.assertEqual(
                len(cors_findings),
                0,
                "RULE-009 triggered without wildcard CORS evidence.",
            )


if __name__ == "__main__":
    unittest.main()
