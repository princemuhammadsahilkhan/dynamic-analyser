import unittest
from unittest.mock import MagicMock, patch
import json
import os
import time
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestIntegrationHttpFormSubmissionRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(package_name="com.example.app", apk_path="/tmp/test.apk")
        self.runner = AnalysisRunner()
        self.timestamp = time.time()

    def _create_http_evidence(self, content: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=content,
            timestamp=self.timestamp,
            source="mitmproxy",
            serial="serial1"
        )

    def _create_https_evidence(self, content: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            content=content,
            timestamp=self.timestamp,
            source="mitmproxy",
            serial="serial1"
        )

    @patch("dynamic_analysis.runner.AndroidRuntimeOrchestrator")
    @patch("dynamic_analysis.runner.ProxyManager")
    @patch("dynamic_analysis.runner.NetworkObserver")
    @patch("dynamic_analysis.runner.LogcatCollector")
    @patch("dynamic_analysis.runner.RuntimeObserver")
    @patch("dynamic_analysis.runner.APKLifecycleManager")
    def test_pipeline_identifies_http_form_submissions(
        self,
        mock_apk_manager,
        mock_observer,
        mock_logcat,
        mock_network,
        mock_proxy,
        mock_orchestrator
    ):
        orchestrator_instance = mock_orchestrator.return_value
        orchestrator_instance.config = MagicMock()
        orchestrator_instance.config.avd_name = "test_avd"
        orchestrator_instance.config.serial = "test_serial"
        
        http_content = json.dumps({
            "url": "http://example.com/login?email=user@example.com",
            "request_content": "username=alice&password=secret123"
        })
        
        https_content = json.dumps({
            "url": "https://example.com/login",
            "request_content": "username=bob&password=secure456"
        })
        
        evidence1 = self._create_http_evidence(http_content)
        evidence2 = self._create_https_evidence(https_content)

        proxy_instance = mock_proxy.return_value
        proxy_instance.get_status.return_value.proxy_configured = True
        proxy_instance.get_evidence_items.return_value = [evidence1, evidence2]
        
        observer_instance = mock_observer.return_value
        observer_instance.collect_properties.return_value = []
        observer_instance.collect_processes.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="adb",
            content="proc"
        )
        observer_instance.collect_logcat_dump.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="adb",
            content=""
        )
        observer_instance.collect_permissions.return_value = EvidenceItem(
            evidence_type="PERMISSIONS",
            timestamp=int(time.time()),
            serial="test_serial",
            source="adb",
            content="[]"
        )
        
        network_instance = mock_network.return_value
        network_instance.collect_all_network_evidence.return_value = []
        
        logcat_instance = mock_logcat.return_value
        logcat_instance.stop.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="adb",
            content=""
        )
        logcat_instance.get_evidence_items.return_value = []
        
        apk_manager_instance = mock_apk_manager.return_value
        apk_manager_instance.run_lifecycle.return_value = MagicMock(package_name="com.test")
        
        runner = AnalysisRunner(
            orchestrator=orchestrator_instance,
            apk_manager=apk_manager_instance,
            observer=observer_instance,
            logcat_collector=logcat_instance,
            network_observer=network_instance,
            proxy_manager=proxy_instance
        )
        
        result = runner.run(
            session=self.session,
            enable_proxy=True,
            launch_app=False,
            observation_duration=0
        )
        
        self.assertTrue(result.success, msg=getattr(result, "error_message", "No error message"))
        
        findings_file = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
        
        rule025_findings = [f for f in findings_data if f["title"].startswith("[RULE-025]")]
        rule022_findings = [f for f in findings_data if f["title"].startswith("[RULE-022]")]
        
        self.assertEqual(len(rule025_findings), 2) # username and password
        self.assertEqual(len(rule022_findings), 1) # email from URL
        
        # Verify redaction is active and correctly categorized
        for f in rule025_findings:
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["category"], "NETWORK")
            self.assertIn("Insecure HTTP Form Submission Observed", f["title"])
            if "password" in f["title"]:
                self.assertIn("sec...<redacted>", f["description"])

if __name__ == '__main__':
    unittest.main()
