import unittest
from unittest.mock import MagicMock, patch
import json
import os
import time
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestIntegrationHttpSensitiveHeaderRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="test.apk")
        self.session.output_dir = "/tmp/test_session"
        os.makedirs(self.session.findings_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.session.findings_dir):
            import shutil
            shutil.rmtree(self.session.output_dir, ignore_errors=True)

    def _create_http_evidence(self, content_str: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=int(time.time()),
            serial="serial1",
            source="proxy",
            content=content_str
        )

    def _create_https_evidence(self, content_str: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=int(time.time()),
            serial="serial1",
            source="proxy",
            content=content_str
        )

    @patch("dynamic_analysis.runner.AndroidRuntimeOrchestrator")
    @patch("dynamic_analysis.runner.ProxyManager")
    @patch("dynamic_analysis.runner.NetworkObserver")
    @patch("dynamic_analysis.runner.LogcatCollector")
    @patch("dynamic_analysis.runner.RuntimeObserver")
    @patch("dynamic_analysis.runner.APKLifecycleManager")
    def test_pipeline_identifies_sensitive_header(
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
        
        content1 = json.dumps({
            "url": "http://example.com/api/login",
            "method": "GET",
            "request_headers": {
                "Authorization": "Bearer super_secret_token",
                "Host": "example.com"
            }
        })
        
        content2 = json.dumps({
            "url": "https://example.com/api/login",
            "method": "GET",
            "request_headers": {
                "X-API-Key": "my_api_key_123",
                "Host": "example.com"
            }
        })

        content3 = json.dumps({
            "url": "http://example.com/api/public",
            "method": "GET",
            "request_headers": {
                "User-Agent": "curl/7.68.0",
                "Host": "example.com"
            }
        })
        
        evidence1 = self._create_http_evidence(content1)
        evidence2 = self._create_https_evidence(content2)
        evidence3 = self._create_http_evidence(content3)

        proxy_instance = mock_proxy.return_value
        proxy_instance.get_status.return_value.proxy_configured = True
        proxy_instance.get_evidence_items.return_value = [evidence1, evidence2, evidence3]
        
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
        self.assertTrue(result.success)
        
        findings_file = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
            
        rule_27_findings = [f for f in findings_data if f["title"].startswith("[RULE-027]")]
        self.assertEqual(len(rule_27_findings), 1)
        
        finding = rule_27_findings[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["category"], "NETWORK")
        self.assertIn("authorization", finding["description"].lower())
        self.assertIn("Bea...<redacted>", finding["description"])
        self.assertIn("example.com", finding["description"])
        self.assertNotIn("super_secret_token", finding["description"])

        # Ensure no speculative finding for HTTPS
        self.assertFalse(any("x-api-key" in f["description"].lower() for f in findings_data if f["title"].startswith("[RULE-027]")))

if __name__ == '__main__':
    unittest.main()

