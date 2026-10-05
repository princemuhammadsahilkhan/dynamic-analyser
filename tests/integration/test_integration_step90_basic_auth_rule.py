import unittest
from unittest.mock import MagicMock, patch
import json
import os
import time
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType

class TestIntegrationHttpBasicAuthRule(unittest.TestCase):
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
    def test_pipeline_identifies_insecure_basic_auth(
        self, mock_apk_manager, mock_runtime_observer, mock_logcat, mock_network, mock_proxy, mock_orchestrator
    ):
        orchestrator_instance = mock_orchestrator.return_value
        proxy_instance = mock_proxy.return_value
        observer_instance = mock_runtime_observer.return_value
        
        # HTTP with basic auth (Finding expected)
        http_basic_auth_content = {
            "request": {
                "method": "GET",
                "url": "http://example.com/api",
                "host": "example.com"
            },
            "response": {
                "status_code": 200
            },
            "raw_metadata": {
                "request_headers": {
                    "Authorization": "Basic dGVzdDp0ZXN0"
                }
            }
        }
        
        # HTTPS with basic auth (No finding expected)
        https_basic_auth_content = {
            "request": {
                "method": "GET",
                "url": "https://example.com/api",
                "host": "example.com"
            },
            "response": {
                "status_code": 200
            },
            "raw_metadata": {
                "request_headers": {
                    "Authorization": "Basic dGVzdDp0ZXN0"
                }
            }
        }
        
        # HTTP with bearer auth (No finding expected)
        http_bearer_auth_content = {
            "request": {
                "method": "GET",
                "url": "http://example.com/api",
                "host": "example.com"
            },
            "response": {
                "status_code": 200
            },
            "raw_metadata": {
                "request_headers": {
                    "Authorization": "Bearer token123"
                }
            }
        }
        
        proxy_instance.get_evidence_items.return_value = [
            self._create_http_evidence(json.dumps(http_basic_auth_content)),
            self._create_https_evidence(json.dumps(https_basic_auth_content)),
            self._create_http_evidence(json.dumps(http_bearer_auth_content))
        ]
        
        proxy_instance.stop.return_value = EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="mitmproxy",
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
        apk_manager_instance_mock_result = MagicMock()
        apk_manager_instance_mock_result.package_name = "com.test"
        # Avoid serialization issue by setting return_value to something json.dumps can handle if needed
        # Or just avoid calling json.dumps on it directly if it's passed through unchanged
        apk_manager_instance.run_lifecycle.return_value = apk_manager_instance_mock_result
        
        orchestrator_instance.config.avd_name = "test_avd"
        orchestrator_instance.config.serial = "test_serial"
        
        observer_instance.collect_properties.return_value = []
        observer_instance.collect_processes.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=int(time.time()),
            serial="test_serial",
            source="adb",
            content="[]"
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
        self.assertTrue(result.success, result.error_message)
        
        findings_file = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
            
        rule_30_findings = [f for f in findings_data if f["title"].startswith("[RULE-030]")]
        
        self.assertEqual(len(rule_30_findings), 1)
        
        finding = rule_30_findings[0]
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["category"], "NETWORK")
        self.assertIn("basic authentication credentials sent over unencrypted http", finding["description"].lower())
        self.assertIn("example.com", finding["description"])
        
        # Check redaction: should not contain "dGVzdDp0ZXN0"
        self.assertIn("<redacted>", finding["description"])
        self.assertNotIn("dGVzdDp0ZXN0", finding["description"])

if __name__ == '__main__':
    unittest.main()
