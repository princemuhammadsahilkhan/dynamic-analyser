import unittest
from unittest.mock import MagicMock, patch
import json
import os
import time
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.observation import EvidenceItem, EvidenceType
from dynamic_analysis.apk import APKLifecycleResult

class TestIntegrationHttpReferrerRule(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="test.apk")
        self.session.output_dir = "/tmp/test_session_referrer"
        os.makedirs(self.session.findings_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.session.findings_dir):
            import shutil
            shutil.rmtree(self.session.output_dir, ignore_errors=True)

    def _create_http_evidence(self, content_str: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            timestamp=str(int(time.time())),
            serial="serial1",
            source="proxy",
            content=content_str
        )

    def _create_https_evidence(self, content_str: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=str(int(time.time())),
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
    def test_pipeline_identifies_insecure_referrer(
        self, mock_apk_manager, mock_runtime_observer, mock_logcat, mock_network, mock_proxy, mock_orchestrator
    ):
        orchestrator_instance = mock_orchestrator.return_value

        from dynamic_analysis.config import AndroidRuntimeConfig
            
            
        
        orchestrator_instance.config = AndroidRuntimeConfig(avd_name="test_avd")

        proxy_instance = mock_proxy.return_value
        observer_instance = mock_runtime_observer.return_value
        
        # HTTP traffic with sensitive Referer
        http_referer_content = {
            "request": {
                "method": "GET",
                "url": "http://example.com/api",
                "host": "example.com"
            },
            "response": {
                "status_code": 200
            },
            "host": "example.com",
            "raw_metadata": {
                "request_headers": {
                    "Referer": "http://example.com/login?password=mysecretpassword&user=admin"
                }
            }
        }
        
        # HTTPS traffic with sensitive Referer (should be ignored by the rule)
        https_referer_content = {
            "request": {
                "method": "GET",
                "url": "https://example.com/api",
                "host": "example.com"
            },
            "response": {
                "status_code": 200
            },
            "host": "example.com",
            "raw_metadata": {
                "request_headers": {
                    "Referer": "https://example.com/login?password=anothersecret"
                }
            }
        }
        
        # HTTP traffic with non-sensitive Referer
        http_normal_referer = {
            "request": {
                "method": "GET",
                "url": "http://example.com/api",
                "host": "example.com"
            },
            "response": {
                "status_code": 200
            },
            "host": "example.com",
            "raw_metadata": {
                "request_headers": {
                    "Referer": "http://example.com/home"
                }
            }
        }
        
        proxy_instance.get_evidence_items.return_value = [
            self._create_http_evidence(json.dumps(http_referer_content)),
            self._create_https_evidence(json.dumps(https_referer_content)),
            self._create_http_evidence(json.dumps(http_normal_referer))
        ]
        
        proxy_instance.stop.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROXY_STATUS.value,
            timestamp=str(int(time.time())),
            serial="test_serial",
            source="mitmproxy",
            content="[]"
        )
        
        network_instance = mock_network.return_value
        network_instance.collect_all_network_evidence.return_value = []
        
        observer_instance.collect_properties.return_value = []
        observer_instance.collect_processes.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=str(int(time.time())),
            serial="test_serial",
            source="adb",
            content=""
        )
        observer_instance.collect_permissions.return_value = EvidenceItem(
            evidence_type=EvidenceType.PERMISSIONS.value,
            timestamp=str(int(time.time())),
            serial="test_serial",
            source="adb",
            content=""
        )
        observer_instance.collect_logcat_dump.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=str(int(time.time())),
            serial="test_serial",
            source="adb",
            content=""
        )
        
        logcat_instance = mock_logcat.return_value
        logcat_instance.stop.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=str(int(time.time())),
            serial="test_serial",
            source="adb",
            content=""
        )
        logcat_instance.get_evidence_items.return_value = []
        
        apk_manager_instance = mock_apk_manager.return_value
        apk_manager_instance.run_lifecycle.return_value = APKLifecycleResult(
            apk_path="test.apk",
            package_name="com.test",
            launchable_activity=".MainActivity",
            installed=True,
            verified=True,
            launched=True,
            install_output="",
            launch_output=""
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
        if not result.success:
            import traceback
            traceback.print_exc()
            print(f"Runner failed with error: {result.error_message}")
        self.assertTrue(result.success)
        
        findings_file = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
            
        rule_29_findings = [f for f in findings_data if f.get("rule_id") == "RULE-029" or f["title"] == "Insecure HTTP Referrer Information Observed"]
        
        # We expect 1 finding from the first evidence item
        self.assertEqual(len(rule_29_findings), 1)
        
        finding = rule_29_findings[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["category"], "NETWORK")
        self.assertIn("Host: example.com", finding["description"])
        self.assertIn("Parameter: password", finding["description"])
        
        # Check redaction: should not contain "mysecretpassword"
        self.assertIn("<redacted>", finding["description"])
        self.assertNotIn("mysecretpassword", finding["description"])

if __name__ == '__main__':
    unittest.main()
