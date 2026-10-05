import os
import json
import unittest
from unittest.mock import patch, MagicMock

from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession
from dynamic_analysis.rules import EvidenceItem, EvidenceType
from dynamic_analysis.observation import _get_utc_timestamp

class TestStep75PermissionsPolicyIntegration(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(
            apk_path="fake.apk",
            base_output_dir="/tmp/fake_output",
            package_name="com.example.app"
        )
        os.makedirs(self.session.findings_dir, exist_ok=True)
        os.makedirs(self.session.evidence_dir, exist_ok=True)

    def _create_http_evidence(self, host: str, headers: dict) -> EvidenceItem:
        content = {
            "host": host,
            "request": {"host": host},
            "raw_metadata": {
                "response_headers": headers
            }
        }
        return EvidenceItem(
            evidence_type=EvidenceType.HTTP_TRAFFIC.value,
            content=json.dumps(content),
            timestamp=_get_utc_timestamp(),
            source="proxy",
            serial="test_serial"
        )

    @patch("dynamic_analysis.runner.AndroidRuntimeOrchestrator")
    @patch("dynamic_analysis.runner.ProxyManager")
    @patch("dynamic_analysis.runner.NetworkObserver")
    @patch("dynamic_analysis.runner.LogcatCollector")
    @patch("dynamic_analysis.runner.RuntimeObserver")
    @patch("dynamic_analysis.runner.APKLifecycleManager")
    def test_integration_permissions_policy_rule(
        self,
        mock_apk_manager,
        mock_observer,
        mock_logcat,
        mock_network,
        mock_proxy,
        mock_orchestrator
    ):
        # Create mock instances
        orchestrator_instance = mock_orchestrator.return_value
        orchestrator_instance.config = MagicMock()
        orchestrator_instance.config.avd_name = "test_avd"
        orchestrator_instance.config.serial = "test_serial"

        proxy_instance = mock_proxy.return_value
        proxy_instance.get_status.return_value.proxy_configured = False

        # Setup evidence
        # 1. Missing Permissions-Policy
        evidence1 = self._create_http_evidence("api.example.com", {
            "Content-Type": "application/json"
        })
        
        # 2. Has Permissions-Policy
        evidence2 = self._create_http_evidence("secure.example.com", {
            "Permissions-Policy": "geolocation=()",
            "Content-Type": "text/html"
        })

        # 3. Duplicate missing
        evidence3 = self._create_http_evidence("api.example.com", {
            "Content-Type": "application/xml"
        })

        proxy_instance.get_evidence_items.return_value = [evidence1, evidence2, evidence3]

        observer_instance = mock_observer.return_value
        observer_instance.collect_properties.return_value = []
        observer_instance.collect_processes.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="adb",
            content="proc"
        )
        observer_instance.collect_logcat_dump.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="adb",
            content="logcat"
        )
        observer_instance.collect_permissions.return_value = EvidenceItem(
            evidence_type="PERMISSIONS",
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="adb",
            content="[]"
        )

        network_instance = mock_network.return_value
        network_instance.collect_all_network_evidence.return_value = []

        logcat_instance = mock_logcat.return_value
        logcat_instance.stop.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="adb",
            content="stream"
        )

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

        # Verify findings are saved
        findings_file = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))

        with open(findings_file, "r") as f:
            findings_data = json.load(f)

        policy_findings = [f for f in findings_data if f["title"].startswith("[RULE-018]")]
        
        # Only 1 finding expected due to deduplication on api.example.com
        # secure.example.com should not trigger since it has the header
        self.assertEqual(len(policy_findings), 1)
        self.assertEqual(policy_findings[0]["title"], "[RULE-018] Missing Permissions-Policy Header Observed - api.example.com")
        self.assertEqual(policy_findings[0]["severity"], "LOW")
        self.assertEqual(policy_findings[0]["category"], "NETWORK")

if __name__ == "__main__":
    unittest.main()
