import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.finding import FindingCategory, FindingSeverity, FindingStatus
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.session import AnalysisSession


class TestStep76LogcatIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.session = AnalysisSession(
            apk_path="fake.apk",
            base_output_dir=self.temp_dir.name
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_logcat_evidence(self, content: str) -> EvidenceItem:
        return EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            content=content,
            timestamp=_get_utc_timestamp(),
            source="logcat",
            serial="test_serial"
        )

    @patch("dynamic_analysis.runner.AndroidRuntimeOrchestrator")
    @patch("dynamic_analysis.runner.ProxyManager")
    @patch("dynamic_analysis.runner.NetworkObserver")
    @patch("dynamic_analysis.runner.LogcatCollector")
    @patch("dynamic_analysis.runner.RuntimeObserver")
    @patch("dynamic_analysis.runner.APKLifecycleManager")
    def test_integration_logcat_rule(
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
        proxy_instance.get_evidence_items.return_value = []
        
        # Setup evidence
        evidence1 = self._create_logcat_evidence("10-25 12:34:56.789  1234  5678 D MyApp: Password: SuperSecretPassword123")
        evidence2 = self._create_logcat_evidence("10-25 12:34:56.789  1234  5678 D MyApp: This is just a normal log.")
        
        observer_instance = mock_observer.return_value
        observer_instance.collect_properties.return_value = []
        observer_instance.collect_processes.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="adb",
            content="proc"
        )
        logcat_content = "10-25 12:34:56.789  1234  5678 D MyApp: Password: SuperSecretPassword123\n10-25 12:34:56.789  1234  5678 D MyApp: This is just a normal log."
        observer_instance.collect_logcat_dump.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial="test_serial",
            source="adb",
            content=logcat_content
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
            content=""
        )
        logcat_instance.get_evidence_items.return_value = [evidence1, evidence2]
        
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
            enable_proxy=False,
            launch_app=False,
            observation_duration=0
        )
        
        self.assertTrue(result.success, msg=getattr(result, "error_message", "No error message"))
        
        # Verify findings are saved
        findings_file = os.path.join(self.session.findings_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_file))
        
        with open(findings_file, "r") as f:
            findings_data = json.load(f)
            
        rule_findings = [f for f in findings_data if f["title"].startswith("[RULE-019]")]
        
        self.assertEqual(len(rule_findings), 1)
        
        for f in rule_findings:
            self.assertEqual(f["severity"], "MEDIUM")
            self.assertEqual(f["category"], "MISC")
            self.assertEqual(f["status"], "VALIDATED")
            self.assertIn("Sup...<redacted>", f["description"])
