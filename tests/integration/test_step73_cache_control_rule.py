import json
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.runner import AnalysisRunner, AnalysisRunResult
from dynamic_analysis.session import AnalysisSession, SessionStatus

class TestMissingCacheControlRuleIntegration(unittest.TestCase):
    def setUp(self):
        self.session = AnalysisSession(apk_path="dummy.apk")
        self.orchestrator = MagicMock()
        self.orchestrator.config = MagicMock(avd_name="test_avd", serial="emulator-5554")
        self.apk_manager = MagicMock()
        self.apk_manager.run_lifecycle.return_value = MagicMock(package_name="com.test.app")
        
        self.observer = MagicMock()
        self.observer.collect_properties.return_value = []
        self.observer.collect_processes.return_value = EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial="serial",
            source="observer",
            content="init\n"
        )
        self.observer.collect_logcat_dump.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial="serial",
            source="observer",
            content="log dump\n"
        )
        
        # Avoid MagicMock in JSON serialization for permissions
        self.observer.collect_permissions.return_value = EvidenceItem(
            evidence_type=EvidenceType.PERMISSIONS.value,
            timestamp=_get_utc_timestamp(),
            serial="serial",
            source="observer",
            content=""
        )
        
        self.logcat_collector = MagicMock()
        self.logcat_collector.stop.return_value = EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial="serial",
            source="logcat",
            content="streamed logs"
        )
        
        self.network_observer = MagicMock()
        self.network_observer.collect_all_network_evidence.return_value = []
        
        self.proxy_manager = MagicMock()
        
        self.runner = AnalysisRunner(
            orchestrator=self.orchestrator,
            apk_manager=self.apk_manager,
            observer=self.observer,
            logcat_collector=self.logcat_collector,
            network_observer=self.network_observer,
            proxy_manager=self.proxy_manager
        )

    @patch("dynamic_analysis.runner.save_evidence_items")
    def test_runner_triggers_cache_control_rule(self, mock_save):
        mock_save.return_value = "/tmp/fake_evidence.json"
        
        # Create evidence missing Cache-Control
        content = {
            "request": {"host": "vulnerable.com"},
            "host": "vulnerable.com",
            "raw_metadata": {
                "response_headers": {
                    "Content-Type": "text/html"
                }
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="serial",
            source="proxy",
            content=json.dumps(content)
        )
        
        self.proxy_manager.get_evidence_items.return_value = [ev]
        self.proxy_manager.get_status.return_value.proxy_configured = False
        self.proxy_manager.is_running.return_value = False
        
        result = self.runner.run(session=self.session, launch_app=False, enable_proxy=True)
        
        self.assertTrue(result.success, msg=result.error_message)
        self.assertEqual(result.session.status, SessionStatus.COMPLETED)
        
        # Ensure RULE-016 triggered
        findings = [f for f in result.findings if "Missing Cache-Control Header Observed" in f.title and "RULE-016" in f.title]
        self.assertEqual(len(findings), 1)
        
        f = findings[0]
        self.assertEqual(f.severity.value, "LOW")
        self.assertEqual(f.category.value, "NETWORK")
        self.assertTrue("vulnerable.com" in f.title)

    @patch("dynamic_analysis.runner.save_evidence_items")
    def test_runner_no_finding_when_cache_control_present(self, mock_save):
        mock_save.return_value = "/tmp/fake_evidence.json"
        
        # Create evidence with Cache-Control
        content = {
            "request": {"host": "secure.com"},
            "host": "secure.com",
            "raw_metadata": {
                "response_headers": {
                    "Cache-Control": "no-cache",
                    "Content-Type": "text/html"
                }
            }
        }
        ev = EvidenceItem(
            evidence_type=EvidenceType.HTTPS_TRAFFIC.value,
            timestamp=_get_utc_timestamp(),
            serial="serial",
            source="proxy",
            content=json.dumps(content)
        )
        
        self.proxy_manager.get_evidence_items.return_value = [ev]
        self.proxy_manager.get_status.return_value.proxy_configured = False
        self.proxy_manager.is_running.return_value = False
        
        result = self.runner.run(session=self.session, launch_app=False, enable_proxy=True)
        
        self.assertTrue(result.success, msg=result.error_message)
        self.assertEqual(result.session.status, SessionStatus.COMPLETED)
        
        # Ensure RULE-016 did NOT trigger
        findings = [f for f in result.findings if "RULE-016" in f.title]
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()
