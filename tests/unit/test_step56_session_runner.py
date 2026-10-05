"""Unit tests for Step 56 — AnalysisSession integration into AnalysisRunner."""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

from dynamic_analysis.apk import APKLifecycleManager, APKLifecycleResult
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.observation import EvidenceItem, EvidenceType, LogcatCollector, RuntimeObserver
from dynamic_analysis.runner import AnalysisRunResult, AnalysisRunner, WorkflowError
from dynamic_analysis.runtime import (
    AndroidRuntimeError,
    AndroidRuntimeOrchestrator,
    BootTimeoutError,
    EmulatorStartError,
)
from dynamic_analysis.session import AnalysisSession, SessionStatus


class _RunnerTestBase(unittest.TestCase):
    """Common mock setup for AnalysisRunner session integration tests."""

    def setUp(self) -> None:
        self.orchestrator = MagicMock(spec=AndroidRuntimeOrchestrator)
        self.orchestrator.is_running.return_value = False
        # Provide a config attribute for metadata population
        self.orchestrator.config = MagicMock()
        self.orchestrator.config.avd_name = "analysis_baseline_api33"
        self.orchestrator.config.serial = "emulator-5554"

        self.apk_manager = MagicMock(spec=APKLifecycleManager)
        self.observer = MagicMock(spec=RuntimeObserver)

        self.prop_item = EvidenceItem(
            evidence_type="SYSTEM_PROPERTY",
            timestamp="2026-09-28T00:00:00Z",
            serial="emulator-5554",
            source="getprop ro.build.version.sdk",
            content="33",
        )
        self.proc_item = EvidenceItem(
            evidence_type="PROCESS_LIST",
            timestamp="2026-09-28T00:00:00Z",
            serial="emulator-5554",
            source="ps -A",
            content="PID NAME\n1 init",
        )
        self.dump_item = EvidenceItem(
            evidence_type="LOGCAT",
            timestamp="2026-09-28T00:00:00Z",
            serial="emulator-5554",
            source="logcat -d",
            content="logcat dump content",
        )
        self.stream_item = EvidenceItem(
            evidence_type="LOGCAT",
            timestamp="2026-09-28T00:00:00Z",
            serial="emulator-5554",
            source="logcat streaming",
            content="streamed log content",
        )

        self.observer.collect_properties.return_value = [self.prop_item]
        self.observer.collect_processes.return_value = self.proc_item
        self.observer.collect_logcat_dump.return_value = self.dump_item
        self.observer.collect_permissions.return_value = EvidenceItem(
            evidence_type="PERMISSIONS",
            timestamp="2026-09-28T00:00:00Z",
            serial="emulator-5554",
            source="dumpsys package",
            content="test permissions",
        )

        self.logcat_collector = MagicMock(spec=LogcatCollector)
        self.logcat_collector.is_running.return_value = False
        self.logcat_collector.stop.return_value = self.stream_item

        self.network_observer = MagicMock()
        self.network_observer.collect_all_network_evidence.return_value = []

        self.proxy_manager = MagicMock()
        self.proxy_manager.is_running.return_value = False
        self.proxy_manager.get_status.return_value = MagicMock(proxy_configured=False)

        self.runner = AnalysisRunner(
            orchestrator=self.orchestrator,
            apk_manager=self.apk_manager,
            observer=self.observer,
            logcat_collector=self.logcat_collector,
            network_observer=self.network_observer,
            proxy_manager=self.proxy_manager,
        )


class TestAutoSessionCreation(_RunnerTestBase):
    """Test automatic AnalysisSession creation when no session is provided."""

    def test_auto_creates_session_when_apk_path_provided(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIsNotNone(result.session)
        self.assertIsInstance(result.session, AnalysisSession)
        self.assertEqual(result.session.apk_path, "/path/to/test.apk")

    def test_auto_creates_session_from_job_apk_path(self):
        job = AnalysisJob(apk_path="/path/to/job.apk")
        result = self.runner.run(job=job)
        self.assertIsNotNone(result.session)
        self.assertEqual(result.session.apk_path, "/path/to/job.apk")

    def test_no_session_when_no_apk_path(self):
        result = self.runner.run()
        self.assertIsNone(result.session)

    def test_no_session_when_empty_job_apk_path(self):
        job = AnalysisJob(apk_path="")
        result = self.runner.run(job=job)
        self.assertIsNone(result.session)


class TestExternalSessionSupport(_RunnerTestBase):
    """Test that externally supplied AnalysisSession objects are respected."""

    def test_supplied_session_is_not_replaced(self):
        session = AnalysisSession(apk_path="/path/to/test.apk")
        original_id = session.analysis_id
        result = self.runner.run(apk_path="/path/to/test.apk", session=session)
        self.assertIs(result.session, session)
        self.assertEqual(result.session.analysis_id, original_id)

    def test_supplied_session_object_identity(self):
        session = AnalysisSession(apk_path="/path/to/test.apk")
        result = self.runner.run(apk_path="/path/to/test.apk", session=session)
        # Must be the exact same object, not a copy
        self.assertIs(result.session, session)


class TestSessionLifecycleOnSuccess(_RunnerTestBase):
    """Test session lifecycle transitions during successful runs."""

    def test_completed_status_on_success(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertEqual(result.session.status, SessionStatus.COMPLETED)

    def test_started_at_populated(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIsNotNone(result.session.started_at)
        self.assertIn("T", result.session.started_at)

    def test_finished_at_populated(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIsNotNone(result.session.finished_at)
        self.assertIn("T", result.session.finished_at)

    def test_external_session_transitions_to_completed(self):
        session = AnalysisSession(apk_path="/path/to/test.apk")
        self.assertEqual(session.status, SessionStatus.CREATED)
        result = self.runner.run(apk_path="/path/to/test.apk", session=session)
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertIsNotNone(session.started_at)
        self.assertIsNotNone(session.finished_at)


class TestSessionLifecycleOnFailure(_RunnerTestBase):
    """Test session lifecycle transitions during failed runs."""

    def test_failed_status_on_emulator_error(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Failed to launch")
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertFalse(result.success)
        self.assertIsNotNone(result.session)
        self.assertEqual(result.session.status, SessionStatus.FAILED)

    def test_finished_at_populated_on_failure(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Failed to launch")
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIsNotNone(result.session.finished_at)

    def test_started_at_populated_on_failure(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Failed to launch")
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIsNotNone(result.session.started_at)

    def test_failed_status_on_boot_timeout(self):
        self.orchestrator.wait_for_boot.side_effect = BootTimeoutError("Boot timeout")
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertEqual(result.session.status, SessionStatus.FAILED)

    def test_session_not_stuck_in_running_on_raise_on_error(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Fatal")
        with self.assertRaises(WorkflowError):
            self.runner.run(apk_path="/path/to/test.apk", raise_on_error=True)


class TestAnalysisRunResultSession(_RunnerTestBase):
    """Test that AnalysisRunResult correctly exposes the session."""

    def test_result_exposes_session(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIsNotNone(result.session)
        self.assertIsInstance(result.session, AnalysisSession)

    def test_result_session_is_none_without_apk(self):
        result = self.runner.run()
        self.assertIsNone(result.session)

    def test_result_has_session_field(self):
        result = AnalysisRunResult(job=None, success=True)
        self.assertIsNone(result.session)


class TestSessionRunDirectory(_RunnerTestBase):
    """Test deterministic run directory behavior."""

    def test_session_run_dir_is_deterministic(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIn(result.session.analysis_id, result.session.run_dir)

    def test_session_evidence_dir_accessible(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertTrue(result.session.evidence_dir.endswith("evidence"))

    @patch("dynamic_analysis.runner.save_evidence_items")
    def test_evidence_saved_to_session_evidence_dir_when_no_output_dir(self, mock_save):
        mock_save.return_value = "/evidence/path/evidence.json"
        result = self.runner.run(apk_path="/path/to/test.apk")
        # When no output_dir is specified, evidence should be saved under session.evidence_dir
        mock_save.assert_called_once()
        called_dir = mock_save.call_args[0][1]
        self.assertEqual(called_dir, result.session.evidence_dir)

    @patch("dynamic_analysis.runner.save_evidence_items")
    def test_explicit_output_dir_overrides_session_dir(self, mock_save):
        mock_save.return_value = "/tmp/custom/evidence.json"
        result = self.runner.run(apk_path="/path/to/test.apk", output_dir="/tmp/custom")
        mock_save.assert_called_once()
        called_dir = mock_save.call_args[0][1]
        self.assertEqual(called_dir, "/tmp/custom")


class TestSessionMetadata(_RunnerTestBase):
    """Test session config_metadata population."""

    def test_metadata_contains_launch_app(self):
        result = self.runner.run(apk_path="/path/to/test.apk", launch_app=True)
        self.assertEqual(result.session.config_metadata["launch_app"], "True")

    def test_metadata_contains_proxy_enabled(self):
        result = self.runner.run(apk_path="/path/to/test.apk", enable_proxy=False)
        self.assertEqual(result.session.config_metadata["proxy_enabled"], "False")

    def test_metadata_contains_avd_name(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertEqual(result.session.config_metadata["avd_name"], "analysis_baseline_api33")

    def test_metadata_contains_boot_timeout_when_set(self):
        result = self.runner.run(apk_path="/path/to/test.apk", boot_timeout=120.0)
        self.assertEqual(result.session.config_metadata["boot_timeout"], "120.0")

    def test_metadata_all_json_safe(self):
        result = self.runner.run(apk_path="/path/to/test.apk", boot_timeout=90.0)
        # All metadata values must be JSON-serializable strings
        for key, value in result.session.config_metadata.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, str)
        json_str = json.dumps(result.session.config_metadata)
        self.assertIsInstance(json_str, str)


class TestSessionEvidenceItem(_RunnerTestBase):
    """Test that a SESSION evidence item is emitted."""

    def test_session_evidence_item_present(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        session_items = [
            e for e in result.evidence_items if e.evidence_type == EvidenceType.SESSION.value
        ]
        self.assertEqual(len(session_items), 1)

    def test_session_evidence_content_is_json(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        session_items = [
            e for e in result.evidence_items if e.evidence_type == EvidenceType.SESSION.value
        ]
        parsed = json.loads(session_items[0].content)
        self.assertIn("analysis_id", parsed)
        self.assertIn("status", parsed)

    def test_no_session_evidence_without_session(self):
        result = self.runner.run()
        session_items = [
            e for e in result.evidence_items if e.evidence_type == EvidenceType.SESSION.value
        ]
        self.assertEqual(len(session_items), 0)


class TestRaiseOnErrorBehavior(_RunnerTestBase):
    """Test raise_on_error preserves correct behavior with sessions."""

    def test_raise_on_error_false_returns_result(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Failed")
        result = self.runner.run(apk_path="/path/to/test.apk", raise_on_error=False)
        self.assertFalse(result.success)
        self.assertIn("Failed", result.error_message)
        self.assertEqual(result.session.status, SessionStatus.FAILED)
        self.assertIsNotNone(result.session.finished_at)

    def test_raise_on_error_true_raises_workflow_error(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Fatal")
        with self.assertRaises(WorkflowError):
            self.runner.run(apk_path="/path/to/test.apk", raise_on_error=True)


class TestCleanupWithSession(_RunnerTestBase):
    """Test that cleanup still executes when workflow fails with sessions."""

    def test_cleanup_executes_on_failure(self):
        self.orchestrator.wait_for_boot.side_effect = AndroidRuntimeError("Runtime error")
        self.logcat_collector.is_running.return_value = True
        self.orchestrator.is_running.return_value = True

        result = self.runner.run(apk_path="/path/to/test.apk")

        self.assertFalse(result.success)
        self.logcat_collector.stop.assert_called()
        self.orchestrator.shutdown.assert_called()

    def test_session_finalized_even_if_cleanup_errors(self):
        self.orchestrator.start.side_effect = EmulatorStartError("Fail")
        self.orchestrator.is_running.return_value = True
        self.orchestrator.shutdown.side_effect = Exception("Cleanup error")

        result = self.runner.run(apk_path="/path/to/test.apk")
        # Session must still be FAILED, not stuck in RUNNING
        self.assertEqual(result.session.status, SessionStatus.FAILED)
        self.assertIsNotNone(result.session.finished_at)


class TestBackwardCompatibility(_RunnerTestBase):
    """Test that existing AnalysisRunner behavior remains compatible."""

    def test_run_without_session_without_apk(self):
        result = self.runner.run()
        self.assertTrue(result.success)
        self.assertIsNone(result.session)
        self.assertIsNone(result.apk_result)

    def test_run_with_job_only(self):
        job = AnalysisJob(apk_path="/path/to/test.apk")
        result = self.runner.run(job=job)
        self.assertTrue(result.success)
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertIsNotNone(result.session)

    def test_run_with_empty_job(self):
        job = AnalysisJob(apk_path="")
        result = self.runner.run(job=job)
        self.assertTrue(result.success)
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertIsNone(result.session)

    @patch("dynamic_analysis.runner.save_evidence_items")
    def test_explicit_output_dir_still_works(self, mock_save):
        mock_save.return_value = "/tmp/out/evidence.json"
        result = self.runner.run(output_dir="/tmp/out")
        self.assertTrue(result.success)
        self.assertEqual(result.evidence_file_path, "/tmp/out/evidence.json")
        mock_save.assert_called_once()

    def test_evidence_items_still_collected(self):
        result = self.runner.run(apk_path="/path/to/test.apk")
        self.assertIn(self.prop_item, result.evidence_items)
        self.assertIn(self.proc_item, result.evidence_items)
        self.assertIn(self.dump_item, result.evidence_items)
        self.assertIn(self.stream_item, result.evidence_items)


if __name__ == "__main__":
    unittest.main()
