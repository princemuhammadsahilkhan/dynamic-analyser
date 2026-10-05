"""Unit tests for the AnalysisRunner workflow orchestration layer."""

import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.apk import APKLifecycleManager, APKLifecycleResult
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.observation import EvidenceItem, LogcatCollector, RuntimeObserver
from dynamic_analysis.runner import AnalysisRunResult, AnalysisRunner, WorkflowError
from dynamic_analysis.runtime import (
    AndroidRuntimeError,
    AndroidRuntimeOrchestrator,
    BootTimeoutError,
    EmulatorStartError,
)


class TestAnalysisRunner(unittest.TestCase):
    """Unit test suite for AnalysisRunner orchestration workflow."""

    def setUp(self) -> None:
        self.orchestrator = MagicMock(spec=AndroidRuntimeOrchestrator)
        self.orchestrator.is_running.return_value = False

        self.apk_manager = MagicMock(spec=APKLifecycleManager)
        self.observer = MagicMock(spec=RuntimeObserver)

        self.prop_item = EvidenceItem(
            evidence_type="SYSTEM_PROPERTY",
            timestamp="2026-09-25T00:00:00Z",
            serial="emulator-5554",
            source="getprop ro.build.version.sdk",
            content="33",
        )
        self.proc_item = EvidenceItem(
            evidence_type="PROCESS_LIST",
            timestamp="2026-09-25T00:00:00Z",
            serial="emulator-5554",
            source="ps -A",
            content="PID NAME\n1 init",
        )
        self.dump_item = EvidenceItem(
            evidence_type="LOGCAT",
            timestamp="2026-09-25T00:00:00Z",
            serial="emulator-5554",
            source="logcat -d",
            content="logcat dump content",
        )
        self.stream_item = EvidenceItem(
            evidence_type="LOGCAT",
            timestamp="2026-09-25T00:00:00Z",
            serial="emulator-5554",
            source="logcat streaming",
            content="streamed log content",
        )

        self.observer.collect_properties.return_value = [self.prop_item]
        self.observer.collect_processes.return_value = self.proc_item
        self.observer.collect_logcat_dump.return_value = self.dump_item
        self.observer.collect_permissions.return_value = EvidenceItem(
            evidence_type="PERMISSIONS",
            timestamp="2026-09-25T00:00:00Z",
            serial="emulator-5554",
            source="dumpsys package",
            content="test permissions",
        )

        self.logcat_collector = MagicMock(spec=LogcatCollector)
        self.logcat_collector.is_running.return_value = False
        self.logcat_collector.stop.return_value = self.stream_item

        self.network_observer = MagicMock()
        self.network_observer.collect_all_network_evidence.return_value = []

        self.runner = AnalysisRunner(
            orchestrator=self.orchestrator,
            apk_manager=self.apk_manager,
            observer=self.observer,
            logcat_collector=self.logcat_collector,
            network_observer=self.network_observer,
        )

    def test_runner_initialization_defaults(self) -> None:
        """Verify default component initialization when dependencies are omitted."""
        runner = AnalysisRunner()
        self.assertIsNotNone(runner.orchestrator)
        self.assertIsNotNone(runner.apk_manager)
        self.assertIsNotNone(runner.observer)
        self.assertIsNotNone(runner.logcat_collector)
        self.assertIsNotNone(runner.network_observer)

    def test_successful_workflow_run_without_apk(self) -> None:
        """Verify complete workflow execution lifecycle when no APK is provided."""
        job = AnalysisJob(apk_path="")
        result = self.runner.run(job=job)

        self.assertTrue(result.success)
        self.assertIsNone(result.error_message)
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertIsNone(result.apk_result)

        self.orchestrator.start.assert_called_once()
        self.orchestrator.wait_for_boot.assert_called_once()
        self.logcat_collector.start.assert_called_once_with(clear_buffer=True)
        self.logcat_collector.stop.assert_called_once()
        self.apk_manager.run_lifecycle.assert_not_called()

        self.assertIn(self.prop_item, result.evidence_items)
        self.assertIn(self.proc_item, result.evidence_items)
        self.assertIn(self.dump_item, result.evidence_items)
        self.assertIn(self.stream_item, result.evidence_items)

    def test_successful_workflow_run_with_apk(self) -> None:
        """Verify complete workflow execution lifecycle when an APK is provided."""
        job = AnalysisJob(apk_path="/path/to/test.apk")
        mock_apk_result = APKLifecycleResult(
            apk_path="/path/to/test.apk",
            package_name="com.example.app",
            launchable_activity="com.example.app.MainActivity",
            installed=True,
            verified=True,
            launched=True,
            install_output="Success",
            launch_output="Starting activity",
        )
        self.apk_manager.run_lifecycle.return_value = mock_apk_result

        result = self.runner.run(job=job)

        if not result.success:
            print("ERROR IN TEST:", result.error_message)
        self.assertTrue(result.success)
        self.assertEqual(job.state, JobState.COMPLETED)
        self.assertEqual(result.apk_result, mock_apk_result)
        self.apk_manager.run_lifecycle.assert_called_once_with("/path/to/test.apk", launch=True)

    @patch("dynamic_analysis.runner.save_evidence_items")
    def test_saves_evidence_when_output_dir_specified(self, mock_save) -> None:
        """Verify save_evidence_items is called when output_dir is provided."""
        mock_save.return_value = "/tmp/test_dir/evidence.json"
        result = self.runner.run(output_dir="/tmp/test_dir")

        self.assertTrue(result.success)
        self.assertEqual(result.evidence_file_path, "/tmp/test_dir/evidence.json")
        mock_save.assert_called_once_with(result.evidence_items, "/tmp/test_dir")

    def test_handles_emulator_start_failure(self) -> None:
        """Verify failure handling when emulator start raises EmulatorStartError."""
        self.orchestrator.start.side_effect = EmulatorStartError("Failed to start")
        job = AnalysisJob(apk_path="")

        result = self.runner.run(job=job)

        self.assertFalse(result.success)
        self.assertIn("Failed to start", result.error_message)
        self.assertEqual(job.state, JobState.FAILED)

    def test_handles_boot_timeout_failure(self) -> None:
        """Verify failure handling when guest boot times out."""
        self.orchestrator.wait_for_boot.side_effect = BootTimeoutError("Boot timeout")
        job = AnalysisJob(apk_path="")

        result = self.runner.run(job=job)

        self.assertFalse(result.success)
        self.assertIn("Boot timeout", result.error_message)
        self.assertEqual(job.state, JobState.FAILED)

    def test_raises_on_error_flag(self) -> None:
        """Verify WorkflowError is raised when raise_on_error=True."""
        self.orchestrator.start.side_effect = EmulatorStartError("Fatal start error")
        job = AnalysisJob(apk_path="")

        with self.assertRaises(WorkflowError):
            self.runner.run(job=job, raise_on_error=True)

        self.assertEqual(job.state, JobState.FAILED)

    def test_guarantees_cleanup_in_finally_block(self) -> None:
        """Verify logcat_collector and orchestrator shutdown are called on error."""
        self.orchestrator.wait_for_boot.side_effect = AndroidRuntimeError("Runtime error")

        # Simulate active state during cleanup
        self.logcat_collector.is_running.return_value = True
        self.orchestrator.is_running.return_value = True

        result = self.runner.run()

        self.assertFalse(result.success)
        self.logcat_collector.stop.assert_called()
        self.orchestrator.shutdown.assert_called()


if __name__ == "__main__":
    unittest.main()
