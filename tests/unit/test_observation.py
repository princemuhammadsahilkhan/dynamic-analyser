"""Unit tests for the runtime observation and evidence collection module."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    LogcatCollector,
    ObservationError,
    ObservationShutdownError,
    ObservationStartupError,
    RuntimeObserver,
    save_evidence_items,
)
from dynamic_analysis.runtime import ShellResult


class TestEvidenceItem(unittest.TestCase):
    """Test suite for EvidenceItem dataclass."""

    def test_evidence_item_to_dict(self):
        """Verify EvidenceItem converts to serializable dictionary."""
        item = EvidenceItem(
            evidence_type="SYSTEM_PROPERTY",
            timestamp="2026-09-25T06:00:00Z",
            serial="emulator-5554",
            source="ro.build.version.sdk",
            content="33",
            exit_code=0,
        )
        d = item.to_dict()
        self.assertEqual(d["evidence_type"], "SYSTEM_PROPERTY")
        self.assertEqual(d["serial"], "emulator-5554")
        self.assertEqual(d["content"], "33")


class TestRuntimeObserver(unittest.TestCase):
    """Test suite for RuntimeObserver using mocks."""

    def setUp(self):
        self.orchestrator = MagicMock()
        self.orchestrator.is_running.return_value = True
        self.orchestrator.config.serial = "emulator-5554"
        self.observer = RuntimeObserver(orchestrator=self.orchestrator)

    def test_collect_properties_success(self):
        """Verify collect_properties queries orchestrator and returns EvidenceItems."""
        self.orchestrator.shell.side_effect = [
            ShellResult(exit_code=0, stdout="33\n", stderr=""),
            ShellResult(exit_code=0, stdout="13\n", stderr=""),
            ShellResult(exit_code=0, stdout="x86_64\n", stderr=""),
            ShellResult(exit_code=0, stdout="Pixel 6\n", stderr=""),
            ShellResult(exit_code=0, stdout="Google\n", stderr=""),
            ShellResult(exit_code=0, stdout="1\n", stderr=""),
        ]

        items = self.observer.collect_properties()

        self.assertEqual(len(items), 6)
        self.assertEqual(items[0].source, "ro.build.version.sdk")
        self.assertEqual(items[0].content, "33")
        self.assertEqual(items[0].serial, "emulator-5554")
        self.assertEqual(items[1].source, "ro.build.version.release")
        self.assertEqual(items[1].content, "13")

    def test_collect_properties_fails_when_runtime_not_running(self):
        """Verify collect_properties raises ObservationError if runtime is stopped."""
        self.orchestrator.is_running.return_value = False
        with self.assertRaises(ObservationError):
            self.observer.collect_properties()

    def test_collect_processes_success(self):
        """Verify collect_processes queries ps -A via orchestrator shell."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="USER PID PPID NAME\nroot 1 0 init\n", stderr=""
        )

        item = self.observer.collect_processes()

        self.assertEqual(item.evidence_type, EvidenceType.PROCESS_LIST.value)
        self.assertEqual(item.source, "ps -A")
        self.assertIn("init", item.content)
        self.orchestrator.shell.assert_called_once_with("ps -A")

    def test_collect_logcat_dump_success(self):
        """Verify collect_logcat_dump queries logcat -d via orchestrator shell."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="09-25 06:00:00.000  100  100 I SystemServer: Init\n", stderr=""
        )

        item = self.observer.collect_logcat_dump(timeout=5.0)

        self.assertEqual(item.evidence_type, EvidenceType.LOGCAT.value)
        self.assertEqual(item.source, "logcat -d")
        self.assertIn("SystemServer", item.content)
        self.orchestrator.shell.assert_called_once_with("logcat -d", timeout=5.0)


class TestLogcatCollector(unittest.TestCase):
    """Test suite for streaming LogcatCollector using process mocks."""

    def setUp(self):
        self.orchestrator = MagicMock()
        self.orchestrator.is_running.return_value = True
        self.orchestrator.config.serial = "emulator-5554"
        self.orchestrator.config.adb_binary = "/usr/bin/adb"
        self.collector = LogcatCollector(orchestrator=self.orchestrator)

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_start_logcat_collector(self, mock_run, mock_popen):
        """Verify start() launches adb logcat subprocess targeted at emulator serial."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        self.collector.start(clear_buffer=True)

        self.assertTrue(self.collector.is_running())
        mock_run.assert_called_once_with(
            ["/usr/bin/adb", "-s", "emulator-5554", "logcat", "-c"],
            capture_output=True,
            timeout=5.0,
        )
        mock_popen.assert_called_once_with(
            ["/usr/bin/adb", "-s", "emulator-5554", "logcat", "-v", "time"],
            stdout=-1,
            stderr=-1,
            text=True,
        )

    def test_start_fails_when_runtime_not_running(self):
        """Verify start() raises ObservationStartupError if runtime is stopped."""
        self.orchestrator.is_running.return_value = False
        with self.assertRaises(ObservationStartupError):
            self.collector.start()

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_stop_logcat_collector(self, mock_run, mock_popen):
        """Verify stop() terminates tracked child process and returns EvidenceItem."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.communicate.return_value = ("Log line 1\nLog line 2\n", "")
        mock_proc.returncode = 0
        self.collector._process = mock_proc

        item = self.collector.stop(timeout=2.0)

        mock_proc.terminate.assert_called_once()
        mock_proc.communicate.assert_called_once_with(timeout=2.0)
        self.assertFalse(self.collector.is_running())
        self.assertEqual(item.evidence_type, EvidenceType.LOGCAT.value)
        self.assertIn("Log line 1", item.content)

    def test_stop_fails_when_not_running(self):
        """Verify stop() raises ObservationShutdownError if no collector process is running."""
        with self.assertRaises(ObservationShutdownError):
            self.collector.stop()


class TestSaveEvidenceItems(unittest.TestCase):
    """Test suite for save_evidence_items file persistence helper."""

    def test_save_evidence_items_json(self):
        """Verify save_evidence_items writes valid JSON file to output_dir."""
        item = EvidenceItem(
            evidence_type="SYSTEM_PROPERTY",
            timestamp="2026-09-25T06:00:00Z",
            serial="emulator-5554",
            source="ro.build.version.sdk",
            content="33",
            exit_code=0,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_evidence_items([item], output_dir=tmpdir, filename="test_evidence.json")
            self.assertTrue(Path(path).is_file())
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["content"], "33")


if __name__ == "__main__":
    unittest.main()
