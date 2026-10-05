"""Unit tests for the Android runtime orchestration module."""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.runtime import (
    ADBError,
    AndroidRuntimeError,
    AndroidRuntimeOrchestrator,
    BootTimeoutError,
    EmulatorStartError,
    ShellCommandError,
    ShellResult,
    ShutdownError,
)


class TestAndroidRuntimeOrchestrator(unittest.TestCase):
    """Test suite for AndroidRuntimeOrchestrator logic and lifecycle methods using mocks."""

    def setUp(self) -> None:
        self.config = AndroidRuntimeConfig(
            sdk_root="/mock/sdk",
            avd_name="test_avd",
            emulator_binary="/mock/sdk/emulator/emulator",
            adb_binary="/mock/bin/adb",
            port=5554,
            boot_timeout=2.0,
            adb_timeout=2.0,
            shutdown_timeout=1.0,
            command_timeout=2.0,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(config=self.config)

    def test_initial_state_not_running(self) -> None:
        """Verify orchestrator reports is_running() as False initially."""
        self.assertFalse(self.orchestrator.is_running())

    @patch("os.path.exists", return_value=True)
    @patch("subprocess.Popen")
    def test_successful_process_startup(self, mock_popen, mock_exists) -> None:
        """Verify start() launches subprocess.Popen with expected CLI flags and environment."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        self.orchestrator.start()

        self.assertTrue(self.orchestrator.is_running())
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        self.assertEqual(cmd[0], "/mock/sdk/emulator/emulator")
        self.assertIn("-avd", cmd)
        self.assertIn("test_avd", cmd)
        self.assertIn("-port", cmd)
        self.assertIn("5554", cmd)
        self.assertIn("-no-window", cmd)
        self.assertIn("-no-audio", cmd)

        env = mock_popen.call_args[1]["env"]
        self.assertEqual(env.get("ANDROID_SDK_ROOT"), "/mock/sdk")
        self.assertEqual(env.get("ANDROID_HOME"), "/mock/sdk")

    @patch("os.path.exists", return_value=False)
    def test_start_fails_missing_binary(self, mock_exists) -> None:
        """Verify start() raises EmulatorStartError if emulator binary does not exist."""
        with self.assertRaises(EmulatorStartError) as ctx:
            self.orchestrator.start()
        self.assertIn("Emulator binary not found", str(ctx.exception))

    @patch("os.path.exists", return_value=True)
    @patch("subprocess.Popen")
    def test_start_fails_immediate_exit(self, mock_popen, mock_exists) -> None:
        """Verify start() raises EmulatorStartError if child process exits immediately."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.stderr.read.return_value = "Fatal graphics error"
        mock_popen.return_value = mock_proc

        with self.assertRaises(EmulatorStartError) as ctx:
            self.orchestrator.start()
        self.assertIn("exited immediately with code 1", str(ctx.exception))
        self.assertFalse(self.orchestrator.is_running())

    @patch("subprocess.run")
    def test_adb_offline_to_device_transition(self, mock_run) -> None:
        """Verify wait_for_adb handles transition from offline to device state."""
        self.orchestrator._process = MagicMock()
        self.orchestrator._process.poll.return_value = None

        offline_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="offline", stderr=""
        )
        device_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="device", stderr=""
        )
        mock_run.side_effect = [offline_res, device_res]

        result = self.orchestrator.wait_for_adb(timeout=5.0)
        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2)

    @patch("subprocess.run")
    def test_boot_completion(self, mock_run) -> None:
        """Verify wait_for_boot succeeds when sys.boot_completed returns '1'."""
        self.orchestrator._process = MagicMock()
        self.orchestrator._process.poll.return_value = None

        adb_state_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="device", stderr=""
        )
        boot_not_ready = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="0", stderr=""
        )
        boot_ready = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="1", stderr=""
        )
        mock_run.side_effect = [adb_state_res, boot_not_ready, boot_ready]

        result = self.orchestrator.wait_for_boot(timeout=5.0)
        self.assertTrue(result)

    @patch("subprocess.run")
    def test_boot_timeout(self, mock_run) -> None:
        """Verify wait_for_boot raises BootTimeoutError if boot property remains '0'."""
        self.orchestrator._process = MagicMock()
        self.orchestrator._process.poll.return_value = None

        adb_state_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="device", stderr=""
        )
        boot_not_ready = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="0", stderr=""
        )
        mock_run.side_effect = [adb_state_res] + [boot_not_ready] * 10

        with self.assertRaises(BootTimeoutError):
            self.orchestrator.wait_for_boot(timeout=0.5)

    @patch("subprocess.run")
    def test_emulator_process_exits_unexpectedly_during_boot(self, mock_run) -> None:
        """Verify wait_for_boot detects process termination and raises EmulatorStartError."""
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, 137]  # Process dies
        mock_proc.stderr.read.return_value = "Out of memory"
        self.orchestrator._process = mock_proc

        adb_state_res = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="device", stderr=""
        )
        mock_run.return_value = adb_state_res

        with self.assertRaises(EmulatorStartError) as ctx:
            self.orchestrator.wait_for_boot(timeout=5.0)
        self.assertIn("terminated unexpectedly", str(ctx.exception))

    @patch("subprocess.run")
    def test_shell_command_execution(self, mock_run) -> None:
        """Verify shell() executes ADB command against target serial and returns ShellResult."""
        self.orchestrator._process = MagicMock()
        self.orchestrator._process.poll.return_value = None

        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="33\n", stderr=""
        )

        res = self.orchestrator.shell("getprop ro.build.version.sdk")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.stdout, "33\n")
        self.assertEqual(res.stderr, "")

        mock_run.assert_called_once_with(
            ["/mock/bin/adb", "-s", "emulator-5554", "shell", "getprop ro.build.version.sdk"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )

    @patch("subprocess.run")
    def test_clean_shutdown(self, mock_run) -> None:
        """Verify shutdown() sends emu kill and waits for tracked process exit."""
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, 0]  # Running, then exited
        self.orchestrator._process = mock_proc

        self.orchestrator.shutdown()

        mock_run.assert_called_once_with(
            ["/mock/bin/adb", "-s", "emulator-5554", "emu", "kill"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        mock_proc.wait.assert_called_once_with(timeout=1.0)
        self.assertFalse(self.orchestrator.is_running())

    @patch("subprocess.run")
    def test_failed_shutdown_handling(self, mock_run) -> None:
        """Verify shutdown() escalates to kill() on tracked process if wait times out."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9999
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="emu kill", timeout=1.0), None]
        self.orchestrator._process = mock_proc

        self.orchestrator.shutdown()

        mock_proc.kill.assert_called_once()
        self.assertFalse(self.orchestrator.is_running())

    def test_cleanup_only_targets_tracked_process(self) -> None:
        """Verify cleanup() calls shutdown/kill exclusively on self._process."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        self.orchestrator._process = mock_proc

        with patch.object(self.orchestrator, "shutdown") as mock_shutdown:
            self.orchestrator.cleanup()
            mock_shutdown.assert_called_once_with(timeout=5.0)


if __name__ == "__main__":
    unittest.main()
