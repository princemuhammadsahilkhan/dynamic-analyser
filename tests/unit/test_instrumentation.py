"""Unit tests for controlled dynamic instrumentation boundary module."""

import sys
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.instrumentation import (
    InstrumentationManager,
    InstrumentationResult,
    InstrumentationStatus,
)
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator, ShellResult


class TestInstrumentationManager(unittest.TestCase):
    """Unit test suite for InstrumentationManager boundary layer."""

    def setUp(self) -> None:
        self.orchestrator = MagicMock(spec=AndroidRuntimeOrchestrator)
        self.orchestrator.is_running.return_value = True
        self.orchestrator.config = MagicMock()
        self.orchestrator.config.serial = "emulator-5554"
        self.manager = InstrumentationManager(orchestrator=self.orchestrator)

    def test_instrumentation_result_to_dict_and_evidence(self) -> None:
        """Verify InstrumentationResult conversion to dict and EvidenceItem."""
        res = InstrumentationResult(
            target_package="com.example.app",
            status=InstrumentationStatus.CONNECTED.value,
            frida_client_version="17.15.3",
            connected=True,
            proof_of_connectivity={"rpc_ping": "pong"},
        )
        data = res.to_dict()
        self.assertEqual(data["target_package"], "com.example.app")
        self.assertTrue(data["connected"])

        evidence = res.to_evidence_item(serial="emulator-5554")
        self.assertEqual(evidence.evidence_type, "INSTRUMENTATION")
        self.assertEqual(evidence.serial, "emulator-5554")
        self.assertEqual(evidence.exit_code, 0)

    @patch.dict("sys.modules", {"frida": None})
    def test_check_client_availability_missing(self) -> None:
        """Verify check_client_availability returns None when frida is missing."""
        # Force ImportError when importing frida
        with patch.object(self.manager, "check_client_availability", return_value=None):
            ver = self.manager.check_client_availability()
            self.assertIsNone(ver)

    def test_check_client_availability_present(self) -> None:
        """Verify check_client_availability returns version string when frida is present."""
        mock_frida = MagicMock()
        mock_frida.__version__ = "17.15.3"
        with patch.dict("sys.modules", {"frida": mock_frida}):
            ver = self.manager.check_client_availability()
            self.assertEqual(ver, "17.15.3")

    def test_check_server_running_when_orchestrator_stopped(self) -> None:
        """Verify check_server_running returns False when orchestrator is not running."""
        self.orchestrator.is_running.return_value = False
        self.assertFalse(self.manager.check_server_running())

    def test_check_server_running_when_server_absent(self) -> None:
        """Verify check_server_running returns False when frida-server is not in ps -A."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="USER PID PPID NAME\nroot 1 0 init\n", stderr=""
        )
        self.assertFalse(self.manager.check_server_running())

    def test_check_server_running_when_server_present(self) -> None:
        """Verify check_server_running returns True when frida-server is in ps -A."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0,
            stdout="USER PID PPID NAME\nroot 1 0 init\nroot 1234 1 frida-server-17.15.3\n",
            stderr="",
        )
        self.assertTrue(self.manager.check_server_running())

    def test_attach_when_client_not_available(self) -> None:
        """Verify attach returns NOT_AVAILABLE when frida package is missing."""
        with patch.object(self.manager, "check_client_availability", return_value=None):
            res = self.manager.attach("com.example.mentorcraft2")
            self.assertEqual(res.status, InstrumentationStatus.NOT_AVAILABLE.value)
            self.assertFalse(res.connected)
            self.assertIn("not installed", res.error_message)

    def test_attach_when_orchestrator_not_running(self) -> None:
        """Verify attach returns FAILED when orchestrator is not running."""
        self.orchestrator.is_running.return_value = False
        with patch.object(self.manager, "check_client_availability", return_value="17.15.3"):
            res = self.manager.attach("com.example.mentorcraft2")
            self.assertEqual(res.status, InstrumentationStatus.FAILED.value)
            self.assertFalse(res.connected)

    def test_attach_when_server_not_running(self) -> None:
        """Verify attach returns SERVER_NOT_RUNNING when frida-server process is missing."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="root 1 0 init", stderr=""
        )
        with patch.object(self.manager, "check_client_availability", return_value="17.15.3"):
            res = self.manager.attach("com.example.mentorcraft2")
            self.assertEqual(res.status, InstrumentationStatus.SERVER_NOT_RUNNING.value)
            self.assertFalse(res.connected)
            self.assertIn("frida-server process is not running", res.error_message)

    def test_attach_successful_proof_of_connectivity(self) -> None:
        """Verify attach executes rpc ping proof of connectivity when server is present."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="root 1234 1 frida-server", stderr=""
        )

        mock_frida = MagicMock()
        mock_dm = MagicMock()
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()

        mock_frida.get_device_manager.return_value = mock_dm
        mock_dm.get_device.return_value = mock_device
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync.ping.return_value = "pong"

        with patch.object(self.manager, "check_client_availability", return_value="17.15.3"):
            with patch.dict("sys.modules", {"frida": mock_frida}):
                res = self.manager.attach("com.example.mentorcraft2")

                self.assertEqual(res.status, InstrumentationStatus.CONNECTED.value)
                self.assertTrue(res.connected)
                self.assertEqual(res.proof_of_connectivity, {"rpc_ping": "pong"})
                mock_session.detach.assert_called_once()


if __name__ == "__main__":
    unittest.main()
