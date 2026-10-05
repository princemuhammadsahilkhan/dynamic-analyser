"""Unit tests for ProxyManager module in dynamic_analysis.proxy."""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.proxy import (
    ProxyConfigError,
    ProxyError,
    ProxyManager,
    ProxyShutdownError,
    ProxyStartupError,
    ProxyStatus,
    TrafficObservation,
)
from dynamic_analysis.runtime import ShellResult


class TestProxyManager(unittest.TestCase):
    """Test suite for ProxyManager class and data models."""

    def setUp(self) -> None:
        self.mock_orchestrator = MagicMock()
        self.mock_orchestrator.config.serial = "emulator-5554"
        self.mock_orchestrator.is_running.return_value = True

        self.proxy_manager = ProxyManager(
            orchestrator=self.mock_orchestrator,
            binary_path="/usr/bin/mitmdump",
        )

    def test_audit_mitmproxy_success(self) -> None:
        """Verify host audit returns True and version string when mitmdump is present."""
        with patch("os.path.exists", return_value=True), patch(
            "subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Mitmproxy: 11.1.3\nPython: 3.14", returncode=0
            )
            available, details = self.proxy_manager.audit_mitmproxy()
            self.assertTrue(available)
            self.assertIn("11.1.3", details)

    def test_audit_mitmproxy_missing(self) -> None:
        """Verify audit returns False when binary is missing."""
        with patch("os.path.exists", return_value=False):
            available, details = self.proxy_manager.audit_mitmproxy()
            self.assertFalse(available)
            self.assertIsNone(details)

    @patch("subprocess.Popen")
    @patch.object(ProxyManager, "audit_mitmproxy", return_value=(True, "v11.1.3"))
    def test_proxy_startup_success(self, mock_audit, mock_popen) -> None:
        """Verify proxy starts cleanly as a child process."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        self.proxy_manager.start(host="127.0.0.1", port=8080)
        self.assertTrue(self.proxy_manager.is_running())
        self.assertEqual(self.proxy_manager.pid, 12345)
        mock_popen.assert_called_once()

    @patch("subprocess.Popen")
    @patch.object(ProxyManager, "audit_mitmproxy", return_value=(True, "v11.1.3"))
    def test_proxy_startup_already_running(self, mock_audit, mock_popen) -> None:
        """Verify startup raises error if already running."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        self.proxy_manager.start()
        with self.assertRaises(ProxyStartupError):
            self.proxy_manager.start()

    @patch("subprocess.Popen")
    @patch.object(ProxyManager, "audit_mitmproxy", return_value=(True, "v11.1.3"))
    def test_proxy_startup_immediate_exit(self, mock_audit, mock_popen) -> None:
        """Verify startup handles immediate process crash."""
        mock_process = MagicMock()
        mock_process.poll.return_value = 1
        mock_process.stderr.read.return_value = "Address already in use"
        mock_popen.return_value = mock_process

        with self.assertRaises(ProxyStartupError) as ctx:
            self.proxy_manager.start()
        self.assertIn("Address already in use", str(ctx.exception))

    def test_proxy_shutdown_success(self) -> None:
        """Verify proxy process stops cleanly using terminate."""
        mock_process = MagicMock()
        mock_process.pid = 9999
        self.proxy_manager._process = mock_process

        self.proxy_manager.stop()
        mock_process.terminate.assert_called_once()
        self.assertFalse(self.proxy_manager.is_running())
        self.assertIsNone(self.proxy_manager.pid)

    def test_configure_emulator_proxy_success(self) -> None:
        """Verify ADB proxy configuration captures previous proxy and sets new proxy."""
        self.mock_orchestrator.shell.side_effect = [
            ShellResult(stdout="null", stderr="", exit_code=0),
            ShellResult(stdout="", stderr="", exit_code=0),
        ]

        result = self.proxy_manager.configure_emulator_proxy(proxy_host="10.0.2.2", proxy_port=8080)
        self.assertEqual(result, "10.0.2.2:8080")
        self.assertTrue(self.proxy_manager.get_status().proxy_configured)

    def test_restore_emulator_proxy_success(self) -> None:
        """Verify restoring emulator proxy deletes or resets global http_proxy."""
        self.proxy_manager._proxy_configured = True
        self.proxy_manager._previous_proxy = None
        self.mock_orchestrator.shell.return_value = ShellResult(
            stdout="", stderr="", exit_code=0
        )

        self.proxy_manager.restore_emulator_proxy()
        self.mock_orchestrator.shell.assert_called_with("settings delete global http_proxy")
        self.assertFalse(self.proxy_manager.get_status().proxy_configured)


    def test_get_evidence_items(self) -> None:
        """Verify get_evidence_items converts status to EvidenceItem format."""
        items = self.proxy_manager.get_evidence_items()
        self.assertTrue(len(items) >= 1)
        self.assertEqual(items[0].evidence_type, EvidenceType.PROXY_LIFECYCLE.value)
        self.assertEqual(items[0].serial, "emulator-5554")


if __name__ == "__main__":
    unittest.main()
