"""Unit tests for the controlled network observation foundation module."""

import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.network import (
    NetworkObservationError,
    NetworkObservationSummary,
    NetworkObserver,
)
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator, ShellResult


class TestNetworkObserver(unittest.TestCase):
    """Unit test suite for NetworkObserver boundary layer."""

    def setUp(self) -> None:
        self.orchestrator = MagicMock(spec=AndroidRuntimeOrchestrator)
        self.orchestrator.is_running.return_value = True
        self.orchestrator.config = MagicMock()
        self.orchestrator.config.serial = "emulator-5554"
        self.observer = NetworkObserver(orchestrator=self.orchestrator)

    def test_summary_to_dict(self) -> None:
        """Verify NetworkObservationSummary serialization."""
        summary = NetworkObservationSummary(
            serial="emulator-5554",
            mitmproxy_available=True,
            mitmproxy_version="/usr/bin/mitmdump v11.1.3",
            https_interception_active=False,
            tls_decryption_active=False,
            evidence_count=5,
        )
        data = summary.to_dict()
        self.assertEqual(data["serial"], "emulator-5554")
        self.assertTrue(data["mitmproxy_available"])
        self.assertFalse(data["https_interception_active"])
        self.assertFalse(data["tls_decryption_active"])

    def test_check_host_proxy_capability(self) -> None:
        """Verify check_host_proxy_capability detects host mitmproxy."""
        avail, detail = self.observer.check_host_proxy_capability()
        self.assertIsInstance(avail, bool)

    def test_collect_interfaces(self) -> None:
        """Verify collect_interfaces executes ip addr shell command."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="1: lo: <LOOPBACK> mtu 65536\n", stderr=""
        )
        item = self.observer.collect_interfaces()
        self.assertEqual(item.evidence_type, "NETWORK_INTERFACE")
        self.assertEqual(item.source, "ip addr")
        self.assertIn("lo", item.content)

    def test_collect_routes(self) -> None:
        """Verify collect_routes executes ip route shell command."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="default via 10.0.2.2 dev eth0\n", stderr=""
        )
        item = self.observer.collect_routes()
        self.assertEqual(item.evidence_type, "NETWORK_ROUTE")
        self.assertEqual(item.source, "ip route")
        self.assertIn("default via 10.0.2.2", item.content)

    def test_collect_dns_properties(self) -> None:
        """Verify collect_dns_properties queries system DNS properties."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="10.0.2.3\n", stderr=""
        )
        items = self.observer.collect_dns_properties()
        self.assertGreater(len(items), 0)
        self.assertTrue(any(i.evidence_type in ("NETWORK_DNS", "NETWORK_PROPERTIES") for i in items))

    def test_collect_connections(self) -> None:
        """Verify collect_connections executes netstat -an command."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="Active Internet connections\ntcp 0 0 0.0.0.0:5555\n", stderr=""
        )
        item = self.observer.collect_connections()
        self.assertEqual(item.evidence_type, "NETWORK_CONNECTIONS")
        self.assertIn("tcp", item.content)

    def test_collect_dumpsys_connectivity(self) -> None:
        """Verify collect_dumpsys_connectivity executes dumpsys connectivity."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="ConnectivityChange: activeNetwork=100\n", stderr=""
        )
        item = self.observer.collect_dumpsys_connectivity()
        self.assertEqual(item.evidence_type, "NETWORK_DUMPSYS")
        self.assertIn("ConnectivityChange", item.content)

    def test_collect_all_network_evidence(self) -> None:
        """Verify collect_all_network_evidence aggregates all network observations."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="sample output", stderr=""
        )
        items = self.observer.collect_all_network_evidence()
        self.assertGreater(len(items), 4)

    def test_network_observer_raises_when_emulator_stopped(self) -> None:
        """Verify NetworkObservationError is raised when orchestrator is not running."""
        self.orchestrator.is_running.return_value = False
        with self.assertRaises(NetworkObservationError):
            self.observer.collect_interfaces()


if __name__ == "__main__":
    unittest.main()
