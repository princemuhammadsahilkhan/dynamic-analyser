"""Unit tests for CertificateTrustManager in dynamic_analysis.certificates."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.certificates import (
    CertificateDetails,
    CertificateError,
    CertificateInstallationError,
    CertificateNotFoundError,
    CertificateTrustManager,
    CertificateTrustStatus,
)
from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.runtime import ShellResult


class TestCertificateTrustManager(unittest.TestCase):
    """Test suite for CertificateTrustManager and certificate evidence models."""

    def setUp(self) -> None:
        self.mock_orchestrator = MagicMock()
        self.mock_orchestrator.config.serial = "emulator-5554"
        self.mock_orchestrator.config.adb_binary = "/usr/bin/adb"
        self.mock_orchestrator.is_running.return_value = True

        self.cert_manager = CertificateTrustManager(
            orchestrator=self.mock_orchestrator,
            ca_path="/home/kali/.mitmproxy/mitmproxy-ca-cert.pem",
        )

    def test_audit_local_ca_success(self) -> None:
        """Verify local CA audit extracts metadata without private keys."""
        with patch("os.path.exists", return_value=True), patch(
            "subprocess.run",
            return_value=MagicMock(
                stdout=(
                    "subject=CN = mitmproxy, O = mitmproxy\n"
                    "issuer=CN = mitmproxy, O = mitmproxy\n"
                    "notBefore=Sep 23 00:00:00 2026 GMT\n"
                    "notAfter=Sep 22 00:00:00 2036 GMT\n"
                    "sha256 Fingerprint=EF:57:83\n"
                    "c8750f0d\n"
                )
            ),
        ):
            details = self.cert_manager.audit_local_ca()
        self.assertIsInstance(details, CertificateDetails)
        self.assertIn("mitmproxy", details.subject)
        self.assertIn("mitmproxy", details.issuer)
        self.assertTrue(len(details.sha256_fingerprint) > 0)
        self.assertEqual(details.subject_hash_old, "c8750f0d")

    def test_audit_local_ca_missing(self) -> None:
        """Verify missing CA file raises CertificateNotFoundError."""
        bad_manager = CertificateTrustManager(ca_path="/nonexistent/cert.pem")
        with self.assertRaises(CertificateNotFoundError):
            bad_manager.audit_local_ca()

    @patch.object(CertificateTrustManager, "audit_local_ca")
    def test_audit_guest_trust_store(self, mock_audit_local_ca) -> None:
        """Verify guest trust store audit returns correct status model."""
        mock_audit_local_ca.return_value = CertificateDetails(
            cert_path="/home/kali/.mitmproxy/mitmproxy-ca-cert.pem",
            subject="CN=mitmproxy",
            issuer="CN=mitmproxy",
            not_before="Sep 23 2026",
            not_after="Sep 22 2036",
            sha256_fingerprint="EF:57:83",
            subject_hash_old="c8750f0d",
        )
        self.mock_orchestrator.shell.side_effect = [
            ShellResult(stdout="uid=0(root) gid=0(root)", stderr="", exit_code=0), # su 0 id
            ShellResult(stdout="", stderr="Read-only file system", exit_code=1),    # touch /system
            ShellResult(stdout="No such file", stderr="", exit_code=1),            # sys cert check
            ShellResult(stdout="No such file", stderr="", exit_code=1),            # user cert check
        ]

        status = self.cert_manager.audit_guest_trust_store()
        self.assertIsInstance(status, CertificateTrustStatus)
        self.assertTrue(status.is_rooted)
        self.assertFalse(status.system_writable)
        self.assertFalse(status.installed_system)
        self.assertFalse(status.installed_user)

    @patch("subprocess.run")
    @patch.object(CertificateTrustManager, "audit_local_ca")
    def test_install_ca_to_user_store(self, mock_audit, mock_run) -> None:
        """Verify CA installation to user store pushes cert and sets permissions."""
        mock_audit.return_value = CertificateDetails(
            cert_path="/home/kali/.mitmproxy/mitmproxy-ca-cert.pem",
            subject="CN=mitmproxy",
            issuer="CN=mitmproxy",
            not_before="Sep 23 2026",
            not_after="Sep 22 2036",
            sha256_fingerprint="EF:57:83",
            subject_hash_old="c8750f0d",
        )
        mock_run.return_value = MagicMock(returncode=0)
        self.mock_orchestrator.shell.return_value = ShellResult(stdout="", stderr="", exit_code=0)

        target_path = self.cert_manager.install_ca_to_user_store()
        self.assertEqual(target_path, "/data/misc/user/0/cacerts-added/c8750f0d.0")
        self.assertEqual(self.cert_manager._installed_user_file, target_path)


    def test_restore_guest_trust_store(self) -> None:
        """Verify restore removes installed CA file from guest."""
        self.cert_manager._installed_user_file = "/data/misc/user/0/cacerts-added/c8750f0d.0"
        self.mock_orchestrator.shell.return_value = ShellResult(stdout="", stderr="", exit_code=0)

        self.cert_manager.restore_guest_trust_store()
        self.mock_orchestrator.shell.assert_called_with("su 0 rm -f /data/misc/user/0/cacerts-added/c8750f0d.0")
        self.assertIsNone(self.cert_manager._installed_user_file)

    @patch.object(CertificateTrustManager, "audit_local_ca")
    def test_get_evidence_items_no_private_keys(self, mock_audit_local_ca) -> None:
        """Verify evidence items contain cert audit and no private keys."""
        mock_audit_local_ca.return_value = CertificateDetails(
            cert_path="/home/kali/.mitmproxy/mitmproxy-ca-cert.pem",
            subject="CN=mitmproxy",
            issuer="CN=mitmproxy",
            not_before="Sep 23 2026",
            not_after="Sep 22 2036",
            sha256_fingerprint="EF:57:83",
            subject_hash_old="c8750f0d",
        )
        items = self.cert_manager.get_evidence_items()
        self.assertTrue(len(items) >= 1)
        self.assertEqual(items[0].evidence_type, EvidenceType.CERTIFICATE_AUDIT.value)
        content = items[0].content
        self.assertNotIn("PRIVATE KEY", content)
        self.assertIn("c8750f0d", content)


if __name__ == "__main__":
    unittest.main()
