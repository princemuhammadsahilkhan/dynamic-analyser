"""Certificate trust manager for Android dynamic analysis using mitmproxy CA."""

import json
import os
import subprocess
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    _get_utc_timestamp,
)
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator


class CertificateError(AndroidRuntimeError):
    """Base exception for certificate management errors."""

    pass


class CertificateNotFoundError(CertificateError):
    """Raised when the mitmproxy CA certificate file is missing."""

    pass


class CertificateInstallationError(CertificateError):
    """Raised when certificate installation or verification fails."""

    pass


@dataclass(frozen=True)
class CertificateDetails:
    """Metadata details of a CA certificate (excluding private keys)."""

    cert_path: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    sha256_fingerprint: str
    subject_hash_old: str

    def to_dict(self) -> Dict:
        """Convert details to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class CertificateTrustStatus:
    """Status summary of certificate audit and guest installation."""

    ca_available: bool
    cert_path: Optional[str]
    subject_hash_old: Optional[str]
    installed_system: bool
    installed_user: bool
    is_rooted: bool
    system_writable: bool

    def to_dict(self) -> Dict:
        """Convert status to dictionary."""
        return asdict(self)


class CertificateTrustManager:
    """Manager for auditing, installing, verifying, and restoring mitmproxy CA on target emulator."""

    DEFAULT_CA_PATH = "/home/kali/.mitmproxy/mitmproxy-ca-cert.pem"

    def __init__(
        self,
        orchestrator: Optional[AndroidRuntimeOrchestrator] = None,
        ca_path: str = DEFAULT_CA_PATH,
    ) -> None:
        self.orchestrator = orchestrator
        self.ca_path = ca_path
        self._installed_system_file: Optional[str] = None
        self._installed_user_file: Optional[str] = None

    def audit_local_ca(self) -> CertificateDetails:
        """Audit host mitmproxy CA certificate file and extract metadata using openssl."""
        if not os.path.exists(self.ca_path):
            raise CertificateNotFoundError(f"mitmproxy CA certificate not found at {self.ca_path}")

        try:
            cmd = [
                "openssl",
                "x509",
                "-in",
                self.ca_path,
                "-noout",
                "-subject",
                "-issuer",
                "-dates",
                "-fingerprint",
                "-sha256",
                "-subject_hash_old",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = res.stdout

            subject = ""
            issuer = ""
            not_before = ""
            not_after = ""
            fingerprint = ""
            subject_hash = ""

            for line in output.splitlines():
                if line.startswith("subject="):
                    subject = line.split("=", 1)[1].strip()
                elif line.startswith("issuer="):
                    issuer = line.split("=", 1)[1].strip()
                elif line.startswith("notBefore="):
                    not_before = line.split("=", 1)[1].strip()
                elif line.startswith("notAfter="):
                    not_after = line.split("=", 1)[1].strip()
                elif "Fingerprint=" in line:
                    fingerprint = line.split("=", 1)[1].strip()
                elif line.strip() and not "=" in line:
                    subject_hash = line.strip()

            return CertificateDetails(
                cert_path=self.ca_path,
                subject=subject,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
                sha256_fingerprint=fingerprint,
                subject_hash_old=subject_hash,
            )
        except Exception as exc:
            raise CertificateError(f"Failed to audit CA certificate at {self.ca_path}: {exc}") from exc

    def audit_guest_trust_store(self) -> CertificateTrustStatus:
        """Audit guest AVD privilege and certificate store locations via ADB."""
        if not self.orchestrator or not self.orchestrator.is_running():
            raise CertificateError("Orchestrator must be running to audit guest trust store")

        details = self.audit_local_ca()
        hash_old = details.subject_hash_old

        # 1. Root privilege check
        res_su = self.orchestrator.shell("su 0 id")
        is_rooted = res_su.exit_code == 0 and "uid=0(root)" in res_su.stdout

        # 2. System writability check
        res_sys = self.orchestrator.shell("su 0 touch /system/etc/security/cacerts/.test_write")
        system_writable = res_sys.exit_code == 0
        if system_writable:
            self.orchestrator.shell("su 0 rm /system/etc/security/cacerts/.test_write")

        # 3. Check system cacerts
        res_sys_cert = self.orchestrator.shell(f"su 0 ls /system/etc/security/cacerts/{hash_old}.0")
        installed_system = res_sys_cert.exit_code == 0

        # 4. Check user cacerts
        res_usr_cert = self.orchestrator.shell(f"su 0 ls /data/misc/user/0/cacerts-added/{hash_old}.0")
        installed_user = res_usr_cert.exit_code == 0

        return CertificateTrustStatus(
            ca_available=True,
            cert_path=self.ca_path,
            subject_hash_old=hash_old,
            installed_system=installed_system,
            installed_user=installed_user,
            is_rooted=is_rooted,
            system_writable=system_writable,
        )

    def install_ca_to_user_store(self) -> str:
        """Install CA to guest user certificate store (/data/misc/user/0/cacerts-added)."""
        if not self.orchestrator or not self.orchestrator.is_running():
            raise CertificateInstallationError("Orchestrator is not running")

        details = self.audit_local_ca()
        target_name = f"{details.subject_hash_old}.0"

        # 1. Push CA cert to /data/local/tmp/
        serial = self.orchestrator.config.serial
        adb_bin = self.orchestrator.config.adb_binary
        tmp_path = f"/data/local/tmp/{target_name}"

        res_push = subprocess.run(
            [adb_bin, "-s", serial, "push", self.ca_path, tmp_path],
            capture_output=True,
            text=True,
        )
        if res_push.returncode != 0:
            raise CertificateInstallationError(f"Failed to push CA to guest: {res_push.stderr}")

        # 2. Ensure /data/misc/user/0/cacerts-added directory exists
        self.orchestrator.shell("su 0 mkdir -p /data/misc/user/0/cacerts-added")
        self.orchestrator.shell("su 0 chown 1000:1000 /data/misc/user/0/cacerts-added")
        self.orchestrator.shell("su 0 chmod 755 /data/misc/user/0/cacerts-added")

        # 3. Copy certificate to user store
        target_path = f"/data/misc/user/0/cacerts-added/{target_name}"
        res_cp = self.orchestrator.shell(f"su 0 cp {tmp_path} {target_path}")
        if res_cp.exit_code != 0:
            raise CertificateInstallationError(f"Failed to copy CA to user store: {res_cp.stderr}")

        self.orchestrator.shell(f"su 0 chown 1000:1000 {target_path}")
        self.orchestrator.shell(f"su 0 chmod 644 {target_path}")
        self.orchestrator.shell(f"su 0 rm {tmp_path}")

        self._installed_user_file = target_path
        return target_path

    def install_ca_to_system_store(self) -> str:
        """Install CA to guest system certificate store using a temporary tmpfs overlay mount."""
        if not self.orchestrator or not self.orchestrator.is_running():
            raise CertificateInstallationError("Orchestrator is not running")

        details = self.audit_local_ca()
        target_name = f"{details.subject_hash_old}.0"

        serial = self.orchestrator.config.serial
        adb_bin = self.orchestrator.config.adb_binary
        tmp_path = f"/data/local/tmp/{target_name}"
        backup_dir = "/data/local/tmp/cacerts_backup"

        # 1. Push CA cert to /data/local/tmp/
        res_push = subprocess.run(
            [adb_bin, "-s", serial, "push", self.ca_path, tmp_path],
            capture_output=True,
            text=True,
        )
        if res_push.returncode != 0:
            raise CertificateInstallationError(f"Failed to push CA to guest: {res_push.stderr}")

        # 2. Backup existing system certs
        self.orchestrator.shell(f"su 0 rm -rf {backup_dir}")
        self.orchestrator.shell(f"su 0 mkdir -p {backup_dir}")
        self.orchestrator.shell(f"su 0 cp -r /system/etc/security/cacerts/* {backup_dir}/")

        # 3. Mount tmpfs overlay on /system/etc/security/cacerts
        res_mount = self.orchestrator.shell("su 0 mount -t tmpfs tmpfs /system/etc/security/cacerts")
        if res_mount.exit_code != 0:
            raise CertificateInstallationError(f"Failed to mount tmpfs on system cacerts: {res_mount.stderr}")

        # 4. Copy system certs backup and mitmproxy CA cert into tmpfs cacerts
        self.orchestrator.shell(f"su 0 cp -r {backup_dir}/* /system/etc/security/cacerts/")
        target_path = f"/system/etc/security/cacerts/{target_name}"
        self.orchestrator.shell(f"su 0 cp {tmp_path} {target_path}")

        # 5. Set proper permissions
        self.orchestrator.shell("su 0 chown root:root /system/etc/security/cacerts/*")
        self.orchestrator.shell("su 0 chmod 644 /system/etc/security/cacerts/*")
        self.orchestrator.shell(f"su 0 rm -f {tmp_path}")
        self.orchestrator.shell(f"su 0 rm -rf {backup_dir}")

        self._installed_system_file = target_path
        return target_path

    def restore_guest_trust_store(self) -> None:
        """Remove installed CA from guest user and system certificate stores."""
        if not self.orchestrator or not self.orchestrator.is_running():
            return

        if self._installed_system_file:
            self.orchestrator.shell("su 0 umount /system/etc/security/cacerts")
            self._installed_system_file = None

        if self._installed_user_file:
            self.orchestrator.shell(f"su 0 rm -f {self._installed_user_file}")
            self._installed_user_file = None


    def get_evidence_items(self) -> List[EvidenceItem]:
        """Collect structured evidence items for certificate audit and trust state."""
        serial = self.orchestrator.config.serial if self.orchestrator else "unknown"
        items: List[EvidenceItem] = []

        # 1. Certificate Details (NO PRIVATE KEYS)
        details = self.audit_local_ca()
        items.append(
            EvidenceItem(
                evidence_type=EvidenceType.CERTIFICATE_AUDIT.value,
                timestamp=_get_utc_timestamp(),
                serial=serial,
                source="CertificateTrustManager.audit_local_ca",
                content=json.dumps(details.to_dict()),
                exit_code=0,
            )
        )

        # 2. Guest Trust Store Status
        if self.orchestrator and self.orchestrator.is_running():
            status = self.audit_guest_trust_store()
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.CERTIFICATE_VERIFY.value,
                    timestamp=_get_utc_timestamp(),
                    serial=serial,
                    source="CertificateTrustManager.audit_guest_trust_store",
                    content=json.dumps(status.to_dict()),
                    exit_code=0,
                )
            )

        return items
