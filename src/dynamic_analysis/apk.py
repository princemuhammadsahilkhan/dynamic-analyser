"""Domain boundary for target Android APK intake, validation, and execution lifecycle."""

import os
import re
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator


class APKError(Exception):
    """Base exception for APK lifecycle processing errors."""

    pass


class InvalidAPKError(APKError):
    """Raised when an input path is invalid, missing, unreadable, or not a valid APK container."""

    pass


class APKInstallationError(APKError):
    """Raised when ADB installation of an APK fails."""

    pass


class APKVerificationError(APKError):
    """Raised when installation verification fails on guest runtime."""

    pass


class APKLaunchError(APKError):
    """Raised when launching an installed application fails on guest runtime."""

    pass


@dataclass(frozen=True)
class APKInput:
    """Domain representation of a submitted target Android APK artifact."""

    file_path: str

    def is_valid_apk(self) -> bool:
        """Perform basic intake and container validation for the submitted artifact.

        Per DA-004: Accept target Android APK files as input and perform basic
        validation to ensure the submitted artifact is a valid APK prior to
        initiating execution.
        """
        path = Path(self.file_path)
        if not path.is_file():
            return False
        if not os.access(path, os.R_OK):
            return False
        if not self.file_path.lower().endswith(".apk"):
            return False
        return zipfile.is_zipfile(path)


@dataclass(frozen=True)
class APKLifecycleResult:
    """Structured result returned by the APK execution lifecycle manager."""

    apk_path: str
    package_name: Optional[str]
    launchable_activity: Optional[str]
    installed: bool
    verified: bool
    launched: bool
    install_output: str
    launch_output: str


class APKMetadataExtractor:
    """Extracts package metadata (package name, launchable activity) from an APK using aapt."""

    def __init__(self, aapt_binary: str = "/usr/bin/aapt") -> None:
        self.aapt_binary = aapt_binary

    def extract_metadata(self, apk_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract (package_name, launchable_activity) using aapt dump badging."""
        if not os.path.exists(self.aapt_binary):
            return None, None

        try:
            res = subprocess.run(
                [self.aapt_binary, "dump", "badging", apk_path],
                capture_output=True,
                text=True,
                timeout=10.0,
            )
            if res.returncode != 0:
                return None, None

            package_name = None
            launchable_activity = None

            for line in res.stdout.splitlines():
                if line.startswith("package:"):
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        package_name = m.group(1)
                elif line.startswith("launchable-activity:"):
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        launchable_activity = m.group(1)

            return package_name, launchable_activity
        except Exception:
            return None, None


class APKLifecycleManager:
    """Manages target APK intake validation, installation, verification, and launch on runtime."""

    def __init__(
        self,
        orchestrator: AndroidRuntimeOrchestrator,
        extractor: Optional[APKMetadataExtractor] = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.extractor = extractor or APKMetadataExtractor()

    def validate(self, apk_path: str) -> APKInput:
        """Validate APK input path and return APKInput artifact domain object."""
        apk_input = APKInput(file_path=apk_path)
        if not apk_input.is_valid_apk():
            raise InvalidAPKError(
                f"APK path '{apk_path}' is invalid, non-existent, unreadable, or not a valid APK container"
            )
        return apk_input

    def install(self, apk_path: str) -> str:
        """Install target APK through the configured runtime orchestrator."""
        if not self.orchestrator.is_running():
            raise AndroidRuntimeError("Target AndroidRuntimeOrchestrator must be running before installing APK")

        res = self.orchestrator.install_apk(apk_path)
        if res.exit_code != 0 or "Failure" in res.stdout or "INSTALL_FAILED" in res.stdout:
            raise APKInstallationError(
                f"Failed to install APK '{apk_path}' on '{self.orchestrator.config.serial}': {res.stdout} {res.stderr}".strip()
            )
        return res.stdout.strip()

    def verify_installation(self, package_name: Optional[str]) -> bool:
        """Verify that the target package is installed on the guest OS package manager."""
        if not self.orchestrator.is_running():
            raise AndroidRuntimeError("Target AndroidRuntimeOrchestrator must be running to verify installation")

        if not package_name:
            return True

        res = self.orchestrator.shell(f"pm list packages {package_name}")
        if res.exit_code != 0:
            raise APKVerificationError(f"Package verification shell command failed: {res.stderr}")

        expected_line = f"package:{package_name}"
        lines = [line.strip() for line in res.stdout.splitlines()]
        if expected_line in lines:
            return True

        raise APKVerificationError(
            f"Package '{package_name}' is not installed on target device '{self.orchestrator.config.serial}'"
        )

    def launch(
        self, package_name: Optional[str], launchable_activity: Optional[str]
    ) -> str:
        """Launch the installed application on the guest OS."""
        if not self.orchestrator.is_running():
            raise AndroidRuntimeError("Target AndroidRuntimeOrchestrator must be running to launch application")

        if not package_name:
            raise APKLaunchError("Cannot launch application: Package name is unknown")

        if launchable_activity:
            component = f"{package_name}/{launchable_activity}"
            cmd = f"am start -n {component}"
        else:
            cmd = f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"

        res = self.orchestrator.shell(cmd)
        if res.exit_code != 0 or "Error:" in res.stdout or "Exception" in res.stdout:
            raise APKLaunchError(
                f"Failed to launch application '{package_name}' on '{self.orchestrator.config.serial}': {res.stdout} {res.stderr}".strip()
            )
        return res.stdout.strip()

    def run_lifecycle(
        self, apk_path: str, launch: bool = True
    ) -> APKLifecycleResult:
        """Execute the complete APK intake, installation, verification, and launch lifecycle."""
        self.validate(apk_path)

        package_name, launchable_activity = self.extractor.extract_metadata(apk_path)

        install_output = self.install(apk_path)
        verified = self.verify_installation(package_name)

        launch_output = ""
        launched = False
        if launch:
            launch_output = self.launch(package_name, launchable_activity)
            launched = True

        return APKLifecycleResult(
            apk_path=apk_path,
            package_name=package_name,
            launchable_activity=launchable_activity,
            installed=True,
            verified=verified,
            launched=launched,
            install_output=install_output,
            launch_output=launch_output,
        )
