"""Configuration boundary for the dynamic_analysis package."""

import os
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple


@dataclass(frozen=True)
class AndroidRuntimeConfig:
    """Configuration settings for the Android emulator runtime orchestrator."""

    sdk_root: str = "/home/kali/.local/share/android-sdk"
    avd_name: str = "analysis_baseline_api33"
    emulator_binary: Optional[str] = None
    adb_binary: str = "/usr/bin/adb"
    port: int = 5554
    headless: bool = True
    no_audio: bool = True
    read_only: bool = False
    no_snapshot_save: bool = False
    no_snapshot_load: bool = False
    wipe_data: bool = False
    extra_flags: Tuple[str, ...] = ()
    boot_timeout: float = 90.0
    adb_timeout: float = 30.0
    shutdown_timeout: float = 15.0
    command_timeout: float = 30.0

    @property
    def serial(self) -> str:
        """Construct the target ADB device serial number."""
        return f"emulator-{self.port}"

    @property
    def resolved_emulator_binary(self) -> str:
        """Return the absolute path to the emulator binary."""
        if self.emulator_binary:
            return self.emulator_binary
        return os.path.join(self.sdk_root, "emulator", "emulator")


@dataclass(frozen=True)
class AppConfig:
    """Base application configuration structure."""

    runtime: AndroidRuntimeConfig = field(default_factory=AndroidRuntimeConfig)
    target_apk: Optional[str] = None

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "AppConfig":
        """Construct an AppConfig instance from an environment mapping.

        If no mapping is provided, os.environ is used by default.
        """
        _source = os.environ if env is None else env
        sdk_root = _source.get(
            "ANDROID_SDK_ROOT",
            _source.get("ANDROID_HOME", "/home/kali/.local/share/android-sdk"),
        )
        avd_name = _source.get("AVD_NAME", "analysis_baseline_api33")
        adb_binary = _source.get("ADB_PATH", "/usr/bin/adb")
        target_apk = _source.get("TARGET_APK", _source.get("APK_PATH", None))

        runtime_cfg = AndroidRuntimeConfig(
            sdk_root=sdk_root,
            avd_name=avd_name,
            adb_binary=adb_binary,
        )
        return cls(runtime=runtime_cfg, target_apk=target_apk)

