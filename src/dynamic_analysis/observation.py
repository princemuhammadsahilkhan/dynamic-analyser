"""Runtime observation and evidence collection layer for Android dynamic analysis."""

import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple

from dynamic_analysis.runtime import (
    ADBError,
    AndroidRuntimeError,
    AndroidRuntimeOrchestrator,
    ShellResult,
)


class ObservationError(AndroidRuntimeError):
    """Base exception for observation layer errors."""

    pass


class ObservationStartupError(ObservationError):
    """Raised when an observation collector fails to start."""

    pass


class ObservationTimeoutError(ObservationError):
    """Raised when an observation collection times out."""

    pass


class ObservationShutdownError(ObservationError):
    """Raised when stopping an observation collector fails."""

    pass


class EvidenceType(Enum):
    """Supported types of captured runtime evidence."""

    SYSTEM_PROPERTY = "SYSTEM_PROPERTY"
    LOGCAT = "LOGCAT"
    PROCESS_LIST = "PROCESS_LIST"
    PACKAGE_LIST = "PACKAGE_LIST"
    NETWORK_INTERFACE = "NETWORK_INTERFACE"
    NETWORK_ROUTE = "NETWORK_ROUTE"
    NETWORK_DNS = "NETWORK_DNS"
    NETWORK_CONNECTIONS = "NETWORK_CONNECTIONS"
    NETWORK_PROPERTIES = "NETWORK_PROPERTIES"
    NETWORK_DUMPSYS = "NETWORK_DUMPSYS"
    PROXY_LIFECYCLE = "PROXY_LIFECYCLE"
    HTTP_TRAFFIC = "HTTP_TRAFFIC"
    HTTPS_TRAFFIC = "HTTPS_TRAFFIC"
    PROXY_STATUS = "PROXY_STATUS"
    PERMISSIONS = "PERMISSIONS"
    CERTIFICATE_AUDIT = "CERTIFICATE_AUDIT"
    CERTIFICATE_INSTALL = "CERTIFICATE_INSTALL"
    CERTIFICATE_VERIFY = "CERTIFICATE_VERIFY"
    CERTIFICATE_RESTORE = "CERTIFICATE_RESTORE"
    UI_HIERARCHY = "UI_HIERARCHY"
    UI_INTERACTION = "UI_INTERACTION"
    AUTH_BOUNDARY = "AUTH_BOUNDARY"
    AUTH_UI = "AUTH_UI"
    AUTH_VALIDATION = "AUTH_VALIDATION"
    AUTH_NETWORK = "AUTH_NETWORK"
    AUTH_BLOCKED = "AUTH_BLOCKED"
    BEHAVIORAL_STATE = "BEHAVIORAL_STATE"
    BEHAVIORAL_TRANSITION = "BEHAVIORAL_TRANSITION"
    VALIDATION_RESULT = "VALIDATION_RESULT"
    STATIC_METADATA = "STATIC_METADATA"
    STATIC_AUTH_INVENTORY = "STATIC_AUTH_INVENTORY"
    STATIC_ENDPOINT_INVENTORY = "STATIC_ENDPOINT_INVENTORY"
    STATIC_NETWORK_CONFIG = "STATIC_NETWORK_CONFIG"
    STATIC_POST_AUTH_NAV = "STATIC_POST_AUTH_NAV"
    BACKEND_CONTRACT = "BACKEND_CONTRACT"
    SUPABASE_RESOURCE = "SUPABASE_RESOURCE"
    AUTH_DATA_FLOW = "AUTH_DATA_FLOW"
    STORAGE_INVENTORY = "STORAGE_INVENTORY"
    REALTIME_INVENTORY = "REALTIME_INVENTORY"
    LIVE_BACKEND_OBSERVATION = "LIVE_BACKEND_OBSERVATION"
    LIVE_BACKEND_BLOCKED = "LIVE_BACKEND_BLOCKED"
    LIVE_REST_TRAFFIC = "LIVE_REST_TRAFFIC"
    LIVE_STORAGE_TRAFFIC = "LIVE_STORAGE_TRAFFIC"
    LIVE_REALTIME_TRAFFIC = "LIVE_REALTIME_TRAFFIC"
    BACKEND_CORRELATION = "BACKEND_CORRELATION"
    RESOURCE_CORRELATION = "RESOURCE_CORRELATION"
    SESSION = "SESSION"





@dataclass(frozen=True)
class EvidenceItem:
    """Structured, immutable representation of a captured evidence item."""

    evidence_type: str
    timestamp: str
    serial: str
    source: str
    content: str
    exit_code: Optional[int] = 0
    metadata: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict:
        """Convert evidence item to a serializable dictionary."""
        return asdict(self)


TARGET_SYSTEM_PROPERTIES: Tuple[str, ...] = (
    "ro.build.version.sdk",
    "ro.build.version.release",
    "ro.product.cpu.abi",
    "ro.product.model",
    "ro.product.manufacturer",
    "sys.boot_completed",
)


def _get_utc_timestamp() -> str:
    """Return current timestamp in ISO-8601 UTC format."""
    return datetime.now(timezone.utc).isoformat()


class RuntimeObserver:
    """Collector for Android runtime properties and process information."""

    def __init__(self, orchestrator: AndroidRuntimeOrchestrator) -> None:
        self.orchestrator = orchestrator

    def collect_properties(
        self, properties: Tuple[str, ...] = TARGET_SYSTEM_PROPERTIES
    ) -> List[EvidenceItem]:
        """Collect specified system properties from the running guest OS."""
        if not self.orchestrator.is_running():
            raise ObservationError("Emulator runtime is not running")

        items: List[EvidenceItem] = []
        serial = self.orchestrator.config.serial

        for prop_name in properties:
            res = self.orchestrator.shell(f"getprop {prop_name}")
            item = EvidenceItem(
                evidence_type=EvidenceType.SYSTEM_PROPERTY.value,
                timestamp=_get_utc_timestamp(),
                serial=serial,
                source=prop_name,
                content=res.stdout.strip(),
                exit_code=res.exit_code,
            )
            items.append(item)

        return items

    def collect_processes(self) -> EvidenceItem:
        """Collect current running guest process list via ps -A."""
        if not self.orchestrator.is_running():
            raise ObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell("ps -A")
        return EvidenceItem(
            evidence_type=EvidenceType.PROCESS_LIST.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="ps -A",
            content=res.stdout,
            exit_code=res.exit_code,
        )

    def collect_logcat_dump(self, timeout: float = 10.0) -> EvidenceItem:
        """Collect a bounded logcat buffer dump from the target emulator using logcat -d."""
        if not self.orchestrator.is_running():
            raise ObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell("logcat -d", timeout=timeout)
        return EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="logcat -d",
            content=res.stdout,
            exit_code=res.exit_code,
        )

    def collect_permissions(self, package_name: str, timeout: float = 10.0) -> EvidenceItem:
        """Collect declared, requested, and runtime-granted permissions using dumpsys package."""
        if not self.orchestrator.is_running():
            raise ObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell(f"dumpsys package {package_name}", timeout=timeout)
        return EvidenceItem(
            evidence_type=EvidenceType.PERMISSIONS.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source=f"dumpsys package {package_name}",
            content=res.stdout,
            exit_code=res.exit_code,
        )


class LogcatCollector:
    """Streaming logcat process collector with controlled child process lifecycle management."""

    def __init__(self, orchestrator: AndroidRuntimeOrchestrator) -> None:
        self.orchestrator = orchestrator
        self._process: Optional[subprocess.Popen] = None

    def is_running(self) -> bool:
        """Return True if the logcat streaming collector process is active."""
        return self._process is not None and self._process.poll() is None

    def start(self, clear_buffer: bool = True) -> None:
        """Start streaming logcat collection into a tracked child process."""
        if not self.orchestrator.is_running():
            raise ObservationStartupError("Emulator runtime is not running")

        if self.is_running():
            raise ObservationStartupError("LogcatCollector process is already running")

        serial = self.orchestrator.config.serial
        adb_bin = self.orchestrator.config.adb_binary

        if clear_buffer:
            try:
                subprocess.run(
                    [adb_bin, "-s", serial, "logcat", "-c"],
                    capture_output=True,
                    timeout=5.0,
                )
            except Exception:
                pass

        cmd = [adb_bin, "-s", serial, "logcat", "-v", "time"]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            raise ObservationStartupError(
                f"Failed to spawn logcat collector process: {exc}"
            ) from exc

        time.sleep(0.2)
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            self._process = None
            raise ObservationStartupError(
                f"Logcat collector process exited immediately with code {self._process.poll()}: {stderr}"
            )

    def stop(self, timeout: float = 5.0) -> EvidenceItem:
        """Stop the logcat streaming process cleanly and return captured evidence."""
        proc = self._process
        if proc is None:
            raise ObservationShutdownError("No logcat collector process is running")

        serial = self.orchestrator.config.serial

        try:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5.0)
            except Exception as exc:
                raise ObservationShutdownError(
                    f"Failed to kill logcat collector process {proc.pid}: {exc}"
                ) from exc
        finally:
            self._process = None

        return EvidenceItem(
            evidence_type=EvidenceType.LOGCAT.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="logcat streaming",
            content=stdout or "",
            exit_code=proc.returncode if proc else 0,
        )


def save_evidence_items(
    items: List[EvidenceItem], output_dir: str, filename: str = "evidence.json"
) -> str:
    """Save a list of EvidenceItem objects to a JSON file in output_dir."""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)
    data = [item.to_dict() for item in items]
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except TypeError as e:
        import traceback
        for i, item in enumerate(data):
            try:
                json.dumps(item)
            except TypeError:
                print(f"Serialization failed for item {i}: {item}")
        raise
    return filepath
