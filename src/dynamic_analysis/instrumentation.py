"""Controlled dynamic instrumentation boundary layer for Android runtime analysis."""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional

from dynamic_analysis.observation import EvidenceItem, _get_utc_timestamp
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator


class InstrumentationError(AndroidRuntimeError):
    """Base exception for dynamic instrumentation errors."""

    pass


class InstrumentationStatus(Enum):
    """Lifecycle and connectivity states for dynamic instrumentation."""

    NOT_AVAILABLE = "NOT_AVAILABLE"
    SERVER_NOT_RUNNING = "SERVER_NOT_RUNNING"
    CONNECTED = "CONNECTED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class InstrumentationResult:
    """Structured result object for dynamic instrumentation connectivity check."""

    target_package: str
    status: str
    frida_client_version: Optional[str] = None
    frida_server_version: Optional[str] = None
    connected: bool = False
    proof_of_connectivity: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result object to dictionary."""
        return asdict(self)

    def to_evidence_item(self, serial: str) -> EvidenceItem:
        """Convert instrumentation result to structured EvidenceItem."""
        return EvidenceItem(
            evidence_type="INSTRUMENTATION",
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="InstrumentationManager",
            content=f"Status: {self.status}, Connected: {self.connected}, Client Ver: {self.frida_client_version or 'N/A'}",
            exit_code=0 if self.connected else 1,
            metadata={
                "target_package": self.target_package,
                "status": self.status,
                "error_message": self.error_message or "",
            },
        )


class InstrumentationManager:
    """Manager boundary for controlled dynamic instrumentation via Frida."""

    def __init__(
        self, orchestrator: Optional[AndroidRuntimeOrchestrator] = None
    ) -> None:
        self.orchestrator = orchestrator or AndroidRuntimeOrchestrator()

    def check_client_availability(self) -> Optional[str]:
        """Check if Frida Python bindings are installed in the host environment.

        Returns Frida version string if available, or None if missing.
        """
        try:
            import frida

            return getattr(frida, "__version__", "unknown")
        except ImportError:
            return None

    def check_server_running(self) -> bool:
        """Check if frida-server process is active on the target guest runtime."""
        if not self.orchestrator.is_running():
            return False

        try:
            res = self.orchestrator.shell("ps -A")
            if res.exit_code == 0 and "frida-server" in res.stdout:
                return True
        except Exception:
            pass

        return False

    def attach(
        self, package_name: str, timeout: float = 5.0
    ) -> InstrumentationResult:
        """Attempt controlled attachment and proof-of-connectivity to target process."""
        client_version = self.check_client_availability()
        if not client_version:
            return InstrumentationResult(
                target_package=package_name,
                status=InstrumentationStatus.NOT_AVAILABLE.value,
                connected=False,
                error_message="Python frida client package is not installed in the host Python environment",
            )

        if not self.orchestrator.is_running():
            return InstrumentationResult(
                target_package=package_name,
                status=InstrumentationStatus.FAILED.value,
                frida_client_version=client_version,
                connected=False,
                error_message="Target AndroidRuntimeOrchestrator is not running",
            )

        server_active = self.check_server_running()
        if not server_active:
            return InstrumentationResult(
                target_package=package_name,
                status=InstrumentationStatus.SERVER_NOT_RUNNING.value,
                frida_client_version=client_version,
                connected=False,
                error_message=f"frida-server process is not running on target guest OS (serial: {self.orchestrator.config.serial})",
            )

        serial = self.orchestrator.config.serial

        try:
            import frida

            device_manager = frida.get_device_manager()
            device = device_manager.get_device(serial, timeout=int(timeout * 1000))
            session = device.attach(package_name)

            # Perform harmless proof of connectivity script RPC ping
            script = session.create_script(
                "rpc.exports = { ping: function() { return 'pong'; } };"
            )
            script.load()
            ping_response = script.exports_sync.ping()

            session.detach()

            return InstrumentationResult(
                target_package=package_name,
                status=InstrumentationStatus.CONNECTED.value,
                frida_client_version=client_version,
                connected=True,
                proof_of_connectivity={"rpc_ping": ping_response},
                error_message=None,
            )
        except Exception as exc:
            return InstrumentationResult(
                target_package=package_name,
                status=InstrumentationStatus.FAILED.value,
                frida_client_version=client_version,
                connected=False,
                error_message=f"Failed to attach or execute proof-of-connectivity: {exc}",
            )
