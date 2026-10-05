"""Analysis session abstraction representing a single APK analysis run."""

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional

from dynamic_analysis.runtime import AndroidRuntimeError


class SessionError(AndroidRuntimeError):
    """Base exception for analysis session errors."""

    pass


class InvalidTransitionError(SessionError):
    """Raised when an invalid session lifecycle state transition is attempted."""

    pass


class SessionStatus(Enum):
    """Lifecycle states for an analysis session."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


# Valid state transitions: source_state -> set of allowed target states
_VALID_TRANSITIONS: Dict[SessionStatus, set] = {
    SessionStatus.CREATED: {SessionStatus.RUNNING, SessionStatus.CANCELLED},
    SessionStatus.RUNNING: {
        SessionStatus.COMPLETED,
        SessionStatus.FAILED,
        SessionStatus.PARTIAL,
        SessionStatus.CANCELLED,
    },
    # Terminal states — no further transitions allowed
    SessionStatus.COMPLETED: set(),
    SessionStatus.FAILED: set(),
    SessionStatus.PARTIAL: set(),
    SessionStatus.CANCELLED: set(),
}


@dataclass
class AnalysisSession:
    """Represents exactly one APK analysis run.

    Provides a unique analysis_id, lifecycle state management with validated
    transitions, a deterministic run directory, and JSON-safe serialization.
    """

    apk_path: str
    package_name: Optional[str] = None
    analysis_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    status: SessionStatus = field(default=SessionStatus.CREATED)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    base_output_dir: str = field(default_factory=lambda: os.path.join(os.getcwd(), "output"))
    config_metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def run_dir(self) -> str:
        """Return the deterministic run directory for this session's artifacts."""
        return os.path.join(self.base_output_dir, self.analysis_id)

    @property
    def evidence_dir(self) -> str:
        """Return the subdirectory path for evidence artifacts."""
        return os.path.join(self.run_dir, "evidence")

    @property
    def logs_dir(self) -> str:
        """Return the subdirectory path for log artifacts."""
        return os.path.join(self.run_dir, "logs")

    @property
    def network_dir(self) -> str:
        """Return the subdirectory path for network artifacts."""
        return os.path.join(self.run_dir, "network")

    @property
    def ui_dir(self) -> str:
        """Return the subdirectory path for UI artifacts."""
        return os.path.join(self.run_dir, "ui")

    @property
    def findings_dir(self) -> str:
        """Return the subdirectory path for findings artifacts."""
        return os.path.join(self.run_dir, "findings")

    @property
    def reports_dir(self) -> str:
        """Return the subdirectory path for report artifacts."""
        return os.path.join(self.run_dir, "reports")

    def transition_to(self, new_status: SessionStatus) -> None:
        """Transition the session to a new lifecycle state.

        Raises InvalidTransitionError if the transition is not permitted.
        Records started_at when transitioning to RUNNING, and finished_at
        when transitioning to any terminal state.
        """
        allowed = _VALID_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise InvalidTransitionError(
                f"Invalid session transition: {self.status.value} -> {new_status.value}"
            )

        now = datetime.now(timezone.utc).isoformat()

        if new_status == SessionStatus.RUNNING:
            self.started_at = now

        if new_status in (
            SessionStatus.COMPLETED,
            SessionStatus.FAILED,
            SessionStatus.PARTIAL,
            SessionStatus.CANCELLED,
        ):
            self.finished_at = now

        self.status = new_status

    def to_dict(self) -> Dict:
        """Return a JSON-compatible dictionary representation of the session.

        Does not serialize live Python objects, subprocesses, ADB handles,
        or other runtime resources.
        """
        return {
            "analysis_id": self.analysis_id,
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "run_dir": self.run_dir,
            "base_output_dir": self.base_output_dir,
            "config_metadata": self.config_metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Return a JSON string representation of the session."""
        return json.dumps(self.to_dict(), indent=indent)
