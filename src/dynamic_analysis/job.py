"""Domain model representation of an analysis job."""

from dataclasses import dataclass
from enum import Enum, auto


class JobState(Enum):
    """Lifecycle states for an analysis job explicitly supported by DA requirements."""

    SUBMITTED = auto()
    EXECUTING = auto()
    COLLECTING_EVIDENCE = auto()
    REPORTING = auto()
    COMPLETED = auto()
    FAILED = auto()


@dataclass
class AnalysisJob:
    """Domain representation of an automated Android APK dynamic analysis job."""

    apk_path: str
    state: JobState = JobState.SUBMITTED

    def transition_to(self, new_state: JobState) -> None:
        """Update the job's current lifecycle state."""
        self.state = new_state
