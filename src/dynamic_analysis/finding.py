"""Finding generation foundation for Dynamic Analysis."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class FindingError(Exception):
    """Base exception for finding generation errors."""
    pass


class FindingValidationError(FindingError):
    """Raised when finding field validation fails."""
    pass


class FindingSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(Enum):
    NETWORK = "NETWORK"
    AUTHENTICATION = "AUTHENTICATION"
    STORAGE = "STORAGE"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    UI = "UI"
    MISC = "MISC"


class FindingStatus(Enum):
    OPEN = "OPEN"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"


class FindingConfidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CERTAIN = "CERTAIN"


@dataclass
class Finding:
    """Structured, evidence-backed representation of an analysis finding."""

    analysis_id: str
    title: str
    description: str
    severity: FindingSeverity
    category: FindingCategory
    status: FindingStatus
    confidence: FindingConfidence
    evidence_references: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, str] = field(default_factory=dict)
    finding_id: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.analysis_id or not str(self.analysis_id).strip():
            raise FindingValidationError("analysis_id cannot be empty")
        if not self.title or not str(self.title).strip():
            raise FindingValidationError("title cannot be empty")
        if not self.description or not str(self.description).strip():
            raise FindingValidationError("description cannot be empty")
        
        if not isinstance(self.severity, FindingSeverity):
            raise FindingValidationError(f"Invalid severity: {self.severity}")
        if not isinstance(self.category, FindingCategory):
            raise FindingValidationError(f"Invalid category: {self.category}")
        if not isinstance(self.status, FindingStatus):
            raise FindingValidationError(f"Invalid status: {self.status}")
        if not isinstance(self.confidence, FindingConfidence):
            raise FindingValidationError(f"Invalid confidence: {self.confidence}")

        if not isinstance(self.evidence_references, list):
            raise FindingValidationError("evidence_references must be a list")

        # Deterministic finding ID based on session and title
        hash_input = f"{self.analysis_id}:{self.title}".encode("utf-8")
        self.finding_id = hashlib.sha256(hash_input).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Convert finding to a JSON-serializable dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        d["status"] = self.status.value
        d["confidence"] = self.confidence.value
        return d

    def to_json(self, indent: int = 2) -> str:
        """Convert finding to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

