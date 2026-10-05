"""Unit tests for the Finding generation foundation (Step 57)."""

import json
import unittest

from dynamic_analysis.finding import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingError,
    FindingSeverity,
    FindingStatus,
    FindingValidationError,
)


class TestFindingDomainModel(unittest.TestCase):
    """Unit tests for Finding class."""

    def test_valid_finding_initialization(self) -> None:
        """Test a fully valid finding initialization."""
        finding = Finding(
            analysis_id="session123",
            title="Valid Finding",
            description="Detailed explanation",
            severity=FindingSeverity.INFO,
            category=FindingCategory.MISC,
            status=FindingStatus.VALIDATED,
            confidence=FindingConfidence.CERTAIN,
            evidence_references=["PROCESS_LIST:2026-01-01T00:00:00Z"]
        )
        
        self.assertEqual(finding.analysis_id, "session123")
        self.assertEqual(finding.title, "Valid Finding")
        self.assertEqual(finding.description, "Detailed explanation")
        self.assertEqual(finding.severity, FindingSeverity.INFO)
        self.assertEqual(finding.category, FindingCategory.MISC)
        self.assertEqual(finding.status, FindingStatus.VALIDATED)
        self.assertEqual(finding.confidence, FindingConfidence.CERTAIN)
        self.assertIsNotNone(finding.finding_id)
        self.assertIsNotNone(finding.created_at)

    def test_deterministic_finding_id(self) -> None:
        """Test that finding ID generation is deterministic and unique by input."""
        f1 = Finding("sess1", "Same Title", "desc", FindingSeverity.INFO, FindingCategory.MISC, FindingStatus.OPEN, FindingConfidence.LOW)
        f2 = Finding("sess1", "Same Title", "desc2", FindingSeverity.HIGH, FindingCategory.NETWORK, FindingStatus.VALIDATED, FindingConfidence.CERTAIN)
        f3 = Finding("sess2", "Same Title", "desc", FindingSeverity.INFO, FindingCategory.MISC, FindingStatus.OPEN, FindingConfidence.LOW)
        
        # ID is based on analysis_id + title
        self.assertEqual(f1.finding_id, f2.finding_id)
        self.assertNotEqual(f1.finding_id, f3.finding_id)

    def test_validation_empty_fields(self) -> None:
        """Test validation fails for empty fields."""
        with self.assertRaisesRegex(FindingValidationError, "analysis_id cannot be empty"):
            Finding("", "title", "desc", FindingSeverity.INFO, FindingCategory.MISC, FindingStatus.OPEN, FindingConfidence.LOW)
        
        with self.assertRaisesRegex(FindingValidationError, "title cannot be empty"):
            Finding("sess1", "   ", "desc", FindingSeverity.INFO, FindingCategory.MISC, FindingStatus.OPEN, FindingConfidence.LOW)
            
        with self.assertRaisesRegex(FindingValidationError, "description cannot be empty"):
            Finding("sess1", "title", "", FindingSeverity.INFO, FindingCategory.MISC, FindingStatus.OPEN, FindingConfidence.LOW)

    def test_validation_invalid_enums(self) -> None:
        """Test validation fails for invalid enum types."""
        with self.assertRaisesRegex(FindingValidationError, "Invalid severity"):
            Finding("sess1", "t", "d", "INFO", FindingCategory.MISC, FindingStatus.OPEN, FindingConfidence.LOW)  # type: ignore

        with self.assertRaisesRegex(FindingValidationError, "Invalid category"):
            Finding("sess1", "t", "d", FindingSeverity.INFO, "MISC", FindingStatus.OPEN, FindingConfidence.LOW)  # type: ignore

        with self.assertRaisesRegex(FindingValidationError, "Invalid status"):
            Finding("sess1", "t", "d", FindingSeverity.INFO, FindingCategory.MISC, "OPEN", FindingConfidence.LOW)  # type: ignore

        with self.assertRaisesRegex(FindingValidationError, "Invalid confidence"):
            Finding("sess1", "t", "d", FindingSeverity.INFO, FindingCategory.MISC, FindingStatus.OPEN, "LOW")  # type: ignore

    def test_json_serialization(self) -> None:
        """Test to_dict and to_json serialization."""
        f = Finding(
            analysis_id="session123",
            title="JSON Test",
            description="desc",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.AUTHENTICATION,
            status=FindingStatus.REJECTED,
            confidence=FindingConfidence.HIGH,
            evidence_references=["ev1", "ev2"],
            metadata={"key": "val"}
        )
        
        d = f.to_dict()
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["category"], "AUTHENTICATION")
        self.assertEqual(d["status"], "REJECTED")
        self.assertEqual(d["confidence"], "HIGH")
        self.assertEqual(d["evidence_references"], ["ev1", "ev2"])
        self.assertEqual(d["metadata"], {"key": "val"})
        
        j = f.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["analysis_id"], "session123")
        self.assertEqual(parsed["title"], "JSON Test")
        self.assertEqual(parsed["finding_id"], f.finding_id)


if __name__ == "__main__":
    unittest.main()
