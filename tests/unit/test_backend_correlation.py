"""Unit tests for Step 55 Static Backend Contract to Runtime Endpoint Correlation."""

import json
import unittest
from unittest.mock import patch

from dynamic_analysis.backend_correlation import (
    BackendCorrelationMapper,
    BackendEvidenceLink,
    BackendRuntimeCorrelation,
)
from dynamic_analysis.backend_contract import BackendContractInventory
from dynamic_analysis.observation import EvidenceType


class TestBackendCorrelationModel(unittest.TestCase):
    """Test suite for backend correlation data structures and mapping logic."""

    def test_backend_evidence_link_creation(self):
        link = BackendEvidenceLink(
            resource_name="courses",
            resource_type="table",
            evidence_category="VERIFIED STATIC REFERENCE",
            static_symbols=["Static string match: 'courses'"],
            associated_screens=["StudentMainScreen", "CourseManagementScreen"],
            confidence_score="HIGH",
            notes="Correlated static table reference.",
        )
        self.assertEqual(link.resource_name, "courses")
        self.assertEqual(link.confidence_score, "HIGH")
        self.assertEqual(len(link.associated_screens), 2)

    def test_backend_runtime_correlation_serialization(self):
        link = BackendEvidenceLink(
            resource_name="users",
            resource_type="table",
            evidence_category="VERIFIED STATIC REFERENCE",
            static_symbols=["Static string match: 'users'"],
            associated_screens=["LoginScreen"],
            confidence_score="HIGH",
            notes="Static reference to users table.",
        )
        correlation = BackendRuntimeCorrelation(
            target_apk="apks/app-release.apk",
            primary_backend_url="https://tqzoozpckrmmprwnhweg.supabase.co",
            evidence_links=[link],
        )

        d = correlation.to_dict()
        self.assertEqual(d["target_apk"], "apks/app-release.apk")
        self.assertEqual(len(d["evidence_links"]), 1)
        self.assertEqual(d["evidence_links"][0]["resource_name"], "users")

        evidence_items = correlation.to_evidence_items(serial="emulator-5554")
        self.assertEqual(len(evidence_items), 2)
        types = [item.evidence_type for item in evidence_items]
        self.assertIn(EvidenceType.BACKEND_CORRELATION.value, types)
        self.assertIn(EvidenceType.RESOURCE_CORRELATION.value, types)

    @patch("dynamic_analysis.backend_correlation.SupabaseContractMapper.analyze")
    @patch.object(BackendCorrelationMapper, "_extract_binary_strings")
    def test_backend_correlation_mapper_correlate(self, mock_extract, mock_analyze):
        mock_extract.return_value = (
            "https://tqzoozpckrmmprwnhweg.supabase.co\n"
            "users\ncourses\nenrollments\nquizzes\nannouncements\ndiscussions\n"
            "modules\ncertificates\nroles\nprofile-images\nmentorcraft-images\n"
            "/realtime/v1\n/rest/v1/\n/storage/v1/\n"
        )
        mock_analyze.return_value = BackendContractInventory(
            target_apk="apks/app-release.apk",
            primary_backend_url="https://tqzoozpckrmmprwnhweg.supabase.co",
        )

        mapper = BackendCorrelationMapper("apks/app-release.apk")
        correlation = mapper.correlate()

        self.assertEqual(correlation.primary_backend_url, "https://tqzoozpckrmmprwnhweg.supabase.co")
        self.assertEqual(len(correlation.evidence_links), 15)

        names = [link.resource_name for link in correlation.evidence_links]
        self.assertIn("users", names)
        self.assertIn("courses", names)
        self.assertIn("/functions/v1/", names)

        # Verify /functions/v1/ is UNVERIFIED
        fn_link = next(link for link in correlation.evidence_links if link.resource_name == "/functions/v1/")
        self.assertEqual(fn_link.evidence_category, "UNVERIFIED")

        # Verify courses screen associations
        courses_link = next(link for link in correlation.evidence_links if link.resource_name == "courses")
        self.assertIn("CourseManagementScreen", courses_link.associated_screens)
        self.assertEqual(courses_link.confidence_score, "HIGH")

    def test_static_vs_runtime_evidence_distinction(self):
        """Test strict distinction between static evidence and actual runtime request evidence."""
        link = BackendEvidenceLink(
            resource_name="courses",
            resource_type="table",
            evidence_category="VERIFIED STATIC REFERENCE",
            static_symbols=["courses"],
            associated_screens=["StudentMainScreen"],
            confidence_score="HIGH",
            notes="Static reference only. Does NOT prove runtime request execution.",
        )
        self.assertIn("Does NOT prove runtime request execution", link.notes)


if __name__ == "__main__":
    unittest.main()
