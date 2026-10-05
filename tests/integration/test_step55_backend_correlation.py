"""Integration test for STEP 55 — Static Backend Contract to Runtime Endpoint Correlation."""

import os
import unittest

from dynamic_analysis.backend_correlation import BackendCorrelationMapper
from dynamic_analysis.observation import EvidenceType


class TestStep55BackendCorrelation(unittest.TestCase):
    """Integration test verifying Step 55 static correlation layer against apks/app-release.apk."""

    APK_PATH = "apks/app-release.apk"
    EXPECTED_SIZE = 65491834  # Byte-for-byte exact size

    def setUp(self):
        self.assertTrue(os.path.exists(self.APK_PATH), f"Target APK missing: {self.APK_PATH}")
        self.assertEqual(
            os.path.getsize(self.APK_PATH),
            self.EXPECTED_SIZE,
            f"Target APK size altered prior to test execution: {os.path.getsize(self.APK_PATH)} != {self.EXPECTED_SIZE}",
        )

    def tearDown(self):
        self.assertEqual(
            os.path.getsize(self.APK_PATH),
            self.EXPECTED_SIZE,
            f"Target APK size altered during test execution: {os.path.getsize(self.APK_PATH)} != {self.EXPECTED_SIZE}",
        )

    def test_static_backend_correlation(self):
        mapper = BackendCorrelationMapper(self.APK_PATH)
        correlation = mapper.correlate()

        # 1. Verify Primary Backend Host
        self.assertEqual(
            correlation.primary_backend_url,
            "https://tqzoozpckrmmprwnhweg.supabase.co",
            "Primary Supabase backend host mismatch.",
        )

        # 2. Verify all 15 target resources are present in correlation result
        self.assertEqual(len(correlation.evidence_links), 15)
        resource_map = {link.resource_name: link for link in correlation.evidence_links}

        required_resources = [
            "users",
            "courses",
            "enrollments",
            "quizzes",
            "announcements",
            "discussions",
            "modules",
            "certificates",
            "roles",
            "profile-images",
            "mentorcraft-images",
            "/realtime/v1",
            "/rest/v1/",
            "/storage/v1/",
            "/functions/v1/",
        ]
        for res in required_resources:
            self.assertIn(res, resource_map, f"Resource missing from correlation map: {res}")

        # 3. Verify screen correlations
        self.assertIn("LoginScreen", resource_map["users"].associated_screens)
        self.assertIn("CourseManagementScreen", resource_map["courses"].associated_screens)
        self.assertIn("QuizTakingScreen", resource_map["quizzes"].associated_screens)
        self.assertIn("LearningHistoryScreen", resource_map["certificates"].associated_screens)
        self.assertIn("RoleSelectionScreen", resource_map["roles"].associated_screens)

        # 4. Verify unverified functions endpoint
        self.assertEqual(resource_map["/functions/v1/"].evidence_category, "UNVERIFIED")

        # 5. Verify evidence serialization and EvidenceType coverage
        evidence_items = correlation.to_evidence_items(serial="N/A")
        evidence_types = {item.evidence_type for item in evidence_items}
        self.assertIn(EvidenceType.BACKEND_CORRELATION.value, evidence_types)
        self.assertIn(EvidenceType.RESOURCE_CORRELATION.value, evidence_types)


if __name__ == "__main__":
    unittest.main()
