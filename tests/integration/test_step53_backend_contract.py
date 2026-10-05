"""Integration test for Step 53 — Static Supabase Data-Flow & Backend Contract Mapping."""

import os
import unittest

from dynamic_analysis.backend_contract import SupabaseContractMapper
from dynamic_analysis.observation import EvidenceType


class TestStep53BackendContractMapping(unittest.TestCase):
    """Integration test verifying Step 53 backend contract mapping against apks/app-release.apk."""

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

    def test_static_backend_contract_mapping(self):
        mapper = SupabaseContractMapper(self.APK_PATH)
        inventory = mapper.analyze()

        # Verify Primary Backend URL
        self.assertEqual(
            inventory.primary_backend_url,
            "https://tqzoozpckrmmprwnhweg.supabase.co",
            "Primary Supabase backend URL mismatch.",
        )

        # Verify Database Resources
        tables = [t.resource_name for t in inventory.supabase_tables]
        self.assertIn("users", tables)
        self.assertIn("courses", tables)
        self.assertIn("enrollments", tables)
        self.assertIn("quizzes", tables)

        # Verify Auth Flows
        self.assertGreaterEqual(len(inventory.auth_flows), 4)

        # Verify Storage Resources
        buckets = [s.bucket_name for s in inventory.storage_resources]
        self.assertIn("profile-images", buckets)
        self.assertIn("mentorcraft-images", buckets)

        # Verify Realtime
        self.assertGreaterEqual(len(inventory.realtime_resources), 1)
        self.assertEqual(inventory.realtime_resources[0].endpoint_or_name, "/realtime/v1")

        # Convert to evidence items and verify type coverage
        evidence_items = inventory.to_evidence_items(serial="N/A")
        evidence_types = {item.evidence_type for item in evidence_items}
        self.assertIn(EvidenceType.BACKEND_CONTRACT.value, evidence_types)
        self.assertIn(EvidenceType.SUPABASE_RESOURCE.value, evidence_types)
        self.assertIn(EvidenceType.AUTH_DATA_FLOW.value, evidence_types)
        self.assertIn(EvidenceType.STORAGE_INVENTORY.value, evidence_types)
        self.assertIn(EvidenceType.REALTIME_INVENTORY.value, evidence_types)


if __name__ == "__main__":
    unittest.main()
