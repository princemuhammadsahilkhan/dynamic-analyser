"""Integration test for STEP 54 — Controlled Live Supabase Backend Observation."""

import os
import unittest

from dynamic_analysis.live_backend import LiveBackendObserver
from dynamic_analysis.observation import EvidenceType


class TestStep54LiveBackendObservation(unittest.TestCase):
    """Integration test verifying Step 54 live backend observation infrastructure and credential boundary."""

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

    def test_live_backend_credential_boundary_without_credentials(self):
        """Verify that missing credentials safely produce LIVE_BACKEND_BLOCKED evidence."""
        observer = LiveBackendObserver(credentials=None)
        result = observer.observe_backend_traffic(captured_flows=[])

        self.assertEqual(result.authentication_status, "LIVE_BACKEND_BLOCKED")
        self.assertFalse(result.credentials_available)
        self.assertIn("No authorized test credentials", result.blocker_reason)

        evidence = observer.to_evidence_items(result, serial="emulator-5554")
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].evidence_type, EvidenceType.LIVE_BACKEND_BLOCKED.value)
        self.assertEqual(evidence[0].metadata["authentication_status"], "LIVE_BACKEND_BLOCKED")

    def test_live_backend_traffic_redaction_and_classification(self):
        """Verify captured flow processing, header redaction, and classification against Supabase endpoints."""
        observer = LiveBackendObserver(credentials={"user": "authorized_test_user"})
        captured_flows = [
            {
                "url": "https://tqzoozpckrmmprwnhweg.supabase.co/rest/v1/users?select=*",
                "method": "GET",
                "status_code": 200,
                "headers": {
                    "Host": "tqzoozpckrmmprwnhweg.supabase.co",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.secret",
                    "apikey": "eyJhbGciOiJIUzI1NiJ9.secret",
                },
                "body": '[{"id":"usr_1","role":"student"}]',
            },
            {
                "url": "https://tqzoozpckrmmprwnhweg.supabase.co/storage/v1/object/public/mentorcraft-images/banner.png",
                "method": "GET",
                "status_code": 200,
                "headers": {"Host": "tqzoozpckrmmprwnhweg.supabase.co"},
                "body": "",
            },
        ]

        result = observer.observe_backend_traffic(captured_flows)
        self.assertEqual(result.authentication_status, "AUTHENTICATED_SESSION")
        self.assertTrue(result.credentials_available)
        self.assertEqual(result.supabase_flows_observed, 2)

        # Verify header redaction
        rest_flow = result.rest_flows[0]
        self.assertEqual(rest_flow.headers["Authorization"], "[REDACTED_SENSITIVE_HEADER]")
        self.assertEqual(rest_flow.headers["apikey"], "[REDACTED_SENSITIVE_HEADER]")
        self.assertEqual(rest_flow.matched_table_or_bucket, "users")

        storage_flow = result.storage_flows[0]
        self.assertEqual(storage_flow.matched_table_or_bucket, "mentorcraft-images")

        # Verify evidence items
        evidence = observer.to_evidence_items(result, serial="emulator-5554")
        types = {item.evidence_type for item in evidence}
        self.assertIn(EvidenceType.LIVE_BACKEND_OBSERVATION.value, types)
        self.assertIn(EvidenceType.LIVE_REST_TRAFFIC.value, types)
        self.assertIn(EvidenceType.LIVE_STORAGE_TRAFFIC.value, types)


if __name__ == "__main__":
    unittest.main()
