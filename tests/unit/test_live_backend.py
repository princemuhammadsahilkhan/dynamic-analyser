"""Unit tests for Step 54 Live Supabase Backend Observation and Credential Boundary Auditing."""

import json
import unittest

from dynamic_analysis.live_backend import (
    LiveBackendObservationResult,
    LiveBackendObserver,
    RedactedTrafficFlow,
)
from dynamic_analysis.observation import EvidenceType


class TestLiveBackendObserver(unittest.TestCase):
    """Test suite for LiveBackendObserver functionality and security sanitization."""

    def test_redact_headers(self):
        observer = LiveBackendObserver()
        headers = {
            "Host": "tqzoozpckrmmprwnhweg.supabase.co",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.secret",
            "apikey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
            "Content-Type": "application/json",
            "Cookie": "sb-access-token=xyz",
        }
        sanitized = observer.redact_headers(headers)
        self.assertEqual(sanitized["Host"], "tqzoozpckrmmprwnhweg.supabase.co")
        self.assertEqual(sanitized["Content-Type"], "application/json")
        self.assertEqual(sanitized["Authorization"], "[REDACTED_SENSITIVE_HEADER]")
        self.assertEqual(sanitized["apikey"], "[REDACTED_SENSITIVE_HEADER]")
        self.assertEqual(sanitized["Cookie"], "[REDACTED_SENSITIVE_HEADER]")

    def test_redact_content(self):
        observer = LiveBackendObserver()
        raw_body = (
            '{"email":"user@example.com","password":"SecretPassword123!",'
            '"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",'
            '"refresh_token":"abcdef123456"}'
        )
        sanitized = observer.redact_content(raw_body)
        self.assertNotIn("SecretPassword123!", sanitized)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", sanitized)
        self.assertNotIn("abcdef123456", sanitized)
        self.assertIn("[REDACTED_PASSWORD]", sanitized)
        self.assertIn("[REDACTED_ACCESS_TOKEN]", sanitized)
        self.assertIn("[REDACTED_REFRESH_TOKEN]", sanitized)

    def test_observe_backend_traffic_without_credentials(self):
        observer = LiveBackendObserver(credentials={})
        captured = [{"url": "https://tqzoozpckrmmprwnhweg.supabase.co/rest/v1/courses", "method": "GET"}]
        result = observer.observe_backend_traffic(captured)

        self.assertEqual(result.authentication_status, "LIVE_BACKEND_BLOCKED")
        self.assertFalse(result.credentials_available)
        self.assertIsNotNone(result.blocker_reason)
        self.assertIn("No authorized test credentials", result.blocker_reason)

        evidence_items = observer.to_evidence_items(result, serial="emulator-5554")
        self.assertEqual(len(evidence_items), 1)
        self.assertEqual(evidence_items[0].evidence_type, EvidenceType.LIVE_BACKEND_BLOCKED.value)

    def test_observe_backend_traffic_with_credentials(self):
        observer = LiveBackendObserver(credentials={"user": "test_user", "token": "test_token"})
        captured_flows = [
            {
                "url": "https://tqzoozpckrmmprwnhweg.supabase.co/rest/v1/courses?select=*",
                "method": "GET",
                "status_code": 200,
                "headers": {"Authorization": "Bearer token123", "Host": "tqzoozpckrmmprwnhweg.supabase.co"},
                "body": '[{"id":1,"name":"Course 1"}]',
            },
            {
                "url": "https://tqzoozpckrmmprwnhweg.supabase.co/storage/v1/object/public/profile-images/user1.png",
                "method": "GET",
                "status_code": 200,
                "headers": {"Host": "tqzoozpckrmmprwnhweg.supabase.co"},
                "body": "",
            },
            {
                "url": "https://tqzoozpckrmmprwnhweg.supabase.co/realtime/v1/websocket",
                "method": "GET",
                "status_code": 101,
                "headers": {"Upgrade": "websocket"},
                "body": "",
            },
            {
                "url": "https://tqzoozpckrmmprwnhweg.supabase.co/auth/v1/token?grant_type=password",
                "method": "POST",
                "status_code": 200,
                "headers": {"apikey": "anon_key_123"},
                "body": '{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.sig"}',
            },
        ]

        result = observer.observe_backend_traffic(captured_flows)
        self.assertEqual(result.authentication_status, "AUTHENTICATED_SESSION")
        self.assertTrue(result.credentials_available)
        self.assertEqual(result.supabase_flows_observed, 4)
        self.assertEqual(len(result.rest_flows), 1)
        self.assertEqual(result.rest_flows[0].matched_table_or_bucket, "courses")
        self.assertEqual(len(result.storage_flows), 1)
        self.assertEqual(result.storage_flows[0].matched_table_or_bucket, "profile-images")
        self.assertEqual(len(result.realtime_flows), 1)
        self.assertEqual(len(result.auth_flows), 1)

        evidence_items = observer.to_evidence_items(result, serial="emulator-5554")
        types = [item.evidence_type for item in evidence_items]
        self.assertIn(EvidenceType.LIVE_BACKEND_OBSERVATION.value, types)
        self.assertIn(EvidenceType.LIVE_REST_TRAFFIC.value, types)
        self.assertIn(EvidenceType.LIVE_STORAGE_TRAFFIC.value, types)
        self.assertIn(EvidenceType.LIVE_REALTIME_TRAFFIC.value, types)


if __name__ == "__main__":
    unittest.main()
