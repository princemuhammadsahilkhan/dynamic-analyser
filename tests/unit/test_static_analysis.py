"""Unit tests for StaticAnalysisManager in dynamic_analysis.static_analysis."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.static_analysis import (
    APKMetadata,
    AuthImplementationInventory,
    BackendEndpointInventory,
    NetworkSecurityInventory,
    PostAuthArchitectureInventory,
    StaticAnalysisError,
    StaticAnalysisManager,
)


class TestStaticAnalysisManager(unittest.TestCase):
    """Test suite for StaticAnalysisManager and static evidence models."""

    def setUp(self) -> None:
        self.manager = StaticAnalysisManager(aapt_binary="/usr/bin/aapt")
        self.apk_path = "apks/app-release.apk"

    def test_inventory_metadata_real_apk(self) -> None:
        """Verify inventory_metadata parses real target APK metadata."""
        if not os.path.exists(self.apk_path):
            self.skipTest(f"APK file missing at {self.apk_path}")

        meta = self.manager.inventory_metadata(self.apk_path)
        self.assertIsInstance(meta, APKMetadata)
        self.assertEqual(meta.package_name, "com.example.mentorcraft2")
        self.assertEqual(meta.version_code, "1")
        self.assertEqual(meta.version_name, "1.0.0")
        self.assertEqual(meta.min_sdk, "24")
        self.assertEqual(meta.target_sdk, "36")
        self.assertIn("android.permission.INTERNET", meta.permissions)
        self.assertIn("com.example.mentorcraft2.MainActivity", meta.exported_activities)

    def test_inventory_auth_and_endpoints_real_apk(self) -> None:
        """Verify inventory_auth_and_endpoints parses Supabase host, JWT payload, and API endpoints from target APK."""
        if not os.path.exists(self.apk_path):
            self.skipTest(f"APK file missing at {self.apk_path}")

        auth, endpoints = self.manager.inventory_auth_and_endpoints(self.apk_path)
        self.assertIsInstance(auth, AuthImplementationInventory)
        self.assertIsInstance(endpoints, BackendEndpointInventory)

        self.assertEqual(endpoints.backend_host, "https://tqzoozpckrmmprwnhweg.supabase.co")
        self.assertEqual(endpoints.auth_endpoint, "https://tqzoozpckrmmprwnhweg.supabase.co/auth/v1")
        self.assertEqual(endpoints.rest_endpoint, "https://tqzoozpckrmmprwnhweg.supabase.co/rest/v1")
        self.assertEqual(auth.supabase_anon_key_payload.get("iss"), "supabase")
        self.assertEqual(auth.supabase_anon_key_payload.get("role"), "anon")

    def test_inventory_network_security_real_apk(self) -> None:
        """Verify inventory_network_security inspects network configuration and libraries."""
        if not os.path.exists(self.apk_path):
            self.skipTest(f"APK file missing at {self.apk_path}")

        sec = self.manager.inventory_network_security(self.apk_path)
        self.assertIsInstance(sec, NetworkSecurityInventory)
        self.assertFalse(sec.has_network_security_config)
        self.assertFalse(sec.cleartext_permitted_by_default)
        self.assertIn("Supabase Flutter SDK", sec.networking_libraries)

    def test_inventory_post_auth_architecture_real_apk(self) -> None:
        """Verify inventory_post_auth_architecture discovers post-auth screens from libapp.so."""
        if not os.path.exists(self.apk_path):
            self.skipTest(f"APK file missing at {self.apk_path}")

        post = self.manager.inventory_post_auth_architecture(self.apk_path)
        self.assertIsInstance(post, PostAuthArchitectureInventory)
        self.assertGreater(post.total_screens_discovered, 10)
        self.assertTrue(len(post.student_screens) > 0)
        self.assertTrue(len(post.teacher_screens) > 0)
        self.assertIn("StudentMainScreen", post.student_screens)
        self.assertIn("TeacherMainScreen", post.teacher_screens)

    def test_get_evidence_items(self) -> None:
        """Verify get_evidence_items formats static inventories into EvidenceItem objects."""
        if not os.path.exists(self.apk_path):
            self.skipTest(f"APK file missing at {self.apk_path}")

        self.manager.inventory_metadata(self.apk_path)
        self.manager.inventory_auth_and_endpoints(self.apk_path)
        self.manager.inventory_network_security(self.apk_path)
        self.manager.inventory_post_auth_architecture(self.apk_path)

        items = self.manager.get_evidence_items()
        self.assertEqual(len(items), 5)

        types = [item.evidence_type for item in items]
        self.assertIn(EvidenceType.STATIC_METADATA.value, types)
        self.assertIn(EvidenceType.STATIC_AUTH_INVENTORY.value, types)
        self.assertIn(EvidenceType.STATIC_ENDPOINT_INVENTORY.value, types)
        self.assertIn(EvidenceType.STATIC_NETWORK_CONFIG.value, types)
        self.assertIn(EvidenceType.STATIC_POST_AUTH_NAV.value, types)

    def test_missing_file_raises_error(self) -> None:
        """Verify StaticAnalysisError is raised when given a non-existent file path."""
        with self.assertRaises(StaticAnalysisError):
            self.manager.inventory_metadata("non_existent.apk")


if __name__ == "__main__":
    unittest.main()
