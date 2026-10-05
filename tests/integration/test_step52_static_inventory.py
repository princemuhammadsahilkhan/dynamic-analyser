"""Integration test for Step 52: Static Authentication & Backend Endpoint Inventory on apks/app-release.apk."""

import json
import os
import tempfile
import unittest

from dynamic_analysis.observation import save_evidence_items
from dynamic_analysis.static_analysis import StaticAnalysisManager


class TestStep52StaticInventoryIntegration(unittest.TestCase):
    """Integration test verifying complete static authentication and backend endpoint inventory on apks/app-release.apk."""

    def test_step52_static_inventory(self) -> None:
        """Execute end-to-end static APK inspection without network activity, credential submission, or binary modifications."""
        apk_path = "apks/app-release.apk"
        self.assertTrue(os.path.exists(apk_path), f"Target APK missing at {apk_path}")

        initial_size = os.path.getsize(apk_path)
        self.assertEqual(initial_size, 65491834, "Target APK size changed before analysis")

        manager = StaticAnalysisManager(aapt_binary="/usr/bin/aapt")

        # 1. Inventory Metadata
        print("\n[Step 52 Integration] Executing static APK metadata inventory...")
        meta = manager.inventory_metadata(apk_path)
        self.assertEqual(meta.package_name, "com.example.mentorcraft2")
        self.assertEqual(meta.version_code, "1")
        self.assertEqual(meta.version_name, "1.0.0")
        self.assertEqual(meta.min_sdk, "24")
        self.assertEqual(meta.target_sdk, "36")
        self.assertIn("android.permission.INTERNET", meta.permissions)
        self.assertIn("com.example.mentorcraft2.MainActivity", meta.exported_activities)

        # 2. Inventory Auth & Endpoints
        print("[Step 52 Integration] Executing static auth & backend endpoint inventory...")
        auth, endpoints = manager.inventory_auth_and_endpoints(apk_path)
        self.assertEqual(endpoints.backend_host, "https://tqzoozpckrmmprwnhweg.supabase.co")
        self.assertEqual(endpoints.auth_endpoint, "https://tqzoozpckrmmprwnhweg.supabase.co/auth/v1")
        self.assertEqual(endpoints.rest_endpoint, "https://tqzoozpckrmmprwnhweg.supabase.co/rest/v1")
        self.assertEqual(auth.supabase_anon_key_payload.get("iss"), "supabase")
        self.assertEqual(auth.supabase_anon_key_payload.get("role"), "anon")

        # 3. Inventory Network Security Configuration
        print("[Step 52 Integration] Executing static network security configuration inventory...")
        sec = manager.inventory_network_security(apk_path)
        self.assertFalse(sec.has_network_security_config)
        self.assertFalse(sec.cleartext_permitted_by_default)

        # 4. Inventory Post-Authentication Architecture
        print("[Step 52 Integration] Executing static post-authentication architecture discovery...")
        post = manager.inventory_post_auth_architecture(apk_path)
        self.assertGreater(post.total_screens_discovered, 20)
        self.assertIn("StudentMainScreen", post.student_screens)
        self.assertIn("TeacherMainScreen", post.teacher_screens)

        # 5. Save Evidence Items
        evidence_items = manager.get_evidence_items()
        self.assertEqual(len(evidence_items), 5)

        temp_dir = tempfile.mkdtemp(prefix="step52_static_test_")
        evidence_dir = os.path.join(temp_dir, "evidence")
        evidence_file = save_evidence_items(evidence_items, output_dir=evidence_dir)
        self.assertTrue(os.path.exists(evidence_file))
        print(f"[Step 52 Integration] Saved static evidence artifact to {evidence_file}")

        # 6. Verify APK Integrity Unchanged
        post_size = os.path.getsize(apk_path)
        self.assertEqual(initial_size, post_size, "Target APK size changed after static analysis")
        print("[Step 52 Integration] Verified target APK remains 100% byte-for-byte unchanged.")


if __name__ == "__main__":
    unittest.main()
