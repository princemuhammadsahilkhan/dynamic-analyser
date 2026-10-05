"""Verification integration test for Step 39: APK Intake Verification of apks/app-release.apk."""

import os
import unittest

from dynamic_analysis.apk import APKInput, APKMetadataExtractor


class TestStep39APKVerification(unittest.TestCase):
    """Integration test suite for verifying apks/app-release.apk intake and metadata extraction."""

    def setUp(self) -> None:
        self.apk_path = "apks/app-release.apk"
        self.abs_path = os.path.abspath(self.apk_path)

    def test_apk_file_existence_and_readability(self) -> None:
        """Verify that apks/app-release.apk exists, is a regular file, and is readable."""
        self.assertTrue(os.path.exists(self.abs_path), f"APK file missing at {self.abs_path}")
        self.assertTrue(os.path.isfile(self.abs_path), f"Path {self.abs_path} is not a regular file")
        self.assertTrue(os.access(self.abs_path, os.R_OK), f"File {self.abs_path} is not readable")
        self.assertGreater(os.path.getsize(self.abs_path), 0, "APK file size must be > 0 bytes")

    def test_apk_container_validation(self) -> None:
        """Verify that APKInput.is_valid_apk() validates the APK extension and zip container format."""
        apk_input = APKInput(file_path=self.abs_path)
        self.assertTrue(apk_input.is_valid_apk(), f"APKInput failed container validation for {self.abs_path}")

    def test_apk_metadata_extraction(self) -> None:
        """Verify that APKMetadataExtractor extracts package name and launchable activity via aapt."""
        extractor = APKMetadataExtractor()
        package_name, launchable_activity = extractor.extract_metadata(self.abs_path)

        self.assertEqual(package_name, "com.example.mentorcraft2")
        self.assertEqual(launchable_activity, "com.example.mentorcraft2.MainActivity")


if __name__ == "__main__":
    unittest.main()
