"""Unit tests for APK intake, validation, metadata extraction, and lifecycle management."""

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from dynamic_analysis.apk import (
    APKInput,
    APKInstallationError,
    APKLaunchError,
    APKLifecycleManager,
    APKLifecycleResult,
    APKMetadataExtractor,
    APKVerificationError,
    InvalidAPKError,
)
from dynamic_analysis.runtime import AndroidRuntimeError, ShellResult


class TestAPKInput(unittest.TestCase):
    """Test suite for APKInput intake and basic container validation behavior."""

    def test_apk_input_instantiation(self):
        """Verify APKInput stores file_path."""
        apk = APKInput(file_path="/tmp/sample.apk")
        self.assertEqual(apk.file_path, "/tmp/sample.apk")

    def test_is_valid_apk_nonexistent_file(self):
        """Verify is_valid_apk returns False for non-existent file."""
        apk = APKInput(file_path="/nonexistent/sample.apk")
        self.assertFalse(apk.is_valid_apk())

    def test_is_valid_apk_invalid_extension(self):
        """Verify is_valid_apk returns False for non-APK extension."""
        with tempfile.NamedTemporaryFile(suffix=".txt") as tmp:
            apk = APKInput(file_path=tmp.name)
            self.assertFalse(apk.is_valid_apk())

    def test_is_valid_apk_not_a_zip(self):
        """Verify is_valid_apk returns False for file with .apk extension that is not a zip archive."""
        with tempfile.NamedTemporaryFile(suffix=".apk") as tmp:
            tmp.write(b"not a zip file content")
            tmp.flush()
            apk = APKInput(file_path=tmp.name)
            self.assertFalse(apk.is_valid_apk())

    def test_is_valid_apk_valid_zip_archive(self):
        """Verify is_valid_apk returns True for a valid zip container with .apk extension."""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_file = Path(tmpdir) / "test.apk"
            with zipfile.ZipFile(apk_file, "w") as zf:
                zf.writestr("AndroidManifest.xml", "<manifest/>")
            apk = APKInput(file_path=str(apk_file))
            self.assertTrue(apk.is_valid_apk())


class TestAPKMetadataExtractor(unittest.TestCase):
    """Test suite for APKMetadataExtractor."""

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=True)
    def test_extract_metadata_success(self, mock_exists, mock_run):
        """Verify aapt output parsing for package_name and launchable_activity."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "package: name='com.example.testapp' versionCode='1'\n"
                "launchable-activity: name='com.example.testapp.MainActivity' label='Test'\n"
            ),
        )

        extractor = APKMetadataExtractor()
        pkg, act = extractor.extract_metadata("/path/to/test.apk")
        self.assertEqual(pkg, "com.example.testapp")
        self.assertEqual(act, "com.example.testapp.MainActivity")

    @patch("os.path.exists", return_value=False)
    def test_extract_metadata_missing_aapt(self, mock_exists):
        """Verify extractor returns None, None if aapt binary is missing."""
        extractor = APKMetadataExtractor(aapt_binary="/nonexistent/aapt")
        pkg, act = extractor.extract_metadata("/path/to/test.apk")
        self.assertIsNone(pkg)
        self.assertIsNone(act)


class TestAPKLifecycleManager(unittest.TestCase):
    """Test suite for APKLifecycleManager using orchestrator mocks."""

    def setUp(self):
        self.orchestrator = MagicMock()
        self.orchestrator.is_running.return_value = True
        self.orchestrator.config.serial = "emulator-5554"

        self.extractor = MagicMock()
        self.extractor.extract_metadata.return_value = (
            "com.example.testapp",
            "com.example.testapp.MainActivity",
        )

        self.manager = APKLifecycleManager(
            orchestrator=self.orchestrator, extractor=self.extractor
        )

    def test_validate_invalid_apk_raises_error(self):
        """Verify validate() raises InvalidAPKError for missing or non-APK file."""
        with self.assertRaises(InvalidAPKError):
            self.manager.validate("/nonexistent/file.apk")

    def test_install_fails_when_runtime_not_running(self):
        """Verify install() raises AndroidRuntimeError if orchestrator is not running."""
        self.orchestrator.is_running.return_value = False
        with self.assertRaises(AndroidRuntimeError):
            self.manager.install("/path/to/test.apk")

    def test_successful_installation(self):
        """Verify install() calls orchestrator.install_apk() and returns stdout."""
        self.orchestrator.install_apk.return_value = ShellResult(
            exit_code=0, stdout="Success\n", stderr=""
        )
        out = self.manager.install("/path/to/test.apk")
        self.assertEqual(out, "Success")
        self.orchestrator.install_apk.assert_called_once_with("/path/to/test.apk")

    def test_failed_installation_raises_error(self):
        """Verify install() raises APKInstallationError when install output reports Failure."""
        self.orchestrator.install_apk.return_value = ShellResult(
            exit_code=1, stdout="Failure [INSTALL_FAILED_ALREADY_EXISTS]\n", stderr=""
        )
        with self.assertRaises(APKInstallationError) as ctx:
            self.manager.install("/path/to/test.apk")
        self.assertIn("INSTALL_FAILED_ALREADY_EXISTS", str(ctx.exception))

    def test_installation_verification_success(self):
        """Verify verify_installation returns True when pm list packages contains package."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="package:com.example.testapp\n", stderr=""
        )
        verified = self.manager.verify_installation("com.example.testapp")
        self.assertTrue(verified)
        self.orchestrator.shell.assert_called_once_with(
            "pm list packages com.example.testapp"
        )

    def test_installation_verification_failure_raises_error(self):
        """Verify verify_installation raises APKVerificationError when package is missing."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout="", stderr=""
        )
        with self.assertRaises(APKVerificationError):
            self.manager.verify_installation("com.example.testapp")

    def test_launch_success_with_activity(self):
        """Verify launch() calls am start -n when launchable_activity is present."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0,
            stdout="Starting: Intent { cmp=com.example.testapp/.MainActivity }\n",
            stderr="",
        )
        out = self.manager.launch(
            "com.example.testapp", "com.example.testapp.MainActivity"
        )
        self.assertIn("Starting", out)
        self.orchestrator.shell.assert_called_once_with(
            "am start -n com.example.testapp/com.example.testapp.MainActivity"
        )

    def test_launch_success_fallback_monkey(self):
        """Verify launch() falls back to monkey when launchable_activity is None."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=0, stdout=":Monkey: seed=0 count=1\n", stderr=""
        )
        out = self.manager.launch("com.example.testapp", None)
        self.assertIn("Monkey", out)
        self.orchestrator.shell.assert_called_once_with(
            "monkey -p com.example.testapp -c android.intent.category.LAUNCHER 1"
        )

    def test_launch_failure_raises_error(self):
        """Verify launch() raises APKLaunchError when shell output contains Error:."""
        self.orchestrator.shell.return_value = ShellResult(
            exit_code=1,
            stdout="Error: Activity class does not exist.\n",
            stderr="",
        )
        with self.assertRaises(APKLaunchError):
            self.manager.launch(
                "com.example.testapp", "com.example.testapp.BadActivity"
            )

    def test_full_lifecycle_execution(self):
        """Verify run_lifecycle executes validation, installation, verification, and launch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = str(Path(tmpdir) / "app.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", "<manifest/>")

            self.orchestrator.install_apk.return_value = ShellResult(
                exit_code=0, stdout="Success\n", stderr=""
            )
            self.orchestrator.shell.side_effect = [
                ShellResult(exit_code=0, stdout="package:com.example.testapp\n", stderr=""),
                ShellResult(exit_code=0, stdout="Starting: Intent ...\n", stderr=""),
            ]

            res = self.manager.run_lifecycle(apk_path, launch=True)

            self.assertIsInstance(res, APKLifecycleResult)
            self.assertEqual(res.package_name, "com.example.testapp")
            self.assertTrue(res.installed)
            self.assertTrue(res.verified)
            self.assertTrue(res.launched)

            # Crucial requirement: Runtime ownership remains with caller (no shutdown called)
            self.orchestrator.shutdown.assert_not_called()


if __name__ == "__main__":
    unittest.main()
