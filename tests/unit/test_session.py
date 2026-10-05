"""Unit tests for Step 55 — AnalysisSession foundation."""

import json
import os
import unittest

from dynamic_analysis.session import (
    AnalysisSession,
    InvalidTransitionError,
    SessionError,
    SessionStatus,
)


class TestSessionCreation(unittest.TestCase):
    """Test AnalysisSession construction and initial state."""

    def test_session_creation_minimal(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        self.assertEqual(session.apk_path, "apks/app-release.apk")
        self.assertIsNone(session.package_name)
        self.assertEqual(session.status, SessionStatus.CREATED)
        self.assertIsNotNone(session.analysis_id)
        self.assertIsNotNone(session.created_at)
        self.assertIsNone(session.started_at)
        self.assertIsNone(session.finished_at)

    def test_session_creation_with_package_name(self):
        session = AnalysisSession(
            apk_path="apks/app-release.apk",
            package_name="com.example.mentorcraft2",
        )
        self.assertEqual(session.package_name, "com.example.mentorcraft2")

    def test_session_creation_with_config_metadata(self):
        session = AnalysisSession(
            apk_path="apks/app-release.apk",
            config_metadata={"avd": "analysis_baseline_api33", "serial": "emulator-5554"},
        )
        self.assertEqual(session.config_metadata["avd"], "analysis_baseline_api33")

    def test_unique_analysis_ids(self):
        s1 = AnalysisSession(apk_path="apks/app-release.apk")
        s2 = AnalysisSession(apk_path="apks/app-release.apk")
        self.assertNotEqual(s1.analysis_id, s2.analysis_id)

    def test_initial_status_is_created(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        self.assertEqual(session.status, SessionStatus.CREATED)

    def test_apk_path_preserved(self):
        session = AnalysisSession(apk_path="/absolute/path/to/test.apk")
        self.assertEqual(session.apk_path, "/absolute/path/to/test.apk")

    def test_created_at_is_iso_format(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        # Should not raise on a valid ISO datetime
        self.assertIn("T", session.created_at)
        self.assertTrue(session.created_at.endswith("+00:00"))


class TestRunDirectory(unittest.TestCase):
    """Test deterministic run directory generation."""

    def test_run_dir_contains_analysis_id(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        self.assertIn(session.analysis_id, session.run_dir)

    def test_run_dir_is_under_base_output_dir(self):
        session = AnalysisSession(
            apk_path="apks/app-release.apk",
            base_output_dir="/tmp/test_output",
        )
        self.assertTrue(session.run_dir.startswith("/tmp/test_output"))
        self.assertEqual(session.run_dir, f"/tmp/test_output/{session.analysis_id}")

    def test_subdirectory_paths(self):
        session = AnalysisSession(
            apk_path="apks/app-release.apk",
            base_output_dir="/tmp/test_output",
        )
        self.assertEqual(session.evidence_dir, os.path.join(session.run_dir, "evidence"))
        self.assertEqual(session.logs_dir, os.path.join(session.run_dir, "logs"))
        self.assertEqual(session.network_dir, os.path.join(session.run_dir, "network"))
        self.assertEqual(session.ui_dir, os.path.join(session.run_dir, "ui"))
        self.assertEqual(session.findings_dir, os.path.join(session.run_dir, "findings"))
        self.assertEqual(session.reports_dir, os.path.join(session.run_dir, "reports"))


class TestLifecycleTransitions(unittest.TestCase):
    """Test validated lifecycle state transitions."""

    def test_created_to_running(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        self.assertEqual(session.status, SessionStatus.RUNNING)
        self.assertIsNotNone(session.started_at)

    def test_created_to_cancelled(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.CANCELLED)
        self.assertEqual(session.status, SessionStatus.CANCELLED)
        self.assertIsNotNone(session.finished_at)

    def test_running_to_completed(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.COMPLETED)
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertIsNotNone(session.finished_at)

    def test_running_to_failed(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.FAILED)
        self.assertEqual(session.status, SessionStatus.FAILED)
        self.assertIsNotNone(session.finished_at)

    def test_running_to_partial(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.PARTIAL)
        self.assertEqual(session.status, SessionStatus.PARTIAL)
        self.assertIsNotNone(session.finished_at)

    def test_running_to_cancelled(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.CANCELLED)
        self.assertEqual(session.status, SessionStatus.CANCELLED)
        self.assertIsNotNone(session.finished_at)

    def test_invalid_completed_to_running(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.COMPLETED)
        with self.assertRaises(InvalidTransitionError):
            session.transition_to(SessionStatus.RUNNING)

    def test_invalid_failed_to_running(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.FAILED)
        with self.assertRaises(InvalidTransitionError):
            session.transition_to(SessionStatus.RUNNING)

    def test_invalid_cancelled_to_completed(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.CANCELLED)
        with self.assertRaises(InvalidTransitionError):
            session.transition_to(SessionStatus.COMPLETED)

    def test_invalid_created_to_completed(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        with self.assertRaises(InvalidTransitionError):
            session.transition_to(SessionStatus.COMPLETED)

    def test_invalid_created_to_failed(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        with self.assertRaises(InvalidTransitionError):
            session.transition_to(SessionStatus.FAILED)

    def test_invalid_partial_to_running(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.PARTIAL)
        with self.assertRaises(InvalidTransitionError):
            session.transition_to(SessionStatus.RUNNING)

    def test_invalid_transition_error_is_session_error(self):
        self.assertTrue(issubclass(InvalidTransitionError, SessionError))

    def test_started_at_set_on_running(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        self.assertIsNone(session.started_at)
        session.transition_to(SessionStatus.RUNNING)
        self.assertIsNotNone(session.started_at)
        self.assertIn("T", session.started_at)

    def test_finished_at_not_set_while_running(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        self.assertIsNone(session.finished_at)


class TestSerialization(unittest.TestCase):
    """Test JSON-compatible serialization."""

    def test_to_dict_keys(self):
        session = AnalysisSession(
            apk_path="apks/app-release.apk",
            package_name="com.example.mentorcraft2",
        )
        d = session.to_dict()
        expected_keys = {
            "analysis_id",
            "apk_path",
            "package_name",
            "status",
            "created_at",
            "started_at",
            "finished_at",
            "run_dir",
            "base_output_dir",
            "config_metadata",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_to_dict_status_is_string(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        d = session.to_dict()
        self.assertIsInstance(d["status"], str)
        self.assertEqual(d["status"], "CREATED")

    def test_to_json_roundtrip(self):
        session = AnalysisSession(
            apk_path="apks/app-release.apk",
            package_name="com.example.mentorcraft2",
            config_metadata={"avd": "analysis_baseline_api33"},
        )
        json_str = session.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["apk_path"], "apks/app-release.apk")
        self.assertEqual(parsed["package_name"], "com.example.mentorcraft2")
        self.assertEqual(parsed["status"], "CREATED")
        self.assertEqual(parsed["config_metadata"]["avd"], "analysis_baseline_api33")

    def test_serialization_after_transitions(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        session.transition_to(SessionStatus.RUNNING)
        session.transition_to(SessionStatus.COMPLETED)
        d = session.to_dict()
        self.assertEqual(d["status"], "COMPLETED")
        self.assertIsNotNone(d["started_at"])
        self.assertIsNotNone(d["finished_at"])

    def test_finish_timestamp_none_before_terminal(self):
        session = AnalysisSession(apk_path="apks/app-release.apk")
        d = session.to_dict()
        self.assertIsNone(d["finished_at"])
        self.assertIsNone(d["started_at"])


if __name__ == "__main__":
    unittest.main()
