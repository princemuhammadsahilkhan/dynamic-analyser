"""Real emulator integration test for Step 56 — AnalysisSession + AnalysisRunner."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.runner import AnalysisRunner
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator
from dynamic_analysis.session import AnalysisSession, SessionStatus


APK_PATH = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "apks", "app-release.apk"
)
PACKAGE_NAME = "com.example.mentorcraft2"
MAIN_ACTIVITY = "com.example.mentorcraft2.MainActivity"
EXPECTED_SHA256 = (
    "c06568ac3d86ac9a0632db650ed577d2dbbcbae76b3f77eaef02ae903d736215"
)


class TestStep56SessionRunnerIntegration(unittest.TestCase):
    """Real integration test: AnalysisSession lifecycle through AnalysisRunner
    using analysis_baseline_api33 and the target APK."""

    def setUp(self) -> None:
        self.config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(self.config)
        self.runner = AnalysisRunner(orchestrator=self.orchestrator)
        self.temp_dir = tempfile.mkdtemp(prefix="step56_session_")
        self.apk_path = os.path.abspath(APK_PATH)

    def tearDown(self) -> None:
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _check_no_orphan_processes(self) -> None:
        """Verify no orphan qemu/adb/mitmdump processes remain."""
        for pname in ("qemu-system-x86_64", "mitmdump"):
            result = subprocess.run(
                ["pgrep", "-f", pname],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode,
                1,
                f"Orphan {pname} process detected: {result.stdout.strip()}",
            )

    def test_session_integration_full_lifecycle(self) -> None:
        """Verify AnalysisSession lifecycle through a real APK analysis run."""
        print("\n--- Starting Step 56 Session Runner Integration Test ---")

        # 1. Create an AnalysisSession with the target APK
        session = AnalysisSession(
            apk_path=self.apk_path,
            package_name=PACKAGE_NAME,
            base_output_dir=self.temp_dir,
        )
        original_analysis_id = session.analysis_id
        print(f"Session created: {session.analysis_id}")

        # 2. Verify session initial state
        self.assertEqual(session.status, SessionStatus.CREATED)
        self.assertIsNone(session.started_at)
        self.assertIsNone(session.finished_at)

        # 3. Run the analysis with the session
        result = self.runner.run(
            apk_path=self.apk_path,
            session=session,
            boot_timeout=120.0,
            observation_duration=5.0,
        )

        # 4. Verify run success
        print(f"Workflow Success: {result.success}")
        print(f"Session Status: {session.status.value}")
        print(f"Analysis ID: {session.analysis_id}")
        print(f"Evidence Count: {len(result.evidence_items)}")
        print(f"Execution Duration: {result.execution_duration:.2f}s")

        self.assertTrue(result.success, f"Runner workflow failed: {result.error_message}")
        self.assertIsNone(result.error_message)

        # 5. Verify the returned session is the same object
        self.assertIs(result.session, session)
        self.assertEqual(result.session.analysis_id, original_analysis_id)

        # 6. Verify session lifecycle transitions completed correctly
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertIsNotNone(session.started_at)
        self.assertIsNotNone(session.finished_at)

        # 7. Verify APK lifecycle
        self.assertIsNotNone(result.apk_result)
        self.assertTrue(result.apk_result.installed)
        self.assertTrue(result.apk_result.verified)
        self.assertTrue(result.apk_result.launched)
        self.assertEqual(result.apk_result.package_name, PACKAGE_NAME)
        print(f"APK installed: {result.apk_result.installed}")
        print(f"APK verified: {result.apk_result.verified}")
        print(f"APK launched: {result.apk_result.launched}")

        # 8. Verify com.example.mentorcraft2 appeared in process observations
        proc_items = [
            e for e in result.evidence_items if e.evidence_type == "PROCESS_LIST"
        ]
        self.assertGreater(len(proc_items), 0)
        found_package = any(
            PACKAGE_NAME in e.content for e in proc_items
        )
        self.assertTrue(found_package, f"{PACKAGE_NAME} not found in process list evidence")
        print(f"Package in process list: {found_package}")

        # 9. Verify evidence items collected
        self.assertGreater(len(result.evidence_items), 0)
        prop_items = [
            e for e in result.evidence_items if e.evidence_type == "SYSTEM_PROPERTY"
        ]
        prop_map = {p.source: p.content for p in prop_items}
        self.assertEqual(prop_map.get("ro.build.version.sdk"), "33")
        print(f"System properties: {prop_map}")

        # 10. Verify SESSION evidence item is present
        session_items = [
            e for e in result.evidence_items if e.evidence_type == "SESSION"
        ]
        self.assertEqual(len(session_items), 1)
        session_content = json.loads(session_items[0].content)
        self.assertEqual(session_content["analysis_id"], session.analysis_id)
        print(f"Session evidence analysis_id: {session_content['analysis_id']}")

        # 11. Verify evidence persisted under session evidence directory
        # When no explicit output_dir is passed, evidence goes to session.evidence_dir
        # But since we didn't pass output_dir, check session.evidence_dir
        # Actually for this test, output_dir was NOT explicitly provided, so 
        # evidence should be stored under session.evidence_dir
        self.assertIsNotNone(result.evidence_file_path)
        self.assertTrue(os.path.exists(result.evidence_file_path))
        evidence_parent = os.path.dirname(result.evidence_file_path)
        self.assertEqual(evidence_parent, session.evidence_dir)
        print(f"Evidence file: {result.evidence_file_path}")

        # 12. Verify session run directory structure
        self.assertTrue(session.run_dir.startswith(self.temp_dir))
        self.assertIn(session.analysis_id, session.run_dir)
        print(f"Session run directory: {session.run_dir}")

        # 13. Verify emulator cleanup
        self.assertFalse(
            self.orchestrator.is_running(),
            "Emulator should not be running after workflow completion",
        )
        print("Emulator cleanup: OK")

        # 14. Verify no orphan processes
        self._check_no_orphan_processes()
        print("No orphan processes: OK")

        # 15. Verify session serialization
        session_dict = session.to_dict()
        json_str = session.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["status"], "COMPLETED")
        self.assertEqual(parsed["analysis_id"], session.analysis_id)
        print(f"Session JSON serialization: OK")

        print("--- Step 56 Integration Test Completed Successfully ---")


if __name__ == "__main__":
    unittest.main()
