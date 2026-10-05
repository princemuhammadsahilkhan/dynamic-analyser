"""Real emulator integration test for Step 36 Runtime Observation and Evidence Collection."""

import os
import shutil
import tempfile
import time
import unittest

from dynamic_analysis.config import AndroidRuntimeConfig
from dynamic_analysis.observation import (
    EvidenceType,
    LogcatCollector,
    RuntimeObserver,
    save_evidence_items,
)
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


class TestStep36ObservationIntegration(unittest.TestCase):
    """Real integration test for RuntimeObserver and LogcatCollector using analysis_baseline_api33."""

    def setUp(self) -> None:
        self.config = AndroidRuntimeConfig(
            avd_name="analysis_baseline_api33",
            headless=True,
            wipe_data=False,
            port=5554,
        )
        self.orchestrator = AndroidRuntimeOrchestrator(self.config)
        self.temp_dir = tempfile.mkdtemp(prefix="step36_evidence_")

    def tearDown(self) -> None:
        if self.orchestrator.is_running():
            try:
                self.orchestrator.shutdown()
            except Exception as e:
                print(f"Warning during tearDown shutdown: {e}")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_real_emulator_observation_lifecycle(self) -> None:
        print("\n--- Starting Emulator for Integration Test ---")
        self.orchestrator.start()
        self.assertTrue(self.orchestrator.is_running(), "Emulator should be running after start()")

        print("Waiting for guest boot completion (sys.boot_completed=1)...")
        self.orchestrator.wait_for_boot(timeout=120.0)

        observer = RuntimeObserver(self.orchestrator)

        # 1. Collect Properties
        print("Collecting system properties...")
        props = observer.collect_properties()
        self.assertGreater(len(props), 0, "System properties should not be empty")

        prop_dict = {p.source: p.content for p in props}
        print(f"Captured Properties: {prop_dict}")

        self.assertEqual(prop_dict.get("ro.build.version.sdk"), "33")
        self.assertEqual(prop_dict.get("sys.boot_completed"), "1")
        self.assertEqual(prop_dict.get("ro.product.cpu.abi"), "x86_64")

        # 2. Collect Processes
        print("Collecting guest process list...")
        proc_item = observer.collect_processes()
        self.assertEqual(proc_item.evidence_type, EvidenceType.PROCESS_LIST.value)
        self.assertEqual(proc_item.exit_code, 0)
        self.assertIn("ps", proc_item.content)
        print(f"Process list length: {len(proc_item.content.splitlines())} lines")

        # 3. Collect Logcat Dump
        print("Collecting logcat dump...")
        logcat_dump = observer.collect_logcat_dump(timeout=10.0)
        self.assertEqual(logcat_dump.evidence_type, EvidenceType.LOGCAT.value)
        self.assertEqual(logcat_dump.exit_code, 0)
        self.assertGreater(len(logcat_dump.content), 0, "Logcat dump should contain text")
        print(f"Logcat dump size: {len(logcat_dump.content)} bytes")

        # 4. Stream Logcat Collector
        print("Testing LogcatCollector streaming...")
        collector = LogcatCollector(self.orchestrator)
        collector.start(clear_buffer=True)
        self.assertTrue(collector.is_running(), "LogcatCollector should be running")

        # Trigger guest log activity via shell
        self.orchestrator.shell('log -t Step36Integration "Test log message from Step 36"')
        time.sleep(1.0)

        streamed_item = collector.stop(timeout=5.0)
        self.assertFalse(collector.is_running(), "LogcatCollector should be stopped")
        self.assertEqual(streamed_item.evidence_type, EvidenceType.LOGCAT.value)
        print(f"Streamed logcat size: {len(streamed_item.content)} bytes")

        # 5. Save Evidence Items
        all_items = props + [proc_item, logcat_dump, streamed_item]
        saved_path = save_evidence_items(all_items, self.temp_dir, "step36_evidence.json")
        self.assertTrue(os.path.exists(saved_path), "Saved evidence JSON file must exist")
        print(f"Saved evidence to: {saved_path}")

        # 6. Shutdown Emulator
        print("Shutting down emulator...")
        self.orchestrator.shutdown()
        self.assertFalse(self.orchestrator.is_running(), "Emulator should not be running after shutdown()")
        print("--- Integration Test Completed Successfully ---")


if __name__ == "__main__":
    unittest.main()
