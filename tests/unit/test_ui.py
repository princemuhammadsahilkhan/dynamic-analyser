"""Unit tests for UIInteractionManager in dynamic_analysis.ui."""

import json
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.runtime import ShellResult
from dynamic_analysis.ui import (
    UIDumpError,
    UIElement,
    UIError,
    UIHierarchy,
    UIInteractionManager,
    UIInteractionResult,
)


SAMPLE_UI_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.mentorcraft2" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,0][1080,2146]">
    <node index="0" text="" resource-id="" class="android.widget.Button" package="com.example.mentorcraft2" content-desc="Skip" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[870,170][1038,296]" />
    <node index="1" text="" resource-id="" class="android.widget.Button" package="com.example.mentorcraft2" content-desc="Next" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[752,2067][1017,2146]" />
    <node index="2" text="Welcome to MentorCraft" resource-id="title" class="android.widget.TextView" package="com.example.mentorcraft2" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,338][1080,1899]" />
  </node>
</hierarchy>
"""


class TestUIInteractionManager(unittest.TestCase):
    """Test suite for UIInteractionManager and UI evidence models."""

    def setUp(self) -> None:
        self.mock_orchestrator = MagicMock()
        self.mock_orchestrator.config.serial = "emulator-5554"
        self.mock_orchestrator.is_running.return_value = True

        self.ui_manager = UIInteractionManager(orchestrator=self.mock_orchestrator)

    def test_parse_bounds(self) -> None:
        """Verify _parse_bounds extracts coordinates and calculates center."""
        x1, y1, x2, y2 = self.ui_manager._parse_bounds("[870,170][1038,296]")
        self.assertEqual((x1, y1, x2, y2), (870, 170, 1038, 296))

    def test_dump_hierarchy_success(self) -> None:
        """Verify dump_hierarchy executes uiautomator dump and parses UI elements."""
        self.mock_orchestrator.shell.side_effect = [
            ShellResult(stdout="UI hierchary dumped to: /data/local/tmp/ui_dump.xml", stderr="", exit_code=0),
            ShellResult(stdout=SAMPLE_UI_XML, stderr="", exit_code=0),
            ShellResult(stdout="", stderr="", exit_code=0),
        ]

        hierarchy = self.ui_manager.dump_hierarchy()
        self.assertIsInstance(hierarchy, UIHierarchy)
        self.assertTrue(len(hierarchy.elements) >= 3)

        skip_btn = self.ui_manager.find_element(hierarchy, content_desc="Skip")
        self.assertIsNotNone(skip_btn)
        self.assertEqual(skip_btn.center_x, 954)
        self.assertEqual(skip_btn.center_y, 233)

    def test_dump_hierarchy_failure(self) -> None:
        """Verify dump_hierarchy raises UIDumpError on command failure."""
        self.mock_orchestrator.shell.return_value = ShellResult(
            stdout="", stderr="ERROR: null root node", exit_code=1
        )
        with self.assertRaises(UIDumpError):
            self.ui_manager.dump_hierarchy()

    def test_tap_element(self) -> None:
        """Verify tap_element executes input tap with center coordinates."""
        elem = UIElement(
            class_name="android.widget.Button",
            resource_id="",
            text="",
            content_desc="Skip",
            clickable=True,
            enabled=True,
            bounds="[870,170][1038,296]",
            center_x=954,
            center_y=233,
        )
        self.mock_orchestrator.shell.return_value = ShellResult(stdout="", stderr="", exit_code=0)

        res = self.ui_manager.tap_element(elem)
        self.assertTrue(res.success)
        self.assertEqual(res.target_x, 954)
        self.assertEqual(res.target_y, 233)
        self.mock_orchestrator.shell.assert_called_with("input tap 954 233")

    def test_get_evidence_items(self) -> None:
        """Verify get_evidence_items formats hierarchy dumps and interaction results."""
        self.mock_orchestrator.shell.side_effect = [
            ShellResult(stdout="UI hierchary dumped", stderr="", exit_code=0),
            ShellResult(stdout=SAMPLE_UI_XML, stderr="", exit_code=0),
            ShellResult(stdout="", stderr="", exit_code=0),
            ShellResult(stdout="", stderr="", exit_code=0),
        ]

        hier = self.ui_manager.dump_hierarchy()
        skip_btn = self.ui_manager.find_element(hier, content_desc="Skip")
        self.ui_manager.tap_element(skip_btn)

        items = self.ui_manager.get_evidence_items()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].evidence_type, EvidenceType.UI_HIERARCHY.value)
        self.assertEqual(items[1].evidence_type, EvidenceType.UI_INTERACTION.value)

    @patch("time.sleep", return_value=None)
    def test_exercise_deeper_navigation_flow(self, mock_sleep: MagicMock) -> None:
        """Verify exercise_deeper_navigation_flow executes multi-step exploration."""
        hier1 = MagicMock()
        elem_skip = MagicMock(center_x=954, center_y=233, content_desc="Skip")
        elem_student = MagicMock(center_x=540, center_y=1277, content_desc="Student")
        elem_signup = MagicMock(center_x=740, center_y=1905, content_desc="Sign Up")
        elem_back = MagicMock(center_x=74, center_y=202, content_desc="Back")
        elem_forgot = MagicMock(center_x=540, center_y=1695, content_desc="Forgot Password")

        self.ui_manager.dump_hierarchy = MagicMock(return_value=hier1)
        self.ui_manager.find_element = MagicMock(
            side_effect=[
                elem_skip,     # 1. Skip on Screen 1
                elem_student,  # 2. Student on Screen 4
                elem_signup,   # 3. Sign Up on Screen 5
                elem_back,     # 4. Back on Screen 6
                elem_forgot,   # 5. Forgot Password on Screen 5 returned
            ]
        )
        self.ui_manager.tap_element = MagicMock(
            side_effect=[
                UIInteractionResult(action="tap", target_desc="Skip", target_x=954, target_y=233, success=True),
                UIInteractionResult(action="tap", target_desc="Student", target_x=540, target_y=1277, success=True),
                UIInteractionResult(action="tap", target_desc="Sign Up", target_x=740, target_y=1905, success=True),
                UIInteractionResult(action="tap", target_desc="Back", target_x=74, target_y=202, success=True),
                UIInteractionResult(action="tap", target_desc="Forgot Password", target_x=540, target_y=1695, success=True),
            ]
        )

        results = self.ui_manager.exercise_deeper_navigation_flow()
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r.success for r in results))


if __name__ == "__main__":
    unittest.main()
