"""Unit tests for PreAuthBehaviorObserver in dynamic_analysis.behavior."""

import json
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.behavior import (
    BehavioralState,
    BehavioralTransition,
    PreAuthBehaviorInventory,
    PreAuthBehaviorObserver,
    ValidationResult,
)
from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.ui import UIElement, UIHierarchy


class TestPreAuthBehaviorObserver(unittest.TestCase):
    """Test suite for PreAuthBehaviorObserver and behavioral evidence models."""

    def setUp(self) -> None:
        self.mock_orchestrator = MagicMock()
        self.mock_orchestrator.config.serial = "emulator-5554"
        self.mock_orchestrator.is_running.return_value = True

        self.mock_ui_manager = MagicMock()
        from dynamic_analysis.ui import UIInteractionResult
        self.mock_ui_manager.tap_element.return_value = UIInteractionResult(
            action="tap", target_desc="Button", target_x=100, target_y=100, success=True
        )
        self.mock_proxy_manager = MagicMock()
        self.mock_proxy_manager.parse_flow_file.return_value = []

        self.observer = PreAuthBehaviorObserver(
            orchestrator=self.mock_orchestrator,
            ui_manager=self.mock_ui_manager,
            proxy_manager=self.mock_proxy_manager,
        )

    def test_record_state(self) -> None:
        """Verify record_state parses UIHierarchy and creates a BehavioralState object."""
        mock_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.widget.TextView",
                    resource_id="",
                    text="",
                    content_desc="Welcome to MentorCraft\nYour learning journey",
                    clickable=False,
                    enabled=True,
                    bounds="[0,338][1080,1899]",
                    center_x=540,
                    center_y=1118,
                ),
                UIElement(
                    class_name="android.widget.Button",
                    resource_id="",
                    text="",
                    content_desc="Next",
                    clickable=True,
                    enabled=True,
                    bounds="[752,2067][1017,2146]",
                    center_x=884,
                    center_y=2106,
                ),
            ],
            raw_xml="<xml></xml>",
        )

        state = self.observer.record_state("ONBOARDING_1", "Welcome Screen", mock_hierarchy)
        self.assertEqual(state.state_id, "ONBOARDING_1")
        self.assertEqual(state.title, "Welcome to MentorCraft")
        self.assertEqual(state.element_count, 2)
        self.assertIn("Next", state.interactive_elements)

    def test_record_transition(self) -> None:
        """Verify record_transition tracks state transitions and network flow counts."""
        trans = self.observer.record_transition(
            from_state="ONBOARDING_1",
            to_state="ONBOARDING_2",
            action="tap",
            target_desc="Next",
            success=True,
        )
        self.assertEqual(trans.from_state, "ONBOARDING_1")
        self.assertEqual(trans.to_state, "ONBOARDING_2")
        self.assertEqual(trans.network_flows_generated, 0)
        self.assertFalse(trans.process_changed)

    @patch("time.sleep", return_value=None)
    def test_exercise_onboarding_sequence(self, mock_sleep: MagicMock) -> None:
        """Verify exercise_onboarding_sequence steps through screens 1, 2, previous to 1, 2, 3, and 4."""
        mock_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.widget.Button",
                    resource_id="",
                    text="",
                    content_desc="Next",
                    clickable=True,
                    enabled=True,
                    bounds="[752,2067][1017,2146]",
                    center_x=884,
                    center_y=2106,
                ),
                UIElement(
                    class_name="android.widget.Button",
                    resource_id="",
                    text="",
                    content_desc="Previous",
                    clickable=True,
                    enabled=True,
                    bounds="[63,2076][308,2146]",
                    center_x=185,
                    center_y=2111,
                ),
            ],
            raw_xml="<xml></xml>",
        )
        self.mock_ui_manager.dump_hierarchy.return_value = mock_hierarchy
        self.mock_ui_manager.find_element.return_value = mock_hierarchy.elements[0]

        self.observer.exercise_onboarding_sequence()
        self.assertTrue(len(self.observer.states) >= 4)
        self.assertTrue(len(self.observer.transitions) >= 3)

    def test_compare_role_selection(self) -> None:
        """Verify compare_role_selection returns True for Student vs Teacher pre-auth convergence."""
        mock_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.view.View",
                    resource_id="",
                    text="",
                    content_desc="Student",
                    clickable=True,
                    enabled=True,
                    bounds="[63,1146][1017,1408]",
                    center_x=540,
                    center_y=1277,
                ),
            ],
            raw_xml="<xml></xml>",
        )
        self.mock_ui_manager.dump_hierarchy.return_value = mock_hierarchy
        self.mock_ui_manager.find_element.return_value = mock_hierarchy.elements[0]

        identical = self.observer.compare_role_selection()
        self.assertTrue(identical)

    @patch("time.sleep", return_value=None)
    def test_collect_inventory(self, mock_sleep: MagicMock) -> None:
        """Verify collect_inventory aggregates states, transitions, validations, and evidence items."""
        mock_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.widget.Button",
                    resource_id="",
                    text="",
                    content_desc="Next",
                    clickable=True,
                    enabled=True,
                    bounds="[752,2067][1017,2146]",
                    center_x=884,
                    center_y=2106,
                ),
            ],
            raw_xml="<xml></xml>",
        )
        self.mock_ui_manager.dump_hierarchy.return_value = mock_hierarchy
        self.mock_ui_manager.find_element.return_value = mock_hierarchy.elements[0]
        from dynamic_analysis.ui import UIInteractionResult
        self.mock_ui_manager.tap_element.return_value = UIInteractionResult(
            action="tap", target_desc="Next", target_x=884, target_y=2106, success=True
        )

        inventory, evidence_items = self.observer.collect_inventory()
        self.assertIsInstance(inventory, PreAuthBehaviorInventory)
        self.assertTrue(len(evidence_items) > 0)

        types = [item.evidence_type for item in evidence_items]
        self.assertIn(EvidenceType.BEHAVIORAL_STATE.value, types)
        self.assertIn(EvidenceType.BEHAVIORAL_TRANSITION.value, types)
        self.assertIn(EvidenceType.VALIDATION_RESULT.value, types)
        self.assertIn(EvidenceType.AUTH_BOUNDARY.value, types)


if __name__ == "__main__":
    unittest.main()
