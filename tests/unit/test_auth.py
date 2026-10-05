"""Unit tests for AuthenticationBoundaryObserver in dynamic_analysis.auth."""

import json
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.auth import (
    AuthBoundaryResult,
    AuthError,
    AuthFormField,
    AuthValidationResult,
    AuthenticationBoundaryObserver,
)
from dynamic_analysis.observation import EvidenceType
from dynamic_analysis.ui import UIElement, UIHierarchy


class TestAuthenticationBoundaryObserver(unittest.TestCase):
    """Test suite for AuthenticationBoundaryObserver and authentication evidence models."""

    def setUp(self) -> None:
        self.mock_orchestrator = MagicMock()
        self.mock_orchestrator.config.serial = "emulator-5554"
        self.mock_orchestrator.is_running.return_value = True

        self.mock_ui_manager = MagicMock()
        self.mock_proxy_manager = MagicMock()
        self.mock_proxy_manager.parse_flow_file.return_value = []

        self.auth_observer = AuthenticationBoundaryObserver(
            orchestrator=self.mock_orchestrator,
            ui_manager=self.mock_ui_manager,
            proxy_manager=self.mock_proxy_manager,
        )

    def test_inspect_signin_screen(self) -> None:
        """Verify inspect_signin_screen catalogs input fields and buttons."""
        mock_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.widget.EditText",
                    resource_id="",
                    text="",
                    content_desc="Email",
                    clickable=True,
                    enabled=True,
                    bounds="[63,1002][1017,1149]",
                    center_x=540,
                    center_y=1075,
                ),
                UIElement(
                    class_name="android.widget.Button",
                    resource_id="",
                    text="",
                    content_desc="Sign In",
                    clickable=True,
                    enabled=True,
                    bounds="[63,1422][1017,1569]",
                    center_x=540,
                    center_y=1495,
                ),
            ],
            raw_xml="<xml></xml>",
        )
        self.mock_ui_manager.dump_hierarchy.return_value = mock_hierarchy

        fields = self.auth_observer.inspect_signin_screen()
        self.assertEqual(len(fields), 2)
        self.assertEqual(fields[0].field_type, "input")
        self.assertEqual(fields[1].field_type, "button")
        self.assertEqual(fields[1].content_desc, "Sign In")

    @patch("time.sleep", return_value=None)
    def test_exercise_signin_validation(self, mock_sleep: MagicMock) -> None:
        """Verify exercise_signin_validation collects local validation messages on empty submission."""
        mock_elem_signin = UIElement(
            class_name="android.widget.Button",
            resource_id="",
            text="",
            content_desc="Sign In",
            clickable=True,
            enabled=True,
            bounds="[63,1422][1017,1569]",
            center_x=540,
            center_y=1495,
        )
        self.mock_ui_manager.find_element.return_value = mock_elem_signin

        post_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.view.View",
                    resource_id="",
                    text="",
                    content_desc="Please enter your email",
                    clickable=False,
                    enabled=True,
                    bounds="[105,1160][456,1202]",
                    center_x=280,
                    center_y=1181,
                ),
                UIElement(
                    class_name="android.view.View",
                    resource_id="",
                    text="",
                    content_desc="Please enter your password",
                    clickable=False,
                    enabled=True,
                    bounds="[105,1401][520,1443]",
                    center_x=312,
                    center_y=1422,
                ),
            ],
            raw_xml="<xml></xml>",
        )
        self.mock_ui_manager.dump_hierarchy.return_value = post_hierarchy

        result = self.auth_observer.exercise_signin_validation()
        self.assertIsInstance(result, AuthValidationResult)
        self.assertEqual(result.screen_name, "Sign In")
        self.assertEqual(len(result.validation_messages), 2)
        self.assertIn("Please enter your email", result.validation_messages)
        self.assertTrue(result.local_validation_only)
        self.assertFalse(result.network_traffic_detected)

    @patch("time.sleep", return_value=None)
    def test_exercise_signup_validation(self, mock_sleep: MagicMock) -> None:
        """Verify exercise_signup_validation collects local validation messages on Create Account tap."""
        mock_link = UIElement(
            class_name="android.widget.Button",
            resource_id="",
            text="",
            content_desc="Sign Up",
            clickable=True,
            enabled=True,
            bounds="[629,1842][852,1968]",
            center_x=740,
            center_y=1905,
        )
        mock_create = UIElement(
            class_name="android.widget.Button",
            resource_id="",
            text="",
            content_desc="Create Account",
            clickable=True,
            enabled=True,
            bounds="[63,1779][1017,1926]",
            center_x=540,
            center_y=1852,
        )

        self.mock_ui_manager.find_element.side_effect = [mock_link, mock_create]

        post_hierarchy = UIHierarchy(
            timestamp="2026-09-26T00:00:00Z",
            elements=[
                UIElement(
                    class_name="android.view.View",
                    resource_id="",
                    text="",
                    content_desc="Please enter your full name",
                    clickable=False,
                    enabled=True,
                    bounds="[105,1139][514,1181]",
                    center_x=309,
                    center_y=1160,
                ),
                UIElement(
                    class_name="android.view.View",
                    resource_id="",
                    text="",
                    content_desc="Please confirm your password",
                    clickable=False,
                    enabled=True,
                    bounds="[105,1863][559,1905]",
                    center_x=332,
                    center_y=1884,
                ),
            ],
            raw_xml="<xml></xml>",
        )
        self.mock_ui_manager.dump_hierarchy.return_value = post_hierarchy

        result = self.auth_observer.exercise_signup_validation()
        self.assertEqual(result.screen_name, "Sign Up")
        self.assertEqual(len(result.validation_messages), 2)
        self.assertTrue(result.local_validation_only)

    def test_record_authentication_boundary(self) -> None:
        """Verify record_authentication_boundary creates AuthBoundaryResult."""
        boundary = self.auth_observer.record_authentication_boundary(
            screen_name="Sign In",
            reason="Authentication requires valid account credentials; no credentials provided.",
        )
        self.assertEqual(boundary.boundary_type, "CREDENTIALS_REQUIRED")
        self.assertTrue(boundary.blocked)
        self.assertEqual(len(self.auth_observer.recorded_boundaries), 1)

    def test_get_evidence_items(self) -> None:
        """Verify get_evidence_items generates AUTH_UI, AUTH_VALIDATION, AUTH_BOUNDARY, and AUTH_BLOCKED items."""
        self.auth_observer.recorded_form_fields.append(
            AuthFormField(
                field_type="input",
                class_name="android.widget.EditText",
                content_desc="Email",
                text="",
                bounds="[63,1002][1017,1149]",
                clickable=True,
            )
        )
        self.auth_observer.recorded_validations.append(
            AuthValidationResult(
                screen_name="Sign In",
                action_performed="Submit Empty Sign In Form",
                validation_messages=["Please enter your email"],
                local_validation_only=True,
                network_traffic_detected=False,
                timestamp="2026-09-26T00:00:00Z",
            )
        )
        self.auth_observer.record_authentication_boundary(
            screen_name="Sign In",
            reason="Credentials required",
        )

        items = self.auth_observer.get_evidence_items()
        self.assertEqual(len(items), 4)

        types = [item.evidence_type for item in items]
        self.assertIn(EvidenceType.AUTH_UI.value, types)
        self.assertIn(EvidenceType.AUTH_VALIDATION.value, types)
        self.assertIn(EvidenceType.AUTH_BOUNDARY.value, types)
        self.assertIn(EvidenceType.AUTH_BLOCKED.value, types)


if __name__ == "__main__":
    unittest.main()
