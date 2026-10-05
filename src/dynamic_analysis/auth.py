"""Controlled authentication boundary observation layer for Android dynamic analysis."""

import json
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    _get_utc_timestamp,
)
from dynamic_analysis.proxy import ProxyManager
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator
from dynamic_analysis.ui import UIHierarchy, UIInteractionManager, UIInteractionResult


class AuthError(AndroidRuntimeError):
    """Base exception for authentication boundary analysis errors."""

    pass


@dataclass(frozen=True)
class AuthFormField:
    """Representation of an observed authentication form field."""

    field_type: str
    class_name: str
    content_desc: str
    text: str
    bounds: str
    clickable: bool

    def to_dict(self) -> Dict:
        """Convert form field to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class AuthValidationResult:
    """Representation of observed form validation feedback."""

    screen_name: str
    action_performed: str
    validation_messages: List[str]
    local_validation_only: bool
    network_traffic_detected: bool
    timestamp: str

    def to_dict(self) -> Dict:
        """Convert validation result to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class AuthBoundaryResult:
    """Representation of an established authentication boundary state."""

    screen_name: str
    boundary_type: str
    reason: str
    blocked: bool
    timestamp: str

    def to_dict(self) -> Dict:
        """Convert boundary result to dictionary."""
        return asdict(self)


class AuthenticationBoundaryObserver:
    """Observer for identifying authentication UI components, validation feedback, and boundary conditions."""

    def __init__(
        self,
        orchestrator: AndroidRuntimeOrchestrator,
        ui_manager: Optional[UIInteractionManager] = None,
        proxy_manager: Optional[ProxyManager] = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.ui_manager = ui_manager or UIInteractionManager(orchestrator)
        self.proxy_manager = proxy_manager
        self.recorded_form_fields: List[AuthFormField] = []
        self.recorded_validations: List[AuthValidationResult] = []
        self.recorded_boundaries: List[AuthBoundaryResult] = []

    def inspect_signin_screen(self) -> List[AuthFormField]:
        """Inspect Sign In screen and catalog all input fields, buttons, and labels."""
        hier = self.ui_manager.dump_hierarchy()
        fields: List[AuthFormField] = []

        for elem in hier.elements:
            desc = elem.content_desc
            text = elem.text
            cls = elem.class_name

            if "EditText" in cls:
                fields.append(
                    AuthFormField(
                        field_type="input",
                        class_name=cls,
                        content_desc=desc,
                        text=text,
                        bounds=elem.bounds,
                        clickable=elem.clickable,
                    )
                )
            elif "Button" in cls or elem.clickable:
                fields.append(
                    AuthFormField(
                        field_type="button" if "Button" in cls else "clickable",
                        class_name=cls,
                        content_desc=desc,
                        text=text,
                        bounds=elem.bounds,
                        clickable=elem.clickable,
                    )
                )

        self.recorded_form_fields.extend(fields)
        return fields

    def exercise_signin_validation(self) -> AuthValidationResult:
        """Trigger empty Sign In submission to observe client-side validation rules without submitting credentials."""
        import time

        hier = self.ui_manager.dump_hierarchy()
        signin_btn = self.ui_manager.find_element(hier, content_desc="Sign In")

        local_val = False
        val_messages: List[str] = []

        if signin_btn:
            self.ui_manager.tap_element(signin_btn)
            time.sleep(2.0)
            post_hier = self.ui_manager.dump_hierarchy()

            for elem in post_hier.elements:
                desc = elem.content_desc
                if "Please enter" in desc or "invalid" in desc.lower():
                    val_messages.append(desc)
                    local_val = True

        net_detected = False
        if self.proxy_manager:
            flows = self.proxy_manager.parse_flow_file()
            net_detected = len(flows) > 0

        res = AuthValidationResult(
            screen_name="Sign In",
            action_performed="Submit Empty Sign In Form",
            validation_messages=val_messages,
            local_validation_only=not net_detected,
            network_traffic_detected=net_detected,
            timestamp=_get_utc_timestamp(),
        )
        self.recorded_validations.append(res)
        return res

    def exercise_signup_validation(self) -> AuthValidationResult:
        """Trigger empty Sign Up submission to observe client-side validation rules without creating account."""
        import time

        hier = self.ui_manager.dump_hierarchy()
        signup_link = self.ui_manager.find_element(hier, content_desc="Sign Up")

        val_messages: List[str] = []
        local_val = False

        if signup_link:
            self.ui_manager.tap_element(signup_link)
            time.sleep(2.0)

            hier_signup = self.ui_manager.dump_hierarchy()
            create_btn = self.ui_manager.find_element(hier_signup, content_desc="Create Account")
            if create_btn:
                self.ui_manager.tap_element(create_btn)
                time.sleep(2.0)
                post_signup_hier = self.ui_manager.dump_hierarchy()

                for elem in post_signup_hier.elements:
                    desc = elem.content_desc
                    if "Please enter" in desc or "Please confirm" in desc or "invalid" in desc.lower():
                        val_messages.append(desc)
                        local_val = True

        net_detected = False
        if self.proxy_manager:
            flows = self.proxy_manager.parse_flow_file()
            net_detected = len(flows) > 0

        res = AuthValidationResult(
            screen_name="Sign Up",
            action_performed="Submit Empty Create Account Form",
            validation_messages=val_messages,
            local_validation_only=not net_detected,
            network_traffic_detected=net_detected,
            timestamp=_get_utc_timestamp(),
        )
        self.recorded_validations.append(res)
        return res

    def record_authentication_boundary(
        self, screen_name: str, reason: str
    ) -> AuthBoundaryResult:
        """Record an explicit authentication boundary reached where credentials or user registration is required."""
        boundary = AuthBoundaryResult(
            screen_name=screen_name,
            boundary_type="CREDENTIALS_REQUIRED",
            reason=reason,
            blocked=True,
            timestamp=_get_utc_timestamp(),
        )
        self.recorded_boundaries.append(boundary)
        return boundary

    def get_evidence_items(self) -> List[EvidenceItem]:
        """Convert recorded auth form fields, validation feedback, and boundary states into EvidenceItem objects."""
        serial = self.orchestrator.config.serial
        items: List[EvidenceItem] = []

        for field in self.recorded_form_fields:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.AUTH_UI.value,
                    timestamp=_get_utc_timestamp(),
                    serial=serial,
                    source="AuthenticationBoundaryObserver.inspect_fields",
                    content=json.dumps(field.to_dict()),
                    exit_code=0,
                )
            )

        for val in self.recorded_validations:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.AUTH_VALIDATION.value,
                    timestamp=val.timestamp,
                    serial=serial,
                    source=f"AuthenticationBoundaryObserver.{val.screen_name}",
                    content=json.dumps(val.to_dict()),
                    exit_code=0,
                )
            )

        for b in self.recorded_boundaries:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.AUTH_BOUNDARY.value,
                    timestamp=b.timestamp,
                    serial=serial,
                    source=f"AuthenticationBoundaryObserver.{b.screen_name}",
                    content=json.dumps(b.to_dict()),
                    exit_code=0,
                )
            )
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.AUTH_BLOCKED.value,
                    timestamp=b.timestamp,
                    serial=serial,
                    source=f"AuthenticationBoundaryObserver.{b.screen_name}",
                    content=json.dumps(b.to_dict()),
                    exit_code=0,
                )
            )

        return items
