"""Controlled UI interaction and hierarchy inspection layer for Android dynamic analysis."""

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    _get_utc_timestamp,
)
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator


class UIError(AndroidRuntimeError):
    """Base exception for UI interaction errors."""

    pass


class UIDumpError(UIError):
    """Raised when uiautomator dump fails."""

    pass


class UIElementNotFoundError(UIError):
    """Raised when a specified UI element cannot be located in the current screen hierarchy."""

    pass


@dataclass(frozen=True)
class UIElement:
    """Representation of a single UI element extracted from Android UI hierarchy dump."""

    class_name: str
    resource_id: str
    text: str
    content_desc: str
    clickable: bool
    enabled: bool
    bounds: str
    center_x: int
    center_y: int

    def to_dict(self) -> Dict:
        """Convert element to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class UIHierarchy:
    """Representation of an inspected screen UI hierarchy."""

    timestamp: str
    elements: List[UIElement]
    raw_xml: str

    def to_dict(self) -> Dict:
        """Convert hierarchy to dictionary."""
        return {
            "timestamp": self.timestamp,
            "elements": [elem.to_dict() for elem in self.elements],
            "raw_xml_length": len(self.raw_xml),
        }


@dataclass(frozen=True)
class UIInteractionResult:
    """Result summary of a single performed UI interaction."""

    action: str
    target_desc: str
    target_x: Optional[int]
    target_y: Optional[int]
    success: bool
    error_message: Optional[str] = None
    timestamp: str = ""

    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return asdict(self)


class UIInteractionManager:
    """Manager for parsing Android UI hierarchy dumps and executing deterministic UI interactions."""

    def __init__(self, orchestrator: AndroidRuntimeOrchestrator) -> None:
        self.orchestrator = orchestrator
        self.recorded_hierarchies: List[UIHierarchy] = []
        self.recorded_interactions: List[UIInteractionResult] = []

    def _parse_bounds(self, bounds_str: str) -> Tuple[int, int, int, int]:
        """Parse bounds string like '[870,170][1038,296]' into (x1, y1, x2, y2)."""
        match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
        if not match:
            return 0, 0, 0, 0
        return (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
        )

    def dump_hierarchy(self, dump_file: str = "/data/local/tmp/ui_dump.xml") -> UIHierarchy:
        """Dump UI hierarchy from current foreground screen via uiautomator dump and parse elements."""
        if not self.orchestrator.is_running():
            raise UIDumpError("Emulator runtime is not running")

        # 1. Execute uiautomator dump
        res_dump = self.orchestrator.shell(f"uiautomator dump {dump_file}")
        if res_dump.exit_code != 0:
            raise UIDumpError(f"uiautomator dump failed: {res_dump.stderr or res_dump.stdout}")

        # 2. Retrieve XML content
        res_cat = self.orchestrator.shell(f"cat {dump_file}")
        xml_content = res_cat.stdout
        self.orchestrator.shell(f"rm -f {dump_file}")

        if not xml_content.strip():
            raise UIDumpError("uiautomator dump returned empty content")

        # 3. Parse XML elements
        elements: List[UIElement] = []
        try:
            root = ET.fromstring(xml_content)
            for elem in root.iter("node"):
                cls = elem.attrib.get("class", "")
                res_id = elem.attrib.get("resource-id", "")
                text = elem.attrib.get("text", "")
                desc = elem.attrib.get("content-desc", "")
                clickable = elem.attrib.get("clickable", "false").lower() == "true"
                enabled = elem.attrib.get("enabled", "true").lower() == "true"
                bounds = elem.attrib.get("bounds", "[0,0][0,0]")

                x1, y1, x2, y2 = self._parse_bounds(bounds)
                center_x = (x1 + x2) // 2
                center_y = (y1 + y2) // 2

                ui_elem = UIElement(
                    class_name=cls,
                    resource_id=res_id,
                    text=text,
                    content_desc=desc,
                    clickable=clickable,
                    enabled=enabled,
                    bounds=bounds,
                    center_x=center_x,
                    center_y=center_y,
                )
                elements.append(ui_elem)
        except Exception as exc:
            raise UIDumpError(f"Failed to parse UI hierarchy XML: {exc}") from exc

        hierarchy = UIHierarchy(
            timestamp=_get_utc_timestamp(),
            elements=elements,
            raw_xml=xml_content,
        )
        self.recorded_hierarchies.append(hierarchy)
        return hierarchy

    def find_element(
        self,
        hierarchy: UIHierarchy,
        content_desc: Optional[str] = None,
        text: Optional[str] = None,
        resource_id: Optional[str] = None,
        class_name: Optional[str] = None,
    ) -> Optional[UIElement]:
        """Find the first matching UIElement in the given hierarchy."""
        for elem in hierarchy.elements:
            if content_desc and content_desc not in elem.content_desc:
                continue
            if text and text not in elem.text:
                continue
            if resource_id and resource_id not in elem.resource_id:
                continue
            if class_name and class_name not in elem.class_name:
                continue
            return elem
        return None

    def tap_element(self, element: UIElement) -> UIInteractionResult:
        """Tap on the specified UI element center coordinates."""
        if not self.orchestrator.is_running():
            raise UIError("Emulator runtime is not running")

        target_desc = element.content_desc or element.text or element.class_name
        res = self.orchestrator.shell(f"input tap {element.center_x} {element.center_y}")
        success = res.exit_code == 0

        result = UIInteractionResult(
            action="tap",
            target_desc=target_desc,
            target_x=element.center_x,
            target_y=element.center_y,
            success=success,
            error_message=res.stderr if not success else None,
            timestamp=_get_utc_timestamp(),
        )
        self.recorded_interactions.append(result)
        return result

    def exercise_onboarding_flow(self) -> List[UIInteractionResult]:
        """Exercise target application onboarding flow and role selection deterministically."""
        results: List[UIInteractionResult] = []

        # 1. Dump initial Screen 1
        hier1 = self.dump_hierarchy()
        skip_btn = self.find_element(hier1, content_desc="Skip")
        next_btn = self.find_element(hier1, content_desc="Next")

        if skip_btn:
            res_skip = self.tap_element(skip_btn)
            results.append(res_skip)
        elif next_btn:
            res_next = self.tap_element(next_btn)
            results.append(res_next)

        # 2. Wait and dump Screen 2 (Role selection or Onboarding 2)
        import time
        time.sleep(2.0)
        hier2 = self.dump_hierarchy()

        student_role = self.find_element(hier2, content_desc="Student")
        teacher_role = self.find_element(hier2, content_desc="Teacher")
        skip_btn2 = self.find_element(hier2, content_desc="Skip")

        if not student_role and skip_btn2:
            self.tap_element(skip_btn2)
            time.sleep(2.0)
            hier2 = self.dump_hierarchy()
            student_role = self.find_element(hier2, content_desc="Student")

        if student_role:
            res_student = self.tap_element(student_role)
            results.append(res_student)
        elif teacher_role:
            res_teacher = self.tap_element(teacher_role)
            results.append(res_teacher)

        return results

    def exercise_deeper_navigation_flow(self) -> List[UIInteractionResult]:
        """Extend controlled UI interaction past role selection into Sign In, Sign Up, and password reset flows."""
        import time

        results: List[UIInteractionResult] = []

        # 1. Onboarding screen 1: Dump hierarchy -> Tap Skip
        hier1 = self.dump_hierarchy()
        skip_btn = self.find_element(hier1, content_desc="Skip")
        if skip_btn:
            res_skip = self.tap_element(skip_btn)
            results.append(res_skip)

        time.sleep(2.0)

        # 2. Role selection screen: Dump hierarchy -> Tap Student role
        hier2 = self.dump_hierarchy()
        student_role = self.find_element(hier2, content_desc="Student")
        if not student_role:
            skip_btn2 = self.find_element(hier2, content_desc="Skip")
            if skip_btn2:
                self.tap_element(skip_btn2)
                time.sleep(2.0)
                hier2 = self.dump_hierarchy()
                student_role = self.find_element(hier2, content_desc="Student")

        if student_role:
            res_student = self.tap_element(student_role)
            results.append(res_student)

        time.sleep(2.0)

        # 3. Sign In screen (Screen 5): Dump hierarchy -> Tap Sign Up
        hier_signin = self.dump_hierarchy()
        signup_btn = self.find_element(hier_signin, content_desc="Sign Up")
        if signup_btn:
            res_signup = self.tap_element(signup_btn)
            results.append(res_signup)

        time.sleep(2.0)

        # 4. Sign Up screen (Screen 6): Dump hierarchy -> Tap Back
        hier_signup = self.dump_hierarchy()
        back_btn = self.find_element(hier_signup, content_desc="Back")
        if back_btn:
            res_back = self.tap_element(back_btn)
            results.append(res_back)

        time.sleep(2.0)

        # 5. Sign In screen (returned): Dump hierarchy -> Tap Forgot Password?
        hier_signin_returned = self.dump_hierarchy()
        forgot_btn = self.find_element(hier_signin_returned, content_desc="Forgot Password")
        if forgot_btn:
            res_forgot = self.tap_element(forgot_btn)
            results.append(res_forgot)

        time.sleep(2.0)

        # 6. Final post-interaction hierarchy dump (Screen 5 with toast/boundary)
        self.dump_hierarchy()

        return results

    def get_evidence_items(self) -> List[EvidenceItem]:
        """Convert recorded UI hierarchy dumps and interactions into EvidenceItem objects."""
        serial = self.orchestrator.config.serial
        items: List[EvidenceItem] = []

        # 1. Hierarchy Evidence
        for h in self.recorded_hierarchies:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.UI_HIERARCHY.value,
                    timestamp=h.timestamp,
                    serial=serial,
                    source="UIInteractionManager.dump_hierarchy",
                    content=json.dumps(h.to_dict()),
                    exit_code=0,
                )
            )

        # 2. Interaction Evidence
        for inter in self.recorded_interactions:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.UI_INTERACTION.value,
                    timestamp=inter.timestamp,
                    serial=serial,
                    source=f"UIInteractionManager.{inter.action}",
                    content=json.dumps(inter.to_dict()),
                    exit_code=0 if inter.success else 1,
                )
            )

        return items
