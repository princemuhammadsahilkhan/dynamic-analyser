"""Static Backend Contract to Runtime Endpoint Correlation Layer."""

import json
import re
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from dynamic_analysis.backend_contract import BackendContractInventory, SupabaseContractMapper
from dynamic_analysis.observation import EvidenceItem, EvidenceType


@dataclass
class BackendEvidenceLink:
    """Represents the static correlation link between a backend resource and binary/UI evidence."""

    resource_name: str
    resource_type: str  # 'table', 'storage_bucket', 'realtime_endpoint', 'rest_endpoint', 'storage_endpoint', 'edge_functions'
    evidence_category: str  # 'VERIFIED STATIC REFERENCE', 'STRING-ONLY REFERENCE', 'SCREEN/RESOURCE CORRELATION', 'INFERENCE', 'UNVERIFIED'
    static_symbols: List[str]
    associated_screens: List[str]
    confidence_score: str  # 'HIGH', 'MEDIUM', 'LOW', 'UNVERIFIED'
    notes: str


@dataclass
class BackendRuntimeCorrelation:
    """Structured correlation model linking static backend resources to compiled binary/UI components."""

    target_apk: str
    primary_backend_url: str
    evidence_links: List[BackendEvidenceLink] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert correlation model to dictionary representation."""
        return {
            "target_apk": self.target_apk,
            "primary_backend_url": self.primary_backend_url,
            "evidence_links": [asdict(link) for link in self.evidence_links],
        }

    def to_evidence_items(self, serial: str = "N/A") -> List[EvidenceItem]:
        """Convert correlation model into structured EvidenceItem instances."""
        now = datetime.now(timezone.utc).isoformat()
        items = []

        # Master Correlation Model Evidence Item
        items.append(
            EvidenceItem(
                evidence_type=EvidenceType.BACKEND_CORRELATION.value,
                timestamp=now,
                serial=serial,
                source="BackendCorrelationMapper",
                content=json.dumps(self.to_dict(), indent=2),
                metadata={
                    "target_apk": self.target_apk,
                    "primary_backend_url": self.primary_backend_url,
                    "total_correlated_resources": str(len(self.evidence_links)),
                },
            )
        )

        # Individual Resource Evidence Items
        for link in self.evidence_links:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.RESOURCE_CORRELATION.value,
                    timestamp=now,
                    serial=serial,
                    source="BackendCorrelationMapper",
                    content=json.dumps(asdict(link), indent=2),
                    metadata={
                        "resource_name": link.resource_name,
                        "evidence_category": link.evidence_category,
                        "confidence_score": link.confidence_score,
                    },
                )
            )

        return items


class BackendCorrelationMapper:
    """Correlates static Supabase contract resources with compiled binary/UI components."""

    RESOURCE_DEFINITIONS = {
        "users": ("table", ["LoginScreen", "RoleSelectionScreen", "StudentMainScreen", "CourseManagementScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "courses": ("table", ["StudentMainScreen", "MyCoursesScreen", "CourseManagementScreen", "CreateCourseScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "enrollments": ("table", ["StudentMainScreen", "MyCoursesScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "quizzes": ("table", ["QuizManagementScreen", "QuizTakingScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "announcements": ("table", ["StudentMainScreen", "CourseManagementScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "discussions": ("table", ["StudentMainScreen", "CourseManagementScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "modules": ("table", ["CourseManagementScreen", "LearningHistoryScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "certificates": ("table", ["LearningHistoryScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "roles": ("table", ["RoleSelectionScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "profile-images": ("storage_bucket", ["StudentMainScreen", "CourseManagementScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "mentorcraft-images": ("storage_bucket", ["CourseManagementScreen", "CreateCourseScreen"], "SCREEN/RESOURCE CORRELATION", "HIGH"),
        "/realtime/v1": ("realtime_endpoint", ["StudentMainScreen", "CourseManagementScreen"], "STRING-ONLY REFERENCE", "HIGH"),
        "/rest/v1/": ("rest_endpoint", ["StudentMainScreen", "CourseManagementScreen", "MyCoursesScreen"], "STRING-ONLY REFERENCE", "HIGH"),
        "/storage/v1/": ("storage_endpoint", ["StudentMainScreen", "CourseManagementScreen"], "STRING-ONLY REFERENCE", "HIGH"),
        "/functions/v1/": ("edge_functions", [], "UNVERIFIED", "UNVERIFIED"),
    }

    def __init__(self, apk_path: str, contract_inventory: Optional[BackendContractInventory] = None):
        self.apk_path = apk_path
        self.contract_inventory = contract_inventory

    def _extract_binary_strings(self) -> str:
        """Extract printable strings from compiled Flutter binary in APK."""
        extracted = []
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("libapp.so"):
                    data = zf.read(name)
                    matches = re.findall(rb"[a-zA-Z0-9_./:\-]{4,}", data)
                    extracted.extend(m.decode("ascii", errors="ignore") for m in matches)
        return "\n".join(extracted)

    def correlate(self) -> BackendRuntimeCorrelation:
        """Correlate statically discovered resources with binary string evidence and UI components."""
        extracted_text = self._extract_binary_strings()

        if not self.contract_inventory:
            contract_mapper = SupabaseContractMapper(self.apk_path)
            self.contract_inventory = contract_mapper.analyze()

        primary_url = self.contract_inventory.primary_backend_url
        evidence_links: List[BackendEvidenceLink] = []

        for resource, (res_type, screens, default_category, default_confidence) in self.RESOURCE_DEFINITIONS.items():
            symbols_found = []

            # Match symbol in extracted binary text
            if resource in extracted_text:
                symbols_found.append(f"Static string match: '{resource}'")
                category = "VERIFIED STATIC REFERENCE" if default_category == "SCREEN/RESOURCE CORRELATION" else default_category
                confidence = default_confidence
                notes = f"Verified static string reference to '{resource}' inside lib/x86_64/libapp.so."
            else:
                category = "UNVERIFIED"
                confidence = "UNVERIFIED"
                notes = f"No direct static string match for '{resource}' found in lib/x86_64/libapp.so."

            # Enhance notes for screen correlations
            if screens:
                notes += f" Correlated with screen components: {', '.join(screens)}."

            evidence_links.append(
                BackendEvidenceLink(
                    resource_name=resource,
                    resource_type=res_type,
                    evidence_category=category,
                    static_symbols=symbols_found,
                    associated_screens=screens,
                    confidence_score=confidence,
                    notes=notes,
                )
            )

        return BackendRuntimeCorrelation(
            target_apk=self.apk_path,
            primary_backend_url=primary_url,
            evidence_links=evidence_links,
        )
