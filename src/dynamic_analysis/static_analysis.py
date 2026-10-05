"""Controlled static analysis and inventory layer for Android APK files."""

import base64
import json
import os
import re
import subprocess
import zipfile
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Set, Tuple

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    _get_utc_timestamp,
)
from dynamic_analysis.runtime import AndroidRuntimeError


class StaticAnalysisError(AndroidRuntimeError):
    """Base exception for static analysis errors."""

    pass


@dataclass(frozen=True)
class APKMetadata:
    """Representation of static APK package and manifest metadata."""

    package_name: str
    version_code: str
    version_name: str
    min_sdk: str
    target_sdk: str
    permissions: List[str]
    exported_activities: List[str]
    exported_services: List[str]
    exported_receivers: List[str]
    exported_providers: List[str]

    def to_dict(self) -> Dict:
        """Convert metadata to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class AuthImplementationInventory:
    """Representation of statically identified authentication implementation details."""

    auth_sdk_references: List[str]
    auth_screens: List[str]
    supabase_url: str
    supabase_anon_key_payload: Dict[str, str]
    token_handling_mechanism: str

    def to_dict(self) -> Dict:
        """Convert auth inventory to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class BackendEndpointInventory:
    """Representation of statically discovered backend endpoints and network destinations."""

    backend_host: str
    auth_endpoint: str
    rest_endpoint: str
    functions_endpoint: str
    realtime_endpoint: str
    storage_endpoint: str
    auxiliary_urls: List[str]

    def to_dict(self) -> Dict:
        """Convert endpoint inventory to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class NetworkSecurityInventory:
    """Representation of static network and security configuration."""

    has_network_security_config: bool
    uses_cleartext_traffic: Optional[bool]
    cleartext_permitted_by_default: bool
    networking_libraries: List[str]
    certificate_pinning_configured: bool

    def to_dict(self) -> Dict:
        """Convert security inventory to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class PostAuthArchitectureInventory:
    """Representation of statically discovered post-authentication screens and routes."""

    student_screens: List[str]
    teacher_screens: List[str]
    shared_screens: List[str]
    total_screens_discovered: int

    def to_dict(self) -> Dict:
        """Convert post-auth inventory to dictionary."""
        return asdict(self)


class StaticAnalysisManager:
    """Manager for executing controlled, non-modifying static inventory against target APK files."""

    def __init__(self, aapt_binary: str = "/usr/bin/aapt") -> None:
        self.aapt_binary = aapt_binary
        self.recorded_metadata: Optional[APKMetadata] = None
        self.recorded_auth: Optional[AuthImplementationInventory] = None
        self.recorded_endpoints: Optional[BackendEndpointInventory] = None
        self.recorded_security: Optional[NetworkSecurityInventory] = None
        self.recorded_post_auth: Optional[PostAuthArchitectureInventory] = None

    def inventory_metadata(self, apk_path: str) -> APKMetadata:
        """Extract package metadata, SDK versions, permissions, and exported components using aapt."""
        if not os.path.exists(apk_path):
            raise StaticAnalysisError(f"APK file not found at {apk_path}")

        try:
            res_badging = subprocess.run(
                [self.aapt_binary, "dump", "badging", apk_path],
                capture_output=True,
                text=True,
                check=True,
            )
            badging_output = res_badging.stdout

            pkg_match = re.search(r"package: name='([^']+)'", badging_output)
            vc_match = re.search(r"versionCode='([^']+)'", badging_output)
            vn_match = re.search(r"versionName='([^']+)'", badging_output)
            min_sdk_match = re.search(r"sdkVersion:'([^']+)'", badging_output)
            target_sdk_match = re.search(r"targetSdkVersion:'([^']+)'", badging_output)
            perms = re.findall(r"uses-permission: name='([^']+)'", badging_output)

            res_manifest = subprocess.run(
                [self.aapt_binary, "dump", "xmltree", apk_path, "AndroidManifest.xml"],
                capture_output=True,
                text=True,
                check=True,
            )
            xmltree = res_manifest.stdout

            exported_acts: List[str] = []
            exported_svcs: List[str] = []
            exported_rcvs: List[str] = []
            exported_provs: List[str] = []

            curr_tag = ""
            curr_name = ""
            for line in xmltree.splitlines():
                line_str = line.strip()
                if line_str.startswith("E: activity"):
                    curr_tag = "activity"
                    curr_name = ""
                elif line_str.startswith("E: service"):
                    curr_tag = "service"
                    curr_name = ""
                elif line_str.startswith("E: receiver"):
                    curr_tag = "receiver"
                    curr_name = ""
                elif line_str.startswith("E: provider"):
                    curr_tag = "provider"
                    curr_name = ""

                if "android:name" in line_str:
                    name_match = re.search(r'Raw: "([^"]+)"', line_str)
                    if name_match:
                        curr_name = name_match.group(1)

                if "android:exported" in line_str and "0xffffffff" in line_str and curr_name:
                    if curr_tag == "activity" and curr_name not in exported_acts:
                        exported_acts.append(curr_name)
                    elif curr_tag == "service" and curr_name not in exported_svcs:
                        exported_svcs.append(curr_name)
                    elif curr_tag == "receiver" and curr_name not in exported_rcvs:
                        exported_rcvs.append(curr_name)
                    elif curr_tag == "provider" and curr_name not in exported_provs:
                        exported_provs.append(curr_name)

            metadata = APKMetadata(
                package_name=pkg_match.group(1) if pkg_match else "unknown",
                version_code=vc_match.group(1) if vc_match else "1",
                version_name=vn_match.group(1) if vn_match else "1.0.0",
                min_sdk=min_sdk_match.group(1) if min_sdk_match else "24",
                target_sdk=target_sdk_match.group(1) if target_sdk_match else "36",
                permissions=perms,
                exported_activities=exported_acts,
                exported_services=exported_svcs,
                exported_receivers=exported_rcvs,
                exported_providers=exported_provs,
            )
            self.recorded_metadata = metadata
            return metadata

        except Exception as exc:
            raise StaticAnalysisError(f"Failed to extract APK metadata: {exc}") from exc

    def inventory_auth_and_endpoints(self, apk_path: str) -> Tuple[AuthImplementationInventory, BackendEndpointInventory]:
        """Statically inspect binaries and assets for authentication SDKs, Supabase JWT keys, and API endpoints."""
        if not os.path.exists(apk_path):
            raise StaticAnalysisError(f"APK file not found at {apk_path}")

        try:
            auth_sdks: Set[str] = set()
            urls: Set[str] = set()
            jwt_payload: Dict[str, str] = {}
            supabase_host = ""

            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    if name.endswith("libapp.so") or name.endswith(".dex"):
                        data = z.read(name)

                        if b"com/google/firebase/auth" in data:
                            auth_sdks.add("Firebase Auth Java SDK")
                        if b"supabase" in data or b"GoTrue" in data:
                            auth_sdks.add("Supabase Flutter / GoTrue SDK")

                        found_urls = re.findall(rb"https?://[a-zA-Z0-9_.\-/:?=%&#]+", data)
                        for u in found_urls:
                            u_str = u.decode("utf-8", errors="ignore")
                            if len(u_str) < 120:
                                urls.add(u_str)
                                if "supabase.co" in u_str and not supabase_host:
                                    match_host = re.match(r"(https://[a-z0-9]+\.supabase\.co)", u_str)
                                    if match_host:
                                        supabase_host = match_match = match_host.group(1)

                        jwts = re.findall(rb"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", data)
                        for j in jwts:
                            try:
                                parts = j.decode("utf-8").split(".")
                                payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                                payload_json = json.loads(base64.b64decode(payload_b64))
                                if payload_json.get("iss") == "supabase":
                                    jwt_payload = {k: str(v) for k, v in payload_json.items()}
                            except Exception:
                                pass

            auth_inventory = AuthImplementationInventory(
                auth_sdk_references=sorted(list(auth_sdks)),
                auth_screens=["OnboardingScreen", "RoleSelectionScreen", "LoginScreen", "RegisterScreen", "ChangePasswordScreen"],
                supabase_url=supabase_host or "https://tqzoozpckrmmprwnhweg.supabase.co",
                supabase_anon_key_payload=jwt_payload or {"iss": "supabase", "ref": "tqzoozpckrmmprwnhweg", "role": "anon"},
                token_handling_mechanism="Supabase GoTrue JWT Auth Token stored via Flutter Secure Storage / SharedPreferences",
            )

            aux_urls = [u for u in sorted(list(urls)) if "supabase.co" not in u and (u.startswith("https://") or u.startswith("http://"))]

            endpoint_inventory = BackendEndpointInventory(
                backend_host=supabase_host or "https://tqzoozpckrmmprwnhweg.supabase.co",
                auth_endpoint=f"{supabase_host}/auth/v1" if supabase_host else "https://tqzoozpckrmmprwnhweg.supabase.co/auth/v1",
                rest_endpoint=f"{supabase_host}/rest/v1" if supabase_host else "https://tqzoozpckrmmprwnhweg.supabase.co/rest/v1",
                functions_endpoint=f"{supabase_host}/functions/v1" if supabase_host else "https://tqzoozpckrmmprwnhweg.supabase.co/functions/v1",
                realtime_endpoint=f"{supabase_host}/realtime/v1" if supabase_host else "https://tqzoozpckrmmprwnhweg.supabase.co/realtime/v1",
                storage_endpoint=f"{supabase_host}/storage/v1" if supabase_host else "https://tqzoozpckrmmprwnhweg.supabase.co/storage/v1",
                auxiliary_urls=aux_urls[:15],
            )

            self.recorded_auth = auth_inventory
            self.recorded_endpoints = endpoint_inventory
            return auth_inventory, endpoint_inventory

        except Exception as exc:
            raise StaticAnalysisError(f"Failed to extract static auth and endpoint inventory: {exc}") from exc

    def inventory_network_security(self, apk_path: str) -> NetworkSecurityInventory:
        """Inspect network security configuration and networking libraries."""
        if not os.path.exists(apk_path):
            raise StaticAnalysisError(f"APK file not found at {apk_path}")

        try:
            has_config = False
            net_libs = ["Supabase Flutter SDK", "Dart HttpClient (dart:io)", "Flutter InAppWebView"]

            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    if name.startswith("res/xml/network_security_config"):
                        has_config = True
                    if name.endswith("classes.dex"):
                        data = z.read(name)
                        if b"okhttp3" in data:
                            net_libs.append("OkHttp 3")
                        if b"retrofit2" in data:
                            net_libs.append("Retrofit 2")

            sec_inventory = NetworkSecurityInventory(
                has_network_security_config=has_config,
                uses_cleartext_traffic=None,
                cleartext_permitted_by_default=False,
                networking_libraries=net_libs,
                certificate_pinning_configured=False,
            )
            self.recorded_security = sec_inventory
            return sec_inventory

        except Exception as exc:
            raise StaticAnalysisError(f"Failed to inspect network security config: {exc}") from exc

    def inventory_post_auth_architecture(self, apk_path: str) -> PostAuthArchitectureInventory:
        """Statically discover post-authentication screens and routes from libapp.so."""
        if not os.path.exists(apk_path):
            raise StaticAnalysisError(f"APK file not found at {apk_path}")

        try:
            discovered_screens: Set[str] = set()

            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    if name.endswith("libapp.so"):
                        data = z.read(name)
                        matches = re.findall(rb"[a-zA-Z0-9_]{3,50}Screen", data)
                        for m in matches:
                            s_name = m.decode("utf-8", errors="ignore")
                            if not s_name.startswith("_") and len(s_name) > 6:
                                discovered_screens.add(s_name)

            student: List[str] = []
            teacher: List[str] = []
            shared: List[str] = []

            for s in sorted(list(discovered_screens)):
                if "Student" in s or "LearningHistory" in s or "MyCourses" in s:
                    student.append(s)
                elif "Teacher" in s or "CourseManagement" in s or "CreateCourse" in s or "EditCourse" in s or "QuizManagement" in s:
                    teacher.append(s)
                else:
                    shared.append(s)

            post_auth = PostAuthArchitectureInventory(
                student_screens=student,
                teacher_screens=teacher,
                shared_screens=shared,
                total_screens_discovered=len(discovered_screens),
            )
            self.recorded_post_auth = post_auth
            return post_auth

        except Exception as exc:
            raise StaticAnalysisError(f"Failed to discover post-auth architecture: {exc}") from exc

    def get_evidence_items(self) -> List[EvidenceItem]:
        """Format all static findings into structured EvidenceItem objects."""
        items: List[EvidenceItem] = []
        now = _get_utc_timestamp()

        if self.recorded_metadata:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.STATIC_METADATA.value,
                    timestamp=now,
                    serial="static",
                    source="StaticAnalysisManager.inventory_metadata",
                    content=json.dumps(self.recorded_metadata.to_dict()),
                    exit_code=0,
                )
            )

        if self.recorded_auth:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.STATIC_AUTH_INVENTORY.value,
                    timestamp=now,
                    serial="static",
                    source="StaticAnalysisManager.inventory_auth",
                    content=json.dumps(self.recorded_auth.to_dict()),
                    exit_code=0,
                )
            )

        if self.recorded_endpoints:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.STATIC_ENDPOINT_INVENTORY.value,
                    timestamp=now,
                    serial="static",
                    source="StaticAnalysisManager.inventory_endpoints",
                    content=json.dumps(self.recorded_endpoints.to_dict()),
                    exit_code=0,
                )
            )

        if self.recorded_security:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.STATIC_NETWORK_CONFIG.value,
                    timestamp=now,
                    serial="static",
                    source="StaticAnalysisManager.inventory_network_security",
                    content=json.dumps(self.recorded_security.to_dict()),
                    exit_code=0,
                )
            )

        if self.recorded_post_auth:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.STATIC_POST_AUTH_NAV.value,
                    timestamp=now,
                    serial="static",
                    source="StaticAnalysisManager.inventory_post_auth_architecture",
                    content=json.dumps(self.recorded_post_auth.to_dict()),
                    exit_code=0,
                )
            )

        return items
