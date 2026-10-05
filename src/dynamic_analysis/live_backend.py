"""Live Supabase backend observation and evidence collection layer."""

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from dynamic_analysis.backend_contract import BackendContractInventory
from dynamic_analysis.observation import EvidenceItem, EvidenceType


@dataclass
class RedactedTrafficFlow:
    """Represents a sanitized, redacted network traffic flow."""

    method: str
    url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    resource_category: str  # 'rest', 'storage', 'realtime', 'auth', 'other'
    matched_table_or_bucket: Optional[str] = None
    redacted_body_snippet: Optional[str] = None


@dataclass
class LiveBackendObservationResult:
    """Structured result of live backend observation and credential boundary auditing."""

    authentication_status: str  # 'AUTHENTICATED_SESSION', 'AUTHENTICATION_REQUIRED', 'LIVE_BACKEND_BLOCKED'
    credentials_available: bool
    total_flows_observed: int
    supabase_flows_observed: int
    rest_flows: List[RedactedTrafficFlow] = field(default_factory=list)
    storage_flows: List[RedactedTrafficFlow] = field(default_factory=list)
    realtime_flows: List[RedactedTrafficFlow] = field(default_factory=list)
    auth_flows: List[RedactedTrafficFlow] = field(default_factory=list)
    blocker_reason: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert observation result to dictionary representation."""
        return {
            "authentication_status": self.authentication_status,
            "credentials_available": self.credentials_available,
            "total_flows_observed": self.total_flows_observed,
            "supabase_flows_observed": self.supabase_flows_observed,
            "rest_flows": [asdict(f) for f in self.rest_flows],
            "storage_flows": [asdict(s) for s in self.storage_flows],
            "realtime_flows": [asdict(r) for r in self.realtime_flows],
            "auth_flows": [asdict(a) for a in self.auth_flows],
            "blocker_reason": self.blocker_reason,
        }


class LiveBackendObserver:
    """Observer for controlled live Supabase backend interactions and traffic sanitization."""

    SENSITIVE_HEADER_KEYS = {
        "authorization",
        "apikey",
        "api-key",
        "x-supabase-auth",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    }

    SUPABASE_DOMAIN = "supabase.co"

    def __init__(
        self,
        backend_contract: Optional[BackendContractInventory] = None,
        credentials: Optional[Dict[str, str]] = None,
    ):
        self.backend_contract = backend_contract
        self.credentials = credentials or {}

    def redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive authorization tokens, API keys, and cookie headers."""
        redacted = {}
        for key, value in headers.items():
            if key.lower() in self.SENSITIVE_HEADER_KEYS:
                redacted[key] = "[REDACTED_SENSITIVE_HEADER]"
            else:
                redacted[key] = value
        return redacted

    def redact_content(self, content: str) -> str:
        """Redact sensitive token strings, passwords, and secret keys in body text."""
        if not content:
            return ""
        # Redact JWT tokens (eyJ...)
        content = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT_TOKEN]", content)
        # Redact password fields
        content = re.sub(r'("password"\s*:\s*")[^"]+(")', r'\1[REDACTED_PASSWORD]\2', content)
        # Redact refresh_token fields
        content = re.sub(r'("refresh_token"\s*:\s*")[^"]+(")', r'\1[REDACTED_REFRESH_TOKEN]\2', content)
        # Redact access_token fields
        content = re.sub(r'("access_token"\s*:\s*")[^"]+(")', r'\1[REDACTED_ACCESS_TOKEN]\2', content)
        return content

    def observe_backend_traffic(self, captured_flows: List[Dict]) -> LiveBackendObservationResult:
        """Process captured traffic flows safely and evaluate authentication boundary."""
        if not self.credentials:
            blocker_msg = (
                "No authorized test credentials or persistent authenticated session provided. "
                "Live backend interaction stopped safely to prevent unauthorized requests or invalid authentication attempts."
            )
            return LiveBackendObservationResult(
                authentication_status="LIVE_BACKEND_BLOCKED",
                credentials_available=False,
                total_flows_observed=len(captured_flows),
                supabase_flows_observed=0,
                blocker_reason=blocker_msg,
            )

        # Process captured flows if credentials / session exist
        rest_flows: List[RedactedTrafficFlow] = []
        storage_flows: List[RedactedTrafficFlow] = []
        realtime_flows: List[RedactedTrafficFlow] = []
        auth_flows: List[RedactedTrafficFlow] = []
        supabase_count = 0

        for flow in captured_flows:
            url = flow.get("url", "")
            if self.SUPABASE_DOMAIN not in url:
                continue

            supabase_count += 1
            method = flow.get("method", "GET")
            status_code = flow.get("status_code")
            raw_headers = flow.get("headers", {})
            raw_body = flow.get("body", "")

            sanitized_headers = self.redact_headers(raw_headers)
            sanitized_body = self.redact_content(raw_body)

            # Categorize flow
            category = "other"
            matched_resource = None

            if "/rest/v1/" in url:
                category = "rest"
                # Match table name
                match = re.search(r"/rest/v1/([a-zA-Z0-9_-]+)", url)
                if match:
                    matched_resource = match.group(1)
                redacted_flow = RedactedTrafficFlow(
                    method=method,
                    url=url,
                    status_code=status_code,
                    headers=sanitized_headers,
                    resource_category=category,
                    matched_table_or_bucket=matched_resource,
                    redacted_body_snippet=sanitized_body[:200] if sanitized_body else None,
                )
                rest_flows.append(redacted_flow)

            elif "/storage/v1/" in url:
                category = "storage"
                match = re.search(r"/storage/v1/object/(?:public/)?([a-zA-Z0-9_-]+)", url)
                if match:
                    matched_resource = match.group(1)
                redacted_flow = RedactedTrafficFlow(
                    method=method,
                    url=url,
                    status_code=status_code,
                    headers=sanitized_headers,
                    resource_category=category,
                    matched_table_or_bucket=matched_resource,
                    redacted_body_snippet=sanitized_body[:200] if sanitized_body else None,
                )
                storage_flows.append(redacted_flow)

            elif "/realtime/v1" in url or "websocket" in url.lower():
                category = "realtime"
                redacted_flow = RedactedTrafficFlow(
                    method=method,
                    url=url,
                    status_code=status_code,
                    headers=sanitized_headers,
                    resource_category=category,
                    redacted_body_snippet=sanitized_body[:200] if sanitized_body else None,
                )
                realtime_flows.append(redacted_flow)

            elif "/auth/v1/" in url:
                category = "auth"
                redacted_flow = RedactedTrafficFlow(
                    method=method,
                    url=url,
                    status_code=status_code,
                    headers=sanitized_headers,
                    resource_category=category,
                    redacted_body_snippet=sanitized_body[:200] if sanitized_body else None,
                )
                auth_flows.append(redacted_flow)

        return LiveBackendObservationResult(
            authentication_status="AUTHENTICATED_SESSION",
            credentials_available=True,
            total_flows_observed=len(captured_flows),
            supabase_flows_observed=supabase_count,
            rest_flows=rest_flows,
            storage_flows=storage_flows,
            realtime_flows=realtime_flows,
            auth_flows=auth_flows,
        )

    def to_evidence_items(self, result: LiveBackendObservationResult, serial: str = "N/A") -> List[EvidenceItem]:
        """Convert observation result into structured EvidenceItem list."""
        now = datetime.now(timezone.utc).isoformat()
        items = []

        if result.authentication_status == "LIVE_BACKEND_BLOCKED":
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.LIVE_BACKEND_BLOCKED.value,
                    timestamp=now,
                    serial=serial,
                    source="LiveBackendObserver",
                    content=json.dumps(result.to_dict(), indent=2),
                    metadata={
                        "authentication_status": result.authentication_status,
                        "credentials_available": str(result.credentials_available),
                        "blocker_reason": result.blocker_reason or "",
                    },
                )
            )
            return items

        # General Observation Evidence
        items.append(
            EvidenceItem(
                evidence_type=EvidenceType.LIVE_BACKEND_OBSERVATION.value,
                timestamp=now,
                serial=serial,
                source="LiveBackendObserver",
                content=json.dumps(result.to_dict(), indent=2),
                metadata={
                    "authentication_status": result.authentication_status,
                    "supabase_flows_observed": str(result.supabase_flows_observed),
                },
            )
        )

        # REST Flows Evidence
        for flow in result.rest_flows:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.LIVE_REST_TRAFFIC.value,
                    timestamp=now,
                    serial=serial,
                    source="LiveBackendObserver",
                    content=json.dumps(asdict(flow), indent=2),
                    metadata={"url": flow.url, "table": flow.matched_table_or_bucket or ""},
                )
            )

        # Storage Flows Evidence
        for flow in result.storage_flows:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.LIVE_STORAGE_TRAFFIC.value,
                    timestamp=now,
                    serial=serial,
                    source="LiveBackendObserver",
                    content=json.dumps(asdict(flow), indent=2),
                    metadata={"url": flow.url, "bucket": flow.matched_table_or_bucket or ""},
                )
            )

        # Realtime Flows Evidence
        for flow in result.realtime_flows:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.LIVE_REALTIME_TRAFFIC.value,
                    timestamp=now,
                    serial=serial,
                    source="LiveBackendObserver",
                    content=json.dumps(asdict(flow), indent=2),
                    metadata={"url": flow.url},
                )
            )

        return items
