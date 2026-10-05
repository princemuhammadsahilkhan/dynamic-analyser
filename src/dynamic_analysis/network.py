"""Controlled network observation foundation layer for Android dynamic analysis."""

import os
import subprocess
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    _get_utc_timestamp,
)
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator


class NetworkObservationError(AndroidRuntimeError):
    """Base exception for network observation layer errors."""

    pass


TARGET_NETWORK_PROPERTIES: Tuple[str, ...] = (
    "net.dns1",
    "net.dns2",
    "net.hostname",
    "net.gprs.local-ip",
    "gsm.network.type",
)


@dataclass(frozen=True)
class NetworkObservationSummary:
    """Summary of guest network observation collection and host proxy capability."""

    serial: str
    mitmproxy_available: bool
    mitmproxy_version: Optional[str]
    https_interception_active: bool = False
    tls_decryption_active: bool = False
    evidence_count: int = 0

    def to_dict(self) -> dict:
        """Convert summary object to dictionary."""
        return asdict(self)


class NetworkObserver:
    """Collector for Android guest network interfaces, routes, DNS, and connections."""

    def __init__(self, orchestrator: AndroidRuntimeOrchestrator) -> None:
        self.orchestrator = orchestrator

    def check_host_proxy_capability(self) -> Tuple[bool, Optional[str]]:
        """Audit host system for mitmproxy / mitmdump executable and version."""
        for binary in ("/usr/bin/mitmdump", "/usr/bin/mitmproxy"):
            if os.path.exists(binary):
                try:
                    res = subprocess.run(
                        [binary, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5.0,
                    )
                    for line in res.stdout.splitlines():
                        if "Mitmproxy:" in line:
                            version = line.split(":")[-1].strip()
                            return True, f"{binary} v{version}"
                    return True, binary
                except Exception:
                    return True, binary
        return False, None

    def collect_interfaces(self) -> EvidenceItem:
        """Collect guest network interface information via ip addr."""
        if not self.orchestrator.is_running():
            raise NetworkObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell("ip addr")
        return EvidenceItem(
            evidence_type=EvidenceType.NETWORK_INTERFACE.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="ip addr",
            content=res.stdout,
            exit_code=res.exit_code,
        )

    def collect_routes(self) -> EvidenceItem:
        """Collect guest routing table via ip route."""
        if not self.orchestrator.is_running():
            raise NetworkObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell("ip route")
        return EvidenceItem(
            evidence_type=EvidenceType.NETWORK_ROUTE.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="ip route",
            content=res.stdout,
            exit_code=res.exit_code,
        )

    def collect_dns_properties(
        self, properties: Tuple[str, ...] = TARGET_NETWORK_PROPERTIES
    ) -> List[EvidenceItem]:
        """Collect network and DNS system properties from guest OS."""
        if not self.orchestrator.is_running():
            raise NetworkObservationError("Emulator runtime is not running")

        items: List[EvidenceItem] = []
        serial = self.orchestrator.config.serial

        for prop_name in properties:
            res = self.orchestrator.shell(f"getprop {prop_name}")
            item = EvidenceItem(
                evidence_type=EvidenceType.NETWORK_DNS.value
                if "dns" in prop_name
                else EvidenceType.NETWORK_PROPERTIES.value,
                timestamp=_get_utc_timestamp(),
                serial=serial,
                source=f"getprop {prop_name}",
                content=res.stdout.strip(),
                exit_code=res.exit_code,
            )
            items.append(item)

        return items

    def collect_connections(self) -> EvidenceItem:
        """Collect active guest socket and network connections via netstat -an."""
        if not self.orchestrator.is_running():
            raise NetworkObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell("netstat -an")
        if res.exit_code != 0 or not res.stdout.strip():
            res = self.orchestrator.shell("ss -tupn")

        return EvidenceItem(
            evidence_type=EvidenceType.NETWORK_CONNECTIONS.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="netstat -an",
            content=res.stdout,
            exit_code=res.exit_code,
        )

    def collect_dumpsys_connectivity(self) -> EvidenceItem:
        """Collect connectivity manager state via dumpsys connectivity."""
        if not self.orchestrator.is_running():
            raise NetworkObservationError("Emulator runtime is not running")

        serial = self.orchestrator.config.serial
        res = self.orchestrator.shell("dumpsys connectivity")
        return EvidenceItem(
            evidence_type=EvidenceType.NETWORK_DUMPSYS.value,
            timestamp=_get_utc_timestamp(),
            serial=serial,
            source="dumpsys connectivity",
            content=res.stdout,
            exit_code=res.exit_code,
        )

    def collect_all_network_evidence(self) -> List[EvidenceItem]:
        """Collect comprehensive network observation evidence set."""
        evidence: List[EvidenceItem] = []
        evidence.append(self.collect_interfaces())
        evidence.append(self.collect_routes())
        evidence.extend(self.collect_dns_properties())
        evidence.append(self.collect_connections())
        evidence.append(self.collect_dumpsys_connectivity())
        return evidence
