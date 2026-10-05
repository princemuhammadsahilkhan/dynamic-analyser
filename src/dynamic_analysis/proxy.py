"""Controlled mitmproxy/mitmdump child process manager and network traffic collector for Android dynamic analysis."""

import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    _get_utc_timestamp,
)
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator


class ProxyError(AndroidRuntimeError):
    """Base exception for proxy layer errors."""

    pass


class ProxyStartupError(ProxyError):
    """Raised when the mitmdump proxy process fails to start."""

    pass


class ProxyShutdownError(ProxyError):
    """Raised when stopping the mitmdump proxy process fails."""

    pass


class ProxyConfigError(ProxyError):
    """Raised when setting or restoring emulator proxy fails."""

    pass


@dataclass(frozen=True)
class ProxyStatus:
    """Status summary of the proxy manager."""

    binary_path: str
    is_running: bool
    pid: Optional[int]
    host: Optional[str]
    port: Optional[int]
    flow_file: Optional[str]
    proxy_configured: bool = False

    def to_dict(self) -> Dict:
        """Convert status object to dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class TrafficObservation:
    """Structured representation of a single captured proxy flow/traffic observation."""

    timestamp: str
    scheme: str
    host: str
    port: int
    method: str
    url: str
    status_code: Optional[int] = None
    tls_established: bool = False
    error: Optional[str] = None
    raw_metadata: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict:
        """Convert traffic observation to dictionary."""
        return asdict(self)


class ProxyManager:
    """Child process manager for mitmdump with isolated lifecycle, flow logging, and guest proxy configuration."""

    DEFAULT_BINARY = "/usr/bin/mitmdump"

    def __init__(
        self,
        orchestrator: Optional[AndroidRuntimeOrchestrator] = None,
        binary_path: str = DEFAULT_BINARY,
    ) -> None:
        self.orchestrator = orchestrator
        self.binary_path = binary_path
        self._process: Optional[subprocess.Popen] = None
        self._port: Optional[int] = None
        self._host: Optional[str] = None
        self._flow_file: Optional[str] = None
        self._previous_proxy: Optional[str] = None
        self._proxy_configured: bool = False

    def is_running(self) -> bool:
        """Return True if the proxy process is active."""
        return self._process is not None and self._process.poll() is None

    @property
    def pid(self) -> Optional[int]:
        """Return process ID of running proxy child process."""
        return self._process.pid if self.is_running() and self._process else None

    def audit_mitmproxy(self) -> Tuple[bool, Optional[str]]:
        """Audit host system for mitmdump presence and version."""
        if not os.path.exists(self.binary_path):
            return False, None
        try:
            res = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10.0,
            )
            for line in res.stdout.splitlines():
                if "Mitmproxy:" in line:
                    version = line.split(":")[-1].strip()
                    return True, f"{self.binary_path} v{version}"
            return True, self.binary_path
        except Exception:
            return True, self.binary_path


    def start(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        flow_file: Optional[str] = None,
        quiet: bool = True,
    ) -> None:
        """Start mitmdump process cleanly as a Python-owned child process."""
        if self.is_running():
            raise ProxyStartupError("Proxy process is already running")

        available, _ = self.audit_mitmproxy()
        if not available:
            raise ProxyStartupError(f"mitmdump binary not found at {self.binary_path}")

        self._host = host
        self._port = port
        self._flow_file = flow_file

        cmd = [
            self.binary_path,
            "--listen-host",
            host,
            "--listen-port",
            str(port),
        ]
        if quiet:
            cmd.extend(["--flow-detail", "0"])
        if flow_file:
            cmd.extend(["-w", flow_file])

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            raise ProxyStartupError(f"Failed to spawn mitmdump process: {exc}") from exc

        time.sleep(0.3)
        returncode = self._process.poll()
        if returncode is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            self._process = None
            raise ProxyStartupError(
                f"mitmdump process exited immediately with code {returncode}: {stderr}"
            )


    def stop(self, timeout: float = 5.0) -> None:
        """Stop mitmdump child process cleanly without affecting unrelated host processes."""
        proc = self._process
        if proc is None:
            return

        try:
            proc.terminate()
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5.0)
        except Exception as exc:
            raise ProxyShutdownError(f"Failed to stop proxy process {proc.pid}: {exc}") from exc
        finally:
            self._process = None

    def configure_emulator_proxy(
        self, proxy_host: str = "10.0.2.2", proxy_port: Optional[int] = None
    ) -> str:
        """Configure http_proxy on target emulator via ADB."""
        if not self.orchestrator or not self.orchestrator.is_running():
            raise ProxyConfigError("Orchestrator must be running to configure emulator proxy")

        port = proxy_port or self._port or 8080
        target = f"{proxy_host}:{port}"

        # 1. Capture existing proxy setting
        res_get = self.orchestrator.shell("settings get global http_proxy")
        prev = res_get.stdout.strip() if res_get.exit_code == 0 else ""
        self._previous_proxy = prev if (prev and prev != "null") else None

        # 2. Set new proxy
        res_set = self.orchestrator.shell(f"settings put global http_proxy {target}")
        if res_set.exit_code != 0:
            raise ProxyConfigError(f"Failed to set http_proxy to {target}: {res_set.stderr}")

        self._proxy_configured = True
        return target

    def restore_emulator_proxy(self) -> None:
        """Restore previous http_proxy setting on target emulator via ADB."""
        if not self.orchestrator or not self.orchestrator.is_running() or not self._proxy_configured:
            return

        if self._previous_proxy:
            self.orchestrator.shell(f"settings put global http_proxy {self._previous_proxy}")
        else:
            res = self.orchestrator.shell("settings delete global http_proxy")
            if res.exit_code != 0:
                self.orchestrator.shell("settings put global http_proxy :0")

        self._proxy_configured = False

    def parse_flow_file(self, flow_file: Optional[str] = None) -> List[TrafficObservation]:
        """Read saved mitmproxy flow file and return structured TrafficObservation objects."""
        target_file = flow_file or self._flow_file
        if not target_file or not os.path.exists(target_file):
            return []

        observations: List[TrafficObservation] = []
        try:
            from mitmproxy import io as mitm_io
            with open(target_file, "rb") as f:
                reader = mitm_io.FlowReader(f)
                for flow in reader.stream():
                    if hasattr(flow, "request") and flow.request:
                        req = flow.request
                        resp = getattr(flow, "response", None)
                        err = getattr(flow, "error", None)
                        server_conn = getattr(flow, "server_conn", None)

                        tls_established = (
                            bool(getattr(server_conn, "tls_established", False))
                            if server_conn
                            else False
                        )
                        status_code = resp.status_code if resp else None
                        error_msg = err.msg if err else None

                        raw_metadata = {
                            "http_version": getattr(req, "http_version", ""),
                            "content_length": str(len(req.content)) if req.content else "0",
                        }
                        if resp and hasattr(resp, "headers"):
                            headers_dict = {}
                            try:
                                items = resp.headers.items(multi=True)
                            except TypeError:
                                items = resp.headers.items()
                            
                            for k, v in items:
                                kl = k.lower()
                                if kl in headers_dict:
                                    if isinstance(headers_dict[kl], list):
                                        headers_dict[kl].append(v)
                                    else:
                                        headers_dict[kl] = [headers_dict[kl], v]
                                else:
                                    headers_dict[kl] = v
                            raw_metadata["response_headers"] = headers_dict
                        
                        if tls_established and server_conn:
                            raw_metadata["tls_version"] = getattr(server_conn, "tls_version", None)
                            raw_metadata["cipher_suite"] = getattr(server_conn, "cipher", None)
                            raw_metadata["sni"] = getattr(server_conn, "sni", None)
                            alpn_val = getattr(server_conn, "alpn_proto_negotiated", getattr(server_conn, "alpn", None))
                            if isinstance(alpn_val, bytes):
                                alpn_val = alpn_val.decode("utf-8", errors="ignore")
                            raw_metadata["alpn"] = alpn_val

                        obs = TrafficObservation(
                            timestamp=_get_utc_timestamp(),
                            scheme=req.scheme,
                            host=req.host,
                            port=req.port,
                            method=req.method,
                            url=req.url,
                            status_code=status_code,
                            tls_established=tls_established,
                            error=error_msg,
                            raw_metadata=raw_metadata,
                        )
                        observations.append(obs)
        except Exception:
            pass

        return observations

    def get_status(self) -> ProxyStatus:
        """Return current ProxyStatus object."""
        return ProxyStatus(
            binary_path=self.binary_path,
            is_running=self.is_running(),
            pid=self.pid,
            host=self._host,
            port=self._port,
            flow_file=self._flow_file,
            proxy_configured=self._proxy_configured,
        )

    def get_evidence_items(self) -> List[EvidenceItem]:
        """Convert captured proxy status and flows into EvidenceItem objects."""
        serial = self.orchestrator.config.serial if self.orchestrator else "unknown"
        items: List[EvidenceItem] = []

        # 1. Proxy lifecycle evidence
        status = self.get_status()
        items.append(
            EvidenceItem(
                evidence_type=EvidenceType.PROXY_LIFECYCLE.value,
                timestamp=_get_utc_timestamp(),
                serial=serial,
                source="ProxyManager",
                content=json.dumps(status.to_dict()),
                exit_code=0,
            )
        )

        # 2. Parsed traffic flows evidence
        flows = self.parse_flow_file()
        for flow in flows:
            ev_type = (
                EvidenceType.HTTPS_TRAFFIC.value
                if flow.scheme.lower() == "https"
                else EvidenceType.HTTP_TRAFFIC.value
            )
            items.append(
                EvidenceItem(
                    evidence_type=ev_type,
                    timestamp=flow.timestamp,
                    serial=serial,
                    source=f"mitmdump {flow.scheme.upper()} {flow.method} {flow.host}:{flow.port}",
                    content=json.dumps(flow.to_dict()),
                    exit_code=0,
                )
            )

        return items
