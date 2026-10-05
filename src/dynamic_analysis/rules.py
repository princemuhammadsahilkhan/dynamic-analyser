"""Rule Engine for evaluating evidence and generating findings."""

import abc
import json
import re
import urllib.parse
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from dynamic_analysis.finding import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
)
from dynamic_analysis.observation import EvidenceItem, EvidenceType, _get_utc_timestamp
from dynamic_analysis.session import AnalysisSession


class RuleError(Exception):
    """Base exception for rule evaluation errors."""


class RuleValidationError(RuleError):
    """Exception for invalid rule configuration or state."""


@dataclass
class RuleResult:
    """The result of evaluating a single rule against a collection of evidence."""

    rule_id: str
    triggered: bool
    findings: List[Finding] = field(default_factory=list)
    evidence_references: List[str] = field(default_factory=list)
    evaluation_details: Dict[str, Any] = field(default_factory=dict)
    evaluated_at: str = field(default_factory=_get_utc_timestamp)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule result to a JSON-safe dictionary."""
        return {
            "rule_id": self.rule_id,
            "triggered": self.triggered,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_references": self.evidence_references,
            "evaluation_details": self.evaluation_details,
            "evaluated_at": self.evaluated_at,
        }

    def to_json(self) -> str:
        """Serialize the rule result to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class Rule(abc.ABC):
    """Abstract base class for all detection rules."""

    @property
    @abc.abstractmethod
    def rule_id(self) -> str:
        """A stable, unique identifier for the rule (e.g., 'RULE-001')."""
        pass

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """A human-readable name for the rule."""
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """A detailed description of what the rule detects."""
        pass

    @property
    @abc.abstractmethod
    def category(self) -> FindingCategory:
        """The primary finding category associated with this rule."""
        pass

    @abc.abstractmethod
    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        """
        Evaluate this rule against the collected evidence.

        Args:
            session: The active analysis session context.
            evidence_items: The complete list of collected evidence.

        Returns:
            A RuleResult indicating whether the rule triggered, any generated
            findings, and the specific evidence references supporting the result.
        """
        pass


class TargetProcessObservedRule(Rule):
    """Rule verifying whether the target package process was observed executing."""

    @property
    def rule_id(self) -> str:
        return "RULE-001"

    @property
    def name(self) -> str:
        return "Target Process Observed"

    @property
    def description(self) -> str:
        return "The target package was observed executing in the guest OS."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.MISC

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        target = session.package_name or "com.example.mentorcraft2"
        
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.PROCESS_LIST.value:
                if target in ev.content:
                    ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title="Target Package Process Detected",
                        description=self.description,
                        severity=FindingSeverity.INFO,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.CERTAIN,
                        evidence_references=[ev_ref],
                    )
                    return RuleResult(
                        rule_id=self.rule_id,
                        triggered=True,
                        findings=[finding],
                        evidence_references=[ev_ref],
                        evaluation_details={"target_package": target},
                    )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "Target process not found in PROCESS_LIST evidence."},
        )


class ProxyConfiguredRule(Rule):
    """Rule verifying whether an active network proxy observation occurred."""

    @property
    def rule_id(self) -> str:
        return "RULE-002"

    @property
    def name(self) -> str:
        return "Network Proxy Configured"

    @property
    def description(self) -> str:
        return "A network proxy was observed configured and running for interception."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        # PROXY_LIFECYCLE evidence indicates the proxy was configured/started
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.PROXY_LIFECYCLE.value:
                ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                finding = Finding(
                    analysis_id=session.analysis_id,
                    title="Network Proxy Configured",
                    description=self.description,
                    severity=FindingSeverity.INFO,
                    category=self.category,
                    status=FindingStatus.VALIDATED,
                    confidence=FindingConfidence.CERTAIN,
                    evidence_references=[ev_ref],
                )
                return RuleResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    findings=[finding],
                    evidence_references=[ev_ref],
                    evaluation_details={"evidence_type": ev.evidence_type},
                )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No proxy-related evidence found."},
        )


class CleartextTrafficRule(Rule):
    """Rule verifying whether the application transmitted data over unencrypted HTTP."""

    @property
    def rule_id(self) -> str:
        return "RULE-003"

    @property
    def name(self) -> str:
        return "Cleartext HTTP Traffic Observed"

    @property
    def description(self) -> str:
        return "The application transmitted data over unencrypted HTTP, exposing it to interception."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        evidence_references = []
        cleartext_hosts = []
        
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.HTTP_TRAFFIC.value:
                try:
                    flow = json.loads(ev.content)
                    host = flow.get("host", "")
                    
                    if host and host not in ["localhost", "127.0.0.1", "::1"]:
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        if ev_ref not in evidence_references:
                            evidence_references.append(ev_ref)
                        if host not in cleartext_hosts:
                            cleartext_hosts.append(host)
                except Exception:
                    continue
        
        if evidence_references:
            finding = Finding(
                analysis_id=session.analysis_id,
                title=self.name,
                description=self.description,
                severity=FindingSeverity.HIGH,
                category=self.category,
                status=FindingStatus.VALIDATED,
                confidence=FindingConfidence.CERTAIN,
                evidence_references=evidence_references,
            )
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=[finding],
                evidence_references=evidence_references,
                evaluation_details={"cleartext_hosts": cleartext_hosts},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No external cleartext HTTP traffic evidence found."},
        )


class WeakTLSRule(Rule):
    """Rule verifying whether the application communicated using a deprecated and insecure version of TLS."""

    @property
    def rule_id(self) -> str:
        return "RULE-004"

    @property
    def name(self) -> str:
        return "Weak TLS Version Observed"

    @property
    def description(self) -> str:
        return "The application communicated using a deprecated and insecure version of TLS (e.g., TLS 1.0 or TLS 1.1), which is vulnerable to cryptographic attacks."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        evidence_references = []
        
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value:
                try:
                    flow = json.loads(ev.content)
                    raw_metadata = flow.get("raw_metadata", {})
                    tls_version = raw_metadata.get("tls_version", "").upper()
                    
                    if tls_version and ("TLSV1.0" in tls_version or "TLSV1.1" in tls_version or tls_version in ("TLS 1.0", "TLS 1.1")):
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        if ev_ref not in evidence_references:
                            evidence_references.append(ev_ref)
                except Exception:
                    continue
        
        if evidence_references:
            finding = Finding(
                analysis_id=session.analysis_id,
                title=self.name,
                description=self.description,
                severity=FindingSeverity.HIGH,
                category=self.category,
                status=FindingStatus.VALIDATED,
                confidence=FindingConfidence.CERTAIN,
                evidence_references=evidence_references,
            )
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=[finding],
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No weak TLS version evidence found or metadata missing."},
        )

class WeakTLSCipherRule(Rule):
    """Rule verifying whether the application communicated using a weak TLS cipher suite."""

    @property
    def rule_id(self) -> str:
        return "RULE-005"

    @property
    def name(self) -> str:
        return "Weak TLS Cipher Suite Observed"

    @property
    def description(self) -> str:
        return "The application communicated using a weak or deprecated TLS cipher suite (e.g., NULL, RC4, DES), which is vulnerable to cryptographic attacks."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        evidence_references = []
        evaluation_details = {}
        
        weak_patterns = ["NULL", "ANULL", "EXPORT", "RC4", "DES", "3DES"]
        
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value:
                try:
                    flow = json.loads(ev.content)
                    raw_metadata = flow.get("raw_metadata", {})
                    cipher_suite = raw_metadata.get("cipher_suite")
                    
                    if not cipher_suite:
                        evaluation_details["reason"] = "Missing cipher_suite metadata"
                        continue
                        
                    cipher_upper = cipher_suite.upper()
                    
                    is_weak = False
                    for pattern in weak_patterns:
                        if pattern == "DES" and "3DES" in cipher_upper:
                            continue
                        if pattern in cipher_upper:
                            is_weak = True
                            break
                            
                    if is_weak:
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        if ev_ref not in evidence_references:
                            evidence_references.append(ev_ref)
                except Exception as e:
                    continue
        
        if evidence_references:
            finding = Finding(
                analysis_id=session.analysis_id,
                title=self.name,
                description=self.description,
                severity=FindingSeverity.HIGH,
                category=self.category,
                status=FindingStatus.VALIDATED,
                confidence=FindingConfidence.CERTAIN,
                evidence_references=evidence_references,
            )
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=[finding],
                evidence_references=evidence_references,
                evaluation_details={},
            )
            
        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details=evaluation_details,
        )


class MissingHSTSRule(Rule):
    """Rule verifying whether the application server enforces Strict-Transport-Security (HSTS)."""

    @property
    def rule_id(self) -> str:
        return "RULE-006"

    @property
    def name(self) -> str:
        return "Missing Strict-Transport-Security Header Observed"

    @property
    def description(self) -> str:
        return "The application communicated over HTTPS with a server that did not provide a Strict-Transport-Security (HSTS) header, leaving connections vulnerable to downgrade attacks."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        evidence_references = []
        evaluation_details = {}
        
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value:
                try:
                    flow = json.loads(ev.content)
                    raw_metadata = flow.get("raw_metadata", {})
                    
                    if "response_headers" not in raw_metadata:
                        evaluation_details["reason"] = "Missing response_headers metadata"
                        continue
                        
                    response_headers = raw_metadata["response_headers"]
                    if "strict-transport-security" not in response_headers:
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        if ev_ref not in evidence_references:
                            evidence_references.append(ev_ref)
                except Exception:
                    continue
        
        if evidence_references:
            finding = Finding(
                analysis_id=session.analysis_id,
                title=self.name,
                description=self.description,
                severity=FindingSeverity.MEDIUM,
                category=self.category,
                status=FindingStatus.VALIDATED,
                confidence=FindingConfidence.CERTAIN,
                evidence_references=evidence_references,
            )
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=[finding],
                evidence_references=evidence_references,
                evaluation_details={},
            )
            
        if not evaluation_details:
            evaluation_details = {"reason": "No missing HSTS evidence found or metadata missing."}
            
        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details=evaluation_details,
        )


class MissingXCTORule(Rule):
    """Rule verifying whether the application server explicitly enforces X-Content-Type-Options."""

    @property
    def rule_id(self) -> str:
        return "RULE-007"

    @property
    def name(self) -> str:
        return "Missing X-Content-Type-Options Header Observed"

    @property
    def description(self) -> str:
        return "The HTTPS response is missing the X-Content-Type-Options header, exposing it to MIME-sniffing attacks."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        evidence_references = []
        evaluation_details = {}
        
        for ev in evidence_items:
            if ev.evidence_type == EvidenceType.HTTPS_TRAFFIC.value:
                try:
                    flow = json.loads(ev.content)
                    raw_metadata = flow.get("raw_metadata")
                    if not isinstance(raw_metadata, dict):
                        continue
                        
                    if "response_headers" not in raw_metadata:
                        continue
                        
                    headers = raw_metadata.get("response_headers")
                    if not isinstance(headers, dict):
                        continue
                        
                    # Evaluate presence of the header (case-insensitive keys)
                    xcto_present = False
                    for key in headers.keys():
                        if key.lower() == "x-content-type-options":
                            xcto_present = True
                            break
                            
                    if not xcto_present:
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        if ev_ref not in evidence_references:
                            evidence_references.append(ev_ref)
                except Exception:
                    continue
        
        if evidence_references:
            finding = Finding(
                analysis_id=session.analysis_id,
                title=self.name,
                description=self.description,
                severity=FindingSeverity.MEDIUM,
                category=self.category,
                status=FindingStatus.VALIDATED,
                confidence=FindingConfidence.CERTAIN,
                evidence_references=evidence_references,
            )
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=[finding],
                evidence_references=evidence_references,
                evaluation_details={},
            )
            
        if not evaluation_details:
            evaluation_details = {"reason": "No missing X-Content-Type-Options evidence found or metadata missing."}
            
        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details=evaluation_details,
        )
class Rule008InsecureCookieAttributeRule(Rule):
    """Rule verifying that Set-Cookie headers contain necessary security attributes."""

    @property
    def rule_id(self) -> str:
        return "RULE-008"

    @property
    def name(self) -> str:
        return "Insecure Cookie Attribute Observed"

    @property
    def description(self) -> str:
        return "The application received a Set-Cookie header missing essential security attributes (Secure, HttpOnly, SameSite)."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        evidence_references_missing_secure = []
        evidence_references_missing_httponly = []
        evidence_references_missing_samesite = []
        
        evaluation_details = {}
        
        for ev in evidence_items:
            if ev.evidence_type in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                try:
                    flow = json.loads(ev.content)
                    raw_metadata = flow.get("raw_metadata", {})
                    
                    if "response_headers" not in raw_metadata:
                        continue
                        
                    response_headers = raw_metadata["response_headers"]
                    if "set-cookie" not in response_headers:
                        continue
                    
                    set_cookies = response_headers["set-cookie"]
                    if isinstance(set_cookies, str):
                        set_cookies = [set_cookies]
                    
                    for cookie_str in set_cookies:
                        attributes = [attr.strip().lower() for attr in cookie_str.split(";")]
                        
                        has_secure = "secure" in attributes
                        has_httponly = "httponly" in attributes
                        
                        has_samesite = False
                        for attr in attributes:
                            if attr.startswith("samesite=") or attr == "samesite":
                                has_samesite = True
                                break
                        
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        
                        if not has_secure:
                            if ev_ref not in evidence_references_missing_secure:
                                evidence_references_missing_secure.append(ev_ref)
                                
                        if not has_httponly:
                            if ev_ref not in evidence_references_missing_httponly:
                                evidence_references_missing_httponly.append(ev_ref)
                                
                        if not has_samesite:
                            if ev_ref not in evidence_references_missing_samesite:
                                evidence_references_missing_samesite.append(ev_ref)
                                
                except Exception:
                    continue
        
        findings = []
        if evidence_references_missing_secure:
            findings.append(
                Finding(
                    analysis_id=session.analysis_id,
                    title="Missing Secure Cookie Attribute Observed",
                    description="One or more cookies were set without the 'Secure' attribute, which may allow them to be transmitted over unencrypted HTTP connections.",
                    severity=FindingSeverity.MEDIUM,
                    category=self.category,
                    status=FindingStatus.VALIDATED,
                    confidence=FindingConfidence.CERTAIN,
                    evidence_references=evidence_references_missing_secure,
                )
            )
            
        if evidence_references_missing_httponly:
            findings.append(
                Finding(
                    analysis_id=session.analysis_id,
                    title="Missing HttpOnly Cookie Attribute Observed",
                    description="One or more cookies were set without the 'HttpOnly' attribute, making them accessible to client-side scripts and vulnerable to Cross-Site Scripting (XSS) attacks.",
                    severity=FindingSeverity.MEDIUM,
                    category=self.category,
                    status=FindingStatus.VALIDATED,
                    confidence=FindingConfidence.CERTAIN,
                    evidence_references=evidence_references_missing_httponly,
                )
            )
            
        if evidence_references_missing_samesite:
            findings.append(
                Finding(
                    analysis_id=session.analysis_id,
                    title="Missing SameSite Cookie Attribute Observed",
                    description="One or more cookies were set without the 'SameSite' attribute, potentially exposing the application to Cross-Site Request Forgery (CSRF) attacks.",
                    severity=FindingSeverity.MEDIUM,
                    category=self.category,
                    status=FindingStatus.VALIDATED,
                    confidence=FindingConfidence.CERTAIN,
                    evidence_references=evidence_references_missing_samesite,
                )
            )
            
        all_refs = list(set(
            evidence_references_missing_secure + 
            evidence_references_missing_httponly + 
            evidence_references_missing_samesite
        ))
            
        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=all_refs,
                evaluation_details={},
            )
            
        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details=evaluation_details,
        )
class InsecureCORSRule(Rule):
    """Rule verifying whether the application server sends an insecure CORS policy."""

    @property
    def rule_id(self) -> str:
        return "RULE-009"

    @property
    def name(self) -> str:
        return "Insecure CORS Policy Observed"

    @property
    def description(self) -> str:
        return "The application received a response with an insecure Cross-Origin Resource Sharing (CORS) policy."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def _get_header_value(self, headers: Dict, header_name: str) -> str:
        """Retrieve a header value case-insensitively, returning the first value if it's a list."""
        val = headers.get(header_name)
        if val is None:
            # Fallback: iterate keys for case-insensitive match (headers should already be lowercase from proxy)
            for k in headers:
                if isinstance(k, str) and k.lower() == header_name:
                    val = headers[k]
                    break
        if val is None:
            return ""
        if isinstance(val, list):
            return val[0].strip() if val else ""
        if isinstance(val, str):
            return val.strip()
        return ""

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                continue
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                acao = self._get_header_value(response_headers, "access-control-allow-origin")
                if not acao:
                    continue

                ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                host = flow.get("host", "unknown")

                if acao == "*":
                    acac = self._get_header_value(response_headers, "access-control-allow-credentials")

                    if acac.lower() == "true":
                        # Condition B — Wildcard + Credentials (higher severity finding)
                        dedup_key = f"cors_wildcard_creds:{host}"
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            if ev_ref not in evidence_references:
                                evidence_references.append(ev_ref)
                            findings.append(
                                Finding(
                                    analysis_id=session.analysis_id,
                                    title="Wildcard CORS Origin With Credentials Observed",
                                    description=(
                                        f"The server at {host} responded with "
                                        f"Access-Control-Allow-Origin: * and "
                                        f"Access-Control-Allow-Credentials: true. "
                                        f"This combination is explicitly prohibited by the CORS specification "
                                        f"and may indicate a misconfigured server."
                                    ),
                                    severity=FindingSeverity.HIGH,
                                    category=self.category,
                                    status=FindingStatus.VALIDATED,
                                    confidence=FindingConfidence.CERTAIN,
                                    evidence_references=[ev_ref],
                                )
                            )
                    else:
                        # Condition A — Wildcard Origin only
                        dedup_key = f"cors_wildcard:{host}"
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            if ev_ref not in evidence_references:
                                evidence_references.append(ev_ref)
                            findings.append(
                                Finding(
                                    analysis_id=session.analysis_id,
                                    title="Wildcard CORS Origin Observed",
                                    description=(
                                        f"The server at {host} responded with "
                                        f"Access-Control-Allow-Origin: *. "
                                        f"This permits any origin to read the response."
                                    ),
                                    severity=FindingSeverity.MEDIUM,
                                    category=self.category,
                                    status=FindingStatus.VALIDATED,
                                    confidence=FindingConfidence.CERTAIN,
                                    evidence_references=[ev_ref],
                                )
                            )
                # Condition C — Specific origin: do NOT auto-classify as vulnerable.

            except Exception:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No insecure CORS policy evidence found."},
        )


class MissingReferrerPolicyRule(Rule):
    """Rule verifying whether the application server sends a Referrer-Policy header."""

    @property
    def rule_id(self) -> str:
        return "RULE-010"

    @property
    def name(self) -> str:
        return "Missing Referrer-Policy Header Observed"

    @property
    def description(self) -> str:
        return "The application received a response without a Referrer-Policy header."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def _header_exists(self, headers: Dict, header_name: str) -> bool:
        """Check if a header exists case-insensitively."""
        if header_name in headers:
            return True
        for k in headers:
            if isinstance(k, str) and k.lower() == header_name:
                return True
        return False

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                continue
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                # If the header is present, we skip
                if self._header_exists(response_headers, "referrer-policy"):
                    continue

                ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                host = flow.get("host", "unknown")

                # Condition B: Header Missing
                dedup_key = f"missing_referrer_policy:{host}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    if ev_ref not in evidence_references:
                        evidence_references.append(ev_ref)
                    findings.append(
                        Finding(
                            analysis_id=session.analysis_id,
                            title="Missing Referrer-Policy Header",
                            description=(
                                f"The server at {host} responded without a Referrer-Policy header. "
                                f"This may result in unintended leakage of Referer information. "
                                f"Note: This is an observed configuration condition, not necessarily an exploitable vulnerability."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            category=self.category,
                            status=FindingStatus.VALIDATED,
                            confidence=FindingConfidence.CERTAIN,
                            evidence_references=[ev_ref],
                        )
                    )
            except Exception:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No missing Referrer-Policy evidence found."},
        )


class MissingCSPRule(Rule):
    """
    RULE-011: Missing Content-Security-Policy Header Observed
    
    Generates a finding when explicit response_headers evidence is captured,
    but no 'Content-Security-Policy' header is present.
    """
    
    def __init__(self) -> None:
        self.seen_hosts: set = set()

    @property
    def rule_id(self) -> str:
        return "RULE-011"

    @property
    def name(self) -> str:
        return "Missing Content-Security-Policy Header Observed"

    @property
    def description(self) -> str:
        return "The observed HTTP response did not include a Content-Security-Policy header."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.MEDIUM

    def _header_exists(self, headers: Dict, header_name: str) -> bool:
        """Check if a header exists case-insensitively."""
        if header_name in headers:
            return True
        for k in headers:
            if isinstance(k, str) and k.lower() == header_name:
                return True
        return False

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                continue
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                host = flow.get("request", {}).get("host", "unknown")

                dedup_key = f"{self.rule_id}_{host}"
                if dedup_key in seen_keys:
                    continue

                has_csp = self._header_exists(response_headers, "content-security-policy")

                if not has_csp:
                    seen_keys.add(dedup_key)
                    finding = Finding(
                        analysis_id=session.id,
                        title=f"[{self.rule_id}] {self.name} - {host}",
                        description=(
                            f"{self.description}\n"
                            f"Host: {host}\n"
                        ),
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.CERTAIN,
                        evidence_references=[f"Evidence from {ev.timestamp} (host: {host})"]
                    )
                    findings.append(finding)
                    evidence_references.append(f"Evidence from {ev.timestamp} (host: {host})")
            except json.JSONDecodeError:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No missing Content-Security-Policy evidence found."},
        )

class MissingXFrameOptionsRule(Rule):
    """
    RULE-013: Missing X-Frame-Options Header Observed
    
    Generates a finding when explicit response_headers evidence is captured,
    but no 'X-Frame-Options' header is present.
    """
    
    def __init__(self) -> None:
        self.seen_hosts: set = set()

    @property
    def rule_id(self) -> str:
        return "RULE-013"

    @property
    def name(self) -> str:
        return "Missing X-Frame-Options Header Observed"

    @property
    def description(self) -> str:
        return "The observed HTTP response did not include an X-Frame-Options header, which may leave the application vulnerable to clickjacking attacks if rendered in a webview."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.MEDIUM

    def _header_exists(self, headers: Dict, header_name: str) -> bool:
        """Check if a header exists case-insensitively."""
        if header_name in headers:
            return True
        for k in headers:
            if isinstance(k, str) and k.lower() == header_name:
                return True
        return False

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                continue
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                host = flow.get("request", {}).get("host")
                if not host:
                    host = flow.get("host", "unknown")

                dedup_key = f"{self.rule_id}_{host}"
                if dedup_key in seen_keys:
                    continue

                has_xfo = self._header_exists(response_headers, "x-frame-options")

                if not has_xfo:
                    seen_keys.add(dedup_key)
                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {host}",
                        description=(
                            f"{self.description}\n"
                            f"Host: {host}\n"
                        ),
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.CERTAIN,
                        evidence_references=[f"Evidence from {ev.timestamp} (host: {host})"]
                    )
                    findings.append(finding)
                    evidence_references.append(f"Evidence from {ev.timestamp} (host: {host})")
            except json.JSONDecodeError:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No missing X-Frame-Options evidence found."},
        )


class MissingContentSecurityPolicyRule(Rule):
    """
    RULE-014: Missing Content-Security-Policy Header Observed
    
    Generates a finding when explicit response_headers evidence is captured,
    but no 'Content-Security-Policy' header is present.
    """
    
    def __init__(self) -> None:
        self.seen_hosts: set = set()

    @property
    def rule_id(self) -> str:
        return "RULE-014"

    @property
    def name(self) -> str:
        return "Missing Content-Security-Policy Header Observed"

    @property
    def description(self) -> str:
        return "The observed HTTP response did not include a Content-Security-Policy header, which may leave the application vulnerable to injection attacks if rendered in a webview without strict constraints."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.MEDIUM

    def _header_exists(self, headers: Dict, header_name: str) -> bool:
        """Check if a header exists case-insensitively."""
        if header_name in headers:
            return True
        for k in headers:
            if isinstance(k, str) and k.lower() == header_name:
                return True
        return False

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                continue
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                host = flow.get("request", {}).get("host")
                if not host:
                    host = flow.get("host", "unknown")

                dedup_key = f"{self.rule_id}_{host}"
                if dedup_key in seen_keys:
                    continue

                has_csp = self._header_exists(response_headers, "content-security-policy")

                if not has_csp:
                    seen_keys.add(dedup_key)
                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {host}",
                        description=(
                            f"{self.description}\n"
                            f"Host: {host}\n"
                        ),
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.CERTAIN,
                        evidence_references=[f"Evidence from {ev.timestamp} (host: {host})"]
                    )
                    findings.append(finding)
                    evidence_references.append(f"Evidence from {ev.timestamp} (host: {host})")
            except json.JSONDecodeError:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No missing Content-Security-Policy evidence found."},
        )



class SensitivePermissionObservedRule(Rule):
    """
    Identifies sensitive Android permissions explicitly observed 
    in the application's declared/requested or runtime-granted permissions.
    """

    @property
    def rule_id(self) -> str:
        return "RULE-012"

    @property
    def name(self) -> str:
        return "Sensitive Permission Observed"

    @property
    def description(self) -> str:
        return "The target application was observed declaring or requesting the sensitive Android permission"

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.INFO

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.AUTHENTICATION

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        sensitive_permissions = {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        }

        findings = []
        evidence_references = []
        seen_permissions = set()

        for ev in evidence_items:
            if ev.evidence_type != EvidenceType.PERMISSIONS.value:
                continue
            
            if not ev.content:
                continue
            
            lines = ev.content.splitlines()
            in_requested = False
            in_runtime = False
            
            for line in lines:
                line_stripped = line.strip()
                if line_stripped == "requested permissions:":
                    in_requested = True
                    in_runtime = False
                    continue
                elif line_stripped == "runtime permissions:":
                    in_requested = False
                    in_runtime = True
                    continue
                elif line_stripped.endswith(":"):
                    in_requested = False
                    in_runtime = False
                    continue
                
                perm = None
                status_str = ""
                
                if in_requested and line_stripped.startswith("android.permission."):
                    perm = line_stripped.split(":")[0].strip()
                    status_str = "declared/requested"
                elif in_runtime and line_stripped.startswith("android.permission."):
                    perm = line_stripped.split(":")[0].strip()
                    status_str = "runtime-granted"
                
                if perm and perm in sensitive_permissions:
                    # Deduplicate by permission and status
                    dedup_key = f"{perm}_{status_str}"
                    if dedup_key not in seen_permissions:
                        seen_permissions.add(dedup_key)
                        
                        finding = Finding(
                            analysis_id=session.analysis_id,
                            title=f"[{self.rule_id}] Sensitive Permission Observed: {perm}",
                            description=f"The target application was observed {status_str} the sensitive Android permission {perm}.",
                            severity=self.severity,
                            category=self.category,
                            status=FindingStatus.VALIDATED,
                            confidence=FindingConfidence.CERTAIN,
                            evidence_references=[f"Evidence from {ev.timestamp} (source: {ev.source})"]
                        )
                        findings.append(finding)
                        evidence_references.append(f"Evidence from {ev.timestamp} (source: {ev.source})")
        
        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )
            
        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No sensitive permissions observed."},
        )


class InsecureCookieAttributeRule(Rule):
    """
    RULE-015: Insecure Cookie Attribute Observed
    """

    @property
    def rule_id(self) -> str:
        return "RULE-015"

    @property
    def name(self) -> str:
        return "Insecure Cookie Attribute Observed"

    @property
    def description(self) -> str:
        return "The observed HTTP response set a cookie that lacks one or more required security attributes (Secure, HttpOnly, SameSite)."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.MEDIUM

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTPS_TRAFFIC.value, EvidenceType.HTTP_TRAFFIC.value):
                continue
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                # Find Set-Cookie case-insensitively
                set_cookies = []
                for k, v in response_headers.items():
                    if k.lower() == "set-cookie":
                        if isinstance(v, list):
                            set_cookies.extend(v)
                        else:
                            set_cookies.append(v)

                if not set_cookies:
                    continue

                host = flow.get("request", {}).get("host")
                if not host:
                    host = flow.get("host", "unknown")

                for cookie_str in set_cookies:
                    if not isinstance(cookie_str, str):
                        continue
                    parts = [p.strip() for p in cookie_str.split(";")]
                    if not parts:
                        continue
                    
                    cookie_name_part = parts[0]
                    if "=" in cookie_name_part:
                        cookie_name = cookie_name_part.split("=", 1)[0].strip()
                    else:
                        cookie_name = cookie_name_part.strip()
                        
                    if not cookie_name:
                        continue
                        
                    attributes = [p.lower() for p in parts[1:]]
                    has_secure = "secure" in attributes
                    has_httponly = "httponly" in attributes
                    has_samesite = any(a.startswith("samesite=") or a == "samesite" for a in attributes)

                    missing_attrs = []
                    if not has_secure:
                        missing_attrs.append("Secure")
                    if not has_httponly:
                        missing_attrs.append("HttpOnly")
                    if not has_samesite:
                        missing_attrs.append("SameSite")

                    if missing_attrs:
                        ev_ref = f"Evidence from {ev.timestamp} (host: {host})"
                        
                        for missing_attr in missing_attrs:
                            dedup_key = f"{self.rule_id}_{host}_{cookie_name}_{missing_attr}"
                            if dedup_key not in seen_keys:
                                seen_keys.add(dedup_key)
                                
                                finding = Finding(
                                    analysis_id=session.analysis_id,
                                    title=f"[{self.rule_id}] Missing {missing_attr} Cookie Attribute",
                                    description=(
                                        f"The server at {host} set a cookie '{cookie_name}' without the '{missing_attr}' attribute."
                                    ),
                                    severity=self.severity,
                                    category=self.category,
                                    status=FindingStatus.VALIDATED,
                                    confidence=FindingConfidence.CERTAIN,
                                    evidence_references=[ev_ref]
                                )
                                findings.append(finding)
                                if ev_ref not in evidence_references:
                                    evidence_references.append(ev_ref)

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No insecure cookie attribute evidence found."},
        )


class MissingCacheControlRule(Rule):
    """Detects HTTP/HTTPS responses missing the Cache-Control header when explicitly observed."""

    @property
    def rule_id(self) -> str:
        return "RULE-016"

    @property
    def name(self) -> str:
        return "Missing Cache-Control Header Observed"

    @property
    def description(self) -> str:
        return (
            "Analyzes HTTP/HTTPS response headers to detect the absence of a Cache-Control header. "
            "Does not trigger if evidence is missing, malformed, or if the header exists."
        )

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.LOW

    def evaluate(
        self, session: AnalysisSession, evidence_items: List[EvidenceItem]
    ) -> RuleResult:
        """Evaluate evidence for missing Cache-Control headers."""
        findings: List[Finding] = []
        evidence_references: List[str] = []
        seen_hosts: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (
                EvidenceType.HTTP_TRAFFIC.value,
                EvidenceType.HTTPS_TRAFFIC.value,
            ):
                continue

            try:
                # Content must be valid JSON
                data = json.loads(ev.content)

                raw_metadata = data.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue
                    
                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                host = data.get("request", {}).get("host")
                if not host:
                    host = data.get("host", "unknown")

                # Case-insensitive check for cache-control
                headers_lower = {k.lower(): v for k, v in response_headers.items()}
                
                if "cache-control" not in headers_lower:
                    dedup_key = f"{self.rule_id}_{host}"
                    if dedup_key not in seen_hosts:
                        seen_hosts.add(dedup_key)
                        ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                        finding = Finding(
                            analysis_id=session.analysis_id,
                            title=f"[{self.rule_id}] {self.name} - {host}",
                            description=(
                                f"The server at {host} returned an HTTP response without a Cache-Control header. "
                                "This may allow intermediate caches to store sensitive information."
                            ),
                            severity=self.severity,
                            category=self.category,
                            status=FindingStatus.VALIDATED,
                            confidence=FindingConfidence.CERTAIN,
                            evidence_references=[ev_ref]
                        )
                        findings.append(finding)
                        evidence_references.append(ev_ref)

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No missing Cache-Control header evidence found."},
        )


class ServerHeaderDisclosureRule(Rule):
    """Detects HTTP/HTTPS responses with Server or X-Powered-By headers."""

    @property
    def rule_id(self) -> str:
        return "RULE-017"

    @property
    def name(self) -> str:
        return "Server Header Information Disclosure Observed"

    @property
    def description(self) -> str:
        return (
            "Analyzes HTTP/HTTPS response headers to detect the presence of Server or "
            "X-Powered-By headers, which may disclose backend technology details to an attacker."
        )

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.INFO

    def evaluate(
        self, session: AnalysisSession, evidence_items: List[EvidenceItem]
    ) -> RuleResult:
        """Evaluate evidence for information disclosure headers."""
        findings: List[Finding] = []
        evidence_references: List[str] = []
        seen_hosts_headers: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (
                EvidenceType.HTTP_TRAFFIC.value,
                EvidenceType.HTTPS_TRAFFIC.value,
            ):
                continue

            try:
                # Content must be valid JSON
                data = json.loads(ev.content)

                raw_metadata = data.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue
                    
                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                host = data.get("request", {}).get("host")
                if not host:
                    host = data.get("host", "unknown")
                if not host or host == "unknown":
                    continue

                # Case-insensitive check for server and x-powered-by
                headers_lower = {k.lower(): (k, v) for k, v in response_headers.items()}
                
                for target_header in ("server", "x-powered-by"):
                    if target_header in headers_lower:
                        actual_header_name, header_value = headers_lower[target_header]
                        
                        # Use a list for header values if multiple are present
                        if isinstance(header_value, list):
                            val_str = ", ".join(str(v) for v in header_value)
                        else:
                            val_str = str(header_value)
                            
                        dedup_key = f"{self.rule_id}_{host}_{target_header}"
                        if dedup_key not in seen_hosts_headers:
                            seen_hosts_headers.add(dedup_key)
                            ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                            finding = Finding(
                                analysis_id=session.analysis_id,
                                title=f"[{self.rule_id}] {self.name} ({actual_header_name}) - {host}",
                                description=(
                                    f"The server at {host} returned an HTTP response with a '{actual_header_name}' header "
                                    f"containing the value: '{val_str}'. This may disclose sensitive backend technology details."
                                ),
                                severity=self.severity,
                                category=self.category,
                                status=FindingStatus.VALIDATED,
                                confidence=FindingConfidence.CERTAIN,
                                evidence_references=[ev_ref]
                            )
                            findings.append(finding)
                            evidence_references.append(ev_ref)

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No Server or X-Powered-By headers found."},
        )


class MissingPermissionsPolicyRule(Rule):
    """
    RULE-018: Missing Permissions-Policy Header Observed

    Identifies HTTP/HTTPS responses that explicitly omit the Permissions-Policy
    header.
    """

    @property
    def rule_id(self) -> str:
        return "RULE-018"

    @property
    def name(self) -> str:
        return "Missing Permissions-Policy Header Observed"

    @property
    def description(self) -> str:
        return (
            "The Permissions-Policy header provides a mechanism to allow and deny the use of browser features "
            "in its own frame, and in content within any <iframe> elements in the document."
        )

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.LOW

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        findings = []
        evidence_references = []
        seen_hosts = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTP_TRAFFIC.value, EvidenceType.HTTPS_TRAFFIC.value):
                continue

            try:
                data = json.loads(ev.content)
                raw_metadata = data.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                if "response_headers" not in raw_metadata:
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                host = data.get("request", {}).get("host")
                if not host:
                    host = data.get("host", "unknown")
                if not host or host == "unknown":
                    continue

                if host in seen_hosts:
                    continue

                # Case-insensitive check for permissions-policy
                headers_lower = [k.lower() for k in response_headers.keys()]
                if "permissions-policy" not in headers_lower:
                    seen_hosts.add(host)
                    ev_ref = f"{ev.evidence_type}:{ev.timestamp}"
                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {host}",
                        description=(
                            f"The server at {host} returned an HTTP response without a 'Permissions-Policy' header. "
                            "This header is recommended to explicitly declare which browser features (like camera, microphone, geolocation) "
                            "the page and its iframes are allowed to use."
                        ),
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.CERTAIN,
                        evidence_references=[ev_ref]
                    )
                    findings.append(finding)
                    evidence_references.append(ev_ref)

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

        if findings:
            return RuleResult(
                rule_id=self.rule_id,
                triggered=True,
                findings=findings,
                evidence_references=evidence_references,
                evaluation_details={},
            )

        return RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            evaluation_details={"reason": "No valid proxy evidence lacked Permissions-Policy."},
        )



class SensitiveLogcatDataRule(Rule):
    """Detects explicitly exposed sensitive data in logcat."""

    def __init__(self):
        super().__init__()
        self.patterns = {
            "Authorization Header": re.compile(r'(?i)Authorization:\s*(Bearer|Basic)\s+([A-Za-z0-9\-\._~+/]+=*)'),
            "API Key / Token": re.compile(r'(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key)["\'\s:=]+([A-Za-z0-9\-\._~+/]{16,})'),
            "Password": re.compile(r'(?i)(?:password|passwd)["\'\s:=]+([A-Za-z0-9@#$%^&+=!]{6,})')
        }

    @property
    def rule_id(self) -> str:
        return "RULE-019"

    @property
    def name(self) -> str:
        return "Sensitive Data Observed in Logcat"

    @property
    def description(self) -> str:
        return "Clearly identifiable sensitive data (e.g., passwords, access tokens, API keys) was explicitly exposed in logcat output."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.MISC

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.MEDIUM

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            if ev.evidence_type != EvidenceType.LOGCAT.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
                
            for match_type, pattern in self.patterns.items():
                for match in pattern.finditer(ev.content):
                    secret_val = match.group(len(match.groups()))
                    redacted = f"{secret_val[:3]}...<redacted>" if len(secret_val) > 3 else "<redacted>"
                    full_match = match.group(0)
                    redacted_match = full_match.replace(secret_val, redacted)

                    dedup_key = f"{match_type}:{redacted_match}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {match_type}",
                        description=f"Sensitive data ({match_type}) was observed in logcat: {redacted_match}",
                        severity=FindingSeverity.MEDIUM,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class SensitiveNetworkDataRule(Rule):
    """
    Analyzes network traffic for exposed sensitive data like API keys, tokens, or passwords.
    """

    def __init__(self):
        super().__init__()
        self.patterns = {
            "Authorization Header": re.compile(r'(?i)Authorization[\'"]?\s*[:=]\s*[\'"]?(Bearer|Basic)\s+([A-Za-z0-9\-\._~+/]+=*)'),
            "API Key / Token": re.compile(r'(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9\-\._~+/]{16,})'),
            "Password": re.compile(r'(?i)(?:password|passwd)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9@#$%^&+=!]{6,})')
        }

    @property
    def rule_id(self) -> str:
        return "RULE-020"

    @property
    def name(self) -> str:
        return "Sensitive Data Observed in Network Traffic"

    @property
    def description(self) -> str:
        return "Clearly identifiable sensitive data (e.g., passwords, access tokens, API keys) was explicitly exposed in network traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTP_TRAFFIC.value, EvidenceType.HTTPS_TRAFFIC.value):
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
                
            for match_type, pattern in self.patterns.items():
                for match in pattern.finditer(ev.content):
                    secret_val = match.group(len(match.groups()))
                    redacted = f"{secret_val[:3]}...<redacted>" if len(secret_val) > 3 else "<redacted>"
                    full_match = match.group(0)
                    redacted_match = full_match.replace(secret_val, redacted)

                    dedup_key = f"{match_type}:{redacted_match}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {match_type}",
                        description=f"Sensitive data ({match_type}) was observed in network traffic: {redacted_match}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result
class InsecureHttpAuthRule(Rule):
    """Rule verifying whether explicit authentication credentials are transmitted over HTTP."""

    def __init__(self):
        super().__init__()
        self.patterns = {
            "Authorization Header": re.compile(r'(?i)Authorization[\'"]?\s*[:=]\s*[\'"]?(Bearer|Basic)\s+([A-Za-z0-9\-\._~+/]+=*)'),
            "Credential Field": re.compile(r'(?i)(?:username|password|passwd|api[_-]?key|access[_-]?token)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9@#$%^&+=!\-\._~+/]{3,})')
        }

    @property
    def rule_id(self) -> str:
        return "RULE-021"

    @property
    def name(self) -> str:
        return "Insecure HTTP Authentication Observed"

    @property
    def description(self) -> str:
        return "Explicit authentication credentials were observed being transmitted over unencrypted HTTP traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
                
            for match_type, pattern in self.patterns.items():
                for match in pattern.finditer(ev.content):
                    secret_val = match.group(len(match.groups()))
                    redacted = f"{secret_val[:3]}...<redacted>" if len(secret_val) > 3 else "<redacted>"
                    full_match = match.group(0)
                    redacted_match = full_match.replace(secret_val, redacted)

                    dedup_key = f"{match_type}:{redacted_match}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {match_type}",
                        description=f"Insecure HTTP Authentication ({match_type}) observed: {redacted_match}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class InsecureHttpSensitiveDataRule(Rule):
    """Rule verifying whether explicit sensitive data is transmitted over HTTP."""

    def __init__(self):
        super().__init__()
        self.patterns = {
            "Sensitive Field": re.compile(r'(?i)(?:email|phone|ssn|credit[_-]?card|card[_-]?number|cvv|address|date[_-]?of[_-]?birth|dob)[\'"]?\s*[:=]\s*[\'"]?([^\s&"\'{}]{1,})')
        }

    @property
    def rule_id(self) -> str:
        return "RULE-022"

    @property
    def name(self) -> str:
        return "Insecure HTTP Sensitive Data Observed"

    @property
    def description(self) -> str:
        return "Explicit sensitive data was observed being transmitted over unencrypted HTTP traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
                
            for match_type, pattern in self.patterns.items():
                for match in pattern.finditer(ev.content):
                    secret_val = match.group(len(match.groups()))
                    
                    # Deduce field name to include in description
                    full_match = match.group(0)
                    field_name = full_match.split('=')[0].split(':')[0].strip(' "\'')
                    
                    redacted = f"{secret_val[:3]}...<redacted>" if len(secret_val) > 3 else "<redacted>"
                    redacted_match = full_match.replace(secret_val, redacted)

                    dedup_key = f"{match_type}:{redacted_match}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {field_name}",
                        description=f"Sensitive field '{field_name}' observed in unencrypted HTTP traffic: {redacted_match}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class InsecureHttpCookieTransmissionRule(Rule):
    """Rule verifying whether explicit cookies are transmitted over unencrypted HTTP."""

    def __init__(self):
        super().__init__()
        # Matches Cookie: <name>=<value> pattern or similar in content
        self.cookie_header_pattern = re.compile(r'(?i)cookie\s*:\s*(.+)')

    @property
    def rule_id(self) -> str:
        return "RULE-023"

    @property
    def name(self) -> str:
        return "Insecure HTTP Cookie Transmission Observed"

    @property
    def description(self) -> str:
        return "Explicit cookie data was observed being transmitted over unencrypted HTTP traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def _parse_cookies(self, cookie_string: str) -> List[tuple]:
        cookies = []
        parts = cookie_string.split(';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if '=' in part:
                name, val = part.split('=', 1)
                cookies.append((name.strip(), val.strip()))
            else:
                cookies.append((part.strip(), ""))
        return cookies

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
            
            try:
                flow = json.loads(ev.content)
            except json.JSONDecodeError:
                # Flow isn't valid JSON, fallback to regex search on raw content
                flow = {}
                
            url = flow.get("url", "")
            host = ""
            if "://" in url:
                host = url.split("://")[1].split("/")[0].split(":")[0]
                
            # Search in request headers if available
            headers = flow.get("request_headers", {})
            cookie_strings = []
            
            for k, v in headers.items():
                if k.lower() == "cookie":
                    cookie_strings.append(v)
                    
            # Also search in raw content if JSON wasn't parsed properly or if we want to catch raw headers
            if not cookie_strings:
                for match in self.cookie_header_pattern.finditer(ev.content):
                    cookie_strings.append(match.group(1))

            for cookie_str in cookie_strings:
                cookies = self._parse_cookies(cookie_str)
                for c_name, c_val in cookies:
                    if not c_name or not c_val:
                        continue
                        
                    redacted_val = f"{c_val[:3]}...<redacted>" if len(c_val) > 3 else "<redacted>"
                    
                    dedup_key = f"{host}:{c_name}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {c_name}",
                        description=f"Cookie '{c_name}' observed over unencrypted HTTP: {redacted_val}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                        result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class InsecureHttpAuthCookieRule(Rule):
    """Rule verifying whether explicit authentication/session cookies are transmitted over unencrypted HTTP."""

    def __init__(self):
        super().__init__()
        # Matches Cookie: <name>=<value> pattern or similar in content
        self.cookie_header_pattern = re.compile(r'(?i)cookie\s*:\s*(.+)')
        self.auth_cookie_names = {
            "session", "sessionid", "session_id", "sid", "jsessionid", 
            "phpsessid", "auth", "auth_token", "access_token", 
            "refresh_token", "id_token", "jwt", "token"
        }

    @property
    def rule_id(self) -> str:
        return "RULE-024"

    @property
    def name(self) -> str:
        return "Insecure HTTP Authentication Cookie Observed"

    @property
    def description(self) -> str:
        return "Authentication/session cookie data was observed being transmitted over unencrypted HTTP traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def _parse_cookies(self, cookie_string: str) -> List[tuple]:
        cookies = []
        parts = cookie_string.split(';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if '=' in part:
                name, val = part.split('=', 1)
                cookies.append((name.strip(), val.strip()))
            else:
                cookies.append((part.strip(), ""))
        return cookies

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
            
            try:
                flow = json.loads(ev.content)
            except json.JSONDecodeError:
                # Flow isn't valid JSON, fallback to regex search on raw content
                flow = {}
                
            url = flow.get("url", "")
            host = ""
            if "://" in url:
                host = url.split("://")[1].split("/")[0].split(":")[0]
                
            # Search in request headers if available
            headers = flow.get("request_headers", {})
            cookie_strings = []
            
            for k, v in headers.items():
                if k.lower() == "cookie":
                    cookie_strings.append(v)
                    
            # Also search in raw content if JSON wasn't parsed properly or if we want to catch raw headers
            if not cookie_strings:
                for match in self.cookie_header_pattern.finditer(ev.content):
                    cookie_strings.append(match.group(1))

            for cookie_str in cookie_strings:
                cookies = self._parse_cookies(cookie_str)
                for c_name, c_val in cookies:
                    if not c_name or not c_val:
                        continue
                        
                    # Filter for authentication/session cookies
                    if c_name.lower() not in self.auth_cookie_names:
                        continue
                        
                    redacted_val = f"{c_val[:3]}...<redacted>" if len(c_val) > 3 else "<redacted>"
                    
                    dedup_key = f"{host}:{c_name}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {c_name}",
                        description=f"Authentication/session cookie '{c_name}' observed over unencrypted HTTP: {redacted_val}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                        result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class InsecureHttpFormSubmissionRule(Rule):
    """Rule verifying whether explicit sensitive form fields are submitted over unencrypted HTTP."""

    def __init__(self):
        super().__init__()
        self.sensitive_fields = {
            "username", "password", "email", "phone", "credit_card", 
            "card_number", "cvv", "ssn", "access_token", "api_key"
        }
        
        # Matches url-encoded like username=alice or json-like "username":"alice"
        self.url_encoded_pattern = re.compile(r'(?i)(?:^|&)([^=&]+)=([^&]+)')
        self.json_pattern = re.compile(r'(?i)"([^"]+)"\s*:\s*"([^"]+)"')

    @property
    def rule_id(self) -> str:
        return "RULE-025"

    @property
    def name(self) -> str:
        return "Insecure HTTP Form Submission Observed"

    @property
    def description(self) -> str:
        return "Explicit sensitive form/request fields were observed being transmitted over unencrypted HTTP traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
            
            try:
                flow = json.loads(ev.content)
            except json.JSONDecodeError:
                flow = {}
                
            url = flow.get("url", "")
            host = ""
            if "://" in url:
                host = url.split("://")[1].split("/")[0].split(":")[0]
                
            content = flow.get("request_content", "")
            if not content:
                continue

            extracted_pairs = []
            
            # Try parsing as JSON body first if applicable
            try:
                if content.strip().startswith("{"):
                    body_json = json.loads(content)
                    if isinstance(body_json, dict):
                        for k, v in body_json.items():
                            if isinstance(v, (str, int, float, bool)) and v != "":
                                extracted_pairs.append((str(k).strip(), str(v).strip()))
            except json.JSONDecodeError:
                pass
                
            if not extracted_pairs:
                # Try url-encoded
                for match in self.url_encoded_pattern.finditer(content):
                    extracted_pairs.append((match.group(1).strip(), match.group(2).strip()))
                    
                # Try raw json-like pattern
                for match in self.json_pattern.finditer(content):
                    extracted_pairs.append((match.group(1).strip(), match.group(2).strip()))

            for field_name, field_val in extracted_pairs:
                if not field_name or not field_val:
                    continue
                    
                field_name = urllib.parse.unquote(field_name)
                field_val = urllib.parse.unquote(field_val)
                
                field_name_lower = field_name.lower()
                is_sensitive = False
                matched_field = ""
                
                for sf in self.sensitive_fields:
                    if sf == field_name_lower:
                        is_sensitive = True
                        matched_field = sf
                        break
                        
                if not is_sensitive:
                    continue
                    
                redacted_val = f"{field_val[:3]}...<redacted>" if len(field_val) > 3 else "<redacted>"
                
                dedup_key = f"{host}:{matched_field}"
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                finding = Finding(
                    analysis_id=session.analysis_id,
                    title=f"[{self.rule_id}] {self.name} - {matched_field}",
                    description=f"Sensitive form field '{matched_field}' observed in unencrypted HTTP traffic: {redacted_val}",
                    severity=self.severity,
                    category=self.category,
                    status=FindingStatus.VALIDATED,
                    confidence=FindingConfidence.HIGH,
                    evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                )
                result.findings.append(finding)
                if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                    result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                result.triggered = True

        return result


class InsecureHttpQueryParameterRule(Rule):
    """
    RULE-026: Insecure HTTP Sensitive Query Parameter Observed
    
    Identifies sensitive values transmitted through URL query parameters 
    over unencrypted HTTP traffic.
    """

    def __init__(self) -> None:
        self.sensitive_params = {
            "password", "passwd", "pass",
            "api_key", "apikey",
            "access_token", "refresh_token", "auth_token", "token",
            "secret", "client_secret",
            "ssn", "social_security",
            "credit_card", "card_number", "cvv", "security_code"
        }

    @property
    def rule_id(self) -> str:
        return "RULE-026"

    @property
    def name(self) -> str:
        return "Insecure HTTP Sensitive Query Parameter Observed"

    @property
    def description(self) -> str:
        return "Sensitive query parameter observed in unencrypted HTTP traffic"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            findings=[],
            evidence_references=[],
            evaluation_details={}
        )

        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
            
            try:
                flow = json.loads(ev.content)
            except json.JSONDecodeError:
                continue
                
            url = flow.get("url", "")
            if not url or "://" not in url:
                continue
                
            host = url.split("://")[1].split("/")[0].split(":")[0]
            
            # Parse URL safely
            try:
                parsed_url = urllib.parse.urlparse(url)
            except Exception:
                continue
                
            query = parsed_url.query
            if not query:
                continue
                
            query_params = urllib.parse.parse_qsl(query, keep_blank_values=True)
            
            for param_name, param_val in query_params:
                if not param_name or not param_val:
                    continue
                    
                param_name_lower = param_name.lower().strip()
                param_val = param_val.strip()
                
                if param_name_lower in self.sensitive_params:
                    redacted_val = f"{param_val[:3]}...<redacted>" if len(param_val) > 3 else "<redacted>"
                    
                    dedup_key = f"{host}:{param_name_lower}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {param_name_lower}",
                        description=f"Sensitive query parameter '{param_name_lower}' observed in unencrypted HTTP traffic: {redacted_val}\nHost: {host}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                        result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class InsecureHttpSensitiveHeaderRule(Rule):
    """
    RULE-027: Sensitive Header Observed Over HTTP
    
    Identifies sensitive request headers transmitted over 
    explicitly unencrypted HTTP traffic.
    """

    def __init__(self) -> None:
        self.sensitive_headers = {
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-client-secret"
        }

    @property
    def rule_id(self) -> str:
        return "RULE-027"

    @property
    def name(self) -> str:
        return "Sensitive Header Observed Over HTTP"

    @property
    def description(self) -> str:
        return "Sensitive header observed over unencrypted HTTP"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(
            rule_id=self.rule_id,
            triggered=False,
            findings=[],
            evidence_references=[],
            evaluation_details={}
        )

        seen_matches = set()

        for ev in evidence_items:
            # ONLY analyze HTTP_TRAFFIC (not HTTPS)
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            if not ev.content or not isinstance(ev.content, str):
                continue
            
            try:
                flow = json.loads(ev.content)
            except json.JSONDecodeError:
                continue
                
            if not isinstance(flow, dict):
                continue
                
            url = flow.get("url", "")
            host = ""
            if url and "://" in url:
                host = url.split("://")[1].split("/")[0].split(":")[0]
                
            headers = flow.get("request_headers", {})
            if not isinstance(headers, dict):
                continue
                
            for header_name, header_val in headers.items():
                if not header_name or not header_val:
                    continue
                    
                header_name_lower = header_name.lower().strip()
                header_val = str(header_val).strip()
                
                if not header_val:
                    continue
                    
                if header_name_lower in self.sensitive_headers:
                    redacted_val = f"{header_val[:3]}...<redacted>" if len(header_val) > 3 else "<redacted>"
                    
                    dedup_key = f"{host}:{header_name_lower}"
                    if dedup_key in seen_matches:
                        continue
                    seen_matches.add(dedup_key)

                    finding = Finding(
                        analysis_id=session.analysis_id,
                        title=f"[{self.rule_id}] {self.name} - {header_name_lower}",
                        description=f"Sensitive header '{header_name_lower}' observed over unencrypted HTTP: {redacted_val}\nHost: {host}",
                        severity=self.severity,
                        category=self.category,
                        status=FindingStatus.VALIDATED,
                        confidence=FindingConfidence.HIGH,
                        evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                    )
                    result.findings.append(finding)
                    if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                        result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                    result.triggered = True

        return result


class InsecureHttpRedirectRule(Rule):
    """
    RULE-028: Insecure HTTP Redirect Observed
    Identifies explicitly observed unencrypted HTTP redirects via Location response header.
    """

    @property
    def rule_id(self) -> str:
        return "RULE-028"

    @property
    def name(self) -> str:
        return "Insecure HTTP Redirect Observed"

    @property
    def description(self) -> str:
        return "The application was explicitly redirected to an unencrypted HTTP destination."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.HIGH
        
    @property
    def confidence(self) -> FindingConfidence:
        return FindingConfidence.HIGH

    def _get_header_values(self, headers: Dict, header_name: str) -> List[str]:
        """Get all values for a header case-insensitively."""
        values = []
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == header_name:
                if isinstance(v, list):
                    values.extend([str(item) for item in v if item])
                elif v:
                    values.append(str(v))
        return values
        
    def _redact_url(self, url: str) -> str:
        """Redact query strings and fragments from URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            redacted = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query or parsed.fragment:
                redacted += "?<redacted>"
            return redacted
        except Exception:
            return "<redacted>"

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type not in (EvidenceType.HTTP_TRAFFIC.value, EvidenceType.HTTPS_TRAFFIC.value):
                continue
            
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                response_headers = raw_metadata.get("response_headers")
                if not isinstance(response_headers, dict):
                    continue

                location_values = self._get_header_values(response_headers, "location")
                if not location_values:
                    continue
                    
                source_host = flow.get("request", {}).get("host", "unknown")
                
                for location in location_values:
                    parsed = urllib.parse.urlparse(location)
                    if parsed.scheme.lower() == "http":
                        dest_host = parsed.netloc or "unknown"
                        dedup_key = f"{self.rule_id}_{source_host}_{dest_host}"
                        
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            redacted_url = self._redact_url(location)
                            
                            finding = Finding(
                                analysis_id=session.analysis_id,
                                title=f"[{self.rule_id}] {self.name} - {dest_host}",
                                description=(
                                    f"Insecure HTTP redirect observed to {redacted_url}\n"
                                    f"Source Host: {source_host}\n"
                                    f"Destination Host: {dest_host}"
                                ),
                                severity=self.severity,
                                category=self.category,
                                status=FindingStatus.VALIDATED,
                                confidence=self.confidence,
                                evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                            )
                            result.findings.append(finding)
                            if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                                result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                            result.triggered = True
            except Exception:
                continue

        return result


class InsecureHttpReferrerRule(Rule):
    """Rule verifying whether sensitive information is transmitted via the Referer header over unencrypted HTTP."""

    @property
    def rule_id(self) -> str:
        return "RULE-029"

    @property
    def name(self) -> str:
        return "Insecure HTTP Referrer Information Observed"

    @property
    def description(self) -> str:
        return "Explicit sensitive information was transmitted through the HTTP Referer request header over unencrypted HTTP traffic."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_parameters = set()

        sensitive_params = {
            "password", "passwd", "api_key", "access_token",
            "refresh_token", "auth_token", "token", "secret",
            "client_secret", "ssn", "credit_card", "card_number", "cvv"
        }

        for ev in evidence_items:
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue

            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                req_headers = raw_metadata.get("request_headers")
                if not isinstance(req_headers, dict):
                    continue
                
                # Case-insensitive header lookup
                referer_value = None
                for k, v in req_headers.items():
                    if k.lower() == "referer":
                        referer_value = v
                        break
                        
                if not referer_value:
                    continue
                
                if isinstance(referer_value, list):
                    referer_value = referer_value[0]
                    
                if not isinstance(referer_value, str) or not referer_value.strip():
                    continue

                parsed_url = urllib.parse.urlparse(referer_value)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                host = flow.get("host", "unknown")

                for param_name, param_values in query_params.items():
                    param_name_lower = param_name.lower()
                    if param_name_lower in sensitive_params:
                        for val in param_values:
                            if not val.strip():
                                continue

                            dedup_key = f"{host}_{param_name_lower}"
                            if dedup_key not in seen_parameters:
                                seen_parameters.add(dedup_key)
                                
                                redacted_value = "<redacted>"
                                
                                finding = Finding(
                                    analysis_id=session.analysis_id,
                                    title=self.name,
                                    description=f"Host: {host}\nParameter: {param_name}\nValue: {redacted_value}",
                                    severity=FindingSeverity.HIGH,
                                    category=self.category,
                                    status=FindingStatus.VALIDATED,
                                    confidence=FindingConfidence.CERTAIN,
                                    evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"],
                                )
                                result.findings.append(finding)
                                if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                                    result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                                result.triggered = True
            except Exception:
                continue

        return result


class InsecureHttpBasicAuthRule(Rule):
    """
    RULE-030: Insecure HTTP Basic Authentication Observed
    """

    @property
    def rule_id(self) -> str:
        return "RULE-030"

    @property
    def name(self) -> str:
        return "Insecure HTTP Basic Authentication Observed"

    @property
    def description(self) -> str:
        return "The application transmitted HTTP Basic Authentication credentials over an unencrypted HTTP connection."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.CRITICAL

    @property
    def confidence(self) -> FindingConfidence:
        return FindingConfidence.HIGH

    def _get_header_values(self, headers: Dict, header_name: str) -> List[str]:
        """Get all values for a header case-insensitively."""
        values = []
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == header_name:
                if isinstance(v, list):
                    values.extend([str(item) for item in v if item])
                elif v:
                    values.append(str(v))
        return values

    def evaluate(self, session: AnalysisSession, evidence_items: List[EvidenceItem]) -> RuleResult:
        result = RuleResult(rule_id=self.rule_id, triggered=False)
        seen_keys: set = set()

        for ev in evidence_items:
            if ev.evidence_type != EvidenceType.HTTP_TRAFFIC.value:
                continue
            
            try:
                flow = json.loads(ev.content)
                raw_metadata = flow.get("raw_metadata")
                if not isinstance(raw_metadata, dict):
                    continue

                request_headers = raw_metadata.get("request_headers")
                if not isinstance(request_headers, dict):
                    continue

                auth_values = self._get_header_values(request_headers, "authorization")
                if not auth_values:
                    continue

                for auth_header in auth_values:
                    if auth_header.lower().strip().startswith("basic "):
                        source_host = flow.get("request", {}).get("host", "unknown")
                        dest_host = source_host

                        dedup_key = f"{self.rule_id}_{dest_host}"
                        
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            
                            finding = Finding(
                                analysis_id=session.analysis_id,
                                title=f"[{self.rule_id}] {self.name} - {dest_host}",
                                description=(
                                    f"Basic Authentication credentials sent over unencrypted HTTP to {dest_host}.\n"
                                    f"Payload: Basic <redacted>"
                                ),
                                severity=self.severity,
                                category=self.category,
                                status=FindingStatus.VALIDATED,
                                confidence=self.confidence,
                                evidence_references=[f"evidence_{ev.timestamp}_{ev.source}"]
                            )
                            result.findings.append(finding)
                            if f"evidence_{ev.timestamp}_{ev.source}" not in result.evidence_references:
                                result.evidence_references.append(f"evidence_{ev.timestamp}_{ev.source}")
                            result.triggered = True
            except Exception:
                continue

        return result


class RuleEngine:
    """Evaluates registered rules against an evidence collection."""

    def __init__(self) -> None:
        self._rules: List[Rule] = []

    def register_rule(self, rule: Rule) -> None:
        """Register a new Rule instance with the engine."""
        if not isinstance(rule, Rule):
            raise RuleValidationError("Provided object is not a Rule subclass.")
        
        for r in self._rules:
            if r.rule_id == rule.rule_id:
                raise RuleValidationError(f"Rule with ID {rule.rule_id} already registered.")
        
        self._rules.append(rule)

    def evaluate_all(
        self, session: AnalysisSession, evidence_items: List[EvidenceItem]
    ) -> List[RuleResult]:
        """
        Evaluate all registered rules against the provided evidence.

        Args:
            session: The analysis session.
            evidence_items: The collected evidence items.

        Returns:
            A list of RuleResult objects for each evaluated rule.
        """
        results: List[RuleResult] = []
        for rule in self._rules:
            try:
                result = rule.evaluate(session, evidence_items)
                results.append(result)
            except Exception as e:
                # Catch any unexpected evaluation errors to ensure other rules still run.
                results.append(
                    RuleResult(
                        rule_id=rule.rule_id,
                        triggered=False,
                        evaluation_details={"error": str(e)},
                    )
                )
        return results

