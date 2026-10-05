"""Automated dynamic-analysis run orchestration workflow layer."""

import json
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

from dynamic_analysis.apk import APKLifecycleManager, APKLifecycleResult
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.observation import (
    EvidenceItem,
    EvidenceType,
    LogcatCollector,
    RuntimeObserver,
    _get_utc_timestamp,
    save_evidence_items,
)
from dynamic_analysis.runtime import AndroidRuntimeError, AndroidRuntimeOrchestrator
from dynamic_analysis.session import AnalysisSession, SessionStatus
from dynamic_analysis.finding import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
)


from dynamic_analysis.network import NetworkObserver
from dynamic_analysis.proxy import ProxyManager


class WorkflowError(AndroidRuntimeError):
    """Base exception for analysis workflow runner errors."""

    pass


@dataclass
class AnalysisRunResult:
    """Structured result object produced by an AnalysisRunner workflow run."""

    job: Optional[AnalysisJob]
    success: bool
    error_message: Optional[str] = None
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    evidence_file_path: Optional[str] = None
    apk_result: Optional[APKLifecycleResult] = None
    execution_duration: float = 0.0
    session: Optional[AnalysisSession] = None
    findings: List[Finding] = field(default_factory=list)


def _build_session_evidence(session: AnalysisSession) -> EvidenceItem:
    """Create a SESSION evidence item from the session's JSON-safe state."""
    return EvidenceItem(
        evidence_type=EvidenceType.SESSION.value,
        timestamp=_get_utc_timestamp(),
        serial="",
        source="AnalysisSession",
        content=session.to_json(),
        metadata={
            "analysis_id": session.analysis_id,
            "status": session.status.value,
        },
    )


class AnalysisRunner:
    """Orchestrates runtime, APK lifecycle, observation, network, and proxy collection into a single workflow."""

    def __init__(
        self,
        orchestrator: Optional[AndroidRuntimeOrchestrator] = None,
        apk_manager: Optional[APKLifecycleManager] = None,
        observer: Optional[RuntimeObserver] = None,
        logcat_collector: Optional[LogcatCollector] = None,
        network_observer: Optional[NetworkObserver] = None,
        proxy_manager: Optional[ProxyManager] = None,
    ) -> None:
        if orchestrator is None:
            orchestrator = AndroidRuntimeOrchestrator()
        self.orchestrator = orchestrator
        self.apk_manager = apk_manager or APKLifecycleManager(self.orchestrator)
        self.observer = observer or RuntimeObserver(self.orchestrator)
        self.logcat_collector = logcat_collector or LogcatCollector(self.orchestrator)
        self.network_observer = network_observer or NetworkObserver(self.orchestrator)
        self.proxy_manager = proxy_manager or ProxyManager(self.orchestrator)

    def run(
        self,
        job: Optional[AnalysisJob] = None,
        apk_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        launch_app: bool = True,
        boot_timeout: Optional[float] = None,
        raise_on_error: bool = False,
        enable_proxy: bool = False,
        observation_duration: float = 3.0,
        session: Optional[AnalysisSession] = None,
    ) -> AnalysisRunResult:

        """Execute a complete, repeatable dynamic-analysis run workflow."""
        start_time = time.time()
        evidence_items: List[EvidenceItem] = []
        findings: List[Finding] = []
        apk_result: Optional[APKLifecycleResult] = None
        evidence_file_path: Optional[str] = None

        # --- Session resolution ---
        target_apk = job.apk_path if job else apk_path
        if session is None and target_apk:
            session = AnalysisSession(
                apk_path=target_apk,
                base_output_dir=output_dir if output_dir else os.path.join(os.getcwd(), "output"),
            )
        elif target_apk is None and session is not None:
            target_apk = session.apk_path

        # Populate session config_metadata with JSON-safe run parameters
        if session is not None:
            
            session.config_metadata.update({
                "launch_app": str(launch_app),
                "proxy_enabled": str(enable_proxy),
            })
            if boot_timeout is not None:
                session.config_metadata["boot_timeout"] = str(boot_timeout)
            if hasattr(self.orchestrator, "config"):
                cfg = self.orchestrator.config
                session.config_metadata["avd_name"] = cfg.avd_name
                session.config_metadata["adb_serial"] = cfg.serial

        # Resolve effective output directory: explicit output_dir wins, otherwise session run_dir
        effective_output_dir = output_dir
        if effective_output_dir is None and session is not None:
            effective_output_dir = session.evidence_dir

        # --- Session lifecycle: CREATED -> RUNNING ---
        if session is not None and session.status == SessionStatus.CREATED:
            session.transition_to(SessionStatus.RUNNING)

        if job:
            job.transition_to(JobState.EXECUTING)

        try:
            # 1. Start AVD emulator child process
            self.orchestrator.start()

            # 2. Wait for guest OS boot completion
            self.orchestrator.wait_for_boot(timeout=boot_timeout)

            # 3. Start proxy and configure emulator proxy if enabled
            if enable_proxy:
                flow_file = (
                    os.path.join(effective_output_dir, "mitm_traffic.mitm") if effective_output_dir else None
                )
                self.proxy_manager.start(flow_file=flow_file)
                self.proxy_manager.configure_emulator_proxy()

            # 4. Start streaming logcat observation prior to application execution
            self.logcat_collector.start(clear_buffer=True)

            # 5. Collect baseline guest system properties and process list
            initial_props = self.observer.collect_properties()
            initial_procs = self.observer.collect_processes()
            evidence_items.extend(initial_props)
            evidence_items.append(initial_procs)

            # 6. Execute APK lifecycle if a target APK is specified
            if target_apk:
                apk_result = self.apk_manager.run_lifecycle(target_apk, launch=launch_app)
                if launch_app and observation_duration > 0:
                    time.sleep(observation_duration)

            # 7. Update job state to evidence collection
            if job:
                job.transition_to(JobState.COLLECTING_EVIDENCE)

            # 8. Collect post-execution guest processes, logcat dump, and network evidence
            post_procs = self.observer.collect_processes()
            logcat_dump = self.observer.collect_logcat_dump()
            evidence_items.append(post_procs)
            evidence_items.append(logcat_dump)

            if target_apk and apk_result and apk_result.package_name:
                try:
                    permission_evidence = self.observer.collect_permissions(apk_result.package_name)
                    evidence_items.append(permission_evidence)
                except Exception as e:


                    # Log or ignore if permissions cannot be collected
                    pass

            network_evidence = self.network_observer.collect_all_network_evidence()
            evidence_items.extend(network_evidence)

            if enable_proxy:
                proxy_evidence = self.proxy_manager.get_evidence_items()
                evidence_items.extend(proxy_evidence)

            # 9. Stop streaming logcat collector and capture streamed evidence
            streamed_logcat = self.logcat_collector.stop()
            evidence_items.append(streamed_logcat)

            # 10. Update job state to reporting
            if job:
                job.transition_to(JobState.REPORTING)

            # 11. Append session evidence item
            if session is not None:
                evidence_items.append(_build_session_evidence(session))

            # 12. Persist structured evidence items if an output directory is available
            if effective_output_dir:
                evidence_file_path = save_evidence_items(evidence_items, effective_output_dir)

            # 13. Update job state to completed
            if job:
                job.transition_to(JobState.COMPLETED)

            # 14. Session lifecycle: RUNNING -> COMPLETED
            if session is not None and session.status == SessionStatus.RUNNING:
                session.transition_to(SessionStatus.COMPLETED)

            # 15. Finding Generation using RuleEngine
            if session:
                from dynamic_analysis.rules import (
                    RuleEngine, 
                    TargetProcessObservedRule, 
                    ProxyConfiguredRule,
                    CleartextTrafficRule,
                    WeakTLSRule,
                    WeakTLSCipherRule,
                    MissingHSTSRule,
                    MissingXCTORule,
                    Rule008InsecureCookieAttributeRule,
                    InsecureCORSRule,
                    MissingReferrerPolicyRule,
                    MissingCSPRule,
                    MissingXFrameOptionsRule,
                    MissingContentSecurityPolicyRule,
                    SensitivePermissionObservedRule,
                    InsecureCookieAttributeRule,
                    MissingCacheControlRule,
                    ServerHeaderDisclosureRule,
                    MissingPermissionsPolicyRule,
                    SensitiveLogcatDataRule,
                    SensitiveNetworkDataRule,
                    InsecureHttpAuthRule,
                    InsecureHttpSensitiveDataRule,
                    InsecureHttpCookieTransmissionRule,
                    InsecureHttpAuthCookieRule,
                    InsecureHttpFormSubmissionRule,
                    InsecureHttpQueryParameterRule,
                    InsecureHttpSensitiveHeaderRule,
                    InsecureHttpRedirectRule,
                    InsecureHttpReferrerRule,
                    InsecureHttpBasicAuthRule
                )
                engine = RuleEngine()
                engine.register_rule(TargetProcessObservedRule())
                engine.register_rule(ProxyConfiguredRule())
                engine.register_rule(CleartextTrafficRule())
                engine.register_rule(WeakTLSRule())
                engine.register_rule(WeakTLSCipherRule())
                engine.register_rule(MissingHSTSRule())
                engine.register_rule(MissingXCTORule())
                engine.register_rule(Rule008InsecureCookieAttributeRule())
                engine.register_rule(InsecureCORSRule())
                engine.register_rule(MissingReferrerPolicyRule())
                engine.register_rule(MissingCSPRule())
                engine.register_rule(MissingXFrameOptionsRule())
                engine.register_rule(MissingContentSecurityPolicyRule())
                engine.register_rule(SensitivePermissionObservedRule())
                engine.register_rule(InsecureCookieAttributeRule())
                engine.register_rule(MissingCacheControlRule())
                engine.register_rule(ServerHeaderDisclosureRule())
                engine.register_rule(MissingPermissionsPolicyRule())
                engine.register_rule(SensitiveLogcatDataRule())
                engine.register_rule(SensitiveNetworkDataRule())
                engine.register_rule(InsecureHttpAuthRule())
                engine.register_rule(InsecureHttpSensitiveDataRule())
                engine.register_rule(InsecureHttpCookieTransmissionRule())
                engine.register_rule(InsecureHttpAuthCookieRule())
                engine.register_rule(InsecureHttpFormSubmissionRule())
                engine.register_rule(InsecureHttpQueryParameterRule())
                engine.register_rule(InsecureHttpSensitiveHeaderRule())
                engine.register_rule(InsecureHttpRedirectRule())
                engine.register_rule(InsecureHttpReferrerRule())
                engine.register_rule(InsecureHttpBasicAuthRule())
                
                results = engine.evaluate_all(session, evidence_items)
                
                seen_finding_ids = set()
                for res in results:
                    if res.triggered:
                        for f in res.findings:
                            if f.finding_id not in seen_finding_ids:
                                findings.append(f)
                                seen_finding_ids.add(f.finding_id)
                
                os.makedirs(session.findings_dir, exist_ok=True)
                findings_file = os.path.join(session.findings_dir, "findings.json")
                try:
                    with open(findings_file, "w", encoding="utf-8") as f:
                        json.dump([f.to_dict() for f in findings], f, indent=2)
                except TypeError:
                    findings_data = [f.to_dict() for f in findings]
                    for i, item in enumerate(findings_data):
                        try:
                            json.dumps(item)
                        except TypeError:
                            print(f"Serialization failed for finding {i}: {item}")
                    raise

            duration = time.time() - start_time
            return AnalysisRunResult(
                job=job,
                success=True,
                error_message=None,
                evidence_items=evidence_items,
                evidence_file_path=evidence_file_path,
                apk_result=apk_result,
                execution_duration=duration,
                session=session,
                findings=findings,
            )

        except Exception as exc:
            if job:
                job.transition_to(JobState.FAILED)

            # Session lifecycle: RUNNING -> FAILED
            if session is not None and session.status == SessionStatus.RUNNING:
                session.transition_to(SessionStatus.FAILED)

            duration = time.time() - start_time

            if raise_on_error:
                raise WorkflowError(f"Workflow execution failed: {exc}") from exc

            return AnalysisRunResult(
                job=job,
                success=False,
                error_message=str(exc),
                evidence_items=evidence_items,
                evidence_file_path=evidence_file_path,
                apk_result=apk_result,
                execution_duration=duration,
                session=session,
                findings=findings,
            )

        finally:
            # Restore emulator proxy setting if configured
            if self.proxy_manager.get_status().proxy_configured:
                try:
                    self.proxy_manager.restore_emulator_proxy()
                except Exception:
                    pass

            # Guarantee proxy child process termination
            if self.proxy_manager.is_running():
                try:
                    self.proxy_manager.stop()
                except Exception:
                    pass

            # Guarantee logcat streaming process termination
            if self.logcat_collector.is_running():
                try:
                    self.logcat_collector.stop()
                except Exception:
                    pass

            # Guarantee emulator child process shutdown
            if self.orchestrator.is_running():
                try:
                    self.orchestrator.shutdown()
                except Exception:
                    pass
