# Dynamic Analyser

## What it does
The Dynamic Analyser is an automated dynamic analysis engine designed to evaluate Android APKs for security vulnerabilities. It orchestrates a headless Android emulator, captures network and system evidence during runtime, and evaluates that evidence against a suite of 30 specialized security rules. Findings are then serialized into a concise, redacted JSON report.

## Supported Analysis Workflow
1. The user provides a target APK via the CLI.
2. The orchestrator boots a clean Android emulator using QEMU.
3. The engine captures evidence across multiple dimensions (network traffic, IPC, filesystem, logs, etc.).
4. The rule engine processes the collected evidence against `RULE-001` through `RULE-030`.
5. The analyzer halts, tears down the emulator and proxy safely, and saves `findings.json` in a timestamped output directory.

## Required Environment & Dependencies
- Python 3.9+
- QEMU and KVM (for running the headless emulator)
- `mitmproxy` / `mitmdump` for intercepting network traffic
- ADB (Android Debug Bridge) installed and accessible in the system path
- Enough memory to support headless Android VMs

## APK Requirements
- The APK must be a valid, standard Android application package.
- Ensure the APK is untampered and verified before processing (e.g., matching the expected SHA-256 hash).
- The current verified target is `apks/app-release.apk` with SHA-256 `c06568ac3d86ac9a0632db650ed577d2dbbcbae76b3f77eaef02ae903d736215`.

### Quick Start (Version 1.0)
1. **Install prerequisites**: Ensure QEMU, KVM, `mitmdump`, ADB, and Python 3.9+ are installed and on your PATH.
2. **Prepare APK**: Place your target APK in an accessible directory (e.g. `apks/app-release.apk`).
3. **Run analyser**: Execute the following command from the project root:
   ```bash
   PYTHONPATH=src python3 -m dynamic_analysis.cli --apk apks/app-release.apk
   ```
4. **Locate results**: The engine will generate a timestamped output directory (e.g., `output/27ea6114042c41bb/evidence/findings.json`).
5. **Review findings**: Open `findings.json` to review any triggered security rules and collected evidence.

## Output and Interpreting `findings.json`
- **Output Location**: Each run creates a new timestamped directory in the project root containing evidence and the `findings.json` report.
- **Interpreting Results**: `findings.json` contains a list of triggered security rules. Each finding includes:
  - `rule_id`: The ID of the triggered rule (e.g., `RULE-030`).
  - `title`: A human-readable name of the vulnerability.
  - `severity`: Denotes the risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - `confidence`: Indicates the certainty of the finding (`LOW`, `MEDIUM`, `HIGH`, `CERTAIN`).
  - `evidence_summary`: A sanitized explanation of what triggered the rule.

## Sensitive-Data Redaction Behavior
The Dynamic Analyser is designed with strict redaction constraints. Any sensitive payload values (e.g., Basic Auth credentials, PII) are inherently redacted from findings. The evidence summary will confirm the presence of the data, but never expose the concrete payload itself.

## Session Cleanup Behavior
Cleanup is strictly bound to the `AnalysisSession`. When the analysis completes (or fails), the orchestrator safely and explicitly terminates its own managed processes (`qemu-system-x86_64`, `mitmdump`) without relying on host-wide destructive actions like `pkill` or `killall`.

## Operator Troubleshooting and Failure Handling
- **Failure Handling**: If the orchestrator fails to launch the emulator or collect evidence, it will gracefully tear down partial environments and log the exception details.
- **Known Limitations**:
  - **Memory Mapping Errors**: When running analyses in rapid succession (e.g., back-to-back integration test suites), you may encounter kernel-level memory mapping warnings in QEMU (`cannot unmap ptr...`). This is a test-environment limitation due to nested virtualization constraints and not a production defect in the Analyser. Wait a few moments between sequential runs if this occurs.
  - **No GUI / Frontend**: There is currently no web interface; the CLI is the singular entry point.

## Release Candidate Status
The engine is currently **READY WITH DOCUMENTED NON-BLOCKERS**. The CLI is fully sufficient for initial operational use, with a well-defined boundary for a future frontend or API integration layer to be added later.
