# Changelog

All notable changes to Dynamic Analyser are documented here.

## [1.0.0] - 2026

### Added

- End-to-end Android APK dynamic analysis workflow.
- QEMU-based Android runtime orchestration.
- ADB-backed runtime observation and evidence collection.
- Network interception and HTTP/HTTPS traffic analysis.
- 30 registered security rules (`RULE-001` through `RULE-030`).
- Structured JSON findings output.
- Sensitive-data redaction for reportable evidence.
- Scoped subprocess lifecycle and cleanup.
- Explicit success and failure state handling.
- CLI entry point for running analyses.
- Unit-test suite covering the core engine.
- Documentation for architecture, requirements, security, development, and licensing.

### Security

- Plaintext HTTP Basic Authentication detection with credential payload redaction.
- No host-wide `pkill` or `killall` cleanup in production paths.
- APK inputs are validated before analysis.

### Known limitations

- Full integration suites can be resource-intensive under nested virtualization because of repeated QEMU startup and teardown.
- Frida instrumentation is optional/disabled by design in constrained environments; the analyser provides an observation fallback.

[1.0.0]: https://github.com/princemuhammadsahilkhan/dynamic-analyser/releases/tag/v1.0.0
