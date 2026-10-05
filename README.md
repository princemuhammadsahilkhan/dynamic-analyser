# Dynamic Analyser

Automated Android APK dynamic analysis for security-focused runtime testing.

[![Unit Tests](https://github.com/princemuhammadsahilkhan/dynamic-analyser/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/princemuhammadsahilkhan/dynamic-analyser/actions/workflows/unit-tests.yml)
[![Release](https://img.shields.io/github/v/release/princemuhammadsahilkhan/dynamic-analyser?display_name=tag&sort=semver)](https://github.com/princemuhammadsahilkhan/dynamic-analyser/releases)
[![License](https://img.shields.io/github/license/princemuhammadsahilkhan/dynamic-analyser)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

Dynamic Analyser boots an isolated Android runtime, observes application behavior, collects runtime evidence, and evaluates that evidence against a rule-based security engine. Results are written to structured JSON with sensitive values redacted.

## Highlights

- Headless Android analysis using QEMU/KVM and ADB
- Runtime evidence collection across network, process, filesystem, IPC, and log sources
- 30 built-in security rules (`RULE-001` through `RULE-030`)
- Deterministic, session-scoped analysis state and cleanup
- Structured `findings.json` output
- Sensitive authentication and payload data redaction
- Explicit success and failure states for automation-friendly use
- CLI-first architecture designed to support a future API/UI layer without coupling the engine to a frontend

## Architecture

```text
Target APK
   │
   ▼
CLI
   │
   ▼
Analysis Runner
   ├── Android Runtime / QEMU
   ├── ADB
   ├── Network Proxy / mitmdump
   └── Runtime Observation
          │
          ▼
      Evidence Store
          │
          ▼
       Rule Engine
          │
          ▼
      findings.json
```

The analysis engine is intentionally independent of any web interface. A future product layer can be added as `Web UI → API → Dynamic Analyser Engine` without duplicating analysis logic.

## Requirements

Dynamic Analyser is a host-side security analysis tool and requires a Linux environment capable of running the Android runtime.

- Python 3.10+
- QEMU with KVM support
- Android Debug Bridge (`adb`)
- Android emulator/runtime assets and the configured AVD
- `mitmdump` / mitmproxy
- Sufficient CPU, RAM, and virtualization support for the Android guest

See [`docs/development/HOST_PREREQUISITES.md`](docs/development/HOST_PREREQUISITES.md) for environment details.

## Installation

Clone the repository and install it into a virtual environment:

```bash
git clone https://github.com/princemuhammadsahilkhan/dynamic-analyser.git
cd dynamic-analyser
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify the installation:

```bash
dynamic-analyser --help
```

If you prefer not to install the console command, the module entry point remains available:

```bash
PYTHONPATH=src python3 -m dynamic_analysis.cli --help
```

## Quick Start

Analyze an APK:

```bash
dynamic-analyser --apk /path/to/app.apk
```

Useful options:

```text
--apk PATH             Target APK
--avd NAME             Android AVD name
--output-dir PATH      Output directory
--no-launch            Install/analyze without automatically launching the app
--boot-timeout SECONDS Guest boot timeout
```

The command returns exit code `0` for a successful analysis and `1` when the analysis fails.

Each run receives its own output location. The report includes structured findings and evidence references suitable for further processing.

## Findings

The primary report is `findings.json`. Findings contain structured fields such as:

- `rule_id`
- `title`
- `severity`
- `category`
- `status`
- `confidence`
- `evidence_references`

Sensitive values are deliberately omitted or redacted. For example, a detected HTTP Basic Authentication credential is reported as a security finding without exposing the Base64 credential payload.

> Do not treat the absence of a finding as proof that an application is secure. Dynamic analysis only observes behavior exercised during the analysis session.

## Security and Safety

Dynamic Analyser is designed to keep analysis processes scoped to the active session. It does not rely on host-wide `pkill` or `killall` cleanup commands.

The target APK is analyzed as supplied; the project does not require modifying, repackaging, or instrumenting the APK as part of the standard workflow.

For security-sensitive reports, keep generated output outside version control. The repository's `.gitignore` excludes generated `output/` data and local APK artifacts.

## Testing

Run the unit suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/unit -p "test_*.py"
```

The v1.0.0 release was validated with 519 passing unit tests.

Integration tests exercise the Android/QEMU runtime and are intentionally separate from the lightweight CI unit-test gate. On heavily nested virtualization environments, repeatedly starting QEMU instances can exhaust host memory mappings. Run those tests selectively on a suitable analysis host.

## Project Status

**v1.0.0 — released.**

The core CLI workflow, rule engine, evidence collection, failure handling, serialization, and session cleanup have been validated for the v1.0 release.

Known limitation: bulk sequential QEMU integration testing can be constrained by nested virtualization resources. This does not apply to the normal single-analysis CLI workflow when the host has adequate virtualization resources.

## Documentation

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Requirements](docs/requirements/REQUIREMENTS.md)
- [Traceability](docs/requirements/TRACEABILITY.md)
- [Host prerequisites](docs/development/HOST_PREREQUISITES.md)
- [Security documentation](docs/security/README.md)
- [Licensing](docs/licensing/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

Security vulnerabilities should not be reported through public issues. See [`SECURITY.md`](SECURITY.md) for the reporting process.

## License

Dynamic Analyser is released under the [MIT License](LICENSE).

Copyright © 2026 Prince Muhammad Sahil Khan.
