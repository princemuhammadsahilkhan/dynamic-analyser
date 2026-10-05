# Dynamic Analyser

Automated Android APK dynamic analysis for security-focused runtime testing.

[![Unit Tests](https://github.com/princemuhammadsahilkhan/dynamic-analyser/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/princemuhammadsahilkhan/dynamic-analyser/actions/workflows/unit-tests.yml)
[![Release](https://img.shields.io/github/v/release/princemuhammadsahilkhan/dynamic-analyser?display_name=tag&sort=semver)](https://github.com/princemuhammadsahilkhan/dynamic-analyser/releases)
[![License](https://img.shields.io/github/license/princemuhammadsahilkhan/dynamic-analyser)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

> **Dynamic Analyser v1.0.0** — a CLI-first Android runtime security analysis platform built for repeatable, evidence-driven APK testing.

Dynamic Analyser boots an isolated Android runtime, observes application behavior, collects runtime evidence, and evaluates that evidence against a rule-based security engine. Results are written to structured JSON with sensitive values redacted.

## ✦ What it does

| Capability | Description |
|---|---|
| **Runtime analysis** | Executes an APK inside an isolated Android runtime using QEMU/KVM and ADB. |
| **Evidence collection** | Captures runtime signals across network, process, filesystem, IPC, and log sources. |
| **Security rules** | Evaluates collected evidence against 30 built-in rules (`RULE-001` → `RULE-030`). |
| **Structured reporting** | Produces machine-readable `findings.json` for automation and downstream tooling. |
| **Sensitive-data protection** | Redacts credentials, authentication payloads, cookies, and other sensitive values from findings. |
| **Session isolation** | Keeps runtime state and subprocess cleanup scoped to the active analysis session. |
| **Automation-friendly CLI** | Provides explicit success/failure states and predictable command-line behavior. |

## Architecture

```text
┌──────────────┐
│   Target APK │
└──────┬───────┘
       ▼
┌──────────────┐
│     CLI      │
└──────┬───────┘
       ▼
┌──────────────────────────────┐
│       Analysis Runner        │
│                              │
│  QEMU/KVM  ·  ADB  · Proxy  │
│             │                │
│       Runtime Observation    │
└──────────────┬───────────────┘
               ▼
       ┌──────────────┐
       │   Evidence   │
       └──────┬───────┘
              ▼
       ┌──────────────┐
       │ Rule Engine  │
       └──────┬───────┘
              ▼
       ┌──────────────┐
       │ findings.json│
       └──────────────┘
```

The engine is intentionally independent of a web interface. If a frontend is added later, the intended architecture is:

```text
Web UI → API → Dynamic Analyser Engine
```

This keeps the analysis engine reusable instead of coupling security logic to a presentation layer.

## Requirements

Dynamic Analyser is a host-side security analysis tool and requires a Linux environment capable of running the Android runtime.

- Python 3.10+
- QEMU with KVM support
- Android Debug Bridge (`adb`)
- Android emulator/runtime assets and a configured AVD
- `mitmdump` / mitmproxy
- Sufficient CPU, RAM, and virtualization support

See [`docs/development/HOST_PREREQUISITES.md`](docs/development/HOST_PREREQUISITES.md) for environment details.

## Installation

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

The module entry point is also available without installing the console command:

```bash
PYTHONPATH=src python3 -m dynamic_analysis.cli --help
```

## Quick Start

Analyze an APK:

```bash
dynamic-analyser --apk /path/to/app.apk
```

Each analysis receives an isolated output location containing structured evidence and findings.

The CLI returns `0` for a successful analysis and `1` when analysis fails.

## Findings

The primary report is `findings.json`. Findings include structured fields such as:

- `rule_id`
- `title`
- `severity`
- `category`
- `status`
- `confidence`
- `evidence_references`

Sensitive values are deliberately omitted or redacted. For example, HTTP Basic Authentication detection reports the security issue without exposing the Base64 credential payload.

> **Important:** The absence of a finding does not prove that an application is secure. Dynamic analysis only observes behavior exercised during the analysis session.

## Security & Safety

Dynamic Analyser is designed to keep analysis processes scoped to the active session. Production paths do not rely on host-wide `pkill` or `killall` cleanup commands.

The target APK is analyzed as supplied; the standard workflow does not require modifying, repackaging, or patching the APK.

Generated analysis results and local APK artifacts are excluded from version control by `.gitignore`.

For vulnerability reports, see [`SECURITY.md`](SECURITY.md).

## Testing

Run the unit suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/unit -p "test_*.py"
```

The v1.0.0 release was validated with **519 passing unit tests**.

Integration tests exercise the Android/QEMU runtime and are intentionally separate from the lightweight CI unit-test gate. On heavily nested virtualization environments, repeatedly starting QEMU instances can exhaust host memory mappings. Run those tests selectively on a suitable analysis host.

## Project Status

**Current release: `v1.0.0`**

The core CLI workflow, evidence collection, rule engine, failure handling, serialization, sensitive-data redaction, and session cleanup have been validated for the v1.0 release.

### Known limitation

Bulk sequential QEMU integration testing can be constrained by nested virtualization resources. This is an environment limitation and does not represent the normal single-analysis CLI workflow on a host with adequate virtualization support.

## Documentation

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Requirements](docs/requirements/REQUIREMENTS.md)
- [Traceability](docs/requirements/TRACEABILITY.md)
- [Host prerequisites](docs/development/HOST_PREREQUISITES.md)
- [Security](SECURITY.md)
- [Licensing](docs/licensing/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

Security vulnerabilities should not be reported through public issues. See [`SECURITY.md`](SECURITY.md) for the reporting process.

## License

Dynamic Analyser is released under the [MIT License](LICENSE).

Copyright © 2026 Prince Muhammad Sahil Khan.
