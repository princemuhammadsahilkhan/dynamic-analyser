# ADR-0005: Configuration Boundary

## Status
Accepted

## Decision
Establish a dedicated Python module boundary (`src/dynamic_analysis/config.py`) for application configuration using standard-library dataclasses and environment-variable mapping mechanisms.

## Context
The project requires a clear, decoupled configuration entry point for managing runtime parameters and environment inputs as subsystems are developed. At this stage, no specific subsystem architectures (Android runtime, proxy, database, instrumentation, reporting, API, storage) or specific configuration schemas have been selected.

## Rationale
- Application configuration will have a dedicated Python module boundary.
- Configuration values will not be invented before their owning subsystem is defined.
- Environment variables may be used as an input mechanism where appropriate.
- Secrets must not be hard-coded into source code.
- A configuration framework has not been selected.
- The configuration schema remains intentionally minimal at this stage.

## Scope
This decision applies exclusively to establishing the module boundary and design principles for application configuration management.

## Not Decided
The following items remain explicitly undecided:
- Third-party configuration framework selection (e.g., Pydantic Settings, Dynaconf)
- Subsystem-specific configuration attributes (Android, emulator, proxy, instrumentation, database, storage, API, auth)
- Configuration file formats (TOML, YAML, JSON, INI)
- Secret storage and key management integration

## Consequences
- Subsystems will define their configuration parameters within or extending this dedicated configuration boundary as their architectural decisions are approved.
- Secrets must not be hard-coded into source code under any circumstances.
- Standard library features remain the baseline for configuration parsing until a framework is explicitly evaluated and selected.
