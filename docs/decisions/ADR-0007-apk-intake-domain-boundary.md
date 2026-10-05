# ADR-0007: APK Intake Domain Boundary

## Status
Accepted

## Decision
Establish an `APKInput` domain boundary in `src/dynamic_analysis/apk.py` representing target Android APK inputs and basic format validation per requirement DA-004.

## Context
Requirements DA-002 and DA-004 mandate accepting target Android APK files as input and performing basic validation prior to initiating execution. A domain boundary is required to represent submitted APK artifacts and validate basic integrity without coupling to Android execution engines, storage systems, or static analysis tools.

## Rationale
- Implements a pure domain boundary using standard-library modules (`dataclasses`, `pathlib`, `zipfile`).
- Provides basic artifact validation (file existence, `.apk` extension, and zip container integrity) as required by DA-004 before initiating job execution.
- Strictly decouples APK intake and validation from downstream responsibilities (APK installation, launch, execution, device management, dynamic analysis, and persistence) per Section 17.
- Avoids unapproved fields such as hashes, package names, version strings, signing certificates, database IDs, or extraction paths.

## Scope
This decision applies exclusively to the domain representation of an intake APK artifact and basic format validation.

## Not Decided
This decision explicitly does NOT select or define:
- Third-party APK parsing or Android manifest extraction libraries
- Static code analysis or vulnerability scanner tools
- Signing certificate verification engines or key stores
- Database persistence or file storage mechanisms for APK files
- Android runtime environment installation or adb execution workflows

## Consequences
- Intake interfaces will instantiate `APKInput` and perform basic validation (`is_valid_apk()`) prior to launching execution jobs.
- Downstream execution engines operate on validated `APKInput` references without embedding intake logic.
