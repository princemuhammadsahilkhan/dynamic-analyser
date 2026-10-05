# ADR-0002: Minimum Supported Python Version

## Status
Accepted

## Decision
The backend and orchestration layer targets Python 3.10 or higher (`requires-python = ">=3.10"`).

## Context
Environment inspection confirmed that Python 3.13.3 is installed on the development host. The project requires defining standard packaging metadata (`pyproject.toml`) and specifying a supported Python version range for development and execution.

## Rationale
- Python 3.10 is the minimum active Python version supporting native PEP 621 project metadata and modern language capabilities (e.g., structural pattern matching and modern type hinting syntax).
- Python 3.13.3 is the active host interpreter and is fully compatible with a `>=3.10` version constraint.
- Python 3.13 is not designated as the minimum version solely due to its presence on the current host; declaring `>=3.10` maintains compatibility across modern supported Python 3 releases (3.10 through 3.13+) without imposing an artificial host lock.

## Scope
This decision applies exclusively to the supported Python version range for the backend/orchestration package (`dynamic-analysis`).

## Not Decided
The following items remain explicitly undecided:
- Virtual environment tool selection (e.g. `venv`, `uv`, `poetry`, `conda`)
- Package dependency manager selection
- Third-party library and framework selections
- Container image base OS and Python build choices

## Consequences
Future backend code and dependency selections must maintain compatibility with Python versions 3.10 and higher unless this ADR is later superseded.
