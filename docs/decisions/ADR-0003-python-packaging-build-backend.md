# ADR-0003: Python Packaging Build Backend

## Status
Accepted

## Decision
Select `setuptools` (specifically `setuptools.build_meta`) as the Python packaging build backend for the project (`requires = ["setuptools>=61.0"]`, `build-backend = "setuptools.build_meta"`).

## Context
The project is a greenfield Python system (`dynamic-analysis`) targeting Python >=3.10 with source code located under `src/dynamic_analysis`. To support standard installation, packaging, and PEP 621 metadata declaration (`pyproject.toml`), a PyPA-compliant build backend must be designated for the project per PEP 517 and PEP 518 specifications.

## Rationale
- `setuptools` (and its build backend `setuptools.build_meta`) is available and verified in the development environment.
- `setuptools>=61.0` provides full native compliance with PyPA PEP 621 specification for project metadata (`[project]` table in `pyproject.toml`).
- `setuptools` natively supports automatic layout package discovery for the `src/` directory layout (`[tool.setuptools.packages.find]`).
- It avoids unnecessary build backend dependencies and ensures compatibility across all supported Python versions (3.10 and above).
- Alternative build backends evaluated: `poetry.core` (available, but introduces coupling to Poetry tool conventions), `hatchling` (not installed in host environment), `flit_core` (not installed in host environment).

## Scope
This decision applies strictly and exclusively to the Python package build backend declared in `[build-system]` of `pyproject.toml`.

## Not Decided
This decision explicitly does NOT select:
- dependency manager (e.g., `pip`, `uv`, `poetry`, `pip-tools`)
- virtual-environment manager (e.g., `venv`, `uv`, `virtualenv`, `conda`)
- web framework
- task queue
- database
- frontend technology
- Android runtime
- emulator
- proxy
- instrumentation framework
- deployment model

## Consequences
The project uses `setuptools.build_meta` as its standard build backend in `pyproject.toml`. Package building, wheel creation, and editable installs will use PyPA standards built around `setuptools.build_meta`.
