# ADR-0004: Development Environment and Dependency Workflow

## Status
Accepted

## Decision
Select Python built-in `venv` (`python3 -m venv`) for virtual environment isolation and `pip` for dependency installation and management, aligned with standard PyPA PEP 621 `pyproject.toml` metadata.

## Context
The project uses Python (>=3.10) with `setuptools.build_meta` as its packaging build backend (ADR-0001, ADR-0002, ADR-0003) and a `src/` layout (`src/dynamic_analysis`). A clear, reproducible workflow is needed for developers to manage local virtual environments and project dependencies without conflicting with the selected packaging build backend.

## Rationale
- **Available & Verified**: `venv` (Python 3.13.3 standard library) and `pip` (v25.1.1) are installed and verified on the host system.
- **Standards Compliant**: `pip` (>=21.3) natively supports PEP 621 `[project]` metadata, PEP 517/518 build backends (`setuptools.build_meta`), and PEP 660 editable installs (`pip install -e .`).
- **Clean Separation of Concerns**:
  - **Build Backend**: `setuptools.build_meta` (builds sdist/wheel packages)
  - **Environment Isolation**: `python3 -m venv .venv` (creates isolated runtime environment)
  - **Dependency Installation**: `pip` (installs packages into activated virtual environment)
  - **Runtime Dependencies**: Declared in `pyproject.toml` under `[project.dependencies]`
  - **Development/Test Dependencies**: Declared in `pyproject.toml` under `[project.optional-dependencies]`
- **Avoids Tooling Conflicts**: Alternatives such as Poetry (v2.3.4) couple dependency management with Poetry's own build backend (`poetry.core`), which conflicts with the accepted `ADR-0003` decision to use `setuptools.build_meta`.

## Scope
This decision applies exclusively to local development environment creation, activation, and dependency installation workflows for `dynamic-analysis`.

## Not Decided
This decision explicitly does NOT select:
- runtime third-party libraries or packages
- development or test libraries (e.g., pytest, mypy, ruff)
- web framework
- task queue
- database
- Android runtime or emulator
- proxy technology
- instrumentation framework
- deployment model

## Consequences
- Local development virtual environments will be created via `python3 -m venv .venv`.
- Project dependencies will be recorded standardly in `pyproject.toml` and installed via `pip`.
- Local editable installation of the `dynamic_analysis` package will be performed via `pip install -e .`.
- The packaging build backend (`setuptools.build_meta`) remains unchanged.
