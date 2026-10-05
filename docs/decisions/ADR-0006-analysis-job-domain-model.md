# ADR-0006: Analysis Job Domain Model

## Status
Accepted

## Decision
Establish an in-memory domain model (`AnalysisJob`) and lifecycle state enumeration (`JobState`) in `src/dynamic_analysis/job.py` containing strictly the fields and states explicitly supported by the authoritative product requirements (`docs/requirements/REQUIREMENTS.md`).

## Context
Requirements DA-002, DA-003, DA-013, and DA-016 mandate tracking dynamic analysis jobs from submission through execution, evidence collection, report generation, or failure handling. An in-memory domain representation is required to encapsulate job state without coupling to execution engines, databases, or UI implementations.

## Rationale
- Defines a pure domain model using standard-library dataclasses and enumerations (`dataclasses`, `enum`).
- Retains strictly the fields supported by requirement text: `apk_path` (DA-002, DA-004) and `state` (DA-003, DA-013).
- Retains strictly the job states anchored in explicit requirement text:
  - `SUBMITTED`: DA-003 ("from submission")
  - `EXECUTING`: DA-003 ("through execution"), DA-006 ("APK execution management"), DA-013 ("execution state")
  - `COLLECTING_EVIDENCE`: DA-003 ("evidence collection"), DA-010 ("Collect runtime observation data and evidence")
  - `REPORTING`: DA-003 ("and final report generation"), DA-012 ("structured summary reports")
  - `COMPLETED`: DA-002 ("upon completion")
  - `FAILED`: DA-016 ("execution failures, timeouts, runtime crashes, and invalid inputs")
- Removes unanchored intermediate states (`VALIDATING`, `ANALYZING`) that were not explicitly designated as tracked job states in DA-003.
- Rejects unapproved fields such as database primary keys, UUID schemas, timestamps, user identities, priority levels, or queue routing flags.

## Scope
This decision applies exclusively to the in-memory domain model representation of an analysis job.

## Not Decided
This decision explicitly does NOT select or define:
- Job persistence mechanisms, ORMs, or database schemas
- Unique identifier generation strategy (e.g., UUID vs. sequence)
- Task queues, background workers, or job orchestrators
- Timestamping, auditing, or event history structures
- Concurrency, worker allocation, or job queue priorities
- Execution timeouts, retry policies, or resource quotas

## Consequences
Subsystems (orchestrators, intake handlers, analysis components) will pass and transition `AnalysisJob` domain instances without introducing dependencies on unapproved storage, queuing, or execution technologies.
