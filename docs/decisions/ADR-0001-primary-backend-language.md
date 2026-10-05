# ADR-0001: Primary Backend Language

## Status
Accepted

## Decision
Python is the primary programming language for the backend/orchestration layer.

## Context
The project is a greenfield automated Android APK dynamic analysis system (`dynamic-analysis`). Environment inspection confirmed that Python 3.13.3 is available in the development environment. The product requirements mandate orchestrating and integrating multiple external processes, tools, and subsystems, including APK intake, job lifecycle management, Android runtime infrastructure, device communication, network analysis, certificate management, instrumentation, evidence processing, and report generation.

## Rationale
- Python is already installed in the verified development environment.
- The product requires orchestration of external processes and Android tooling.
- The product will need integration with command-line tools, device communication, runtime infrastructure, network-analysis tooling, instrumentation tooling, evidence processing, and report generation.
- Python is being selected as the initial backend/orchestration language because it is suitable for this type of orchestration and integration work.
- This decision does NOT select a web framework, task queue, database, Android runtime, emulator, proxy, instrumentation framework, deployment model, or frontend technology.

## Scope
This decision applies exclusively to the programming language for the backend/orchestration layer.

## Not Decided
The following technologies and architectural choices remain explicitly undecided:
- web framework
- frontend technology
- job/worker system
- database
- storage
- Android runtime/emulator
- Android API levels
- device strategy
- proxy
- certificate mechanism
- instrumentation
- deployment
- containerization

## Consequences
Future implementation decisions should be compatible with Python for the backend/orchestration layer unless this ADR is later superseded.
