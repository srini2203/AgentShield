# ADR-005: Separate sandbox validation from trusted host-side patch application

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

The prototype validates a fixed remediation patch in Docker, then updates application
state after approval. Describing this as “remediation runs inside Docker” would be
inaccurate.

## Decision

The Docker container returns a constrained validation result. The host application
checks that response against the expected action and exact patch, then applies the
predefined patch through trusted host-side code.

## Consequences

- Approval and exact-patch checks remain deterministic.
- Docker is a patch validator, not the host-state execution environment.
- Documentation and demos must state this boundary clearly.
- A future design that executes mutations inside an isolated environment requires
  a separate architecture decision and threat model.
