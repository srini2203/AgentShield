# ADR-003: Require explicit, single-use human approval for remediation

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

A diagnosis may be wrong, incomplete, or influenced by hostile evidence. Automatic
remediation would allow an investigation error to become a state-changing action.

## Decision

The agent proposes a predefined remediation. A human must create/approve the exact
incident/action pair. Approvals expire after five minutes and can be consumed once.
Rejected, expired, unknown, mismatched, or replayed approvals cannot authorize
execution.

## Consequences

- State changes require an explicit approval record.
- The approval lifecycle is deterministic and covered by tests.
- The current local demo has no user authentication; approval records must not be
  treated as proof of a real person's identity in a public deployment.
