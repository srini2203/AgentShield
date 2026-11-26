# ADR-004: Use a restricted Docker container for patch validation

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

A remediation patch should be validated in a constrained environment before the
trusted application applies it.

## Decision

Run the patch validator in a Docker container with no network, read-only root
filesystem, memory/CPU limits, all Linux capabilities dropped, and
`no-new-privileges`. Do not mount the host filesystem or Docker socket.

## Consequences

- Validation is isolated from normal network and host filesystem access to the
  extent provided by the Docker runtime and its configuration.
- This is not a proof against container escapes or kernel vulnerabilities.
- The container validates a predefined patch; it is not the component that mutates
  the host application's SQLite database.
