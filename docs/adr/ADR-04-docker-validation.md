
# ADR-004: Restricted Docker Patch Validation

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision Owners:** AgentShield project

## Context

Remediation proposals must be validated before they are applied to application state.

Executing arbitrary model-generated commands or patches would introduce unnecessary risk.

The project needs a restricted environment to demonstrate validation of predefined remediation patches.

## Decision

Use a dedicated Docker sandbox to validate predefined remediation actions.

The sandbox is configured with:

- No network access (`--network none`).
- Read-only filesystem (`--read-only`).
- Memory limit of 128 MB.
- CPU limit of 0.5 CPUs.
- All Linux capabilities dropped (`--cap-drop ALL`).
- No privilege escalation (`--security-opt no-new-privileges`).

The sandbox receives a predefined action and returns a validated patch as JSON.

The application validates the returned JSON and patch structure before allowing the remediation workflow to continue.

## Alternatives Considered

- Execute remediation commands directly on the host.
- Use an unrestricted Docker container.
- Use a restricted Docker container for patch validation.
- Implement a separate production-grade sandboxing platform.

The restricted Docker approach was selected as a practical demonstration for the local prototype.

## Consequences

### Positive

- Patch validation is separated from host-side application logic.
- The sandbox has limited resources and no network access.
- Arbitrary host commands are not accepted as remediation actions.
- The validation process is reproducible.

### Negative

- Docker introduces an additional runtime dependency.
- Container isolation depends on the host and Docker configuration.
- The sandbox is not a complete defense against every container escape or host compromise.

## Security Considerations

The sandbox does not receive the Docker socket.

It validates predefined patches; it does not directly modify the application's SQLite database.

Docker hardening reduces the sandbox's capabilities but does not establish a guarantee of complete isolation.
