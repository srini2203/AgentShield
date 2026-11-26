
# ADR-003: Human Approval and Single-Use Authorization

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision Owners:** AgentShield project

## Context

Incident investigation may identify a corrective action, but automatically applying changes based on an LLM-generated diagnosis creates operational risk.

An incorrect diagnosis or manipulated recommendation could lead to unintended application state changes.

## Decision

Require explicit human approval before executing remediation.

The approval system:

- Creates persistent approval records.
- Associates approvals with predefined incident/action combinations.
- Uses a five-minute approval expiry.
- Allows each approval to be consumed only once.
- Supports explicit rejection.
- Rejects expired, rejected, invalid, or already-consumed approvals.

Allowed incident/action combinations:

| Incident | Allowed action |
|---|---|
| database_failure | restore_database |
| high_latency | clear_latency |
| http_500 | clear_http_500 |
| bad_deployment | rollback_deployment |
| malicious_log | disable_malicious_log |

The remediation endpoint validates the approval before proceeding.

## Alternatives Considered

- Fully automatic remediation.
- Manual remediation outside the application.
- Human approval with reusable authorization.
- Human approval with expiring, single-use authorization.

The final approach provides a controlled demonstration of human-in-the-loop remediation.

## Consequences

### Positive

- The agent cannot independently authorize remediation.
- Approvals expire.
- Approval replay is rejected.
- Rejected approvals cannot be executed.
- Remediation actions are restricted to predefined combinations.

### Negative

- Human intervention increases remediation time.
- Approval management adds implementation complexity.
- The current local prototype does not implement user authentication.

## Security Considerations

The approval mechanism is an application-level control, not a complete identity or access-management system.

The local API currently lacks authentication. It must not be exposed publicly without appropriate authentication and authorization controls.
