
# ADR-001: Deterministic Read-Only MCP Tools

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision Owners:** AgentShield project

## Context

The incident-investigation agent needs operational evidence to diagnose application failures. Allowing an LLM to freely select tools or execute arbitrary commands would increase the risk of unintended actions and prompt injection.

The application requires access to logs, metrics, database health, and deployment history.

## Decision

Use a fixed set of four read-only MCP diagnostic tools:

1. `get_application_logs`
2. `get_application_metrics`
3. `get_database_health_status`
4. `get_deployment_history`

The investigation workflow invokes these diagnostics through a deterministic tool sequence.

The model receives diagnostic evidence for analysis but does not have MCP tools bound to it.

Database diagnostics use read-only SQLite access, including `PRAGMA query_only=ON`.

## Alternatives Considered

- Allow the LLM to select tools dynamically.
- Give the agent unrestricted database access.
- Allow arbitrary shell or system commands.
- Use a fixed diagnostic workflow.

The fixed diagnostic workflow was selected because it reduces the model's authority and makes the investigation process more predictable.

## Consequences

### Positive

- The LLM cannot independently invoke arbitrary tools.
- Diagnostic operations are separated from remediation.
- Tool access is easier to audit and test.
- Read-only database access reduces accidental modification risks.

### Negative

- The diagnostic workflow is less flexible.
- New diagnostic capabilities require explicit implementation.
- Deterministic tool execution may perform unnecessary checks for some incidents.

## Security Considerations

Read-only MCP tools reduce the impact of malicious instructions but do not independently guarantee security.

The MCP server runs under the same Windows user context as the application during local development. This is not an OS-level security boundary.
