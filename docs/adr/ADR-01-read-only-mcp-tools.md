# ADR-001: Keep diagnostic MCP tools read-only

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

The incident agent needs application logs, metrics, database health, and deployment
history to diagnose incidents. Giving the model general-purpose execution or write
tools would increase the impact of prompt injection and model mistakes.

## Decision

Expose a fixed set of read-only MCP diagnostic tools. The agent uses a deterministic
tool set/order; the model does not receive arbitrary tool execution capability.
Diagnostics are treated as untrusted evidence.

## Consequences

- Diagnosis can gather relevant evidence without direct state mutation.
- Tool surface area is smaller and easier to test.
- New tools require explicit code review and authorization tests.
- Read-only MCP behavior is an application-level constraint; it is not equivalent
  to a separate OS identity or process sandbox.
