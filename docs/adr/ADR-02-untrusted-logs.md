# ADR-002: Treat logs and diagnostic output as untrusted evidence

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Logs can contain user-controlled strings, copied prompts, fake system messages, or
other hostile content. An LLM may interpret this text as instructions unless the
trust boundary is explicit.

## Decision

Logs and tool outputs are evidence only, never instructions. The agent prompt and
evidence-handling code explicitly separate trusted task instructions from untrusted
diagnostic content. Structured outputs are validated before use.

## Consequences

- Hostile text can be investigated as data without intentionally granting it
  instruction authority.
- Sanitization and structured validation reduce risk but do not prove immunity to
  prompt injection.
- Adversarial evaluations must be reported with their scope and limitations.
