# ADR-006: Separate adversarial security review from root-cause accuracy scoring

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

A model can identify a root cause correctly while still mishandling hostile
instructions. Conversely, a safe-looking answer may be diagnostically wrong.
Combining both into one score hides important failure modes.

## Decision

Maintain separate evaluations:
- a 30-payload adversarial review, with ambiguous outcomes explicitly reported;
- a 25-run root-cause benchmark, five runs per scenario, manually adjudicated;
- deterministic tests for approval enforcement, tool restrictions, and remediation.

Do not calculate an accuracy or attack-success percentage until its scoring criteria
and denominator are explicit and the required review is complete.

## Consequences

- Results are more honest and interpretable.
- Manual adjudication takes additional time.
- Prototype evaluation results must not be represented as production guarantees.
