
# ADR-005: Separate Patch Validation from Host-Side Remediation

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision Owners:** AgentShield project

## Context

The project needs to demonstrate that a proposed remediation can be validated in a restricted environment before application state is changed.

Allowing the AI agent or Docker sandbox to directly modify the host database would blur security boundaries.

## Decision

Separate remediation into two stages.

### Stage 1: Sandbox validation

1. Verify the requested incident/action combination.
2. Consume a valid, single-use human approval.
3. Execute the predefined action in the restricted Docker sandbox.
4. Receive the sandbox's JSON response.
5. Validate the response and exact patch structure.

### Stage 2: Trusted host-side application

1. Accept only the validated predefined patch.
2. Apply the corresponding state change using trusted application code.
3. Record remediation results.
4. For deployment rollback, record the rollback in deployment history.
5. Return the remediation result.

The Docker container validates the patch. Trusted host-side Python code applies the validated change to SQLite.

## Alternatives Considered

- Allow the Docker container to modify the host database directly.
- Allow the LLM to generate arbitrary SQL or shell commands.
- Apply all remediation directly on the host without sandbox validation.
- Validate in Docker and apply through predefined host-side code.

The final approach was selected to keep model output, sandbox validation, and trusted state modification separate.

## Consequences

### Positive

- The LLM does not directly modify application state.
- Arbitrary SQL and shell commands are not accepted as remediation instructions.
- The sandbox does not need access to the host database.
- State changes are restricted to predefined application actions.
- The approval and validation stages are independently testable.

### Negative

- The application must maintain predefined patch mappings.
- The host-side remediation implementation remains security-sensitive.
- The design adds an extra validation stage.

## Security Considerations

The host-side remediation code is part of the trusted computing base.

Docker validation alone does not guarantee that a patch is safe. The application must independently validate the action, approval, and patch structure before applying changes.
