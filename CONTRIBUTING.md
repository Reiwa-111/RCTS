Contributing to RCTS
Development Rules
Before making changes, read:

docs/ROADMAP.md
docs/TESTING.md
The relevant specification for the component being modified
These documents define the current development priorities, testing requirements, and compatibility constraints.

Change Requirements
Before modifying code, create a reproducible test demonstrating the problem or validating the intended behavior.
Keep changes focused and small. Do not combine unrelated refactoring, format changes, and cryptographic parameter changes in a single patch.
Do not modify the RCTS v0.1 container format without an approved ADR and an updated specification.
Prefer simple, explicit, and testable solutions over unnecessary abstractions.
Any new dependency must have a clearly justified technical purpose.
Testing and Verification
For every code change:

Build both Release and Debug configurations.
Run the complete CTest suite.
Verify that existing functionality and compatibility are preserved.
For parser, container-format, or untrusted-input handling changes:

Run the relevant sanitizers.
Add regression cases to the fuzzing corpus where applicable.
Test malformed, truncated, oversized, and otherwise invalid input.
Ensure failures are handled safely and deterministically.
Do not claim a test passed unless it was actually executed and its result verified.

Cryptographic Changes
Any change affecting cryptographic operations, key derivation, nonce generation, authentication, or security-relevant format behavior must document:

The threat model and security assumptions.
The cryptographic parameters and rationale.
Compatibility implications for existing containers.
Relevant test vectors and verification results.
The status of independent review.
Cryptographic changes require independent review. Automated analysis alone must not be presented as a substitute for a professional security audit.

Documentation
Update documentation whenever a change affects:

CLI commands, options, or output.
Container format or compatibility.
Supported platforms or dependencies.
Limits, guarantees, or security assumptions.
User-visible behavior.
Keep the README, specifications, testing documentation, and roadmap consistent with the implementation.

Repository Hygiene
Do not commit:

Cryptographic keys or key material.
Containers containing real or sensitive data.
Plaintext extracted from encrypted containers.
Build directories or generated build artifacts.
User-specific files, local configurations, or temporary files.
Test fixtures must be synthetic, reproducible, and safe to distribute.

Git and Release Policy
The repository is maintained locally by default.

Commits are permitted for logical development milestones and state snapshots.
Pushes, publication, releases, and tags require explicit authorization.
Do not publish changes or modify remote repository state without permission.
Reporting
Every completed task must include a concise, factual report containing:

What changed.
Why it changed.
Files affected.
Commands actually executed.
Build and test results.
Known limitations, failures, or unverified areas.
Clearly distinguish verified results from assumptions and pending verification.

Never fabricate commands, test results, security conclusions, or completed work.
