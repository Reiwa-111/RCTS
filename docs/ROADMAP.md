# last updated: 0.3.0 | 2026-11-20 | ROADMAP REVIEW

# RCTS roadmap


Roadmap versions are engineering milestones, not calendar promises. The container format must not change silently; any incompatible change requires an explicit versioned format design and migration story.

## Current baseline: application 0.3.0 / container v0.1

- [x] CLI keygen/encrypt/decrypt baseline.
- [x] OpenSSL-backed HKDF-SHA-256 and AES-256-GCM.
- [x] Fixed header, record framing, AAD and final-record rules documented.
- [x] Streaming implementation and bounded key parsing.
- [x] Exclusive temporary file creation and no-clobber publication path.
- [x] Smoke test coverage and public compatibility vector.
- [x] Fault-injection hooks and test driver (coverage remains bounded).

## Before a 1.0 decision

### Reliability
- [ ] Capture reproducible Release, Hardened and Analyzer test logs for the exact candidate commit.
- [ ] Complete cross-platform tests for output-path race behavior and symlink edge cases.
- [ ] Expand disk-full, short-write, sync, close and publication fault coverage.
- [ ] Review cleanup behavior after normal errors and abrupt termination.
- [ ] Define supported OS/compiler/OpenSSL combinations and verify them in CI.

### Security assurance
- [ ] Independent review of nonce construction, HKDF parameters, AAD, record framing and GCM usage.
- [ ] Review all secret-bearing buffers, copies, stack lifetime and cleansing claims.
- [ ] Fuzz header/record parser and key decoder.
- [ ] Property-based tests for framing, round-trip, rejection and no-output-on-failure.
- [ ] Document residual risks and response process for vulnerabilities.

### Release engineering
- [ ] CI builds/tests at least the declared supported configurations.
- [ ] Clean-clone reproducibility check.
- [ ] Checksum manifest generation and verification from repository root.
- [ ] License inventory for source and shipped runtime dependencies.
- [ ] Release checklist with captured evidence and review.

## Later, only after the baseline is stable

Potential future work is not committed scope: safer key UX, an explicit recovery/migration tool, container metadata options, and modularization of the current translation unit. Each feature requires threat-model review and format/API compatibility analysis before implementation.

## Exit criteria

A milestone is complete only when code, tests, documentation and release evidence agree. A checked box requires a verified commit and captured evidence; historical or missing output does not qualify.
