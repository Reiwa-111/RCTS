# last updated: 0.3.0 | 2026-11-20 | ROADMAP REVIEW

# RCTS roadmap

Version labels are engineering milestones, not calendar promises. The container format must not change silently: any incompatible revision needs explicit versioning, compatibility policy and migration planning.+

## Current baseline — application 0.3.0 / format v0.1

- [x] CLI: `keygen`, `encrypt`, `decrypt`.
- [x] 32-byte master key with a 32-character Unicode representation.
- [x] HKDF-SHA-256 and AES-256-GCM integration.
- [x] Chunked records, authenticated metadata and final-record validation.
- [x] Streaming implementation and bounded key-file parsing.
- [x] Exclusive temporary-file creation and no-clobber publication.
- [x] Smoke tests, compatibility vector, KAT and test-only fault injection.

## Pre-1.0 engineering gates

### Reliability
- [ ] Capture reproducible Release, Hardened and Analyzer logs for an exact candidate commit.
- [ ] Complete cross-platform tests for output-path races and symlink edge cases.
- [ ] Expand disk-full, short-write, sync, close and publication-failure coverage.
- [ ] Review cleanup after ordinary errors and abnormal termination.
- [ ] Define supported OS/compiler/OpenSSL combinations and verify them in CI.

### Security assurance
- [ ] Independent review of nonce construction, HKDF parameters, AAD, framing and GCM usage.
- [ ] Review secret-bearing buffers, copies, stack lifetime and cleansing claims.
- [ ] Fuzz the container parser and key decoder.
- [ ] Add property-based checks for framing, round-trip and failure rejection.
- [ ] Document residual risk and vulnerability-reporting process.

### Release engineering
- [ ] CI builds and tests the declared supported configurations.
- [ ] Clean-clone reproducibility check.
- [ ] Checksum manifest generation and verification from repository root.
- [ ] License inventory for source and shipped runtime dependencies.
- [ ] Release checklist with captured evidence and review.

## Possible later work

Potential features are not committed scope: safer key workflow, an explicit recovery/migration tool, container metadata options and modularization of the current translation unit. Each proposal requires threat-model review and format/API compatibility analysis.

## Exit criteria

A milestone is complete only when implementation, tests, documentation and release evidence agree. A checkbox requires a verified revision and captured evidence; historical results or missing logs do not qualify.
