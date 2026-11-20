# Changelog

This changelog records user-visible changes. It does not replace test reports or security audits.

## 0.3.1 - Release verification and maintenance (2026-11-20)

- Revalidated v0.1 legacy decryption and v0.3 encryption/decryption behavior across Windows UCRT64 and Ubuntu 24.04.
- Passed release-randomness, deterministic encryption KAT, crypto API and fault-injection suites in the verified local configurations.
- Corrected documentation and release metadata for the current v0.3 container format.
- No container-format or cryptographic-parameter changes from 0.3.0.

## 0.3.0 - RCTS container v0.3 and implementation hardening (2026-11-20)

- New encryption emits container version byte `3`.
- v0.3 derives its key with HKDF info `RCTS v0.3 AES-256-GCM container key`.
- Decryption remains backward-compatible with v0.1 containers (version byte `1`, original HKDF info).
- v0.3 retains the 33-byte header, record layout, AES-GCM, nonce/AAD rules, chunk/record limits and key-file encoding; the HKDF context is version-separated.
- Tightened exclusive output creation and no-clobber publication.
- Added checked output finalization and failure-path tests.
- Extracted CLI, entry, crypto, format helpers and key codec into dedicated source files.
- Added a deterministic v0.3 known-answer fixture while retaining the v0.1 fixture.

## 0.2.0 — container implementation baseline

- Established the RCTS v0.1 chunked authenticated container and CLI workflow.
- Added key generation, encryption and decryption commands.
- Added streaming processing, authenticated record metadata and test coverage.

## 0.1.0 — initial prototype

- Initial research prototype for a local encrypted file container.
