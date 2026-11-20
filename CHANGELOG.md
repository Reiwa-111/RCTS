# Changelog

This changelog records user-visible changes. It does not replace test reports or security audits.

## 0.3.0 — file handling and failure-path hardening (2026-11-20)

- Tightened exclusive output creation and no-clobber publication.
- Added checked finalization behavior for flush, synchronization and close paths.
- Expanded validation of input/key paths and malformed key material.
- Added public compatibility test vector and deterministic known-answer test infrastructure.
- Added test-only fault injection for selected file-operation failures.
- Updated specification, implementation documentation and security limitations.

## 0.2.0 — container implementation baseline

- Established the RCTS v0.1 chunked authenticated container and CLI workflow.
- Added key generation, encryption and decryption commands.
- Added streaming processing, authenticated record metadata and test coverage.

## 0.1.0 — initial prototype

- Initial research prototype for a local encrypted file container.