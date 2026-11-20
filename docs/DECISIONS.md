# last updated: 0.3.0 | 2026-11-20 | ADR REVIEW

# Architecture decision records


This log captures decisions for the current experimental implementation. Decisions may be superseded, but their historical entries should remain and link to the replacement.


## ADR-001 — use OpenSSL primitives, do not invent a cipher

**Status:** Accepted for v0.1.
**Decision:** Use OpenSSL for AES-256-GCM, HKDF-SHA-256 and cryptographic randomness.
**Rationale:** RCTS is an experiment in container format and I/O behavior, not a cryptographic primitive design project.
**Consequences:** Correctness depends on safe integration, parameter discipline and dependency behavior. Independent review remains required.

## ADR-002 — authenticate records independently

**Status:** Accepted for v0.1.
**Decision:** Process up to 1 MiB per record; each record has its own GCM tag and index-derived nonce.
**Rationale:** Streaming with bounded memory and per-record integrity verification.
**Consequences:** Framing, ordering, lengths, flags, final-record handling and nonce uniqueness are security-critical.

## ADR-003 — derive a container-specific key

**Status:** Accepted for v0.1.
**Decision:** Use HKDF-SHA-256 with a random 16-byte salt and fixed info string to derive a 32-byte container key.
**Rationale:** Separate container keys while retaining a generated master key.
**Consequences:** The salt and info string are format compatibility parameters and must not be changed casually.

## ADR-004 — generated Unicode key representation

**Status:** Accepted for v0.1.
**Decision:** Encode each of the 32 key bytes as a code point in `U+4E00..U+4EFF`.
**Rationale:** A simple textual representation with an unambiguous byte mapping.
**Consequences:** Strict UTF-8 and exact character-range validation are required; it is not a mnemonic password.

## ADR-005 — fixed header and authenticated metadata

**Status:** Accepted for v0.1.
**Decision:** Use a 33-byte header; authenticate the header and record index/length/flags as AAD.
**Rationale:** Detect header or framing manipulation during record authentication.
**Consequences:** Parsing rules and serialized bytes are frozen for format version 1.

## ADR-006 — streaming and temporary output

**Status:** Accepted.
**Decision:** Do not load whole files into memory. Write to a destination-directory temporary file and publish after successful finalization without overwriting an existing path.
**Rationale:** Bounded memory, safer failure handling and reduced exposure of partial output.
**Consequences:** Filesystem semantics differ; crash durability and cleanup are not universal guarantees.

## ADR-007 — prototype status and versioning

**Status:** Accepted.
**Decision:** Application version `0.3.0` and container version `v0.1` are separate. The current container format is experimental.
**Rationale:** Software iteration should not imply wire-format changes.
**Consequences:** Release documentation must state both versions. Format changes require a new format version and explicit compatibility decisions.
