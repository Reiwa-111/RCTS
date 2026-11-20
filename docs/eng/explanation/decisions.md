# last updated: 0.3.0 | 2026-11-20 | ADR REVIEW

# Architecture decision records

This file records decisions made for the current prototype. A decision can be superseded, but the historical entry should remain and point to its replacement.+

## ADR-001 — use OpenSSL, not a custom cipher

**Status:** Accepted for v0.1.  
**Decision:** Use OpenSSL for AES-256-GCM, HKDF-SHA-256 and cryptographic randomness.  
**Rationale:** RCTS explores container and I/O behavior rather than cryptographic primitive design.  
**Consequences:** Security depends on correct integration, parameter discipline and dependency behavior. Independent review is still needed.

## ADR-002 — authenticate records independently

**Status:** Accepted for v0.1.  
**Decision:** Process up to 1 MiB per record; each record has its own GCM tag and index-derived nonce.  
**Rationale:** Streaming with bounded memory and per-record integrity verification.  
**Consequences:** Framing, ordering, lengths, flags, final-record handling and nonce uniqueness are security-critical.

## ADR-003 — derive a container-specific key

**Status:** Accepted for v0.1.  
**Decision:** Use HKDF-SHA-256 with a random 16-byte salt and a fixed info string to derive a 32-byte container key.  
**Rationale:** Separate container keys while retaining a generated master key.  
**Consequences:** Salt and info string are compatibility parameters and must not be changed casually.

## ADR-004 — generated Unicode key representation

**Status:** Accepted for v0.1.  
**Decision:** Encode each of the 32 key bytes as a code point in `U+4E00..U+4EFF`.  
**Rationale:** Simple textual representation with an unambiguous byte mapping.  
**Consequences:** Strict UTF-8 and exact code-point validation are required; this is not a mnemonic password.

## ADR-005 — fixed header and authenticated metadata

**Status:** Accepted for v0.1.  
**Decision:** Use a 33-byte header; authenticate the header and record index/length/flags as AAD.  
**Rationale:** Detect manipulation of header and framing fields during authentication.  
**Consequences:** Serialized bytes and parser rules are frozen for format version 1.

## ADR-006 — streaming and temporary output

**Status:** Accepted.  
**Decision:** Do not load whole files into memory. Write to a destination-directory temporary file and publish after successful finalization without replacing an existing path.  
**Rationale:** Bounded memory, safer failure handling and reduced exposure of partial output.  
**Consequences:** Filesystem semantics vary; crash durability and cleanup are not universal guarantees.

## ADR-007 — application and container versioning

**Status:** Accepted.  
**Decision:** Application version `0.3.0` and container version `v0.1` are independent.  
**Rationale:** Software iteration does not imply a wire-format change.  
**Consequences:** Release documentation must state both versions. Incompatible format changes require a new format version and explicit compatibility decisions.
