# last updated: 0.3.1 | 2026-11-20 | IMPLEMENTATION OVERVIEW

# RCTS architecture

## Scope

RCTS is a single-process, user-space command-line application. Platform argument collection and the entry point live in `src/entry.cpp`; command dispatch is in `src/cli.cpp`; v0.1 framing constants and endian/nonce/AAD helpers are in `src/format.hpp`; secure random generation, HKDF and AES-GCM operations are in `src/crypto.cpp` with a narrow interface in `src/crypto.hpp`; fixed-width key encoding/decoding is in `src/key_codec.cpp` and `src/key_codec.hpp`. File I/O and atomic publication live in `src/file_io.cpp`/`src/file_io.hpp`; encryption/decryption/keygen orchestration lives in `src/operations.cpp`. `src/main.cpp` is now a thin translation unit. The split is incremental; some helpers and interfaces can still be refined. New encryption emits v0.3 and decryption selects the matching HKDF context for v0.1 or v0.3. CMake builds the application and registers tests. OpenSSL Crypto supplies the cryptographic primitives.

## Data-flow overview

```text
CLI arguments
  ├─ keygen → random bytes → Unicode key encoding → exclusive file publication
  ├─ encrypt → input validation → header/salt/nonce prefix → HKDF
  │             → 1 MiB chunk loop → AES-GCM + AAD/tag → temp output
  │             → sync/close → no-clobber publish
  └─ decrypt → header validation → HKDF → record parser
                → authenticate records → temp plaintext
                → validate final framing → publish
```

## Key generation

1. OpenSSL `RAND_bytes` supplies 32 random bytes.
2. Each byte is represented as one Unicode code point in `U+4E00..U+4EFF`.
3. The key is serialized as UTF-8 using the accepted line-ending convention.
4. The destination is created without replacing an existing path.
5. Key buffers are cleansed on a best-effort basis. This does not prove all copies are erased.

The key file is a master key, not a password. Neither v0.1 nor v0.3 provides password-based key derivation.

## Encryption path

- Validate input and output paths and the input file type.
- Read and validate the master key using a bounded read.
- Generate the salt and nonce prefix using OpenSSL CSPRNG.
- Derive the container key with HKDF-SHA-256.
- Create a temporary output exclusively in the destination directory.
- Emit the fixed header and process input in chunks of up to 1 MiB.
- Encrypt records with AES-256-GCM and authenticate the header and record metadata as AAD.
- Mark the final record; empty input is represented by an empty final record.
- Finalize, flush, synchronize, close and publish without replacing an existing target.
- Attempt to remove the temporary file on ordinary failures.

## Decryption path

- Validate the container file and read the fixed header.
- Reject unsupported magic, version, chunk size or framing.
- Read the master key and derive the container key from the header salt.
- Parse records sequentially and reconstruct each nonce from the prefix and record index.
- Authenticate each record before accepting its plaintext for output.
- Enforce length, flag, record-order, FINAL and EOF rules.
- Write to a private temporary file and publish only after complete-container validation.
- A malformed container or authentication failure must not publish a final output.

## File publication

Temporary files use exclusive creation (`O_CREAT | O_EXCL` on POSIX; `CreateFileW` with `CREATE_NEW` on Windows). The implementation checks finalization steps and uses no-clobber publication. On Linux it attempts `renameat2(RENAME_NOREPLACE)` and falls back to hard-link publication; Windows uses `MoveFileExW` and a hard-link fallback. It does not rely only on an `exists()` precheck followed by an unsafe open. POSIX directory synchronization is best-effort. Crash recovery does not guarantee cleanup of every orphaned temporary file.

## Memory and concurrency

Processing is chunked and does not load whole files into memory. The current design does not document parallel record processing. Cleansing is best-effort and cannot guarantee that compiler, library, stack, register, allocator or operating-system copies have disappeared.

## Security boundary

RCTS does not implement cryptographic primitives itself. Security depends on correct OpenSSL integration, nonce uniqueness, authenticated framing, key secrecy, filesystem behavior, build provenance and host integrity. Independent cryptographic review is incomplete.

## Architectural limitations

- File I/O, atomic publication and key-file parsing are implemented in `src/file_io.cpp`; file operations are in `src/operations.cpp`.
- `src/main.cpp` is a three-line translation unit. Entry point, CLI, format, crypto, key codec, file I/O and operation orchestration have separate source modules.
- No stable public library/API separate from the CLI.
- Platform filesystem behavior needs continued testing.
- No independently audited secret-memory lifecycle.
- No complete CI matrix or independent crypto review.

See [ROADMAP](ROADMAP.md) for engineering priorities.
