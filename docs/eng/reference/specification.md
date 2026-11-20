# last updated: 0.3.0 | 2026-11-20 | APPLICATION SPECIFICATION

# RCTS v0.1 specification


**Status:** Experimental container format specification.
**Application version:** `0.3.0`.
**Binary version:** `1`.
**Snapshot date:** 2026-11-20.

## Purpose

RCTS converts an input file into a chunked authenticated encrypted container. It relies on OpenSSL primitives and defines framing, metadata authentication and file publication behavior. It is not an audited production security product.

## CLI contract

```text
rcts keygen <key-file>
rcts encrypt <key-file> <input-file> <output.rct>
rcts decrypt <key-file> <input.rct> <output-file>
```

Exit codes: `0` success, `1` operation failure, `2` invalid command-line arguments. Existing destination files are not overwritten. Key and input files must satisfy ordinary-file validation; key reads are bounded.

## Fixed parameters

| Parameter | Value |
|---|---|
| Master key | 32 random bytes |
| Key text | 32 Unicode code points `U+4E00..U+4EFF` |
| KDF | HKDF-SHA-256 |
| KDF salt | 16 bytes |
| KDF info | `RCTS v0.1 AES-256-GCM container key` |
| Derived key | 32 bytes |
| Cipher | AES-256-GCM |
| Tag | 16 bytes per record |
| Header | 33 bytes |
| Chunk | 1 MiB |
| Nonce | 4-byte prefix + 8-byte BE record index |
| Record cap | 65,536 |
| Plaintext cap | 64 GiB |

## Streaming and integrity

Input is processed in bounded chunks. Each record authenticates the header and record metadata as AAD. Decryption validates structure and tags, and only publishes the completed output after final validation. Empty input is encoded with an empty final record.

## Output behavior

Temporary output is created exclusively in the destination directory. Writes and finalization operations are checked; publication avoids replacing an existing target. Temporary cleanup is attempted on ordinary failure. Filesystem crash durability and orphan cleanup are not guaranteed universally.

## Compatibility and error handling

The format version byte is `1`. Unknown versions, unsupported header parameters, malformed record framing, authentication failures, truncation and unexpected trailing data are errors. A future format revision must be versioned explicitly.

## Related normative documents

- [Container byte layout](container-format.md)
- [Key encoding](key-format.md)
- [Security assumptions and limitations](../explanation/security.md)
- [Test coverage](../how-to/testing.md)
