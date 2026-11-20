# RCTS v0.3 specification

**Status:** Experimental format specification.
**Application version:** `0.3.1`.
**Container version byte:** `3`.
**Legacy read compatibility:** v0.1 (version byte `1`).

RCTS encrypts files into a chunked authenticated container. v0.3 uses AES-256-GCM and HKDF-SHA-256 from OpenSSL. It is an experimental prototype, not an independently reviewed security product.

## CLI contract

```text
rcts keygen <key-file>
rcts encrypt <key-file> <input-file> <output.rct>
rcts decrypt <key-file> <input.rct> <output-file>
```
Exit codes: `0` success, `1` operation failure, `2` invalid CLI arguments. Existing destination files are not overwritten. Key/input files must be regular files; key reads are bounded.

## Fixed parameters

| Parameter | Value |
|---|---|
| Master key | 32 random bytes |
| Key text | 32 Unicode code points `U+4E00..U+4EFF` |
| KDF | HKDF-SHA-256 |
| KDF salt | 16 bytes |
| v0.3 KDF info | `RCTS v0.3 AES-256-GCM container key` |
| v0.1 KDF info (legacy) | `RCTS v0.1 AES-256-GCM container key` |
| Derived key | 32 bytes |
| Cipher | AES-256-GCM |
| Tag | 16 bytes per record |
| Header | 33 bytes |
| Chunk | 1 MiB |
| Nonce | 4-byte prefix + 8-byte BE record index |
| Record cap | 65,536 |
| Plaintext cap | 64 GiB |

## Streaming and integrity

Input is processed in bounded chunks. Every record authenticates the header and record metadata as AAD. Decryption validates structure and tags and publishes only after complete-container validation. Empty input uses an empty final record.

## Output behavior

Temporary output is exclusively created in the destination directory. Writes/finalization are checked; publication avoids replacing existing targets. Cleanup is attempted on ordinary failures. Universal crash durability and orphan cleanup are not guaranteed.

## Compatibility

Encrypt writes version byte `3` and uses the v0.3 HKDF context. Decrypt accepts version `1` with its original v0.1 KDF context and version `3` with the v0.3 context. Other versions are rejected. The v0.1 fixture remains in tests to protect legacy readability. The key file format is unchanged. No in-place migration exists: decrypt legacy data and encrypt it again to migrate.

## References

- [Container format](container-format.md)
- [Key-file format](key-format.md)
- [Security limitations](../explanation/security.md)
- [Testing](../how-to/testing.md)
