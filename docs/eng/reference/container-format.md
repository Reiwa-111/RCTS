# RCTS container format v0.3

**Header version byte:** `3`
**Legacy reader:** v0.1 (version byte `1`)
**Integer byte order:** big-endian
**Header size:** 33 bytes
**Chunk size:** 1 MiB

RCTS v0.3 is the current write format. It preserves the v0.1 header, record framing, nonce construction, AAD, AES-256-GCM parameters, key-file format, chunk limits, and final-record rules. The format revision changes the HKDF context string to provide version-specific key separation. New encryption always emits version `3`; decryption supports both v0.1 and v0.3.


## 1. Header (33 bytes)

| Offset | Size | Field | Value/meaning |
|---:|---:|---|---|
| 0 | 8 | Magic | `52 43 54 53 0D 0A 1A 0A` (ASCII `RCTS`, CR, LF, SUB, LF) |
| 8 | 1 | Version | `0x03` for v0.3, `0x01` for legacy v0.1 |
| 9 | 4 | Chunk size | `0x00100000` (1 MiB), BE |
| 13 | 16 | Salt | Random HKDF salt from CSPRNG |
| 29 | 4 | Nonce prefix | Random prefix from CSPRNG |

The complete header is authenticated as part of each record's AAD.


## 2. Record layout

Each record contains:

| Relative offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `plaintext_length`, uint32 big-endian |
| 4 | 1 | `flags` |
| 5 | N | Ciphertext, where N equals `plaintext_length` |
| 5 + N | 16 | AES-GCM authentication tag |

Flags: `0x00` ordinary record, `0x01` final record (`FINAL`). Non-final records are exactly 1 MiB. Final records contain 0..1 MiB. Empty input uses a zero-length final record with a tag.

The maximum is 65,536 records and 64 GiB plaintext. Unknown flags, invalid lengths, missing final markers and trailing bytes are rejected.


## 3. Derived key and version separation

RCTS v0.3:
```text
file_key = HKDF-SHA-256(
    IKM  = master_key[32],
    salt = header.salt[16],
    info = ASCII("RCTS v0.3 AES-256-GCM container key"),
    L    = 32
)
```

Legacy v0.1 uses the original context string `RCTS v0.1 AES-256-GCM container key`. The reader selects the context from the header version. Context strings are not interchangeable.


## 4. Nonce

For record index `i`, starting at zero:
```text
nonce(i) = header.nonce_prefix[4] || uint64_be(i)
```
The 12-byte nonce is unique within a container by construction. Cross-container collision risk depends on fresh random salts and nonce prefixes and is probabilistic.


## 5. AAD

```text
AAD(i) = header[33]
      || uint64_be(i)
      || uint32_be(plaintext_length)
      || flags[1]
```
The tag binds the ciphertext to header, record index, length and record type.


## 6. Termination and metadata

The FINAL record must be followed immediately by EOF. v0.3 exposes exact content length, record count, fixed chunk size and version. It does not store the source filename or extension. No compression or padding is used.


## 7. Compatibility

- Version byte `1` is read using the v0.1 HKDF context and original framing.
- Version byte `3` is written by current encrypt and read using the v0.3 HKDF context.
- The key file encoding is unchanged.
- Unknown versions are rejected.
- The v0.1 public fixture remains a legacy-decryption regression test.
- This implementation does not provide an in-place container migration command; decrypt v0.1 and encrypt the plaintext to produce v0.3.
