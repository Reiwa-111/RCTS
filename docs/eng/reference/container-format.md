# last updated: 0.3.0 | 2026-11-20 | FORMAT REFERENCE

# RCTS container format v0.1

**Header version byte:** `1`  
**Integer byte order:** big-endian  
**Header size:** 33 bytes  
**Chunk size:** 1 MiB

This is the wire-format reference. Any change to serialized bytes, framing, nonce construction or authenticated metadata requires compatibility review and explicit versioning.+

## 1. Header (33 bytes)

| Offset | Size | Field | Value/meaning |
|---:|---:|---|---|
| 0 | 8 | Magic | `52 43 54 53 0D 0A 1A 0A` (`RCTS\r\n\x1A\n`) |
| 8 | 1 | Version | `0x01` |
| 9 | 4 | Chunk size | `0x00100000` (1 MiB), BE |
| 13 | 16 | Salt | Random HKDF salt from CSPRNG |
| 29 | 4 | Nonce prefix | Random prefix from CSPRNG |

The complete header is authenticated as part of each record's AAD.+

## 2. Record layout

Records follow the header. Each record contains:

| Relative offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `plaintext_length`, uint32 big-endian |
| 4 | 1 | `flags` |
| 5 | N | Ciphertext, where N equals `plaintext_length` |
| 5 + N | 16 | AES-GCM authentication tag |

Flags:
- `0x00` — ordinary record.
- `0x01` — final record (`FINAL`).

Every non-final record must contain exactly 1 MiB of plaintext. The final record contains 0 through 1 MiB inclusive. Empty input is represented by a final record with length 0 and a tag.+

The maximum is 65,536 records and 64 GiB of plaintext. The implementation rejects unknown flags, invalid lengths, missing final markers and bytes after the final record.+

## 3. Derived key

Each container uses a separate 32-byte derived key:

```text
file_key = HKDF-SHA-256(
    IKM  = master_key[32],
    salt = header.salt[16],
    info = ASCII("RCTS v0.1 AES-256-GCM container key"),
    L    = 32
)
```

## 4. Nonce

For record index `i`, starting at zero:

```text
nonce(i) = header.nonce_prefix[4] || uint64_be(i)
```

The nonce is 12 bytes (96 bits). The index increments by one per record, preventing nonce reuse within a container. Cross-container key separation depends on fresh random salts; the random nonce prefix provides an additional nonce-space separator. This is probabilistic CSPRNG-based construction, not an absolute collision guarantee across all files ever created.

## 5. AAD

The authenticated byte sequence for each record is:

```text
AAD(i) = header[33]
      || uint64_be(i)
      || uint32_be(plaintext_length)
      || flags[1]
```

The GCM tag therefore binds the ciphertext to the header, record index, length and record type.

## 6. Container termination

The record with `FINAL` terminates the stream. EOF must immediately follow it. Extra bytes are rejected. Removing or reordering records violates framing or authentication.

## 7. Visible metadata

Format v0.1 reveals the exact content length (including final-record length), record count, fixed chunk size and format version. It does not store the original filename, path or extension. No compression or padding is used.+

## 8. Compatibility

Version byte `1` identifies RCTS v0.1. Incompatible changes to structure, nonce/AAD semantics, KDF or record rules require a new format version. Version `1` must not be reused for changed bytes. A 1.0 implementation must preserve v0.1 reading or explicitly document a separate migration tool and support window.
