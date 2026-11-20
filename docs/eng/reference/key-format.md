# last updated: 0.3.1 | 2026-11-20 | KEY REFERENCE

# RCTS v0.3 key-file format (unchanged from v0.1)


## Key material

The generator requests exactly 32 random bytes from OpenSSL `RAND_bytes`. The key is not a password, passphrase or human-selected secret. No password stretching or password-based recovery is implemented.

## Text encoding

Each byte `b` is represented as the Unicode code point `U+4E00 + b`. The allowed range is `U+4E00..U+4EFF`; the file contains exactly 32 code points, encoded in UTF-8 (96 bytes for the code points, excluding the optional line ending). The generator writes a trailing LF. Reading accepts no line ending, one LF or one CRLF.

## Validation

The reader rejects empty, over-limit, truncated, extended, BOM-prefixed, whitespace-padded, invalid UTF-8 and out-of-range characters. It does not normalize arbitrary Unicode or trim whitespace. Key reads are bounded; the accepted key file is an ordinary file.

## Handling

Treat the key file as secret material. Keep it outside source control and backups that are accessible to unintended parties. Protect access, maintain a recovery copy in an appropriately secure location, and do not confuse the public test vector's key with a real secret. Best-effort memory cleansing does not guarantee erasure of every copy.
