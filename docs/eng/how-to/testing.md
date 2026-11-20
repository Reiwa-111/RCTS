# last updated: 0.3.1 | 2026-11-20 | TESTING CONTRACT

# Testing RCTS

## Test philosophy

Tests verify specific behaviors of a particular build. They do not prove cryptographic security, eliminate untested filesystem states or replace independent review. Every result should be tied to a source revision and environment.

## Standard CTest workflow

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

CTest registers Python-driven black-box tests. The primary smoke suite is `tests/smoke_test.py`; it runs the CLI and checks behavior using temporary test files, including legacy v0.1 decrypt. `tests/encryption_kat.py` compares deterministic v0.3 encryption against a frozen fixture and decrypts it. `tests/release_randomness.py` verifies that ordinary encryption does not produce identical per-container headers. Python 3.8+ is required for the test driver.

## Test assets

| Asset | Purpose | Boundary |
|---|---|---|
| `tests/smoke_test.py` | CLI behavior, round-trip, key validation, malformed inputs, no-overwrite and tamper rejection | Functional tests, not a crypto audit |
| `tests/encryption_kat.py` | Deterministic fixture compatibility test | Test-only deterministic configuration |
| `tests/vectors/` | Public fixture container and metadata | Test key is public and must not be used for real data |
| `tests/fault_test.py` | Controlled failures for selected I/O/publication steps and a post-DecryptUpdate tag-setup exception path | Fault-injection build only; not exhaustive filesystem simulation or direct memory-wipe proof |

## Coverage categories

- Key generation, encoding and malformed key files.
- Empty, short, boundary-size and multi-record inputs.
- Round-trip integrity.
- Existing output-path protection, including symlink cases where supported.
- Windows output-file DACL assertions: protected ACL with full access limited to SYSTEM, Administrators and the current user.
- Container header and record framing validation.
- Tampering with authenticated header/record fields and tags.
- Truncation, trailing bytes, malformed record sequences and invalid FINAL placement.
- I/O error handling and temporary-file cleanup through fault hooks.
- Known-answer compatibility fixture.

Exact case names and counts may vary by configuration. Use captured output rather than copying historical totals.

## Fault injection

The separate `RCTS_ENABLE_FAULT_INJECTION` build exercises selected failures at create, write, simulated partial-write, sync, close and publish stages. Tests should confirm failure status and absence of final output or temporary files where cleanup is expected. The partial-write hook performs an actual seven-byte write to the temporary output and then injects an error, exercising cleanup after data has been written. The fault suite now exercises this path for encrypt, decrypt and keygen. It does not emulate disk-full conditions or filesystem-generated short writes, and it does not reproduce every kernel, filesystem, device or power-loss failure.

The GitHub Actions workflow defines Linux, macOS and Windows/MSYS2 UCRT64 build/test jobs. The matrix is considered established only after successful hosted runs; adding a workflow file alone is not compatibility evidence.

## Evidence record

For each run, record date, commit, OS/architecture, compiler, CMake and OpenSSL versions, configure/build/test commands, full output, exit codes, suite counts, skips and environmental caveats. Do not include secrets or real plaintext in test logs. Keep logs local unless scrubbed and approved for publication.

## Not yet established

- Complete Windows compiler/OS matrix and MSVC acceptance.
- macOS acceptance.
- Fuzzing of the complete container parser and key decoder.
- Exhaustive disk-full, short-write, sync, close and publication failure coverage.
- Independent cryptographic audit.
- Formal crash-consistency guarantees across filesystems.

The `rcts_crypto_api` unit test checks successful decrypt into a pre-populated output vector and verifies that short-input and authentication-failure calls leave the output empty. The API clears the prior logical contents before processing a new decrypt request.
