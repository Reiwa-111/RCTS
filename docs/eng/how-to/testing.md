# last updated: 0.3.0 | 2026-11-20 | TESTING CONTRACT

# Testing RCTS

## Test philosophy

Tests verify specific behaviors of a particular build. They do not prove cryptographic security, eliminate untested filesystem states or replace independent review. Every result should be tied to a source revision and environment.+

## Standard CTest workflow

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

CTest registers Python-driven black-box tests. The primary smoke suite is `tests/smoke_test.py`; it runs the CLI and checks behavior using temporary test files. Python 3.8+ is required for the test driver.+

## Test assets

| Asset | Purpose | Boundary |
|---|---|---|
| `tests/smoke_test.py` | CLI behavior, round-trip, key validation, malformed inputs, no-overwrite and tamper rejection | Functional tests, not a crypto audit |
| `tests/encryption_kat.py` | Deterministic fixture compatibility test | Test-only deterministic configuration |
| `tests/vectors/` | Public fixture container and metadata | Test key is public and must not be used for real data |
| `tests/fault_test.py` | Controlled failures for selected I/O and publication steps | Fault-injection build only; not exhaustive filesystem simulation |

## Coverage categories

- Key generation, encoding and malformed key files.
- Empty, short, boundary-size and multi-record inputs.
- Round-trip integrity.
- Existing output-path protection, including symlink cases where supported.
- Container header and record framing validation.
- Tampering with authenticated header/record fields and tags.
- Truncation, trailing bytes, malformed record sequences and invalid FINAL placement.
- I/O error handling and temporary-file cleanup through fault hooks.
- Known-answer compatibility fixture.

Exact case names and counts may vary by configuration. Use captured output rather than copying historical totals.+

## Fault injection

The separate `RCTS_ENABLE_FAULT_INJECTION` build exercises selected failures at create, write, sync, close and publish stages. Tests should confirm failure status and absence of final output or temporary files where cleanup is expected. These hooks do not reproduce every kernel, filesystem, device or power-loss failure.+

## Evidence record

For each run, record date, commit, OS/architecture, compiler, CMake and OpenSSL versions, configure/build/test commands, full output, exit codes, suite counts, skips and environmental caveats. Do not include secrets or real plaintext in test logs. Keep logs local unless scrubbed and approved for publication.+

## Not yet established

- Complete Windows compiler/OS matrix and MSVC acceptance.
- macOS acceptance.
- Fuzzing of the complete container parser and key decoder.
- Exhaustive disk-full, short-write, sync, close and publication failure coverage.
- Independent cryptographic audit.
- Formal crash-consistency guarantees across filesystems.
