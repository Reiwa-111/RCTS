# last updated: 0.3.0 | 2026-11-20 | TESTING CONTRACT

# Тестирование RCTS

## Test philosophy

Tests establish specific behaviors of a particular build. They do not prove cryptographic security, eliminate untested filesystem states or substitute for independent review. Each result must be tied to the source revision and build environment.

## Standard CTest flow

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

CTest registers black-box Python tests. The main smoke suite is `tests/smoke_test.py`; it runs the built CLI and validates behavior using temporary test files. Python 3.8+ is required by the test runner.

## Test assets and scripts

| Asset | Purpose | Limit |
|---|---|---|
| `tests/smoke_test.py` | CLI behavior, round-trip, key validation, malformed inputs, no-overwrite and tamper rejection | Functional tests, not crypto audit |
| `tests/encryption_kat.py` | Deterministic fixture compatibility test | Test-only deterministic configuration |
| `tests/vectors/` | Public fixture container and vector metadata | Test key is intentionally public and must never be reused for real data |
| `tests/fault_test.py` | Exercises fault hooks for selected I/O/publication operations | Only available in fault-injection build; not exhaustive filesystem fault simulation |


## Current coverage categories

- Key generation, encoding and malformed key files.
- Empty, short, boundary-sized and multi-record inputs.
- Round-trip output integrity.
- Existing output path protection, including symlink cases where the host supports them.
- Container header and record framing validation.
- Tampering with authenticated header/record data and tags.
- Truncation, trailing bytes, malformed record sequences and invalid FINAL placement.
- I/O failure paths and temporary-file cleanup through fault hooks.
- Known-answer compatibility fixture.

Exact test names and count vary with the checked-in test script/build configuration. Use the actual captured test output rather than copying a historical count.

## Fault injection

The separate `RCTS_ENABLE_FAULT_INJECTION` build exercises controlled failures at create, write, sync, close and publication steps. The test should confirm failure status and absence of a published final file or leftover temporary file where cleanup is expected. It cannot emulate every kernel, filesystem, hardware or power-loss failure.

## Evidence record

For each formal run, record:

- date and commit hash;
- OS, architecture, compiler and CMake versions;
- OpenSSL version and discovery path;
- configure/build commands and options;
- test command, full output and exit code;
- suite-specific totals and skips;
- deviations, failed tests and environmental caveats.

Do not record secrets or real plaintext. Keep logs in local ignored build/evidence directories unless they are deliberately scrubbed and approved for publication.

## Not yet established

- Complete Windows compiler/OS matrix and MSVC acceptance.
- macOS acceptance.
- Fuzzing of the complete container parser and key decoder.
- Exhaustive disk-full, short-write, flush, close and sync fault coverage.
- Independent cryptographic audit.
- Formal crash-consistency guarantees across filesystems.
