# last updated: 0.3.0 | 2026-11-20 | IMPLEMENTATION OVERVIEW

# Архитектура RCTS 0.3.0

> Документ описывает код, существующий в текущем снимке. Он не является проектом будущей архитектуры.

## 1. Область реализации

RCTS — локальная CLI-программа. Основная реализация сосредоточена в `src/main.cpp`; отдельные криптографические и файловые подсистемы пока не выделены в самостоятельные модули. CMake формирует исполняемый файл и подключает тестовые цели. OpenSSL Crypto используется как внешний криптографический backend.

## 2. Слои потока данных

```text
CLI arguments
    │
    ├── keygen ── random bytes ── Unicode key encoding ── exclusive publication
    │
    ├── encrypt ── input validation ── header / salt / nonce prefix
    │             │
    │             └── HKDF ── per-container key
    │                         │
    │                         └── chunk loop ── AES-256-GCM + AAD + tag
    │                                          │
    │                                          └── temporary output ── sync/close ── no-clobber publish
    │
    └── decrypt ── header validation ── HKDF ── record parser
                                          │
                                          └── GCM authentication ── temporary plaintext
                                                                       │
                                                                       └── publish only after final validation
```


## 3. Key generation

1. OpenSSL `RAND_bytes` supplies 32 random bytes.
2. The byte sequence is represented as 32 Unicode code points in `U+4E00..U+4EFF`.
3. The key is serialized as UTF-8 with the accepted line-ending convention.
4. The destination is created without replacing an existing path.
5. Local key buffers receive best-effort cleansing; this does not guarantee that all memory copies are erased.

The key file is a master key, not a password. There is no password derivation or user-selected secret in v0.1.

## 4. Encryption path

- Validate input/output path conditions and input file type.
- Read and validate the master-key file with a bounded read.
- Generate container salt and nonce prefix with the OpenSSL CSPRNG.
- Derive the 32-byte container key with HKDF-SHA-256.
- Create a temporary output exclusively inside the destination directory.
- Emit the fixed header and process input in 1 MiB chunks.
- For each record, use AES-256-GCM and authenticate header plus record metadata through AAD.
- Mark the final record; empty input has an empty final record.
- Finalize, flush, synchronize, close and publish without overwriting the destination.
- On ordinary failures, remove the temporary file where cleanup is possible.

## 5. Decryption path

- Validate the container as a regular file and read the fixed header.
- Reject unsupported magic, version, chunk size or invalid framing.
- Read the master key and derive the container key from header salt.
- Parse records sequentially and reconstruct each nonce from prefix and index.
- Authenticate each record before its plaintext is accepted for output.
- Enforce lengths, flags, record order, FINAL placement and EOF rules.
- Write to a private temporary file, finalize and publish only after full-container validation.
- A malformed container or authentication failure must not produce a published final output.

## 6. File publication

The implementation uses exclusive temporary-file creation (`O_CREAT | O_EXCL` on POSIX; `CreateFileW` with `CREATE_NEW` on Windows). It checks write/finalization steps and attempts no-clobber publication. The documented publication path is rename-first with hard-link fallback, not a preflight `exists()` check followed by an unsafe open. POSIX directory synchronization is best-effort. Crash recovery is not guaranteed to remove every orphaned temporary file.

## 7. Memory and concurrency

Encryption and decryption are streaming and bounded by record-sized buffers rather than whole-file memory. The implementation has no documented parallel record processing. Buffer cleansing is best-effort and cannot prove that compiler, library, stack, register or OS copies have disappeared.

## 8. Security boundary

The project does not implement cryptographic primitives. Security still depends on correct OpenSSL use, nonce uniqueness, authenticated framing, key secrecy, filesystem semantics, build provenance, compiler correctness and host integrity. The current implementation is experimental and has not undergone independent cryptographic review.

## 9. Architecture debt

- Single translation unit: `src/main.cpp`.
- No separate stable internal library/API.
- Cross-platform filesystem behavior needs continued testing.
- No independently audited secret-memory lifecycle.
- No complete CI matrix or independent crypto review.

See [ROADMAP](ROADMAP.md) for tracked engineering priorities.'@
$files['docs/DEVELOPMENT.md']=@'
# Разработка и сборка


## Инструменты и версии

- C++20 compiler (GCC, Clang or MSVC)
- CMake 3.20 or newer
- OpenSSL 3.x Crypto
- Python 3.8+ for test drivers

Exact supported compiler/platform combinations are not yet defined by a release CI matrix. A local successful build does not establish compatibility with every compiler or operating system.

## Release build (Linux)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## MSYS2 UCRT64

Install the UCRT64 GCC, CMake, OpenSSL and Python packages from MSYS2, then run:


```sh
cmake -S . -B build -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR="C:/msys64/ucrt64"
cmake --build build --parallel
export PATH="/c/msys64/ucrt64/bin:$PATH"
ctest --test-dir build --output-on-failure
```

The runtime DLL path must be available to the test runner. Missing DLLs are environment/build problems and should be distinguished from RCTS runtime failures.

## Visual Studio

```powershell
cmake -S . -B build -A x64 -DCMAKE_PREFIX_PATH="C:/path/to/openssl"
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

## Special build configurations

### Hardened build

Use the project's CMake configuration and record the exact options in the test report. Never describe a build as hardened merely because its directory is named `build-hardened`.

### Analyzer build

Configure the analyzer target/options supported by the current CMake file. Preserve diagnostics and treat warnings as evidence to investigate, not as a complete correctness proof.

### Fault-injection build

```sh
cmake -S . -B build-fault -DCMAKE_BUILD_TYPE=Debug -DRCTS_ENABLE_FAULT_INJECTION=ON
cmake --build build-fault --parallel
ctest --test-dir build-fault --output-on-failure
```

Fault-injection artifacts are test-only and must not be distributed as normal binaries.

### Known-answer test (KAT)

The deterministic KAT configuration is explicitly test-only. It uses a fixed test vector and deterministic entropy plumbing for reproducibility. Do not ship or use the KAT binary for real encryption.

## Development workflow

1. Start from a clean working tree or record every pre-existing change.
2. Read the architecture, format, security and test documents relevant to the task.
3. Make the smallest focused change that preserves format compatibility unless a format change is explicitly planned.
4. Build the affected configuration.
5. Run focused tests, then the applicable full test suite.
6. Capture exact command, exit code, tool versions, commit and log.
7. Review `git diff --check` and inspect the final diff.
8. Update documentation and internal handoff/evidence in the same change.

## Evidence discipline

A test is PASS only when its output/exit status was captured for the current code. A previously reported result must be labeled historical. A test that could not be run is NOT RUN; a test whose output was lost is UNVERIFIED, not PASS.
