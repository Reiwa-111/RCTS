# last updated: 0.3.1 | 2026-11-20 | BUILD AND WORKFLOW

# Development and build guide

## Toolchain

- C++20 compiler
- CMake 3.20 or newer
- OpenSSL 3.x Crypto
- Python 3.8+ for test runners

The project does not yet define a complete CI-backed compiler/platform support matrix. A successful local build is not a claim of compatibility with every toolchain.

## Linux release build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## MSYS2 UCRT64

Install the UCRT64 GCC, CMake, OpenSSL and Python packages, then run from the UCRT64 shell:

```sh
cmake -S . -B build -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR="C:/msys64/ucrt64"
cmake --build build --parallel
export PATH="/c/msys64/ucrt64/bin:$PATH"
ctest --test-dir build --output-on-failure
```

OpenSSL runtime DLLs must be available to the test runner. Missing DLLs are environment issues and should not be misreported as application failures.

## Visual Studio

```powershell
cmake -S . -B build -A x64 -DCMAKE_PREFIX_PATH="C:/path/to/openssl"
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

## Special configurations

### Fault injection

```sh
cmake -S . -B build-fault -DCMAKE_BUILD_TYPE=Debug -DRCTS_ENABLE_FAULT_INJECTION=ON
cmake --build build-fault --parallel
ctest --test-dir build-fault --output-on-failure
```

Fault-injection builds are for tests and must not be distributed as ordinary application binaries.

### Known-answer test

The deterministic KAT configuration exists only to reproduce a test fixture. Do not ship or use the deterministic KAT binary to encrypt real files.

## Contributor workflow

1. Start from a clean worktree or document pre-existing changes.
2. Read the architecture, format, security and testing references relevant to the change.
3. Keep changes focused and preserve format compatibility unless a versioned change is explicitly planned.
4. Build the affected configuration.
5. Run focused tests and then the relevant complete suite.
6. Record exact commands, environment, revision, output and exit code.
7. Inspect the final diff and run `git diff --check`.
8. Update public and internal documentation in the same work session.

## Evidence policy

A test is PASS only when its output and exit status are captured for the current revision. A previous result is historical. Missing output is UNVERIFIED; a skipped test is not a pass.
