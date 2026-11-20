# last updated: 0.3.0 | 2026-11-20 | DOCUMENTATION RESTRUCTURE

# RCTS

**RCTS** is an experimental C++20 command-line tool for encrypting files into a chunked authenticated container. Container format RCTS v0.1 uses AES-256-GCM and HKDF-SHA-256 from OpenSSL 3.x. This is a research prototype, not an independently reviewed security product.

| Property | Value |
|---|---|
| Application version | `0.3.0` (`VERSION`) |
| Container format | `v0.1` (header version byte `1`) |
| Language | C++20 |
| Crypto dependency | OpenSSL 3.x, Crypto |
| Interface | CLI: `keygen`, `encrypt`, `decrypt` |
| Data processing | Streaming, 1 MiB chunks |
| Development platforms | Linux and Windows; verification depends on available environments |
| Status | Experimental; independent cryptographic review is incomplete |

> **Warning:** Do not use RCTS as the sole protection for critical, irreplaceable or sensitive data. Keep independent backups. The presence of AES-GCM does not eliminate implementation, filesystem, key-management or operating-system risks.

## Implemented features

- Generate a 32-byte master key using OpenSSL CSPRNG and encode it as 32 Unicode characters.
- Derive a container-specific key using HKDF-SHA-256 and a random 16-byte salt.
- AES-256-GCM with a separate 16-byte authentication tag per record.
- Stream files in 1 MiB chunks without loading the entire input into memory.
- Authenticate the header, record index, length and flags as AAD.
- Validate container framing and authentication during decryption.
- Exclusively create temporary files, check write/sync/close operations and publish output without replacing existing files.
- Smoke tests, a fixed compatibility vector, fault-injection tests and a separate KAT configuration.

## Build

### Linux (GCC or Clang)

Requirements: C++20 compiler, CMake 3.20+, OpenSSL 3.x Crypto and Python 3.8+ for tests.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Windows / MSYS2 UCRT64

Install UCRT64 GCC, CMake, OpenSSL and Python packages from MSYS2. In a UCRT64 shell:

```sh
cmake -S . -B build -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR="C:/msys64/ucrt64"
cmake --build build --parallel
export PATH="/c/msys64/ucrt64/bin:$PATH"
ctest --test-dir build --output-on-failure
```

### Visual Studio

```powershell
cmake -S . -B build -A x64 -DCMAKE_PREFIX_PATH="C:/path/to/openssl"
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

OpenSSL paths depend on the installation method. Do not set `CMAKE_PREFIX_PATH` if CMake already discovers the correct OpenSSL installation.

## Usage

Commands:

```text
rcts keygen <key-file>
rcts encrypt <key-file> <input-file> <output.rct>
rcts decrypt <key-file> <input.rct> <output-file>
```

Examples, after building:

```sh
./build/rcts keygen secret.key
./build/rcts encrypt secret.key input.bin archive.rct
./build/rcts decrypt secret.key archive.rct restored.bin
```

On Windows, launch `build\\Release\\rcts.exe` for the Visual Studio generator or the corresponding `rcts.exe` in the MinGW build directory. OpenSSL runtime DLLs must be available.

### File behavior

- Existing key and output files are not overwritten.
- Key and input files must be regular files; key reads are bounded.
- Decryption must fail on authentication errors.
- Final output is published only after processing and finalization succeed.
- Exit codes: `0` success, `1` operation failure, `2` invalid arguments.

## Format and cryptography

| Parameter | Value |
|---|---|
| Header | 33 bytes, fixed |
| Salt | 16 bytes |
| Nonce | 4-byte prefix + 64-bit record index (BE) |
| Chunk size | 1 MiB |
| Maximum records | 65,536 |
| Maximum plaintext size | 64 GiB |
| KDF | HKDF-SHA-256 |
| Cipher | AES-256-GCM |
| GCM tag | 16 bytes per record |
| Key encoding | 32 Unicode code points `U+4E00..U+4EFF`, UTF-8 |

See the [specification](docs/eng/reference/specification.md), [container format](docs/eng/reference/container-format.md) and [key format](docs/eng/reference/key-format.md).

## Documentation

- [Documentation index](docs/README.md) — entry point for the English how-to, reference and explanation sections.
- [Architecture](docs/eng/explanation/architecture.md) — actual components, encrypt/decrypt paths, file operations and implementation boundaries.
- [Specification](docs/eng/reference/specification.md) — application and format contract.
- [Binary format](docs/eng/reference/container-format.md) — header, records, nonce, AAD, framing and validation.
- [Key format](docs/eng/reference/key-format.md) — generation, encoding, reading and validation.
- [Security model](docs/eng/explanation/security.md) — threats, assumptions, properties and limitations.
- [Testing](docs/eng/how-to/testing.md) — suites, commands, coverage and limits.
- [Development](docs/eng/how-to/development.md) — build configurations and workflow.
- [Decisions](docs/eng/explanation/decisions.md) — architecture decision records.
- [Roadmap](docs/eng/explanation/roadmap.md) — milestones and completion criteria, without date promises.
- [Changelog](CHANGELOG.md) — user-visible changes by version.
- [License status](LICENSE_STATUS.md) — project and dependency licensing notes.

## Repository layout

```text
RCTS/
├── src/                 # CLI and container implementation
├── tests/               # smoke, KAT, fault injection, fixtures
├── docs/                 # public documentation, Diataxis-style English tree
│   ├── README.md         # documentation landing page
│   └── eng/              # how-to, reference and explanation
├── build*/               # local build/evidence directories (ignored)
├── CMakeLists.txt         # build and test configuration
├── VERSION               # application version
├── LICENSE               # project license
├── LICENSE_STATUS.md     # licensing and third-party notes
├── SHA256SUMS.txt        # checksums for selected tracked files
└── README.md
```

## Testing and limitations

CTest runs the tests registered in the active CMake configuration. Separate configurations cover Release/Hardened/Analyzer builds, fault injection and a cryptographic known-answer test. Results should be considered verified only when logs from the exact source revision and build environment are available.

Known limitations include the lack of independent cryptographic review, an incomplete OS/compiler matrix, limited coverage of rare filesystem failures and no proof of secure erasure of all secret copies in memory. See [SECURITY](docs/eng/explanation/security.md) and [ROADMAP](docs/eng/explanation/roadmap.md).

## License

RCTS-authored code and documentation are licensed under Apache License 2.0. OpenSSL and other external components have their own licenses and distribution conditions. See [`LICENSE`](LICENSE) and [`LICENSE_STATUS.md`](LICENSE_STATUS.md).
