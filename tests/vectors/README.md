# Public compatibility vectors


The fixture files in this directory are deterministic test artifacts. They use known test-only material and are intended only to validate compatibility with the RCTS v0.1 legacy reader and the RCTS v0.3 implementation. Never reuse the fixture key or deterministic KAT configuration to encrypt private data.


The fixed container is consumed by smoke tests for decryption compatibility. The deterministic encryption KAT additionally compares the complete output against this fixture using a test-only salt and nonce-prefix seam. The fixture is checked in intentionally so implementations can verify byte-level behavior without generating a new encrypted output.

The v0.1 fixture remains for legacy-read coverage. `encrypt-hello-world-v0.3.rct` is the deterministic v0.3 encryption KAT artifact; its key and entropy are test-only.
