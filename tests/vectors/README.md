# Public compatibility vectors


The fixture files in this directory are deterministic test artifacts. They use known test-only material and are intended only to validate compatibility with the RCTS v0.1 implementation. Never reuse the fixture key or deterministic KAT configuration to encrypt private data.


The test vector is consumed by the smoke/KAT test scripts. The fixture is checked in intentionally so implementations can verify byte-level behavior without generating a new encrypted output.