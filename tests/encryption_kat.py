#!/usr/bin/env python3
"""Deterministic encryption known-answer test for the v0.3 container."""
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile


def run(binary: pathlib.Path, *args: pathlib.Path) -> None:
    result = subprocess.run(
        [str(binary), *(str(arg) for arg in args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {args}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def main() -> int:
    binary = pathlib.Path(sys.argv[1]).resolve()
    vectors = pathlib.Path(__file__).resolve().parent / "vectors"
    key = vectors / "hello-world-v0.1.key"
    expected = vectors / "encrypt-hello-world-v0.3.rct"
    plaintext = b"HELLO WORLD"

    with tempfile.TemporaryDirectory(prefix="rcts-kat-") as temporary:
        root = pathlib.Path(temporary)
        source = root / "plaintext.bin"
        encrypted = root / "encrypted.rct"
        recovered = root / "recovered.bin"
        source.write_bytes(plaintext)

        run(binary, pathlib.Path("encrypt"), key, source, encrypted)
        actual = encrypted.read_bytes()
        expected_bytes = expected.read_bytes()
        if len(actual) < 9 or actual[8] != 3:
            raise AssertionError("New encryption did not emit container version 3")
        if actual != expected_bytes:
            raise AssertionError(
                "Deterministic encryption output differs from frozen v0.3 vector"
            )

        run(binary, pathlib.Path("decrypt"), key, encrypted, recovered)
        if recovered.read_bytes() != plaintext:
            raise AssertionError("KAT decryption did not recover the expected plaintext")

    print("RCTS encryption KAT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
