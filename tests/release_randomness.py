#!/usr/bin/env python3
"""Verify the normal executable uses randomized per-container entropy."""
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile


def run(binary: pathlib.Path, *args: object) -> None:
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
    if len(sys.argv) != 2:
        print("usage: release_randomness.py <path-to-rcts>", file=sys.stderr)
        return 2
    binary = pathlib.Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)

    with tempfile.TemporaryDirectory(prefix="rcts-randomness-") as temp:
        root = pathlib.Path(temp)
        key = root / "key.txt"
        source = root / "input.bin"
        first = root / "first.rct"
        second = root / "second.rct"
        run(binary, "keygen", key)
        source.write_bytes(b"release entropy regression" * 32)
        run(binary, "encrypt", key, source, first)
        run(binary, "encrypt", key, source, second)
        first_header = first.read_bytes()[:33]
        second_header = second.read_bytes()[:33]
        if first_header == second_header:
            raise AssertionError("normal executable reused deterministic header entropy")
        if first.read_bytes() == second.read_bytes():
            raise AssertionError("normal executable produced identical containers")

    print("RCTS release-randomness regression: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
