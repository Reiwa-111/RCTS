#!/usr/bin/env python3
"""Fault-injection tests for RCTS file publication.

These tests require a build configured with -DRCTS_ENABLE_FAULT_INJECTION=ON.
The hook is compiled out of release binaries.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

FAULTS = ("create", "write", "sync", "close", "publish")


def run(binary: pathlib.Path, *args: object, fault: str | None = None,
        expect: int = 0) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if fault is None:
        environment.pop("RCTS_FAULT", None)
    else:
        environment["RCTS_FAULT"] = fault
    result = subprocess.run(
        [str(binary), *(str(argument) for argument in args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"Command returned {result.returncode}, expected {expect}: "
            f"fault={fault} args={args}\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def partial_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [path for path in root.rglob("*")
            if path.name.startswith(".rcts.partial-")]


def assert_clean_failure(root: pathlib.Path, destination: pathlib.Path,
                         result: subprocess.CompletedProcess[str]) -> None:
    assert "Injected fault" in result.stderr, result.stderr
    assert not destination.exists(), f"fault published output: {destination}"
    leftovers = partial_files(root)
    assert not leftovers, f"fault left temporary files: {leftovers}"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: fault_test.py <path-to-rcts>", file=sys.stderr)
        return 2

    binary = pathlib.Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)

    with tempfile.TemporaryDirectory(prefix="rcts-fault-") as temporary:
        root = pathlib.Path(temporary)

        key = root / "master.key"
        run(binary, "keygen", key)

        source = root / "input.bin"
        source.write_bytes(b"fault injection payload" * 200)
        container = root / "input.rct"
        run(binary, "encrypt", key, source, container)
        restored = root / "input.out"
        run(binary, "decrypt", key, container, restored)
        assert restored.read_bytes() == source.read_bytes()

        # Encryption fails at each publication stage without leaving output.
        for fault in FAULTS:
            destination = root / f"encrypt-{fault}.rct"
            result = run(binary, "encrypt", key, source, destination,
                         fault=fault, expect=1)
            assert_clean_failure(root, destination, result)

        # Decryption fails at each write/publish stage without revealing output.
        for fault in ("create", "write", "sync", "close", "publish"):
            destination = root / f"decrypt-{fault}.out"
            result = run(binary, "decrypt", key, container, destination,
                         fault=fault, expect=1)
            assert_clean_failure(root, destination, result)

        # Key generation also publishes through the same atomic path.
        for fault in FAULTS:
            destination = root / f"keygen-{fault}.key"
            result = run(binary, "keygen", destination, fault=fault, expect=1)
            assert_clean_failure(root, destination, result)

        # Without an injected fault the same operations still succeed.
        final_key = root / "final.key"
        run(binary, "keygen", final_key)
        final_container = root / "final.rct"
        run(binary, "encrypt", final_key, source, final_container)
        final_output = root / "final.out"
        run(binary, "decrypt", final_key, final_container, final_output)
        assert final_output.read_bytes() == source.read_bytes()

        leftovers = partial_files(root)
        assert not leftovers, f"temporary files were left behind: {leftovers}"

    print("RCTS fault-injection tests: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"RCTS fault-injection tests: FAIL: {exc}", file=sys.stderr)
        raise
