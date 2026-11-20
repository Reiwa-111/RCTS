#!/usr/bin/env python3
"""Black-box regression tests for the RCTS CLI (Python standard library only)."""
from __future__ import annotations

import os
import pathlib
import random
import shutil
import stat
import subprocess
import sys
import tempfile

CHUNK = 1024 * 1024
HEADER_SIZE = 33
RECORD_HEADER_SIZE = 5
TAG_SIZE = 16
MAGIC = b"RCTS\r\n\x1a\n"
VERSION = 1
MAX_RECORDS = 1 << 16
MAX_PLAINTEXT = CHUNK * MAX_RECORDS
MIN_CONTAINER = HEADER_SIZE + RECORD_HEADER_SIZE + TAG_SIZE


def run(binary: pathlib.Path, *args: object, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(binary), *(str(arg) for arg in args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != expect:
        raise AssertionError(
            f"Command returned {result.returncode}, expected {expect}: {args}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def must_fail_decrypt(binary: pathlib.Path, key: pathlib.Path, container: pathlib.Path,
                      output: pathlib.Path) -> None:
    run(binary, "decrypt", key, container, output, expect=1)
    assert not output.exists(), f"failed decryption left a published output: {output}"


def partial_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [path for path in root.rglob("*") if path.name.startswith(".rcts.partial-")]


def assert_no_partials(root: pathlib.Path, label: str = "") -> None:
    leftovers = partial_files(root)
    assert not leftovers, f"temporary files were left behind ({label}): {leftovers}"


def parse_container(data: bytes) -> list[tuple[int, int]]:
    """Validate structural invariants and return (plaintext_length, flags) records."""
    assert len(data) >= MIN_CONTAINER
    assert data[:8] == MAGIC, "bad magic"
    assert data[8] == VERSION, "bad version"
    assert int.from_bytes(data[9:13], "big") == CHUNK, "bad chunk size"

    records: list[tuple[int, int]] = []
    offset = HEADER_SIZE
    while True:
        assert offset + RECORD_HEADER_SIZE <= len(data), "truncated record header"
        length = int.from_bytes(data[offset:offset + 4], "big")
        flags = data[offset + 4]
        records.append((length, flags))
        offset += RECORD_HEADER_SIZE + length + TAG_SIZE
        assert offset <= len(data), "truncated record"
        assert len(records) <= MAX_RECORDS, "too many records"
        if flags == 1:
            break
    assert offset == len(data), "trailing bytes in container"
    return records


def split_records(data: bytes) -> tuple[bytes, list[bytes]]:
    header = data[:HEADER_SIZE]
    records: list[bytes] = []
    offset = HEADER_SIZE
    while True:
        length = int.from_bytes(data[offset:offset + 4], "big")
        flags = data[offset + 4]
        end = offset + RECORD_HEADER_SIZE + length + TAG_SIZE
        records.append(data[offset:end])
        offset = end
        if flags == 1:
            break
    assert offset == len(data)
    return header, records


def windows_dacl_sddl(path: pathlib.Path) -> str | None:
    """Return the SDDL description of a file, or None when unavailable."""
    if os.name != "nt":
        return None
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        print("note: PowerShell not found; skipping DACL inspection", file=sys.stderr)
        return None
    literal = str(path).replace("'", "''")
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-Acl -LiteralPath '{literal}').Sddl"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        print(f"note: cannot read DACL for {path}: {result.stderr.strip()}", file=sys.stderr)
        return None
    return result.stdout.strip()


def check_private_windows_dacl(path: pathlib.Path) -> None:
    """Verify the file DACL is protected and does not grant broad principals."""
    sddl = windows_dacl_sddl(path)
    if sddl is None:
        return
    assert "D:P" in sddl, f"DACL is not protected for {path}: {sddl}"
    for sid, name in (
        ("S-1-1-0", "Everyone"),
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-5-32-545", "Users"),
    ):
        assert sid not in sddl, f"DACL grants {name} on {path}: {sddl}"
    assert "S-1-5-21-" in sddl or "S-1-5-32-544" in sddl, (
        f"DACL does not name an owner/administrator SID: {sddl}")


def launch(binary: pathlib.Path, commands: list[list[object]]) -> tuple[list[int], list[str]]:
    processes = [
        subprocess.Popen(
            [str(binary), *(str(argument) for argument in command)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        for command in commands
    ]
    stderr = [process.communicate()[1] for process in processes]
    return [process.returncode for process in processes], stderr


def concurrency_publication(binary: pathlib.Path, root: pathlib.Path,
                            key: pathlib.Path) -> None:
    """Exactly one concurrent publisher may win; no file may be overwritten."""
    contenders = 6
    for round_index in range(6):
        destination = root / f"race-{round_index}.rct"
        inputs: list[pathlib.Path] = []
        for index in range(contenders):
            source = root / f"race-{round_index}-{index}.bin"
            source.write_bytes(bytes([65 + index]) * 2048 + bytes([index]))
            inputs.append(source)
        codes, errors = launch(
            binary,
            [["encrypt", key, source, destination] for source in inputs],
        )
        assert codes.count(0) == 1, (
            f"expected exactly one successful encryption, got {codes}: {errors}")
        assert all(code in (0, 1) for code in codes), (codes, errors)

        restored = root / f"race-{round_index}.out"
        run(binary, "decrypt", key, destination, restored)
        assert restored.read_bytes() in [source.read_bytes() for source in inputs]

    for round_index in range(4):
        destination = root / f"race-key-{round_index}.key"
        codes, errors = launch(
            binary, [["keygen", destination] for _ in range(contenders)])
        assert codes.count(0) == 1, (
            f"expected exactly one successful keygen, got {codes}: {errors}")
        assert all(code in (0, 1) for code in codes), (codes, errors)
        data = destination.read_bytes()
        assert len(data) == 97 and data.endswith(b"\n"), data

    assert_no_partials(root, "concurrency")


def random_mutations(binary: pathlib.Path, root: pathlib.Path, key: pathlib.Path,
                     base: bytes, count: int = 80) -> None:
    """Every single-byte mutation must be rejected without leftovers."""
    generator = random.Random(0x5EED_2026)
    for index in range(count):
        changed = bytearray(base)
        position = generator.randrange(len(changed))
        changed[position] ^= generator.randrange(1, 256)
        container = root / f"mutation-{index}.rct"
        container.write_bytes(bytes(changed))
        must_fail_decrypt(binary, key, container, root / f"mutation-{index}.out")
        assert_no_partials(root, f"mutation-{index}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: smoke_test.py <path-to-rcts>", file=sys.stderr)
        return 2

    binary = pathlib.Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)

    with tempfile.TemporaryDirectory(prefix="rcts-smoke-") as temporary:
        root = pathlib.Path(temporary)

        # CLI usage errors are distinct from operation errors.
        usage = run(binary, expect=2)
        project_version = (pathlib.Path(__file__).resolve().parents[1] / "VERSION").read_text(
            encoding="utf-8").strip()
        assert f"RCTS Sandbox {project_version}" in usage.stderr, usage.stderr
        run(binary, "bogus", expect=2)
        run(binary, "encrypt", "only-one-argument", expect=2)

        # Fixed public vector: protects backward readability of the v0.1 format.
        vectors = pathlib.Path(__file__).resolve().parent / "vectors"
        vector_key = vectors / "hello-world-v0.1.key"
        vector_container = vectors / "hello-world-v0.1.rct"
        vector_output = root / "known-vector.out"
        run(binary, "decrypt", vector_key, vector_container, vector_output)
        assert vector_output.read_bytes() == b"HELLO WORLD"

        # The published vector must remain structurally canonical.
        assert parse_container(vector_container.read_bytes()) == [(11, 1)]

        key = root / "master.key"
        run(binary, "keygen", key)
        key_bytes = key.read_bytes()
        key_text = key_bytes.decode("utf-8")
        assert key_text.endswith("\n")
        assert len(key_bytes) == 97, "key file must be 96 UTF-8 bytes plus one LF"
        symbols = key_text[:-1]
        assert len(symbols) == 32
        assert all(0x4E00 <= ord(char) <= 0x4EFF for char in symbols)
        check_private_windows_dacl(key)

        if os.name == "posix":
            key_mode = stat.S_IMODE(os.stat(key).st_mode)
            assert key_mode & 0o077 == 0, f"key file is not private: {oct(key_mode)}"

        # A second keygen must not silently replace an existing key.
        before = key.read_bytes()
        run(binary, "keygen", key, expect=1)
        assert key.read_bytes() == before

        # Accepted key-file line endings: none, LF, or CRLF.
        vector_key_text = vector_key.read_text(encoding="utf-8")
        assert vector_key_text.endswith("\n")
        accepted = {
            "no-newline": vector_key_text[:-1],
            "lf": vector_key_text,
            "crlf": vector_key_text[:-1] + "\r\n",
        }
        for label, text in accepted.items():
            variant = root / f"accepted-{label}.key"
            variant.write_bytes(text.encode("utf-8"))
            restored = root / f"accepted-{label}.out"
            run(binary, "decrypt", variant, vector_container, restored)
            assert restored.read_bytes() == b"HELLO WORLD", label

        # Rejected key files: malformed envelope, malformed UTF-8, wrong alphabet,
        # duplicates of the trailing newline, and unbounded input.
        raw_key = vector_key_text[:-1].encode("utf-8")
        rejected = {
            "empty": b"",
            "extra-lf": vector_key_text.encode("utf-8") + b"\n",
            "extra-crlf": vector_key_text[:-1].encode("utf-8") + b"\r\n\n",
            "trailing-space": raw_key[:-1] + b" \n",
            "bom": b"\xef\xbb\xbf" + vector_key_text.encode("utf-8"),
            "out-of-alphabet": "\u4f00".encode("utf-8") + raw_key[3:] + b"\n",
            "bad-utf8-lead": b"\xe5" + raw_key[1:] + b"\n",
            "truncated": raw_key[:95] + b"\n",
            "extended": raw_key + b"X" + b"\n",
            "oversized": b"A" * 1024,
        }
        for label, data in rejected.items():
            variant = root / f"rejected-{label}.key"
            variant.write_bytes(data)
            output = root / f"rejected-{label}.out"
            run(binary, "decrypt", variant, vector_container, output, expect=1)
            assert not output.exists(), f"bad key accepted: {label}"

        run(binary, "decrypt", root / "missing.key", vector_container,
            root / "missing-key.out", expect=1)
        run(binary, "decrypt", root, vector_container, root / "directory-key.out", expect=1)

        # Non-regular inputs are rejected quickly. A FIFO must not block the
        # process, because input descriptors are opened non-blocking on POSIX.
        if hasattr(os, "mkfifo"):
            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            run(binary, "encrypt", key, fifo, root / "fifo.rct", expect=1)
            assert not (root / "fifo.rct").exists()
            run(binary, "decrypt", fifo, vector_container, root / "fifo-key.out", expect=1)
            assert not (root / "fifo-key.out").exists()

        payloads = {
            "empty": b"",
            "one-byte": b"R",
            "short": bytes(range(251)),
            "chunk-minus-one": os.urandom(CHUNK - 1),
            "exact-chunk": os.urandom(CHUNK),
            "chunk-plus-one": os.urandom(CHUNK + 1),
            "two-chunks": os.urandom(2 * CHUNK),
            "three-chunks": os.urandom(3 * CHUNK),
            "two-chunks-plus-tail": os.urandom(2 * CHUNK + 37),
            "distinct-chunks": b"A" * CHUNK + b"B" * CHUNK + b"C" * 37,
        }

        containers: dict[str, pathlib.Path] = {}
        for name, payload in payloads.items():
            source = root / f"{name}.bin"
            encrypted = root / f"{name}.rct"
            restored = root / f"{name}.restored"
            source.write_bytes(payload)
            run(binary, "encrypt", key, source, encrypted)
            run(binary, "decrypt", key, encrypted, restored)
            assert restored.read_bytes() == payload, f"round-trip mismatch: {name}"
            if os.name == "posix":
                for output in (encrypted, restored):
                    mode = stat.S_IMODE(os.stat(output).st_mode)
                    assert mode & 0o077 == 0, f"output is not private: {output} {oct(mode)}"
            containers[name] = encrypted

        check_private_windows_dacl(containers["short"])
        check_private_windows_dacl(root / "short.restored")

        assert parse_container(containers["empty"].read_bytes()) == [(0, 1)]
        assert parse_container(containers["one-byte"].read_bytes()) == [(1, 1)]
        assert parse_container(containers["short"].read_bytes()) == [(251, 1)]
        assert parse_container(containers["exact-chunk"].read_bytes()) == [(CHUNK, 1)]
        assert parse_container(containers["two-chunks"].read_bytes()) == [
            (CHUNK, 0), (CHUNK, 1)]
        assert parse_container(containers["three-chunks"].read_bytes()) == [
            (CHUNK, 0), (CHUNK, 0), (CHUNK, 1)]
        assert parse_container(containers["chunk-plus-one"].read_bytes()) == [
            (CHUNK, 0), (1, 1)]
        assert parse_container(containers["distinct-chunks"].read_bytes()) == [
            (CHUNK, 0), (CHUNK, 0), (37, 1)]

        # Same plaintext/key must not produce the same container.
        source = root / "same.bin"
        source.write_bytes(b"same plaintext")
        first = root / "same-1.rct"
        second = root / "same-2.rct"
        run(binary, "encrypt", key, source, first)
        run(binary, "encrypt", key, source, second)
        assert first.read_bytes() != second.read_bytes()

        # Existing destinations are never overwritten, for encrypt and decrypt.
        protected_output = root / "protected.out"
        protected_output.write_bytes(b"keep me")
        run(binary, "decrypt", key, containers["short"], protected_output, expect=1)
        assert protected_output.read_bytes() == b"keep me"

        protected_container = root / "protected.rct"
        protected_container.write_bytes(b"keep me too")
        run(binary, "encrypt", key, source, protected_container, expect=1)
        assert protected_container.read_bytes() == b"keep me too"

        # Existing symlinks (including dangling ones) are never followed or
        # replaced. Symlink creation may be unavailable without extra privileges.
        try:
            victim = root / "symlink-victim.bin"
            victim.write_bytes(b"victim data")
            existing_link = root / "existing-link.rct"
            os.symlink(victim, existing_link)
            dangling_link = root / "dangling-link.rct"
            os.symlink(root / "does-not-exist", dangling_link)
        except (OSError, NotImplementedError):
            pass
        else:
            run(binary, "encrypt", key, source, existing_link, expect=1)
            assert victim.read_bytes() == b"victim data"
            assert existing_link.is_symlink()
            run(binary, "encrypt", key, source, dangling_link, expect=1)
            assert not (root / "does-not-exist").exists()
            assert dangling_link.is_symlink()
            run(binary, "keygen", existing_link, expect=1)
            assert victim.read_bytes() == b"victim data"

        # Directories, missing inputs and missing output parents are rejected
        # without publishing output.
        run(binary, "encrypt", key, root / "missing.bin", root / "missing-input.rct", expect=1)
        assert not (root / "missing-input.rct").exists()
        run(binary, "encrypt", key, root, root / "directory-input.rct", expect=1)
        assert not (root / "directory-input.rct").exists()
        run(binary, "encrypt", key, source, root, expect=1)
        run(binary, "decrypt", key, containers["short"], root, expect=1)
        run(binary, "decrypt", key, root / "missing.rct", root / "missing-container.out", expect=1)
        run(binary, "decrypt", key, root, root / "directory-container.out", expect=1)
        run(binary, "encrypt", key, source, root / "missing-dir" / "out.rct", expect=1)
        assert not (root / "missing-dir").exists()

        # Long destination names must not fail because of the temporary suffix;
        # the temporary file uses a short name in the destination directory.
        long_name = "l" * 180
        long_container = root / f"{long_name}.rct"
        long_restored = root / f"{long_name}.out"
        run(binary, "encrypt", key, source, long_container)
        run(binary, "decrypt", key, long_container, long_restored)
        assert long_restored.read_bytes() == source.read_bytes()
        assert_no_partials(root, "long-name")

        # Paths are Unicode on Windows because the entry point is wmain and all
        # file APIs are wide; POSIX paths are byte strings.
        unicode_dir = root / "каталог 数据 с пробелами"
        unicode_dir.mkdir()
        unicode_key = unicode_dir / "ключ 🔑.key"
        unicode_source = unicode_dir / "файл данных.bin"
        unicode_container = unicode_dir / "контейнер 🔐.rct"
        unicode_restored = unicode_dir / "результат.bin"
        unicode_source.write_bytes("unicode payload ".encode("utf-8") * 100)
        run(binary, "keygen", unicode_key)
        run(binary, "encrypt", unicode_key, unicode_source, unicode_container)
        run(binary, "decrypt", unicode_key, unicode_container, unicode_restored)
        assert unicode_restored.read_bytes() == unicode_source.read_bytes()

        # A read-only output directory must fail without publishing anything.
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
            locked = root / "locked-dir"
            locked.mkdir()
            locked.chmod(0o500)
            try:
                run(binary, "encrypt", key, source, locked / "out.rct", expect=1)
                assert not (locked / "out.rct").exists()
            finally:
                locked.chmod(0o700)

        # 64 GiB is the exact format limit; anything larger is rejected by the
        # size preflight before a temporary file is created. A sparse file keeps
        # this test cheap on POSIX filesystems.
        if os.name == "posix":
            oversized = root / "oversized-sparse.bin"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_PLAINTEXT + 1)
            assert oversized.stat().st_size == MAX_PLAINTEXT + 1
            run(binary, "encrypt", key, oversized, root / "oversized.rct", expect=1)
            assert not (root / "oversized.rct").exists()
            assert_no_partials(root, "oversized-preflight")
            oversized.unlink()

        wrong_key = root / "wrong.key"
        run(binary, "keygen", wrong_key)
        must_fail_decrypt(binary, wrong_key, containers["short"], root / "wrong-key.out")

        original = bytearray(containers["short"].read_bytes())
        assert len(original) == HEADER_SIZE + RECORD_HEADER_SIZE + len(payloads["short"]) + TAG_SIZE

        def corrupt(label: str, mutate) -> None:
            changed = bytearray(original)
            mutate(changed)
            damaged = root / f"damaged-{label}.rct"
            damaged.write_bytes(changed)
            must_fail_decrypt(binary, key, damaged, root / f"damaged-{label}.out")
            assert_no_partials(root, label)

        # Mutate ciphertext, every authenticated header field, and the tag.
        corrupt("ciphertext", lambda data: data.__setitem__(
            HEADER_SIZE + RECORD_HEADER_SIZE, data[HEADER_SIZE + RECORD_HEADER_SIZE] ^ 0x01))
        corrupt("salt", lambda data: data.__setitem__(13, data[13] ^ 0x01))
        corrupt("nonce-prefix", lambda data: data.__setitem__(29, data[29] ^ 0x01))
        corrupt("tag", lambda data: data.__setitem__(len(data) - 1, data[-1] ^ 0x01))
        corrupt("magic", lambda data: data.__setitem__(0, data[0] ^ 0x01))
        corrupt("version", lambda data: data.__setitem__(8, 2))
        corrupt("chunk-size", lambda data: data.__setitem__(
            slice(9, 13), (CHUNK - 1).to_bytes(4, "big")))

        def decrypt_bytes(label: str, data: bytes) -> None:
            path = root / f"{label}.rct"
            path.write_bytes(data)
            output = root / f"{label}.out"
            must_fail_decrypt(binary, key, path, output)
            assert_no_partials(root, label)

        # Header and record truncation at every interesting boundary.
        decrypt_bytes("empty-file", b"")
        for length in range(HEADER_SIZE):
            decrypt_bytes(f"header-{length}", bytes(original[:length]))
        decrypt_bytes("header-only", bytes(original[:HEADER_SIZE]))
        decrypt_bytes("truncated-tag", bytes(original[:-1]))
        decrypt_bytes("missing-tag", bytes(original[:-TAG_SIZE]))
        decrypt_bytes("truncated-ciphertext", bytes(original[:-TAG_SIZE - 1]))

        # Trailing bytes, including a structurally plausible extra final record.
        decrypt_bytes("trailing-byte", bytes(original) + b"x")
        decrypt_bytes("trailing-record", bytes(original) + b"\x00\x00\x00\x00\x01" + b"\x00" * TAG_SIZE)

        # Invalid framing.
        def set_record_header(label: str, length: int, flags: int) -> None:
            changed = bytearray(original)
            changed[HEADER_SIZE:HEADER_SIZE + 4] = length.to_bytes(4, "big")
            changed[HEADER_SIZE + 4] = flags
            decrypt_bytes(label, bytes(changed))

        set_record_header("bad-flags-0x02", len(payloads["short"]), 0x02)
        set_record_header("bad-flags-0x80", len(payloads["short"]), 0x80)
        set_record_header("bad-length-oversized", CHUNK + 1, 1)
        set_record_header("bad-length-short-nonfinal", 10, 0)
        set_record_header("zero-length-nonfinal", 0, 0)
        set_record_header("huge-length", 0xFFFFFFFF, 1)

        # Multi-record framing: missing FINAL, reordered and duplicated records,
        # and a zero-length FINAL at a non-zero index.
        distinct = containers["distinct-chunks"].read_bytes()
        distinct_header, distinct_records = split_records(distinct)
        assert len(distinct_records) == 3

        decrypt_bytes("missing-final",
                      distinct_header + b"".join(distinct_records[:2]))
        decrypt_bytes("reordered-records",
                      distinct_header + distinct_records[1] + distinct_records[0] +
                      distinct_records[2])
        decrypt_bytes("duplicated-record",
                      distinct_header + distinct_records[0] + distinct_records[0] +
                      distinct_records[2])
        decrypt_bytes("zero-final-at-index-1",
                      distinct_header + distinct_records[0] +
                      b"\x00\x00\x00\x00\x01" + b"\x00" * TAG_SIZE)

        # Deterministic single-byte mutations across the whole container.
        random_mutations(binary, root, key, bytes(original))

        # Concurrent publishers: one winner, no overwrite, no leftovers.
        concurrency_publication(binary, root, key)

        # No temporary files may survive any success or failure.
        assert_no_partials(root, "final")

    print("RCTS smoke tests: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # Keep the failure actionable in CTest logs.
        print(f"RCTS smoke tests: FAIL: {exc}", file=sys.stderr)
        raise
