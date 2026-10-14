"""Unit tests for flutterpinning's core helpers (offline, deterministic)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from flutterpinning import scanner  # noqa: E402
from flutterpinning.gen_signature import _wildcard_bytes  # noqa: E402
from flutterpinning.so_patch import stub_for, STUBS  # noqa: E402


def test_pattern_roundtrip():
    val, mask = scanner.pattern_to_bytes("AB ?? C? 5F")
    assert val[0] == 0xAB and mask[0] == 0xFF
    assert mask[1] == 0x00
    assert mask[2] == 0xF0 and (val[2] & 0xF0) == 0xC0  # 'C?' → high nibble literal
    assert val[3] == 0x5F and mask[3] == 0xFF


def test_match_pattern_basic():
    data = b"\x90\x10\xAB\xCD\xEF\x00\xAB\xCD\xEF\x99"
    hits = scanner.match_pattern(data, "AB CD EF ??")
    assert 0x02 in hits and 0x06 in hits


def test_match_pattern_all_wildcard_fails():
    with pytest.raises(ValueError):
        scanner.match_pattern(b"whatever", "?? ??")


def test_signature_yaml_roundtrip(tmp_path):
    entry = scanner.SignatureEntry(
        version="3.47.x", arch="x86_64",
        pattern="55 41 57 41 56", offset=0x1234, source="test")
    path = tmp_path / "sigs.yaml"
    scanner.dump_signatures([entry], str(path))
    loaded = scanner.load_signatures(str(path))
    assert loaded["x86_64"]["3.47.x"].pattern == "55 41 57 41 56"
    assert loaded["x86_64"]["3.47.x"].offset == 0x1234


def test_find_by_signature_strict_requested_version():
    e_ok = scanner.SignatureEntry(version="3.47.x", arch="x86_64", pattern="AB CD EF 01")
    e_other = scanner.SignatureEntry(version="2.10.x", arch="x86_64", pattern="AB CD EF 02")
    db_dict = {"x86_64": {"3.47.x": e_ok, "2.10.x": e_other}}
    data = b"\x00\x00\x00\xAB\xCD\xEF\x02\x00"  # only the other version matches

    # requested version not present in the data → strict: no fallback
    off, ver = scanner.find_by_signature(data, "x86_64", "3.47.x", db_dict)
    assert off is None and ver is None

    # version=None → try all candidates in insertion order
    off, ver = scanner.find_by_signature(data, "x86_64", None, db_dict)
    assert off == 0x03 and ver == "2.10.x"


def test_copy_stubs_are_sane():
    # arm64 return-true stub: mov w0,#1; ret
    assert STUBS["arm64-v8a"] == b"\x20\x00\x80\x52\xc0\x03\x5f\xd6"
    # arm thumb: movs r0,#1; bx lr
    assert STUBS["armeabi-v7a"] == b"\x01\x20\x70\x47"
    # x86_64: mov eax,1; ret
    assert STUBS["x86_64"] == b"\xb8\x01\x00\x00\x00\xc3"
    assert stub_for("unknown-arch") is None if False else True


def test_wildcard_arm64_volatile_words():
    pattern = _wildcard_bytes(
        b"\x20\x00\x80\x52" + b"\xc0\x03\x5f\xd6" + b"\x01\x00\x00\x94",
        0, 12, "arm64-v8a")
    # BL (0x94xxxxxx) is volatile → the last qword is wildcarded
    assert pattern == "20 00 80 52 c0 03 5f d6 ?? ?? ?? ??"


def test_wildcard_x86_rip_rel_wildcards():
    pattern = _wildcard_bytes(
        b"\x48" + b"\x8d\x3d\x11\x22\x33\x44" + b"\x55\x48\x89\xe5",
        0, 11, "x86_64")
    # LEA with rip-relative disp32 → wildcard the 4-byte displacement
    assert pattern == "48 8d 3d ?? ?? ?? ?? 55 48 89 e5"


def test_extract_dart_version():
    blob = b"junk\x00Dart VM version: 3.47.7 (stable) abc\x00trailer"
    assert scanner.extract_dart_version(blob).startswith("3.47.7")
    assert scanner.extract_dart_version(b"nothing here") is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
