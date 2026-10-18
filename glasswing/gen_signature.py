"""Signature generation: extract PR-ready byte-signatures from located entries.

`glasswing gen-sig <apk>` runs the version-independent struct locator on
the app's libflutter.so, then captures the first bytes of the located function
as a wildcard pattern for db/signatures.yaml (fast path for future engines).

The byte ranges that codegen regenerates per engine (immediates, got-relative
addresses) are wildcarded: `??` skips one byte, `5?`-style skips one nibble.
Everything stable (registers, sizes, most opcodes) is preserved.
"""

from __future__ import annotations

import io
import zipfile
from typing import Optional

import yaml
from elftools.elf.elffile import ELFFile
from rich.console import Console

from . import locate
from .detectors import scan_path
from .scanner import SignatureEntry


def _wildcard_bytes(data: bytes, off: int, length: int, arch: str) -> str:
    """Build a wildcard string for data[off:off+length] with volatile bytes masked."""
    tokens = []
    if arch == "arm64-v8a":
        # word-wise: each 4 bytes is one instruction
        for wi in range(off, off + length, 4):
            word = int.from_bytes(data[wi:wi + 4], "little")
            hi = word & 0xFE000000
            volatile = (hi == 0x94000000 or      # BL rel32
                        hi == 0x14000000 or      # B rel32
                        hi == 0x10000000 or      # ADR
                        (word & 0x9F000000) == 0x90000000)  # ADRP
            if volatile:
                tokens += ["??", "??", "??", "??"]
            else:
                tokens += [f"{b:02x}" for b in data[wi:wi + 4]]
    else:
        for i in range(off, off + length):
            tokens.append(f"{data[i]:02x}")
    # post-process: for x86, wildcard the disp32 that follows rip-relative ops
    if arch in ("x86_64", "x86"):
        out: list[str] = []
        i = off
        n = off + length
        while i < n:
            b = data[i]
            if (0x40 <= b <= 0x4F and i + 2 < n and
                    data[i + 1] in (0x8D, 0x8B) and
                    (data[i + 2] & 0xC7) == 0x05):
                out.append(f"{b:02x}")
                out.append("8d" if data[i + 1] == 0x8D else "8b")
                out.append(f"{data[i + 2]:02x}")
                out.append("?? ?? ?? ??")
                i += 7
                continue
            out.append(f"{b:02x}")
            i += 1
        tokens = out
    return " ".join(tokens)


def _blobs_by_abi(path: str, arch: Optional[str]) -> dict[str, bytes]:
    """libflutter.so blobs to process: {abi: bytes}, honoring an --arch pin."""
    res = scan_path(path)
    if res.error:
        raise RuntimeError(res.error)
    if res.is_apk:
        if not res.libflutter:
            raise RuntimeError("no libflutter.so inside the APK — is this a Flutter app?")
        if arch:
            if arch not in res.libflutter:
                raise RuntimeError(
                    f"ABI {arch!r} not present; found: {', '.join(sorted(res.libflutter))}")
            abis = [arch]
        else:
            abis = sorted(res.libflutter)
        with zipfile.ZipFile(path) as zf:
            return {abi: zf.read(res.libflutter[abi].name) for abi in abis}
    # bare libflutter.so
    if not arch:
        raise RuntimeError(
            "cannot infer the ABI of a bare libflutter.so — pass --arch explicitly "
            "(e.g. --arch arm64-v8a)")
    with open(path, "rb") as fh:
        return {arch: fh.read()}


def _va_to_file_off(elf: ELFFile, va: int) -> Optional[int]:
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            vaddr = int(seg["p_vaddr"])
            if vaddr <= va < vaddr + int(seg["p_filesz"]):
                return int(seg["p_offset"]) + (va - vaddr)
    return None


def generate_signature(
    path: str,
    out_path: str,
    arch: Optional[str],
    version: Optional[str],
    console: Optional[Console] = None,
    length: int = 16,
) -> list[SignatureEntry]:
    """Generate signature entries for db/signatures.yaml from a target.

    Returns the generated entries (empty if the locator failed on every ABI);
    nothing is written when no entry could be produced."""
    console = console or Console()
    blobs = _blobs_by_abi(path, arch)

    entries: list[SignatureEntry] = []
    for abi, blob in blobs.items():
        hit = locate.locate_verify_chain(blob, abi)
        if hit is None:
            console.print(f"[red]{abi}: struct-locator failed — no signature possible[/red]")
            continue
        stub_entry_off = hit.entry_vaddr  # VA
        # map VA→file offset via PT_LOAD
        elf = ELFFile(io.BytesIO(blob))
        entry_off = _va_to_file_off(elf, stub_entry_off)
        if entry_off is None:
            console.print(f"[red]{abi}: VA mapping failed[/red]")
            continue
        pattern = _wildcard_bytes(blob, entry_off, length, abi)
        entries.append(SignatureEntry(
            version=version or "UNKNOWN",
            arch=abi,
            pattern=pattern,
            offset=entry_off,
            source=f"gen-sig (entry=0x{stub_entry_off:x}, by={hit.validated_by})",
        ))
        console.print(f"[green]{abi}[/green]: entry=0x{entry_off:x}")
        console.print(f"  pattern: {pattern}")

    if entries:
        with open(out_path, "w") as fh:
            yaml.safe_dump(
                {"signatures": [e.dump() for e in entries]},
                fh, sort_keys=False,
            )
        console.print(f"[green]wrote[/green] {out_path} — review and open a PR "
                      f"to db/signatures.yaml")
    return entries
