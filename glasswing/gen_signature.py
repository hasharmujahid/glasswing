"""Signature generation: extract PR-ready byte-signatures from located entries.

`glasswing gen-sig <apk>` runs the version-independent struct locator on
the app's libflutter.so, then captures the first bytes of the located function
as a wildcard pattern for db/signatures.yaml (fast path for future engines).

The byte ranges that codegen regenerates per engine (immediates, got-relative
addresses) are wildcarded: `??` skips one byte, `5?`-style skips one nibble.
Everything stable (registers, sizes, most opcodes) is preserved.
"""

from __future__ import annotations

import os
import zipfile
from typing import List, Optional, Tuple

import yaml
from rich.console import Console

from . import locate
from .detectors import scan_path
from .scanner import SignatureEntry

# instruction classes volatile across rebuilds (opcodes change with operands)
_VOLATILE_X86 = (
    (0x40, 0x4F),   # REX prefixes settle per register allocation
)
_ARM64_VOLATILE_FRAMES = (
    0x94000000,     # BL rel32
    0x14000000,     # B  rel32
    0x90000000,     # ADRP
)


def _libflutter_bytes(path: str) -> Tuple[bytes, Optional[str]]:
    res = scan_path(path)
    if res.error:
        raise RuntimeError(res.error)
    if res.is_apk:
        entries = [i.name for i in res.libflutter.values()]
        entry = res.libflutter_path()
        if not entry:
            raise RuntimeError("no libflutter.so inside the APK")
        with zipfile.ZipFile(path) as zf:
            return zf.read(entry), res.package
    return open(path, "rb").read(), None


def _arch_of_lib(bare_path: str, arch: Optional[str]) -> str:
    if arch:
        return arch
    raise RuntimeError(
        "cannot infer ABI of a bare libflutter.so — pass --arch explicitly"
    )


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
        out: List[str] = []
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


def _mask_hi(v: int) -> int:
    return 0xFF000000


def generate_signature(
    path: str,
    out_path: str,
    arch: Optional[str],
    version: Optional[str],
    console: Optional[Console] = None,
    length: int = 16,
    db_path: str = "",
) -> None:
    """Generate a signature entry for db/signatures.yaml from a target APK/logo."""
    console = console or Console()
    blob, package = _libflutter_bytes(path)
    res = scan_path(path)

    archs = [arch] if arch else sorted(res.libflutter.keys())
    entries: List[SignatureEntry] = []
    for abi in archs:
        if arch:
            blob, _package = _libflutter_bytes(path)
        else:
            with zipfile.ZipFile(path) as zf:
                blob = zf.read(res.libflutter[abi].name)
        hit = locate.locate_verify_chain(blob, abi)
        if hit is None:
            console.print(f"[red]{abi}: struct-locator failed — no signature possible[/red]")
            continue
        stub_entry_off = hit.entry_vaddr  # VA
        # map VA→file offset via PT_LOAD
        import io as _io
        from elftools.elf.elffile import ELFFile as _ELF

        elf = _ELF(_io.BytesIO(blob))
        entry_off = None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                vaddr = int(seg["p_vaddr"])
                if vaddr <= stub_entry_off < vaddr + int(seg["p_filesz"]):
                    entry_off = int(seg["p_offset"]) + (stub_entry_off - vaddr)
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

    with open(out_path, "w") as fh:
        yaml.safe_dump(
            {"signatures": [e.dump() for e in entries]},
            fh, sort_keys=False,
        )
    console.print(f"[green]wrote[/green] {out_path} — review and open a PR to db/signatures.yaml")
