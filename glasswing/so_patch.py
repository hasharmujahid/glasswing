"""Patch libflutter.so: neutralize the BoringSSL certificate-chain verification.

Strategy priority:
1. **Struct locator** (locate.py) — version-independent; validated on-device.
2. **Byte signatures** (scanner.py, db/signatures.yaml) — fast path when a
   signature for the exact engine exists.

The patch overwrites the function entry with a `return true` stub — the binary
equivalent of reFlutter's engine-rebuild change to ssl_x509.cc.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Optional

from elftools.elf.elffile import ELFFile

from . import locate, scanner
from .scanner import SignatureEntry

# return-true stubs per architecture
STUBS: dict[str, bytes] = {
    "arm64-v8a": b"\x20\x00\x80\x52" + b"\xc0\x03\x5f\xd6",   # mov w0,#1; ret
    "armeabi-v7a": b"\x01\x20\x70\x47",                        # movs r0,#1; bx lr (thumb)
    "x86_64": b"\xB8\x01\x00\x00\x00\xC3",                     # mov eax,1; ret
    "x86": b"\xB8\x01\x00\x00\x00\xC3",
}


class UnsupportedArch(ValueError):
    pass


class LocateFailed(RuntimeError):
    pass


@dataclass
class PatchResult:
    arch: str
    strategy: str            # "struct-locator" or "signature"
    file_off: int            # offset into libflutter.so of the patched entry
    vaddr: Optional[int]     # same address as seen at runtime (module_base + vaddr)
    stub_size: int
    matched_version: Optional[str] = None
    detail: Optional[str] = None


def stub_for(arch: str) -> bytes:
    s = STUBS.get(arch)
    if s is None:
        raise UnsupportedArch(f"unsupported architecture: {arch!r}")
    return s


def _va_to_file_off(elf: ELFFile, va: int) -> Optional[int]:
    """Map a virtual address to its file offset via PT_LOAD segments."""
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            vaddr = int(seg["p_vaddr"])
            if vaddr <= va < vaddr + int(seg["p_filesz"]):
                return int(seg["p_offset"]) + (va - vaddr)
    return None


def _file_off_to_va(elf: ELFFile, off: int) -> Optional[int]:
    """Map a file offset to its virtual address via PT_LOAD segments."""
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            off0, filesz = int(seg["p_offset"]), int(seg["p_filesz"])
            if off0 <= off < off0 + filesz:
                return int(seg["p_vaddr"]) + (off - off0)
    return None


def _resolve_entry(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: dict[str, dict[str, SignatureEntry]],
) -> tuple[str, int, int, Optional[str]]:
    """Resolve the verify-chain entry as (strategy, vaddr, file_off, detail).

    Both addresses are returned because the two bypass modes need different
    views of the same function: static patching writes at the file offset,
    the Frida agent patches at module_base + vaddr (the two diverge in ELFs
    where p_offset != p_vaddr, e.g. 16KB-page-aligned layouts).
    """
    stub_for(arch)  # raises early on unknown arch

    # 1. struct locator (version-independent)
    detail = ""
    hit = None
    try:
        hit = locate.locate_verify_chain(data, arch)
    except Exception as exc:
        detail = f"struct-locator error: {exc}"

    elf = ELFFile(io.BytesIO(data))
    if hit is not None:
        # Thumb entries carry the LSB set in the vtable pointer; the actual
        # instruction address is even.
        thumb = (arch == "armeabi-v7a") and (hit.entry_vaddr & 1) == 1
        va = (hit.entry_vaddr & ~1) if thumb else hit.entry_vaddr
        off = _va_to_file_off(elf, va)
        if off is not None:
            detail = (
                f"entry_va=0x{va:x}{' (thumb ptr, LSB)' if thumb else ''}"
                f" validated_by={hit.validated_by} slot=0x{hit.slot_va:x}"
            )
            return ("struct-locator", va, off, detail)

    # 2. signature fallback (byte patterns from db)
    sig_off, matched = scanner.find_by_signature(data, arch, version, signatures)
    if sig_off is None:
        raise LocateFailed(
            f"could not locate the verify-cert-chain function (arch={arch!r}, "
            f"version={version!r}){': ' + detail if detail else ''}; run "
            f"`glasswing gen-sig` against this release and contribute the "
            f"signature"
        )
    va = _file_off_to_va(elf, sig_off)
    return ("signature", va if va is not None else sig_off, sig_off,
            f"signature matched engine {matched}")


def find_entry(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: dict[str, dict[str, SignatureEntry]],
) -> tuple[str, int, Optional[str]]:
    """Return (strategy, file_off, detail) for the verify-chain function entry."""
    _strategy, _vaddr, off, detail = _resolve_entry(data, arch, version, signatures)
    return _strategy, off, detail


def entry_vaddr(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: dict[str, dict[str, SignatureEntry]],
) -> tuple[str, int, Optional[str]]:
    """Return (strategy, vaddr, detail) — the address as loaded in memory.

    This is the delta the Frida agent must add to the module base; a file
    offset would point at the wrong instruction in ELFs where p_vaddr and
    p_offset diverge (16KB page alignment on Android 15+).
    """
    _strategy, va, _off, detail = _resolve_entry(data, arch, version, signatures)
    return _strategy, va, detail


def patch_so_bytes(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: dict[str, dict[str, SignatureEntry]],
) -> tuple[bytes, PatchResult]:
    """Apply the return-true stub to the verify-chain entry; returns (new, info)."""
    stub = stub_for(arch)
    strategy, va, off, detail = _resolve_entry(data, arch, version, signatures)

    if off + len(stub) > len(data):
        raise LocateFailed("match sits at end of file — refusing to patch")
    patched = bytearray(data)
    patched[off:off + len(stub)] = stub
    result = PatchResult(
        arch=arch,
        strategy=strategy,
        file_off=off,
        vaddr=va,
        stub_size=len(stub),
        detail=detail,
    )
    return bytes(patched), result


def stub_disassembly_hint(arch: str) -> str:
    return {
        "arm64-v8a": "mov w0, #1 ; ret      (always verify OK)",
        "armeabi-v7a": "movs r0, #1 ; bx lr (always verify OK)",
        "x86_64": "mov eax, 1 ; ret         (always verify OK)",
        "x86": "mov eax, 1 ; ret            (always verify OK)",
    }[arch]
