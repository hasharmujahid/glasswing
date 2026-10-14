"""Patch libflutter.so: neutralize the BoringSSL certificate-chain verification.

Strategy priority:
1. **Struct locator** (locate.py) — version-independent; validated on-device.
2. **Byte signatures** (scanner.py, db/signatures.yaml) — fast path when a
   signature for the exact engine exists.

The patch overwrites the function entry with a `return true` stub — the binary
equivalent of reFlutter's engine-rebuild change to ssl_x509.cc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import locate, scanner
from .scanner import SignatureEntry

# return-true stubs per architecture
STUBS: Dict[str, bytes] = {
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
    vaddr: Optional[int]
    stub_size: int
    matched_version: Optional[str] = None
    detail: Optional[str] = None


def stub_for(arch: str) -> bytes:
    s = STUBS.get(arch)
    if s is None:
        raise UnsupportedArch(f"unsupported architecture: {arch!r}")
    return s


def find_entry(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: Dict[str, Dict[str, SignatureEntry]],
) -> Tuple[str, Optional[int], Optional[str]]:
    """Return (strategy, file_off, detail) for the verify-chain function entry."""
    stub_for(arch)  # raises early on unknown arch

    # 1. struct locator (version-independent)
    detail = ""
    try:
        hit = locate.locate_verify_chain(data, arch)
    except Exception as exc:  # noqa: BLE001 — locator is best-effort here
        hit = None
        detail = f"struct-locator error: {exc}"

    if hit is not None:
        import io as _io
        from elftools.elf.elffile import ELFFile as _ELF

        elf = _ELF(_io.BytesIO(data))
        thumb = (arch == "armeabi-v7a") and (hit.entry_vaddr & 1) == 1
        va = (hit.entry_vaddr & ~1) if thumb else hit.entry_vaddr
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                vaddr = int(seg["p_vaddr"])
                end = vaddr + int(seg["p_filesz"])
                foff = int(seg["p_offset"])
                if vaddr <= va < end:
                    off = foff + (va - vaddr)
                    detail = (
                        f"entry_va=0x{va:x}{' (thumb ptr, LSB)' if thumb else ''}"
                        f" validated_by={hit.validated_by} slot=0x{hit.slot_va:x}"
                    )
                    return ("struct-locator", off, detail)

    # 2. signature fallback (byte patterns from db)
    sig_off, matched = scanner.find_by_signature(data, arch, version, signatures)
    if sig_off is None:
        raise LocateFailed(
            f"could not locate the verify-cert-chain function (arch={arch!r}, "
            f"version={version!r}){': ' + detail if detail else ''}; run "
            f"`flutterpinning gen-sig` against this release and contribute the "
            f"signature"
        )
    return ("signature", sig_off, f"signature matched engine {matched}")


def patch_so_bytes(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: Dict[str, Dict[str, SignatureEntry]],
) -> Tuple[bytes, PatchResult]:
    """Apply the return-true stub to the verify-chain entry; returns (new, info)."""
    stub = stub_for(arch)
    strategy, off, detail = find_entry(data, arch, version, signatures)

    if off + len(stub) > len(data):
        raise LocateFailed("match sits at end of file — refusing to patch")
    patched = bytearray(data)
    patched[off:off + len(stub)] = stub
    result = PatchResult(
        arch=arch,
        strategy=strategy,
        file_off=off,
        vaddr=None,
        stub_size=len(stub),
        detail=detail,
    )
    return bytes(patched), result


def entry_offset(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: Dict[str, Dict[str, SignatureEntry]],
) -> Tuple[str, Optional[int], Optional[str]]:
    """Public helper: find the entry offset without patching."""
    return find_entry(data, arch, version, signatures)


def stub_disassembly_hint(arch: str) -> str:
    return {
        "arm64-v8a": "mov w0, #1 ; ret      (always verify OK)",
        "armeabi-v7a": "movs r0, #1 ; bx lr (always verify OK)",
        "x86_64": "mov eax, 1 ; ret         (always verify OK)",
        "x86": "mov eax, 1 ; ret            (always verify OK)",
    }[arch]
