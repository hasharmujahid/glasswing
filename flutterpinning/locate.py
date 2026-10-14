"""Locate BoringSSL's ssl_crypto_x509_session_verify_cert_chain via the SSL_X509_METHOD vtable.

Primary (arch-independent) locator, derived from ground-truth analysis of
BoringSSL's ssl/ssl_x509.cc and validated on real libflutter.so binaries
(x86_64 + arm64 release) plus runtime confirmation on-device with Frida.

How it works (version-independent):
  * Flutter embeds BoringSSL statically in libflutter.so. dart:io TLS uses
    `SSL_CTX_new(TLS_method())` + `SSL_CTX_set_verify(SSL_VERIFY_PEER, cb)`,
    i.e. the X509 method path: every client handshake's certificate
    verification runs through `ssl_crypto_x509_session_verify_cert_chain`.
  * The binary is stripped; function names are not present as strings in
    recent engines (verified empirically).
  * `session_verify_cert_chain` is a member (index 9) of the
    `SSL_X509_METHOD ssl_crypto_x509_method` vtable: consecutive function
    pointers in .data.rel.ro, one RELATIVE dynamic relocation per slot.
  * So: collect RELATIVE relocations, find dense runs of consecutive slots
    whose addends all point into .text with a tight span, then validate the
    candidate whose addend's function body references BOTH "ssl_client" and
    "ssl_server" (the ternary that appears only inside this function).

Validation per engine version is documented in db/signatures.yaml once the
byte-level signature has been extracted (gen-sig), which serves as the fast
path and covers archs where heuristic checks can't be run yet.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from elftools.elf.elffile import ELFFile

# ABI: (RELATIVE reloc code, slot size, thumb entry)
_ARCH = {
    "x86_64": {"rel": 8, "slot": 8, "thumb": False},
    "x86": {"rel": 8, "slot": 4, "thumb": False},
    "arm64-v8a": {"rel": 1027, "slot": 8, "thumb": False},   # R_AARCH64_RELATIVE
    "armeabi-v7a": {"rel": 23, "slot": 4, "thumb": True},    # R_ARM_RELATIVE
}

ANCHOR_STRINGS = (b"ssl_client\x00", b"ssl_server\x00")

METHOD_VTABLE_MEMBERS = 18   # boringssl master ssl_x509.cc (informational)
TARGET_VTABLE_INDEX = 9      # session_verify_cert_chain member index


@dataclass
class RelocSlot:
    slot_va: int     # relocated slot's virtual address
    addend_va: int   # value (target VA) the slot will hold at load time


@dataclass
class MethodVtableCandidate:
    slots: List[RelocSlot]
    base_slot: int

    @property
    def addends(self) -> List[int]:
        return [s.addend_va for s in self.slots]


@dataclass
class VerifyChainHit:
    arch: str
    entry_vaddr: int
    slot_va: int
    vtable_slots: List[int] = field(default_factory=list)
    validated_by: str = "string-anchors"   # or "position" (vtable index 9)


# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------


def _iter_rela_relative(data: bytes, arch: str) -> Dict[int, int]:
    """slot VA -> addend VA for RELATIVE-type dynamic relocations."""
    meta = _ARCH[arch]
    elf = ELFFile(io.BytesIO(data))
    out: Dict[int, int] = {}
    for sec in elf.iter_sections():
        st = sec.header["sh_type"]
        if st not in ("SHT_RELA", "SHT_REL"):
            continue
        is_rela = st == "SHT_RELA"
        for r in sec.iter_relocations():
            if r["r_info_type"] != meta["rel"]:
                continue
            slot = r["r_offset"]
            addend = r["r_addend"] if is_rela else None
            if addend is None:
                off = _va_to_off(elf, slot)
                if off is None:
                    continue
                addend = int.from_bytes(data[off:off + 4], "little")
            out[slot] = addend
    return out


def _vas(data: bytes) -> Tuple[Optional[int], Optional[int], ELFFile]:
    """(text_vaddr, text_size, elf) — from .text section or exec PT_LOAD."""
    elf = ELFFile(io.BytesIO(data))
    for sec in elf.iter_sections():
        if sec.name == ".text":
            return int(sec["sh_addr"]), int(sec["sh_size"]), elf
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 0x1):
            return int(seg["p_vaddr"]), int(seg["p_filesz"]), elf
    return None, None, elf


def _va_to_off(elf: ELFFile, vaddr: int) -> Optional[int]:
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            va, off, filesz = int(seg["p_vaddr"]), int(seg["p_offset"]), int(seg["p_filesz"])
            if va <= vaddr < va + filesz:
                return off + (vaddr - va)
    return None


def _off_to_va(elf: ELFFile, off: int) -> Optional[int]:
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            va, off0, filesz = int(seg["p_vaddr"]), int(seg["p_offset"]), int(seg["p_filesz"])
            if off0 <= off < off0 + filesz:
                return va + (off - off0)
    return None


# ---------------------------------------------------------------------------
# Candidate discovery
# ---------------------------------------------------------------------------


def _dense_runs(
    relocs: Dict[int, int], slot_size: int, text_lo: int, text_hi: int,
    min_members: int = 12, max_span: int = 0x4000,
) -> List[MethodVtableCandidate]:
    """Group slots into dense runs: consecutive slot addresses (exact spacing)
    whose addends all land in the executable range within a tight span.

    Additional structure filter (ground-truthed):
      * the vtable is (almost) ascending: reject runs whose addend sequence
        is not monotonically increasing with <= 2 exceptions."""
    if not relocs:
        return []
    slots = sorted(relocs)
    runs: List[MethodVtableCandidate] = []
    n = len(slots)
    i = 0
    while i < n:
        run: List[RelocSlot] = []
        j = i
        while j < n:
            slot = slots[j]
            addend = relocs[slot]
            expected = run[-1].slot_va + slot_size if run else slot
            if slot != expected:
                break
            if not (text_lo <= addend < text_hi):
                break
            run.append(RelocSlot(slot_va=slot, addend_va=addend))
            if len(run) >= min_members and max(r.addend_va for r in run) - min(r.addend_va for r in run) > max_span:
                break
            j += 1
        if len(run) >= min_members:
            addends = [r.addend_va for r in run]
            excs = sum(
                1 for a, b in zip(addends, addends[1:]) if a >= b
            )
            if excs <= 2:
                runs.append(MethodVtableCandidate(slots=run, base_slot=run[0].slot_va))
        i = max(j, i + 1)
    return runs


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _string_refs_x86(data: bytes, elf: ELFFile, func_off: int, window: int, anchors: set) -> set:
    """RIP-relative LEA references to anchor strings in [func_off, +window]."""
    hits = set()
    for i in range(func_off, min(func_off + window, len(data) - 7)):
        b0 = data[i]
        if not (0x40 <= b0 <= 0x4F):
            continue
        if data[i + 1] != 0x8D:
            continue
        if (data[i + 2] & 0xC7) != 0x05:
            continue
        disp = int.from_bytes(data[i + 3:i + 7], "little", signed=True)
        va = _off_to_va(elf, i)
        if va is None:
            continue
        target = va + 7 + disp
        toff = _va_to_off(elf, target)
        if toff in anchors:
            hits.add(toff)
    return hits


def _string_refs_aarch64(data: bytes, elf: ELFFile, func_off: int, window: int, anchors: set) -> set:
    """ADRP+ADD references to anchor strings in [func_off, +window]."""
    import array as _array
    hits = set()
    code = data[func_off:func_off + window]
    n = len(code) // 4
    if n == 0:
        return hits
    words = _array.array("I")
    words.frombytes(code[:n * 4])
    base_va = _off_to_va(elf, func_off)
    if base_va is None:
        return hits
    adrp: Dict[int, int] = {}
    for k in range(n):
        insn = words[k]
        pc = base_va + k * 4
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= 1 << 21
            adrp[rd] = ((pc >> 12) << 12) + (imm21 << 12)
            continue
        if (insn & 0xFFC00000) == 0x91000000:  # ADD (immediate, 64-bit)
            rd, rn = insn & 0x1F, (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            if rd == rn and rd in adrp:
                toff = _va_to_off(elf, adrp[rd] + imm12)
                if toff in anchors:
                    hits.add(toff)
    return hits


def _string_refs_arm(data: bytes, elf: ELFFile, func_off: int, window: int, anchors: set) -> set:
    """ARM32: literal pool words holding anchor string addresses."""
    hits = set()
    for i in range(func_off, min(func_off + window, len(data) - 4), 4):
        w = int.from_bytes(data[i:i + 4], "little")
        toff = _va_to_off(elf, w)
        if toff in anchors:
            hits.add(toff)
    return hits


def _validate_entry(
    data: bytes, elf: ELFFile, arch: str, entry_va: int, entry_end: int
) -> int:
    """How many DISTINCT anchor strings does the function body reference?

    The vtable supplies each function's size implicitly: the body spans
    [entry_va, entry_end) where entry_end is the next member's entry (the
    compiler packs functions from one translation unit adjacently)."""
    lo = _va_to_off(elf, entry_va)
    hi = _va_to_off(elf, entry_end)
    if lo is None or hi is None or hi <= lo:
        return 0
    refs = _anchor_xrefs(data, elf, arch)  # memoized: {anchor_off: {insn_off, ...}}
    hit_anchors = set()
    for anchor, insns in refs.items():
        for insn_off in insns:
            if lo <= insn_off < hi:
                hit_anchors.add(anchor)
                break
    return len(hit_anchors)


_XREF_MEMO: Dict[Tuple[bytes, object, str], Dict[int, set]] = {}


def _anchor_xrefs(data: bytes, elf: ELFFile, arch: str) -> Dict[int, set]:
    """Memoized map: anchor-string file offset -> set of instruction file offsets
    referencing it. Computed once per (data, arch); references are:
      x86_64/x86 : any rip-relative LEA (REX? 8D mod=00 rm=101)
      arm64-v8a  : ADRP+ADD pair materializing the anchor VA
      armeabi-v7a: 4-byte literal words equal to the anchor VA
    """
    key = (id(data), id(elf), arch)
    if key in _XREF_MEMO:
        return _XREF_MEMO[key]

    anchors = {data.find(s) for s in ANCHOR_STRINGS}
    anchors = {o for o in anchors if o >= 0}
    refs: Dict[int, set] = {a: set() for a in anchors}
    if not anchors:
        _XREF_MEMO[key] = refs
        return refs

    if arch in ("x86_64", "x86"):
        for i in range(len(data) - 7):
            b0 = data[i]
            if not (0x40 <= b0 <= 0x4F):
                continue
            if data[i + 1] != 0x8D:
                continue
            if (data[i + 2] & 0xC7) != 0x05:
                continue
            disp = int.from_bytes(data[i + 3:i + 7], "little", signed=True)
            va = _off_to_va(elf, i)
            if va is None:
                continue
            toff = _va_to_off(elf, va + 7 + disp)
            if toff in refs:
                refs[toff].add(i)
    elif arch == "arm64-v8a":
        import array as _array
        words = None
        # scan every executable PT_LOAD
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            off0, filesz = int(seg["p_offset"]), int(seg["p_filesz"])
            if filesz < 8:
                continue
            code = data[off0:off0 + (filesz // 4) * 4]
            n = len(code) // 4
            if n == 0:
                continue
            if words is None:
                words = _array.array("I")
            words.frombytes(code)
            base_va = int(seg["p_vaddr"])
            adrp: Dict[int, int] = {}
            for k in range(n):
                insn = words[k]
                pc = base_va + k * 4
                if (insn & 0x9F000000) == 0x90000000:  # ADRP
                    rd = insn & 0x1F
                    immlo = (insn >> 29) & 0x3
                    immhi = (insn >> 5) & 0x7FFFF
                    imm21 = (immhi << 2) | immlo
                    if imm21 & (1 << 20):
                        imm21 -= 1 << 21
                    adrp[rd] = ((pc >> 12) << 12) + (imm21 << 12)
                    continue
                if (insn & 0xFFC00000) == 0x91000000:  # ADD (imm, 64-bit)
                    rd, rn = insn & 0x1F, (insn >> 5) & 0x1F
                    imm12 = (insn >> 10) & 0xFFF
                    if rd == rn and rd in adrp:
                        toff = _va_to_off(elf, adrp[rd] + imm12)
                        if toff in refs:
                            refs[toff].add(off0 + k * 4)
                        adrp.pop(rd, None)
            words = None
    else:  # armeabi-v7a literal pools
        import struct
        # find 4-byte words matching anchor VAs
        anchor_vas = {(_off_to_va(elf, a), a) for a in anchors}
        anchor_vas = {(v, o) for v, o in anchor_vas if v is not None}
        for va, aoff in anchor_vas:
            needle = struct.pack("<I", va)
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                refs[aoff].add(i)
                start = i + 4

    _XREF_MEMO[key] = refs
    return refs


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def locate_verify_chain(data: bytes, arch: str, window: int = 0x600) -> Optional[VerifyChainHit]:
    """Locate session_verify_cert_chain's entry VA in a libflutter.so blob."""
    meta = _ARCH.get(arch)
    if meta is None:
        raise ValueError(f"unsupported arch: {arch!r}")

    text_va, text_size, elf = _vas(data)
    if text_va is None:
        return None
    relocs = _iter_rela_relative(data, arch)
    runs = _dense_runs(relocs, meta["slot"], text_va, text_va + text_size,
                       min_members=12, max_span=0x4000)

    # 1st choice: anchor-validated addend, window bounded by the next member
    MAX_FUNC = 0x2000
    for run in runs:
        addends = [s.addend_va for s in run.slots]
        for k, slot in enumerate(run.slots):
            entry = addends[k]
            end = min(addends[k + 1] if k + 1 < len(addends) else entry + MAX_FUNC,
                      entry + MAX_FUNC)
            if _validate_entry(data, elf, arch, entry, end) == 2:
                return VerifyChainHit(
                    arch=arch, entry_vaddr=entry, slot_va=slot.slot_va,
                    vtable_slots=addends,
                    validated_by="string-anchors",
                )

    # 2nd choice: positional — 18+ member runs take slot index 9
    for run in runs:
        if len(run.slots) >= METHOD_VTABLE_MEMBERS:
            hit = run.slots[TARGET_VTABLE_INDEX]
            return VerifyChainHit(
                arch=arch, entry_vaddr=hit.addend_va, slot_va=hit.slot_va,
                vtable_slots=[s.addend_va for s in run.slots],
                validated_by="position",
            )

    return None
