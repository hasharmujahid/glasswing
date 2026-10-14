"""Signature matching and misc libflutter metadata.

Responsibilities kept here (locate.py owns the struct-locator heuristic):
  * wildcard pattern compilation + matching (db fast path),
  * db/signatures.yaml loading / writing / merging,
  * best-effort Dart version extraction from the libflutter.so bytes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import yaml

# ---------------------------------------------------------------------------
# Wildcard patterns
# ---------------------------------------------------------------------------


def pattern_to_bytes(pattern: str) -> Tuple[bytes, bytes]:
    """Convert a hex wildcard string into (value_bytes, mask_bytes).

    'AB CD ??' -> values b'\\xAB\\xCD\\x00', mask b'\\xFF\\xFF\\x00'.
    Mask is 0xFF for literal bytes, 0x00 for skipped ones; `5?`-style tokens
    allow half-byte matching (mask 0xF0 or 0x0F).
    """
    tokens = pattern.split()
    if not tokens:
        raise ValueError("empty pattern")
    val = bytearray()
    mask = bytearray()
    for tok in tokens:
        if tok in ("??", "*", "?"):
            val.append(0x00)
            mask.append(0x00)
            continue
        if len(tok) == 2 and "?" in tok:
            hi_mask = 0x00 if tok[0] == "?" else 0xF0
            lo_mask = 0x00 if tok[1] == "?" else 0x0F
            hi_val = 0x00 if tok[0] == "?" else (int(tok[0], 16) << 4)
            lo_val = 0x00 if tok[1] == "?" else int(tok[1], 16)
            val.append(hi_val | lo_val)
            mask.append(hi_mask | lo_mask)
            continue
        try:
            byte = int(tok, 16)
        except ValueError as exc:
            raise ValueError(f"bad token {tok!r} in pattern {pattern!r}") from exc
        val.append(byte)
        mask.append(0xFF)
    return bytes(val), bytes(mask)


def _longest_literal(value: bytes, mask: bytes) -> Tuple[int, int]:
    """Return (offset, length) of the longest fully-wildcard-free byte run."""
    best_off, best_len, run_off, run_len = 0, 0, 0, 0
    for i, m in enumerate(mask):
        if m == 0xFF:
            if run_len == 0:
                run_off = i
            run_len += 1
            if run_len > best_len:
                best_off, best_len = run_off, run_len
        else:
            run_len = 0
    return best_off, best_len


def match_pattern(data: bytes, pattern: str, max_matches: int = 64) -> List[int]:
    """Return file offsets in `data` matching wildcard `pattern`.

    Fast path: anchor on the longest literal byte-run and use bytes.find, then
    verify the full pattern at each anchor hit."""
    val, mask = pattern_to_bytes(pattern)
    lit_off, lit_len = _longest_literal(val, mask)
    if lit_len == 0:
        raise ValueError("pattern has no literal bytes to anchor on")
    literal = bytes(v & 0xFF for v in val[lit_off:lit_off + lit_len])
    matches: List[int] = []
    start = 0
    while len(matches) < max_matches:
        idx = data.find(literal, start)
        if idx == -1:
            break
        start = idx + 1
        cand = idx - lit_off
        if cand < 0:
            continue
        chunk = data[cand:cand + len(val)]
        if len(chunk) != len(val):
            break
        if all(c & m == v & m for c, v, m in zip(chunk, val, mask)):
            matches.append(cand)
    return matches


# ---------------------------------------------------------------------------
# Signature DB
# ---------------------------------------------------------------------------


@dataclass
class SignatureEntry:
    version: str                  # Dart version string, e.g. "3.24.0"
    arch: str
    pattern: str
    offset: Optional[int] = None  # file offset within libflutter.so (informational)
    source: Optional[str] = None

    def dump(self) -> Dict:
        return {
            "version": self.version,
            "arch": self.arch,
            "pattern": self.pattern,
            "offset": self.offset,
            "source": self.source,
        }


def load_signatures(path: str) -> Dict[str, Dict[str, SignatureEntry]]:
    """Load signatures.yaml into {arch: {version: entry}}."""
    if not os.path.isfile(path):
        return {}
    entries: Dict[str, Dict[str, SignatureEntry]] = {}
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    for item in doc.get("signatures", []):
        entry = SignatureEntry(
            version=str(item["version"]),
            arch=item["arch"],
            pattern=item["pattern"],
            offset=item.get("offset"),
            source=item.get("source"),
        )
        entries.setdefault(entry.arch, {})[entry.version] = entry
    return entries


def dump_signatures(entries: List[SignatureEntry], path: str) -> None:
    """Write a flat signature list to YAML (overwrites)."""
    doc = {"signatures": [e.dump() for e in sorted(entries, key=lambda e: (e.arch, e.version))]}
    with open(path, "w") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)


def merge_signature_list(
    base: Dict[str, Dict[str, SignatureEntry]], new: List[SignatureEntry]
) -> List[SignatureEntry]:
    """Merge `new` entries over `base` (same arch+version => overwrite)."""
    merged: Dict[Tuple[str, str], SignatureEntry] = {}
    for arch_versions in base.values():
        for version, entry in arch_versions.items():
            merged[(entry.arch, version)] = entry
    for entry in new:
        merged[(entry.arch, entry.version)] = entry
    return list(merged.values())


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------

_DART_VERSION_RE = re.compile(rb"Dart VM version: ([0-9][0-9a-zA-Z.+\-_ ]{3,64})")


def extract_dart_version(data: bytes) -> Optional[str]:
    """Best-effort 'Dart VM version: ...' string from the libflutter.so blob."""
    m = _DART_VERSION_RE.search(data)
    if not m:
        return None
    text = m.group(1).decode("ascii", "replace").strip()
    return text or None


# ---------------------------------------------------------------------------
# Strategy: known signature lookup
# ---------------------------------------------------------------------------


def find_by_signature(
    data: bytes,
    arch: str,
    version: Optional[str],
    signatures: Dict[str, Dict[str, SignatureEntry]],
) -> Tuple[Optional[int], Optional[str]]:
    """Locate the verify-cert-chain entry via a known signature.

    Returns (file_offset, matched_version) or (None, None)."""
    candidates = signatures.get(arch, {})
    if not candidates:
        return None, None
    search_order: List[SignatureEntry] = []
    if version and version in candidates:
        search_order.append(candidates[version])
        search_order.extend(e for v, e in candidates.items() if v != version)
    else:
        search_order = list(candidates.values())
    for sig in search_order:
        if version and sig.version != version:
            continue
        matches = match_pattern(data, sig.pattern)
        if matches:
            if sig.offset is not None and sig.offset in matches:
                return sig.offset, sig.version
            return matches[0], sig.version
    return None, None
