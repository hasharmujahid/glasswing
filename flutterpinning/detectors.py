"""Detection of Flutter apps inside APK/IPA archives and bare .so files.

Detects:
  * which native ABIs an app ships (from lib/<abi>/ entries),
  * whether libflutter.so is present (i.e. the app is Flutter),
  * candidate Dart snapshot hashes (used by the Flutter engine to key the VM),
  * basic APK metadata via androguard when available.
"""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

FLUTTER_LIB_NAME = "libflutter.so"
DART_AOT_LIB_NAME = "libapp.so"

# 32 lowercase hex chars — the Dart VM snapshot hash embedded in libflutter.so.
_SNAPSHOT_HASH_RE = re.compile(rb"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")


@dataclass
class SoInfo:
    """A single native library discovered inside a container."""

    abi: str
    name: str  # entry name inside the APK, or file basename
    size: int
    offset: Optional[int] = None  # offset into the archive, when available


@dataclass
class ScanResult:
    """Top-level result of inspecting an APK or a bare .so."""

    path: str
    is_apk: bool
    package: Optional[str] = None
    archs: List[str] = field(default_factory=list)
    libflutter: Dict[str, SoInfo] = field(default_factory=dict)  # abi -> info
    libapp: Dict[str, SoInfo] = field(default_factory=dict)  # abi -> info
    snapshot_hashes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_flutter(self) -> bool:
        return bool(self.libflutter)

    def libflutter_path(self, abi: Optional[str] = None) -> Optional[str]:
        """Return the preferred (or requested) libflutter.so entry name."""
        if abi:
            info = self.libflutter.get(abi)
            return info.name if info else None
        # prefer arm64, then armv7, then x86_64, then x86
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
            if abi in self.libflutter:
                return self.libflutter[abi].name
        return None


def _sniff(path: str) -> str:
    """Return 'apk' | 'elf' | 'unknown' based on magic bytes."""
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        return f"unreadable: {exc}"
    if magic == b"PK\x03\x04":
        return "apk"
    if magic == b"\x7fELF":
        return "elf"
    return "unknown"


def _so_info_from_zip(zf: zipfile.ZipFile, entry: str) -> SoInfo:
    zi = zf.getinfo(entry)
    abi = entry.split("/")[1] if entry.startswith("lib/") else "?"
    return SoInfo(abi=abi, name=entry, size=zi.file_size, offset=None)


def _extract_snapshot_hashes(data: bytes, limit: int = 4) -> List[str]:
    """Best-effort Dart snapshot hash extraction.

    libflutter.so embeds the Dart VM snapshot hash as a 32-char lowercase hex
    string. Other unrelated 32-hex strings may also be present, so we rank by
    frequency and return the most common candidates."""
    seen: Dict[bytes, int] = {}
    for m in _SNAPSHOT_HASH_RE.finditer(data):
        token = m.group(0)
        seen[token] = seen.get(token, 0) + 1
    ranked = sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))
    out: List[str] = []
    for token, _count in ranked[:limit]:
        text = token.decode("ascii", "replace")
        if text not in out:
            out.append(text)
    return out


def _read_zip_entry(zf: zipfile.ZipFile, entry: str) -> bytes:
    with zf.open(entry) as fh:
        return fh.read()


def scan_path(path: str) -> ScanResult:
    """Inspect an APK (zip) or a bare ELF .so file and report Flutter details."""
    kind = _sniff(path)
    if kind == "unknown":
        return ScanResult(path=path, is_apk=False, error=f"unrecognized file type: {path}")

    if kind == "elf":
        data = open(path, "rb").read()
        res = ScanResult(path=path, is_apk=False, archs=[])
        info = SoInfo(abi=os.path.basename(os.path.dirname(path)) or "unknown",
                      name=os.path.basename(path),
                      size=len(data))
        res.libflutter = {info.abi: info} if os.path.basename(path) == FLUTTER_LIB_NAME else {}
        res.snapshot_hashes = _extract_snapshot_hashes(data) if res.libflutter else []
        return res

    # APK path
    res = ScanResult(path=path, is_apk=True)
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            res.archs = []
            for entry in names:
                if entry.startswith("lib/") and entry.endswith(".so"):
                    abi = entry.split("/")[1]
                    if abi not in res.archs:
                        res.archs.append(abi)
                    base = os.path.basename(entry)
                    info = SoInfo(abi=abi, name=entry,
                                  size=zf.getinfo(entry).file_size)
                    if base == FLUTTER_LIB_NAME:
                        res.libflutter[abi] = info
                    elif base == DART_AOT_LIB_NAME:
                        res.libapp[abi] = info
                    # (other libs are ignored, just counted above)
            # package metadata via androguard, best effort
            try:
                from androguard.core.apk import APK  # type: ignore

                apk = APK(path)
                res.package = apk.get_package()
            except Exception:  # noqa: BLE001 — metadata is nice-to-have
                res.package = None
            # snapshot hash from the primary libflutter.so
            entry = res.libflutter_path()
            if entry:
                data = _read_zip_entry(zf, entry)
                res.snapshot_hashes = _extract_snapshot_hashes(data)
    except zipfile.BadZipFile as exc:
        return ScanResult(path=path, is_apk=True, error=f"not a valid zip/apk: {exc}")
    return res
