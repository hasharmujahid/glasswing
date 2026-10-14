"""APK zip handling: extract, repack, and re-sign an APK.

Key detail: Android requires uncompressed, 4-byte-aligned native libraries
(`lib/**/*.so`) when `extractNativeLibs=false`. Most modern Flutter builds ship
that way, so when we repack we must preserve that property or the app crashes on
install with a packaging error. We therefore re-write entries with
`compress_type=ZIP_STORED` for .so files and page-align them with zipalign
before signing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from typing import List, Optional, Tuple

STORED = zipfile.ZIP_STORED
DEFLATED = zipfile.ZIP_DEFLATED

DEFAULT_DEBUG_KEYSTORE = os.path.expanduser("~/.flutterpinning/debug.keystore")
KS_PASS = "flutterpinning"
KEY_ALIAS = "flutterpinning"


def extract_apk(apk_path: str, dest: str) -> str:
    """Extract an APK's contents to `dest` (created). Returns dest."""
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(apk_path) as zf:
        zf.extractall(dest)
    return dest


def verify_apk(apk_path: str) -> List[str]:
    """Return a list of problems with an (unsigned) repacked APK, or [] on success."""
    problems = []
    with zipfile.ZipFile(apk_path) as zf:
        if "AndroidManifest.xml" not in zf.namelist():
            problems.append("missing AndroidManifest.xml")
    return problems


def _find_build_tool(name: str) -> Optional[str]:
    """Locate an Android build-tool binary under $ANDROID_HOME, or on PATH."""
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if home:
        bt_root = os.path.join(home, "build-tools")
        if os.path.isdir(bt_root):
            versions = sorted(
                os.listdir(bt_root),
                key=lambda v: [int(x) for x in v.split(".") if x.isdigit()] or [9999],
                reverse=True,
            )
            for ver in versions:
                candidate = os.path.join(bt_root, ver, name)
                if os.path.isfile(candidate):
                    return candidate
    found = shutil.which(name)
    return found


def run_zipalign(src: str, dst: str) -> str:
    """Page-align the repacked APK in place (operates on `src` → `dst`)."""
    exe = _find_build_tool("zipalign")
    if not exe:
        raise RuntimeError(
            "zipalign not found — install Android build-tools (e.g. `sdkmanager "
            "'build-tools;34.0.0'`) or set ANDROID_HOME."
        )
    subprocess.run([exe, "-f", "-p", "4", src, dst], check=True)
    return dst


def ensure_debug_keystore(keystore_path: Optional[str] = None) -> str:
    """Produce a debug keystore for re-signing, creating it if needed."""
    ks = keystore_path or DEFAULT_DEBUG_KEYSTORE
    os.makedirs(os.path.dirname(ks), exist_ok=True)
    if not os.path.isfile(ks):
        subprocess.run(
            [
                "keytool", "-genkeypair",
                "-storetype", "PKCS12",
                "-keystore", ks,
                "-storepass", KS_PASS,
                "-keypass", KS_PASS,
                "-alias", KEY_ALIAS,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=flutterpinning, OU=Pentest, O=Security, L=Internet, S=Internet, C=O1",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    return ks


def sign_apk(
    apk_path: str,
    keystore_path: Optional[str] = None,
    ks_pass: str = KS_PASS,
    key_alias: str = KEY_ALIAS,
) -> str:
    """Sign an APK with apksigner (v1+v2 schemes). Returns the same path."""
    exe = _find_build_tool("apksigner")
    if not exe:
        raise RuntimeError(
            "apksigner not found — install Android build-tools or set ANDROID_HOME."
        )
    ks = ensure_debug_keystore(keystore_path)
    subprocess.run(
        [
            exe, "sign",
            "--ks", ks,
            "--ks-pass", f"pass:{KS_PASS}",
            "--key-pass", f"pass:{KS_PASS}",
            "--ks-key-alias", key_alias,
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            apk_path,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return apk_path


def verify_signature(apk_path: str) -> bool:
    """Verify a signed APK with apksigner; False if verification fails."""
    exe = _find_build_tool("apksigner")
    if not exe:
        return False
    proc = subprocess.run(
        [exe, "verify", apk_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def repack_apk(
    apk_path: str,
    out_path: str,
    *,
    replacements: Optional[List[Tuple[str, bytes]]] = None,
    added_files: Optional[List[Tuple[str, bytes]]] = None,
    removed: Optional[List[str]] = None,
    work_dir: Optional[str] = None,
) -> str:
    """Rebuild an APK file from `apk_path` with modifications applied.

    Preserves APK entry order (manifest first) and stores native libraries
    uncompressed so Android's `extractNativeLibs=false` layout still works —
    zipalign -p then page-aligns them correctly.

    Args:
        replacements: list of (entry_name, new_bytes) swapped in-place.
        added_files: list of (entry_name, bytes) appended to the archive.
        removed: entry names to drop entirely.
        work_dir: scratch directory (defaults to a new temp dir).
    Returns `out_path`.
    """
    replacements = replacements or []
    added = added_files or []
    removed = set(removed or [])
    replace_map = dict(replacements)

    tmp_out = out_path + ".tmp"
    tmp_align = out_path + ".align"

    with zipfile.ZipFile(apk_path) as src, zipfile.ZipFile(
        tmp_out, "w", compression=zipfile.ZIP_DEFLATED
    ) as dst:
        for info in src.infolist():
            if info.filename in removed:
                continue
            data = replace_map.pop(info.filename, None)
            if data is None:
                data = src.read(info.filename)
            # Android requires lib/*.so AND resources.arsc uncompressed when
            # extractNativeLibs=false / targetSdk>=30 (the latter must also be
            # 4-byte aligned — zipalign handles alignment either way we STORE both).
            compression = STORED if (info.filename.endswith(".so") or
                                     info.filename == "resources.arsc") else DEFLATED
            # Preserve original manifest compression level for v2 signature perf.
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = compression
            zi.external_attr = info.external_attr
            zi.create_system = 0
            dst.writestr(zi, data)
        for name, blob in added:
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = STORED if name.endswith(".so") else DEFLATED
            zi.external_attr = 0o755 << 16
            zi.create_system = 0
            dst.writestr(zi, blob)

    if replace_map:
        leftovers = ", ".join(sorted(replace_map))
        raise ValueError(f"replacement targets not found in apk: {leftovers}")

    # zipalign -p 4: page-align .so libraries; required for extractNativeLibs=false.
    run_zipalign(tmp_out, tmp_align)
    os.replace(tmp_align, out_path)
    # remove tmp file
    if os.path.exists(tmp_out):
        os.remove(tmp_out)
    if work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)
    return out_path


def pull_apk(package: str, out_path: str, adb: str = "adb") -> str:
    """Pull an installed package's APK from a connected (rooted) device."""
    base = subprocess.run(
        [adb, "shell", "pm", "path", package], check=True, capture_output=True, text=True
    ).stdout.strip()
    paths = [line.split(":", 1)[1] for line in base.splitlines() if line.startswith("package:")]
    if not paths:
        raise RuntimeError(f"package {package!r} not found on device")
    # Pull the base.apk (the firstListing is usually base).
    device_path = paths[0]
    subprocess.run([adb, "pull", device_path, out_path], check=True, capture_output=True)
    return out_path


def keep_signature_tmp(name: str) -> str:
    """Return a persistent temp path for intermediate artifacts."""
    fd, path = tempfile.mkstemp(suffix=name)
    os.close(fd)
    return path
