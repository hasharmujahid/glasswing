"""frida-gadget injection into an APK's libflutter.so (LIEF-based).

Adds a DT_NEEDED entry pointing at the gadget .so so it loads before any app
code, drops the gadget and its config into lib/<abi>/, and re-signs — no
apktool / smali needed.
"""

from __future__ import annotations

import json
import lzma
import os
import shutil
import tempfile
import urllib.request
import zipfile
from typing import Optional

GADGET_LIBRARY = "libfrida-gadget.so"
# keep in sync with the frida>=16,<17 pin in pyproject — gadget, frida-server
# and the host bindings must share a major for script compatibility
GADGET_VERSION = "16.7.19"

# glasswing ABI -> frida release naming
ABI_TO_FRIDA_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


def default_gadget_config() -> bytes:
    """Listen-mode config so `frida -U Gadget` can attach to the process."""
    cfg = {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": 27042,
            "on_change": "reload",
        },
        "runtime": "v8",
    }
    return (json.dumps(cfg, indent=2) + "\n").encode()


def inject_gadget(
    apk_path: str,
    out_path: str,
    abi: str,
    gadget_blob: Optional[bytes] = None,
    package: Optional[str] = None,
    keystore_path: Optional[str] = None,
    ks_pass: Optional[str] = None,
    key_alias: Optional[str] = None,
) -> str:
    """Inject frida-gadget into the APK's lib/<abi>/libflutter.so and re-sign.

    gadget_blob may be omitted to skip the payload copy (advanced); in that case
    the config-only injection mode is used and the user must provide the gadget
    library on device at /data/local/tmp/libfrida-gadget.so.
    """
    import lief  # heavy; import lazily

    from . import apk as apkmod

    if abi not in ABI_TO_FRIDA_ARCH:
        raise ValueError(f"unsupported abi for gadget injection: {abi!r}")

    entry_libflutter = f"lib/{abi}/libflutter.so"

    with tempfile.TemporaryDirectory(prefix="glasswing-") as td:
        # 1. pull libflutter.so out of the APK
        with zipfile.ZipFile(apk_path) as zf:
            libflutter_bytes = zf.read(entry_libflutter)

        libflutter_path = os.path.join(td, "libflutter.so")
        with open(libflutter_path, "wb") as fh:
            fh.write(libflutter_bytes)

        # 2. inject a DT_NEEDED reference to the gadget
        lib = lief.parse(libflutter_path)
        if lib is None:
            raise RuntimeError("LIEF could not parse libflutter.so")
        prev_needed = [e.name for e in lib.dynamic_entries if e.tag == lief.ELF.DYNAMIC_TAGS.NEEDED]
        if GADGET_LIBRARY not in prev_needed:
            lib.add_library(GADGET_LIBRARY)
            lib.save(libflutter_path)  # this may reorganize sections; acceptable here
            with open(libflutter_path, "rb") as fh:
                libflutter_bytes = fh.read()

        # 3. assemble added files (config name must end in .so to survive repacking)
        additions: dict[str, bytes] = {entry_libflutter: libflutter_bytes}
        if gadget_blob:
            additions[f"lib/{abi}/{GADGET_LIBRARY}"] = gadget_blob
        additions[f"lib/{abi}/libfrida-gadget.config.so"] = default_gadget_config()

        # 4. repack + re-sign (in-place is safe: repack stages through a temp file)
        apkmod.repack_apk(apk_path, out_path, added_files=list(additions.items()))
        apkmod.sign_apk(out_path, keystore_path=keystore_path,
                        ks_pass=ks_pass or apkmod.KS_PASS,
                        key_alias=key_alias or apkmod.KEY_ALIAS)

    return out_path


def download_gadget(
    version: Optional[str] = None, arch: str = "arm64", dest_dir: Optional[str] = None
) -> str:
    """Download a frida-gadget release from GitHub for `arch`.

    Returns the path to the .so file. `arch` is frida's naming:
    one of 'arm64', 'arm', 'x86_64', 'x86'.
    """
    version = version or GADGET_VERSION
    suffix = {
        "arm64": "android-arm64",
        "arm": "android-arm",
        "x86_64": "android-x86_64",
        "x86": "android-x86",
    }.get(arch)
    if suffix is None:
        raise ValueError(f"unsupported frida arch: {arch!r}")
    url = (
        "https://github.com/frida/frida/releases/download/"
        f"{version}/frida-gadget-{suffix}.so.xz"
    )
    dest_dir = dest_dir or tempfile.gettempdir()
    os.makedirs(dest_dir, exist_ok=True)
    out_file = os.path.join(dest_dir, f"frida-gadget-{suffix}.so")
    if os.path.isfile(out_file):
        return out_file

    xz_path = out_file + ".xz"
    urllib.request.urlretrieve(url, xz_path)
    with lzma.open(xz_path) as fin, open(out_file, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    os.remove(xz_path)
    return out_file
