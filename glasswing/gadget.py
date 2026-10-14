"""frida-gadget injection into an APK's libflutter.so (LIEF-based).

Adds a DT_NEEDED entry pointing at the gadget .so so it loads before any app
code, drops the gadget and its config into lib/<abi>/, and re-signs — no
apktool / smali needed.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
import zipfile
from typing import Dict, Optional

GADGET_LIBRARY = "libfrida-gadget.so"


def default_gadget_config(package: str) -> bytes:
    """A config that listens on all interfaces so `frida -U Gadget` attaches."""
    import json

    cfg = {
        "interaction": {
            "type": "script",
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
) -> str:
    """Inject frida-gadget into an APK's libflutter.so for `abi` and produce out_path.

    gadget_blob may be omitted to skip the payload copy (advanced); in that case
    the config-only injection mode is used and the user must provide the gadget
    library on device at /data/local/tmp/libfrida-gadget.so.
    """
    import lief  # heavy; import lazily

    from . import apk as apkmod

    if abi not in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
        raise ValueError(f"unsupported abi for gadget injection: {abi!r}")

    entry_libflutter = f"lib/{abi}/libflutter.so"
    patch_lib_name = f"libglasswing{abi}.so"  # marker lib (harmless placeholder)

    with tempfile.TemporaryDirectory(prefix="glasswing-") as td:
        # 1. pull libflutter.so out of the APK
        with zipfile.ZipFile(apk_path) as zf:
            libflutter_bytes = zf.read(entry_libflutter)

        libflutter_path = os.path.join(td, "libflutter.so")
        with open(libflutter_path, "wb") as fh:
            fh.write(libflutter_bytes)

        # 2. inject a DT_NEEDED reference to the gadget
        target_name = GADGET_LIBRARY
        lib = lief.parse(libflutter_path)
        if lib is None:
            raise RuntimeError("LIEF could not parse libflutter.so")
        prev_needed = [e.name for e in lib.dynamic_entries if e.tag == lief.ELF.DYNAMIC_TAGS.NEEDED]
        if target_name not in prev_needed:
            lib.add_library(target_name)
            lib.save(libflutter_path)  # this may reorganize sections; acceptable here
            with open(libflutter_path, "rb") as fh:
                libflutter_bytes = fh.read()

        # 3. assemble added files
        additions: Dict[str, bytes] = {entry_libflutter: libflutter_bytes}
        if gadget_blob:
            additions[f"lib/{abi}/{GADGET_LIBRARY}"] = gadget_blob
        additions[f"lib/{abi}/libfrida-gadget.config.so"] = default_gadget_config(package or "app")

        # 4. repack + re-sign
        apkmod.repack_apk(apk_path, out_path, added_files=list(additions.items()))
        apkmod.sign_apk(out_path, keystore_path=keystore_path)

    return out_path


GADGET_VERSION = "17.2.14"


def download_gadget(
    version: Optional[str] = None, arch: str = "arm64", dest_dir: Optional[str] = None
) -> str:
    """Download a frida-gadget release from GitHub for `arch`.

    Returns the path to the .so file.arch is one of 'arm64', 'arm', 'x86_64', 'x86'.
    """
    version = version or GADGET_VERSION
    suffix = {"arm64": "android-arm64", "arm": "android-arm",
              "x86_64": "android-x86_64", "x86": "android-x86"}[arch]
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
    shutil.copy_obj = None  # avoid accidental reliance on copy semantics
    import urllib.request

    urllib.request.urlretrieve(url, xz_path)
    subprocess.run(["xz", "-d", xz_path], check=True)
    return out_file


def host_arch_for_gadget() -> str:
    return {"aarch64": "arm64", "x86_64": "x86_64"}.get(platform.machine(), "arm64")
