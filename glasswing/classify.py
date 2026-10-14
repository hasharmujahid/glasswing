"""Target classification for glasswing.

Determines whether an APK's SSL pinning is actually enforced through Flutter's
BoringSSL (libflutter.so) — the stack this tool covers — or through separate
native TLS stacks, which are out of scope by design.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

# well-known native network stacks that do their own TLS/pinning,
# i.e. NOT Flutter's BoringSSL and NOT covered by glasswing
NON_FLUTTER_TLS_LIBS = {
    "libtnet": "Alibaba ANet (SLIGHT_SSL: custom TLS 1.3 + custom public-key pinning)",
    "libxquic": "Alibaba XQUIC (QUIC; embedded BabaSSL — a BoringSSL fork, but not libflutter's)",
    "libopenssl": "Shared OpenSSL (used by e.g. libgaea.so / gRPC layer, outside the Flutter engine)",
    "libcronet": "Chromium Cronet (own network stack + pinning)",
    "libssl": "Standalone OpenSSL/BoringSSL shlib (not the Flutter engine)",
    "libconscrypt": "Conscrypt (Android Java TLS provider)",
    "libokhttp": "OkHttp marker (native parts; Java-level pinning)",
}


@dataclass
class TargetVerdict:
    is_flutter_target: bool          # true => glasswing can bypass the Flutter-side pinning
    has_flutter_engine: bool
    non_flutter_stacks: List[str] = field(default_factory=list)
    reason: str = ""

    @property
    def mixed(self) -> bool:
        """Flutter present BUT other native TLS stacks may dominate traffic."""
        return self.has_flutter_engine and bool(self.non_flutter_stacks)


def classify_apk(apk_path: str) -> TargetVerdict:
    """Inspect an APK and decide if glasswing is the right tool for it.

    Rule: glasswing targets Flutter/BoringSSL pinning ONLY. If the app
    primarily uses separate native TLS stacks (ANet/SLIGHT_SSL, Cronet, XQUIC,
    shared libopenssl, ...), the APK is not a valid glasswing target and
    the user should not expect the patch to intercept that traffic."""
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        flutter = [n for n in names if n.startswith("lib/") and n.endswith("libflutter.so")]
        found = []
        for marker, why in NON_FLUTTER_TLS_LIBS.items():
            if any(marker in n for n in names):
                found.append(why)

    verdict = TargetVerdict(
        is_flutter_target=False,
        has_flutter_engine=bool(flutter),
        non_flutter_stacks=found,
    )
    if flutter and not found:
        verdict.is_flutter_target = True
        verdict.reason = "pure Flutter app — libflutter.so's BoringSSL handles dart:io TLS"
    elif flutter and found:
        verdict.is_flutter_target = False   # mixed app: pinning likely enforced outside Flutter
        verdict.reason = (
            "mixed app: libflutter.so present, but pinning also enforced by other native "
            "stacks — glasswing covers only the Flutter/dart:io layer"
        )
    elif not flutter:
        verdict.is_flutter_target = False
        verdict.reason = "not a Flutter app (no libflutter.so)"
    return verdict
