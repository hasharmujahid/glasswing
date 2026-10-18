<div align="center">

# 🦋 Glasswing

**See through Flutter's TLS.**

*Bypass BoringSSL certificate pinning in Flutter Android apps — static `libflutter.so` patching + Frida runtime hooks, no engine rebuild required.*

[![CI](https://github.com/hasharmujahid/glasswing/actions/workflows/ci.yml/badge.svg)](https://github.com/hasharmujahid/glasswing/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Flutter](https://img.shields.io/badge/Flutter-3.44+-42A5F5.svg?logo=flutter)](https://flutter.dev)
[![Android](https://img.shields.io/badge/Android-8.0+-3DDC84.svg?logo=android)](https://www.android.com)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB.svg?logo=python)](https://python.org)

*The glasswing butterfly's transparent wings let you see straight through — Glasswing does the same to encrypted Flutter traffic.*

**Authorized penetration testing only.**

</div>

---

## Why Glasswing exists

Flutter apps don't use the OS TLS stack. `dart:io`'s `HttpClient` (and therefore every Dart HTTP client — `dio`, generated gRPC, hand-rolled networking) goes through **BoringSSL statically linked inside `libflutter.so`**. That breaks every standard Android SSL-pinning bypass:

| Standard Android technique | On a Flutter app |
|---|---|
| Install a user CA certificate | ❌ ignored — verification happens in BoringSSL, not Android's trust store |
| Hook `TrustManager` / `OkHttp` / `Conscrypt` | ❌ never called for dart:io traffic |
| `objection` / Frida SSL-pinning scripts | ❌ target Java/Kotlin TLS paths that don't exist here |

What about existing Flutter-specific tools? [reFlutter](https://github.com/Impact-I/reFlutter) rebuilds the **entire Flutter engine** from source with a one-line patch — correct but heavy: you need depot_tools, the matching engine commit, and a full ninja build per engine version. Glasswing applies the **same semantic patch directly to the shipped binary** — a few seconds, per APK, no toolchain.

## What it does

Glasswing locates BoringSSL's `ssl_crypto_x509_session_verify_cert_chain` inside `libflutter.so` and overwrites its entry with a **return-true stub** — the binary equivalent of reFlutter's source-level `return true;`:

| Architecture | Stub injected |
|---|---|
| `arm64-v8a` | `mov w0, #1 ; ret` |
| `armeabi-v7a` (thumb) | `movs r0, #1 ; bx lr` |
| `x86_64` | `mov eax, 1 ; ret` |

Certificate verification now always succeeds → the app accepts your interception proxy's certificate → **traffic appears in Burp Suite / mitmproxy**, decrypted.

### Two bypass modes

| Mode | Command | Needs root? | How it works |
|---|---|---|---|
| **Static patch** | `glasswing patch app.apk -o out.apk` | **No** | Patches `libflutter.so` inside the APK, repacks, re-signs. Install the output and browse. |
| **Runtime hook** | `glasswing hook app.apk` | Yes (frida-server) | Patches the same function **in memory** at process spawn. Original APK untouched on disk. |
| **Static + gadget** | `glasswing patch --gadget` | **No** | Static patch + embedded frida-gadget for later instrumentation. |

### How it finds the function (no offsets table needed)

Engine versions change constantly, so Glasswing doesn't hardcode offsets. `session_verify_cert_chain` is member #10 of BoringSSL's `SSL_X509_METHOD` vtable — a block of consecutive function pointers in `.data.rel.ro`, each with one `RELATIVE` dynamic relocation. Glasswing:

1. Scans the ELF relocation table for dense runs of consecutive slots whose addends all point into `.text`
2. Filters runs whose addend sequence is monotonically increasing with ≤2 outliers (translation-unit link order)
3. Validates the candidate whose function body references **both** `"ssl_client"` and `"ssl_server"` — the compiled `ssl->server ? "ssl_client" : "ssl_server"` ternary that lives only inside this function

Verified on Flutter **3.44** and **3.47** engine binaries (x86_64, arm64-v8a, armeabi-v7a), plus real third-party apps from F-Droid. Byte-signatures in `db/signatures.yaml` act as a fast path; `gen-sig` produces entries for unknown engines in one command.

## Install

```bash
pip install .          # from a checkout
# or straight from GitHub:
pip install git+https://github.com/hasharmujahid/glasswing.git
glasswing --version
```

Patched APKs are re-signed with an auto-generated debug keystore
(`~/.glasswing/debug.keystore`) on first use. To sign with your own identity,
pass `--keystore` (plus `--ks-pass` / `--key-alias`) to `glasswing patch`.

**System requirements** (auto-detected from `$ANDROID_HOME`):

- Android build-tools (`apksigner`, `zipalign`) — for static patching
- `adb` — for `hook` and `--install`
- Frida **16.x** (`pip install 'frida<17'`) — frida-server on the device must match the
  major version. Frida 17 removed the bundled Java bridge that user scripts loaded via
  `-l` rely on.

## Quick start

```bash
# 1. What is this APK? Is it a valid target?
glasswing inspect app.apk

# 2a. Static patch — no root needed
glasswing patch app.apk -o app-patched.apk
adb install app-patched.apk

# 2b. Runtime hook — rooted device / emulator with frida-server
glasswing hook app.apk --package com.target.app

# bring your own Frida scripts — loaded into the same session after the bypass
glasswing hook app.apk -l my-interceptor.js -l log-everything.js

# 3. Configure your proxy (Burp / mitmproxy) and browse the app.
```

### Target classification

Not every app with a `libflutter.so` is a valid target. Glasswing inspects every APK for **other native TLS stacks** (Alibaba ANet/SLIGHT_SSL, XQUIC, Cronet, shared `libopenssl.so`, ...) and warns you **before** you waste time:

```
╭─────────────────── Target classification ───────────────────╮
│ Not a glasswing target.                                    │
│ mixed app: libflutter.so present, but pinning also enforced │
│ by other native stacks — covers only the Flutter layer      │
╰─────────────────────────────────────────────────────────────╯
```

- **Pure Flutter app** → green light, patch and go.
- **Mixed app** → warning: Glasswing still patches the Flutter layer, but the app's *main* traffic may ride a separate pinned stack that Glasswing deliberately does not touch.
- **Non-Flutter app** → refused. Out of scope by design.

## Verified results

Every claim below was reproduced on Android emulators against a hostile HTTPS server presenting an untrusted certificate:

| Target | Flutter version | Mode | Result |
|---|---|---|---|
| pinnedprobe (test corpus) | 3.47.7 | static patch | `HTTP 200` ✅ |
| pinnedprobe | 3.47.7 | Frida runtime hook | `HTTP 200` ✅ |
| pinnedprobe | 3.47.7 | static patch on **rootless production build** | `HTTP 200` ✅ |
| Saber (F-Droid, real app) | 3.47.5 | static patch | Dart HTTP client intercepted ✅ |
| Flutter engine artifacts | 3.44.9 & 3.47.x | offline locate + patch roundtrip | all 3 ABIs ✅ |
| Butterfly, ente auth (F-Droid) | 3.4x | static patch | locator + patch verified ✅ |
| Control (unpatched) | — | — | `CERTIFICATE_VERIFY_FAILED` ✅ |

## Known limitations

- **iOS** not supported (same technique applies to `App.framework` + codesigning; not implemented).
- **Mixed apps** (AliExpress-style): the Flutter layer is patched but ANet/XQUIC/Cronet traffic uses separate pinned stacks — Glasswing warns rather than pretending.
- **WebView traffic** uses the OS TLS stack, not BoringSSL — out of scope; the test harness distinguishes traffic by User-Agent so evidence is never misattributed.
- **New Flutter engine majors**: the locator is structural (works across versions), but validate with `inspect` after major releases; `gen-sig` + a PR to `db/signatures.yaml` is the contribution path.

## Contributing

- `glasswing gen-sig app.apk --version X.Y` → PR-ready signature entry
- CI (`.github/workflows/ci.yml`) validates locate+patch roundtrips against the latest stable engine **weekly** — new engine breakage is caught automatically

## Authorized use only

Glasswing is for **security research and penetration testing** of applications you own, or have **explicit written permission** to assess. Intercepting traffic of apps you are not authorized to test is illegal in most jurisdictions. The authors accept no liability for misuse.

## Credits

- [reFlutter](https://github.com/Impact-I/reFlutter) — proved the `return true;` engine patch works; Glasswing reimplements it as a binary patch
- [BoringSSL](https://github.com/google/boringssl) `ssl_x509.cc` / `x509_vpm.cc` — the source-level ground truth the locator is built on
- The Flutter, Frida, and androguard communities

## License

MIT — see [LICENSE](LICENSE).
