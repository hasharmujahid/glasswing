# flutterpinning

**Bypass Flutter's SSL pinning on Android** — for authorized penetration testing.

Flutter apps statically link BoringSSL inside `libflutter.so`; they do **not** use the
system TLS stack. Installing a user CA and hooking OkHttp / Conscrypt / `TrustManager`
achieves nothing for `dart:io`, `dio`, gRPC or any other Dart HTTP client.
`flutterpinning` neutralizes the certificate-chain verification function inside
BoringSSL itself, so the app accepts your interception proxy's certificate.

Verified end-to-end against **Flutter 3.47.x** (current stable) on rooted emulators
*and* rootless production builds:

| Test | Result |
|------|--------|
| static patch (all ABIs) → self-signed HTTPS | `HTTP 200` ✅ |
| Frida runtime hook → self-signed HTTPS | `HTTP 200` ✅ |
| rootless production Android build | works ✅ |
| unpatched control | `CERTIFICATE_VERIFY_FAILED` ✅ |

## How it works (ground-truth driven)

dart:io TLS goes through `SSL_CTX_new(TLS_method())` +
`SSL_CTX_set_verify(SSL_VERIFY_PEER, …)` (see dart SDK `runtime/bin/security_context.cc`),
i.e. BoringSSL's X509 method: every handshake's certificate verification is
decided by `ssl_crypto_x509_session_verify_cert_chain` inside `libflutter.so`.

The binary is stripped (no symbols, no function-name strings in current engines) —
instead of per-version byte offsets, flutterpinning locates that function
**version-independently**:

1. It is member **#10** (index 9) of the `SSL_X509_METHOD` vtable — a block of
   consecutive function pointers in `.data.rel.ro`, one `RELATIVE` dynamic
   relocation each.
2. We scan the relocation table for dense ascending runs of consecutive slots
   whose addends all point into `.text` with a tight span.
3. The candidate whose function body references *both* `"ssl_client"` and
   `"ssl_server"` (`X509_STORE_CTX_set_default(ssl->server ? prefix : …)`, unique
   to this function) is the verify function.

That's the entry to patch with the arch return-true stub:

```
aarch64    mov w0, #1 ; ret       0x52800020 0xd65f03c0
arm32(thumb) movs r0, #1 ; bx lr  0x2001 0x4770
x86_64     mov eax, 1 ; ret       0xb8 0x01 0x00 0x00 0x00 0xc3
```

—an automated binary equivalent of reFlutter's engine-rebuild patch, without the
rebuild. Byte signatures from `db/signatures.yaml` act as a fast path once a
release has been validated (`gen-sig` produces them).

## Installation

```bash
pip install .
```

Runtime deps auto-installed: `frida`, `pyelftools`, `capstone`, `lief`, `androguard`,
`typer`, `rich`, `PyYAML`.

**System tools** (auto-detected under `$ANDROID_HOME`, needed for static patching):

- `apksigner`, `zipalign` from Android build-tools
- `adb` for `--install`, proxy hints and the `hook` command
- a Frida server matching the tool's version, running on-device, for `hook` mode

## Usage

```bash
# inspect: ABI list, engine info, patch support
flutterpinning inspect app.apk

# static patch: patch EVERY libflutter.so ABI, repack, re-sign (no root needed)
flutterpinning patch app.apk -o app-patched.apk
adb install app-patched.apk

# runtime hook: in-memory patch at spawn via frida (rooted device / emulator)
flutterpinning hook app.apk --package the.target.package

# fingerprint an unknown engine release: PR-ready signature entries
flutterpinning gen-sig app.apk --version 3.48.0 -o new_sigs.yaml
```

Typical pentest workflow:

```bash
# on your workstation (proxy = Burp/mitmproxy)
flutterpinning hook app.apk --package com.target.app
# then browse the app — decrypted traffic appears in your proxy
```

> Engine-signature coverage is intentionally version-scoped. New Flutter
> releases re-compile libflutter.so; the struct locator keeps working, and
> `gen-sig` gives contributors a one-command PR to extend `db/signatures.yaml`.

## Authorized use only

This tool is for **security research and penetration testing** of applications
you own **or have explicit written permission** to test. Intercepting or
modifying traffic of apps you are not authorized to assess is illegal in most
jurisdictions. The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE) (includes the authorized-use notice).
