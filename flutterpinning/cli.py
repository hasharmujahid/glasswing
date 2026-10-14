"""flutterpinning CLI — inspect, patch, and hook Flutter apps for authorized pentesting."""

from __future__ import annotations

import os
import subprocess
import sys

from pathlib import Path
from typing import Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, scanner
from .so_patch import stub_for
from . import apk as apkmod
from .detectors import scan_path
from .so_patch import patch_so_bytes, stub_disassembly_hint

app = typer.Typer(
    name="flutterpinning",
    help="Bypass Flutter SSL pinning for authorized penetration testing.",
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

DISCLAIMER = (
    "[bold yellow]Authorized use only:[/bold yellow] this tool is for security testing "
    "apps you own or have written permission to test."
)

APP_HOOK_SCRIPT = """\
// flutterpinning runtime hook:
//  - pattern-scan libflutter.so for the BoringSSL verify-cert-chain function
//  - replace it so cert verification always succeeds
Java.perform(function () {
  var FLUTTER_MODULE = "libflutter.so";
  var SIGNATURES = %SIGNATURES%;
  var ARCH = %ARCH%;
  function patchMatch(match, size) {
    var stub = %STUB%;
    Memory.patchCode(match, size, function (code) {
      code.writeInstruction = code.writeByteArray;
      // write `mov w0, #1; ret` (or arch-specific equivalent) over entry
      code.writeByteArray(stub);
    });
  }
  function run() {
    var mod = Process.getModuleByName(FLUTTER_MODULE);
    if (!mod) { setTimeout(run, 250); return; }
    %ARCH_SWITCH%
  }
  run();
});
"""

_BANNER = r"""
   __ _                      _       _     _
  / _| |__  _ __ ___  ___| | __ _| |__ (_) ___ ___
 | |_| __| '_ \ ___ \/ __| |/ _` | '_ \| |/ _ \ __|
 |  _| |_| | | | |) \__ \ | (_| | | | | |  __/ |
 |_|  \__,_|_| |_|__/|___/_|\__, |_| |_|_|\___\___|
                             |__/
"""


def _load_signatures() -> dict:
    pkg_db = Path(__file__).parent / "db" / "signatures.yaml"
    return scanner.load_signatures(str(pkg_db))


def _select_arch(res, arch: Optional[str], verbose: bool = False) -> Tuple[str, dict]:
    """Pick an ABI present in the APK, preferring arm64."""
    available = res.libflutter.keys()
    if arch:
        if arch not in available:
            raise typer.BadParameter(f"ABI {arch!r} not present; found: {', '.join(sorted(available))}")
        return arch, res.libflutter[arch]
    for preferred in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
        if preferred in available:
            return preferred, res.libflutter[preferred]
    raise typer.BadParameter(f"no supported ABI in the APK (found: {', '.join(sorted(available))})")


def _read_libflutter_from_apk(apk_path: str, entry: str) -> bytes:
    import zipfile

    with zipfile.ZipFile(apk_path) as zf:
        return zf.read(entry)


def _find_libflutter_entry(res) -> str:
    entry = res.libflutter_path()
    if not entry:
        raise typer.BadParameter("libflutter.so not found — is this a Flutter app?")
    return entry


def _proxy_adb(proxy: Optional[str]) -> None:
    """Apply a global proxy setting via adb (requires a connected device)."""
    if proxy is None:
        return
    subprocess.run(["adb", "shell", "settings", "put", "global", "http_proxy", proxy], check=True)
    console.print(f"[green]adb proxy set to[/green] {proxy}")


def _check_adb() -> bool:
    return subprocess.run(["adb", "version"], capture_output=True).returncode == 0


def _java_version_check() -> None:
    pass  # keytool/apksigner print actionable errors themselves


@app.command()
def inspect(
    path: str = typer.Argument(..., help="APK file (or bare libflutter.so) to scan"),
    arch: Optional[str] = typer.Option(None, "--arch", help="ABI to inspect (default: preferred)"),
    db: Optional[str] = typer.Option(
        None, "--db", help="Path to db/signatures.yaml override"
    ),
    androguard_logs: bool = typer.Option(
        False, "--androguard-logs",
        help="Show androguard's internal DEBUG logs (default: suppressed)"),
) -> None:
    """Show Flutter metadata, supported ABIs, and whether the version is supported."""
    from .detectors import configure_androguard_logging
    from .classify import classify_apk

    configure_androguard_logging(androguard_logs)
    console.print(_BANNER, style="cyan", highlight=False)
    console.print(_disclaimer_panel(), justify="left")
    if not os.path.isfile(path):
        console.print(f"[red]No such file:[/red] {path}")
        raise typer.Exit(1)

    res = scan_path(path)
    if res.error:
        console.print(f"[red]{res.error}[/red]")
        raise typer.Exit(1)

    # target classification: is the pinning actually Flutter/BoringSSL-side?
    if res.is_apk:
        verdict = classify_apk(path)
        if not verdict.is_flutter_target:
            style = "[yellow]" if verdict.mixed else "[red]"
            console.print(Panel(
                f"{style}Not a flutterpinning target.[/]\n{verdict.reason}",
                title="Target classification", border_style="yellow" if verdict.mixed else "red",
            ))
            if not verdict.mixed:
                raise typer.Exit(1)

    res = scan_path(path)
    if res.error:
        console.print(f"[red]{res.error}[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Flutter app summary — {os.path.basename(path)}", show_lines=False)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("path", res.path)
    table.add_row("is Flutter app", "[green]yes[/green]" if res.is_flutter else "[red]no[/red]")
    if res.package:
        table.add_row("package", res.package)
    table.add_row("ABIs (lib/*)", ", ".join(sorted(res.archs)) or "none")
    entry = res.libflutter_path(arch)
    if entry:
        abi = arch or entry.split("/")[1]
        info = res.libflutter[abi]
        table.add_row("libflutter.so", f"{entry} ({info.size:,} bytes)")
        libflutter_bytes = _read_libflutter_from_apk(path, entry)
        version = scanner.extract_dart_version(libflutter_bytes)
        table.add_row("Dart version", version or "[dim]not detectable[/dim]")
        table.add_row("bypass support", _support_status(version, abi))
    for h in res.snapshot_hashes:
        table.add_row("Dart snapshot hash", h)
        table.add_row("Dart snapshot hash", h)
    if res.libapp:
        entryapp = next(iter(res.libapp.values()))
        table.add_row("libapp.so (Dart AOT code)", f"{entryapp.name} ({entryapp.size:,} bytes)")
    console.print(table)


def _support_status(version: Optional[str], arch: str) -> str:
    sigs = _load_signatures()
    if version:
        label = f"Flutter ~{version}"
        return f"[green]struct-locator works across versions ({label})[/green]"
    return "[green]struct-locator works across engine versions[/green]"


def _disclaimer_panel() -> Panel:
    return Panel(DISCLAIMER, expand=False, border_style="yellow")


@app.command()
def patch(
    path: str = typer.Argument(..., help="APK to patch"),
    out: str = typer.Option("patched.apk", "--out", "-o", help="Output APK path"),
    arch: Optional[str] = typer.Option(None, "--arch", help="ABI to patch (default: preferred)"),
    version: Optional[str] = typer.Option(
        None, "--version", help="Override the detected engine (Dart) version"),
    db: Optional[str] = typer.Option(None, "--db", help="Signature DB override (YAML)"),
    gadget: bool = typer.Option(
        False, "--gadget", help="Also embed frida-gadget for runtime instrumentation without root"),
    keystore: Optional[str] = typer.Option(None, "--keystore", help="Keystore for re-signing"),
    install: bool = typer.Option(False, "--install", help="install via adb after patching"),
    androguard_logs: bool = typer.Option(
        False, "--androguard-logs",
        help="Show androguard's internal DEBUG logs (default: suppressed)"),
):
    """Patch libflutter.so (static), repackage, and re-sign — no root needed."""
    from .detectors import configure_androguard_logging
    from .classify import classify_apk

    configure_androguard_logging(androguard_logs)
    console.print(_BANNER, style="cyan", highlight=False)
    console.print(_disclaimer_panel(), justify="left")
    if not os.path.isfile(path):
        console.print(f"[red]No such file:[/red] {path}")
        raise typer.Exit(1)

    res = scan_path(path)
    if res.error:
        console.print(f"[red]{res.error}[/red]")
        raise typer.Exit(1)

    verdict = classify_apk(path)
    if not verdict.is_flutter_target:
        style = "yellow" if verdict.mixed else "red"
        console.print(Panel(
            f"[{style}]Not a flutterpinning target.[/]\n{verdict.reason}",
            title="Target classification", border_style=style,
        ))
        if not verdict.mixed:
            raise typer.Exit(1)
        console.print("[yellow]continuing: Flutter layer will still be patched "
                      "(non-Flutter stacks stay pinned)[/yellow]")
    if not res.is_flutter:
        console.print("[red]Not a Flutter app (no libflutter.so).[/red]")
        raise typer.Exit(1)

    # Patch EVERY ABI shipped in the APK: the device loads whichever matches its
    # own CPU, and pentesters must not depend on the target's architecture.
    targets = ({arch} if arch else set(res.libflutter.keys()))
    sigs = _load_signatures() if db is None else scanner.load_signatures(db)
    replaced = []
    for abi in sorted(targets):
        entry = res.libflutter_path(abi)
        if not entry:
            console.print(f"[yellow]no libflutter.so for {abi}[/yellow]")
            continue
        libflutter = _read_libflutter_from_apk(path, entry)
        dart_version = version or scanner.extract_dart_version(libflutter)
        try:
            patched_libflutter, result = patch_so_bytes(libflutter, abi, dart_version, sigs)
        except RuntimeError as exc:
            console.print(f"[red]{abi}: {exc}[/red]")
            raise typer.Exit(1)
        console.print(f"[cyan]{abi}:[/cyan] target located strategy={result.strategy}"
                      f" offset=0x{result.file_off:x} ({result.detail or ''})")
        console.print(f"  patch: [bright]{stub_disassembly_hint(abi)}[/bright]")
        replaced.append((entry, patched_libflutter))

    apkmod.repack_apk(path, out, replacements=replaced)
    apkmod.sign_apk(out, keystore_path=keystore)

    if gadget:
        from .gadget import GADGET_VERSION, download_gadget, inject_gadget

        gadget_blob = Path(download_gadget(GADGET_VERSION, "arm64")).read_bytes()
        gpath = out.replace(".apk", "-gadget.apk")
        inject_gadget(out, gpath, gadget_blob=gadget_blob, package=res.package)
        console.print(f"[green]gadget variant written to[/green] {gpath}")
        os.replace(gpath, out)  # user asked for a single artifact
        apkmod.sign_apk(out, keystore_path=keystore)

    ok = apkmod.verify_signature(out)
    console.print(f"[green]wrote[/green] {out}  (signature verified: {ok})")

    if install:
        subprocess.run(["adb", "install", "-r", out], check=True)


@app.command()
def hook(
    path: str = typer.Argument(..., help="APK to launch with bypass in memory"),
    package: Optional[str] = typer.Option(None, "--package", "-p", help="Installed package (overrides reading APK)"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="host:port to route device traffic through"),
    arch: Optional[str] = typer.Option(None, "--arch", help="ABI to assume (default: preferred)"),
    gadget: bool = typer.Option(False, "--gadget", help="Expect a gadget build instead of frida-server"),
    no_spawn: bool = typer.Option(False, "--no-spawn", help="Attach to a running process instead of spawning"),
    androguard_logs: bool = typer.Option(
        False, "--androguard-logs",
        help="Show androguard's internal DEBUG logs (default: suppressed)"),
):
    """Launch the app on a device and bypass pinning in memory (needs frida-server)."""
    import frida
    from .hook import build_hook_script
    from .detectors import configure_androguard_logging

    configure_androguard_logging(androguard_logs)
    console.print(_BANNER, style="cyan", highlight=False)
    console.print(_disclaimer_panel(), justify="left")

    if not _check_adb():
        console.print("[red]adb not found — install Android platform-tools.[/red]")
        raise typer.Exit(1)

    _proxy_adb(proxy)

    package = package
    if package is None:
        res = scan_path(path)
        if res.error or not res.package:
            console.print("[red]Could not determine package name — pass --package.[/red]")
            raise typer.Exit(1)
        package = res.package

    res = scan_path(path)
    libflutter_blobs: dict = {}
    offsets: dict = {}
    stub_hexes: dict = {}
    dart_version = None
    sigs = _load_signatures()
    from .so_patch import entry_offset, LocateFailed

    for abi, info in sorted(res.libflutter.items()):
        blob = _read_libflutter_from_apk(path, info.name)
        libflutter_blobs[abi] = blob
        version = scanner.extract_dart_version(blob) or dart_version
        try:
            _strategy, entry_off, _detail = entry_offset(
                blob, abi, version, sigs)
        except LocateFailed as exc:
            console.print(f"[red]{abi}: locate failed:[/red] {exc}")
            continue
        offsets[abi] = entry_off
        stub_hexes[abi] = stub_for(abi).hex()
        console.print(
            f"[cyan]{abi}:[/cyan] entry located strategy={_strategy} "
            f"offset=0x{entry_off:x} ({_detail})")

    if not offsets:
        console.print("[red]no usable ABI offsets — cannot hook[/red]")
        raise typer.Exit(1)
    script_src = build_hook_script(offsets, stub_hexes)

    device = frida.get_usb_device(timeout=10)
    console.print(f"[cyan]hooking[/cyan] {package} on first available device")
    if no_spawn:
        pid = device.get_process(package).pid
        session = device.attach(pid)
    else:
        pid = device.spawn([package])
        session = device.attach(pid)
    script = session.create_script(script_src)
    script.on("message", lambda message, data: console.print(f"  [dim]{message}[/dim]"))
    script.load()
    if not no_spawn:
        device.resume(pid)
    console.print("[green]hooked — traffic should now appear in your proxy.[/green]"
                  " Ctrl-C to exit.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()


@app.command("gen-sig")
def gen_sig(
    path: str = typer.Argument(..., help="libflutter.so (or APK) from an unknown engine release"),
    out: str = typer.Option("signature.yaml", "--out", "-o", help="Where to write the YAML entry"),
    arch: Optional[str] = typer.Option(None, "--arch", help="ABI override"),
    version: Optional[str] = typer.Option(None, "--version", help="Version label override"),
    androguard_logs: bool = typer.Option(
        False, "--androguard-logs",
        help="Show androguard's internal DEBUG logs (default: suppressed)"),
):
    """Generate a signature entry for an engine version missing from the DB."""
    from .detectors import configure_androguard_logging

    configure_androguard_logging(androguard_logs)
    console.print(_BANNER, style="cyan", highlight=False)
    from .gen_signature import generate_signature

    generate_signature(path, out, arch=arch, version=version, console=console)


def _version_callback(value: bool) -> None:
    if value:
        console.print(_BANNER, style="cyan", highlight=False)
        console.print(f"flutterpinning v{__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_flag=True,
        help="Print the version and exit"),
):
    """flutterpinning — authorized-use Flutter SSL pinning bypass."""
