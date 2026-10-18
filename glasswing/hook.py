"""In-memory (Frida) runtime bypass.

Flow: the HOST locates `session_verify_cert_chain` statically for every ABI in
the APK (struct locator — same binaries the device loads), embeds the resulting
offset map in a tiny Frida agent; the agent detects which ABI the actual
process loaded (via the ELF machine type at module base) and patches the
runtime memory at module_base + offset — cert verification always succeeds.

Works with frida-server (rooted device) or a gadget build (rootless).
"""

from __future__ import annotations

AGENT_TEMPLATE = r"""
// glasswing runtime agent — authorized use only.
'use strict';

// ABI -> entry file offset (relative to module base), computed on the host.
var OFFSETS = {{offsets}};          // e.g. { 'arm64-v8a': 1234, 'x86_64': 5678 }
var STUBS = {{stubs}};              // return-true stub per ABI (hex)
var MODULE_NAME = "libflutter.so";

var EM_AARCH64 = 183, EM_ARM = 40, EM_X86_64 = 62, EM_386 = 3;

function archOfModule(base) {
  // ELF header: e_ident 16 bytes, then e_type(2), e_machine(2)
  var e_machine = base.add(0x12).readU16();
  if (e_machine === EM_AARCH64) return 'arm64-v8a';
  if (e_machine === EM_ARM)     return 'armeabi-v7a';
  if (e_machine === EM_X86_64)  return 'x86_64';
  if (e_machine === EM_386)     return 'x86';
  return null;
}

var ATTEMPTS = 0, MAX_ATTEMPTS = 300;   // ~30s at 100ms, then give up loudly

function patchOnce() {
  var mod = Process.findModuleByName(MODULE_NAME);
  if (mod === null) {
    if (++ATTEMPTS >= MAX_ATTEMPTS) {
      send({type:'error', msg: MODULE_NAME + ' not loaded after ~30s — is this a Flutter app?'});
      return;
    }
    setTimeout(patchOnce, 100);
    return;
  }

  var arch = archOfModule(mod.base);
  var offset = arch ? OFFSETS[arch] : null;
  if (arch === null || offset === undefined) {
    send({type:'error', msg:'unsupported arch for loaded module ' +
        '(e_machine detection failed or ABI not patched)'});
    return;
  }

  var target = mod.base.add(offset);
  var hex = STUBS[arch];
  var bytes = [];
  for (var i = 0; i < hex.length; i += 2)
    bytes.push(parseInt(hex.substr(i, 2), 16));

  send({type:'info', msg:'module=' + mod.base + ' arch=' + arch +
        ' entry=' + target + ' stub=' + hex});

  var orig = null;
  try { orig = target.readByteArray(16); } catch (e) {}
  if (orig !== null) send({type:'orig_bytes'}, orig);

  try {
    Memory.patchCode(target, bytes.length, function (code) {
      code.writeByteArray(bytes);
    });
    send({type:'patched', target: target.toString(), arch: arch});
  } catch (e) {
    // fallback: protect + write for sandboxed mappings
    Memory.protect(target, bytes.length, 'rwx');
    target.writeByteArray(bytes);
    Memory.protect(target, bytes.length, 'rx');
    send({type:'patched_fallback', target: target.toString(), arch: arch});
  }
}

patchOnce();
"""


USER_SCRIPT_BOOTSTRAP = r"""
// glasswing: load frida 17+ bridges (Java/ObjC/Swift) on demand — same
// contract as the official REPL. No-op on runtimes that bundle them (frida 16).
function __glasswing_load_bridge(name) {
  var result;
  send({ type: 'frida:load-bridge', name: name });
  recv('frida:bridge-loaded', function (m) {
    result = Script.evaluate('/frida/bridges/' + m.filename, '(function () { ' +
      [m.source,
       "Object.defineProperty(globalThis, '" + name + "', { value: bridge });",
       'return bridge;'].join('\n') + ' })();');
  }).wait();
  return result;
}
['ObjC', 'Swift', 'Java'].forEach(function (name) {
  try {
    if (typeof globalThis[name] !== 'undefined')
      return;                       // runtime bundles this bridge already
    Object.defineProperty(globalThis, name, {
      configurable: true,
      get: function () { return __glasswing_load_bridge(name); }
    });
  } catch (e) {}                    // keep going if the slot is not writable
});
"""


def wrap_user_script(source: str, name: str) -> str:
    """Compose a `-l` user script: bridge bootstrap + named evaluation.

    frida 17 removed the bundled Java/ObjC/Swift bridges; the glasswing host
    serves them when the runtime asks (frida:load-bridge -> frida:bridge-loaded),
    mirroring frida-tools' REPL so community scripts keep working unchanged.
    """
    import json

    return (USER_SCRIPT_BOOTSTRAP + "\n" +
            f"Script.evaluate({json.dumps(name)}, {json.dumps(source)});\n")


def build_hook_script(offsets: dict[str, int], stub_hexes: dict[str, str]) -> str:
    """Render the Frida agent with the host-computed per-ABI offset map."""
    import json

    js = json.dumps(offsets)              # keys are valid JS identifiers
    stubs_js = json.dumps(stub_hexes)
    return AGENT_TEMPLATE.replace("{{offsets}}", js).replace("{{stubs}}", stubs_js)
