---
name: leanrea
description: Reverse engineer shipped software with plain local CLI tools, no MCP needed. Covers Electron/JS bundles, native Mach-O/ELF/PE, Go/Rust/.NET/Flutter/WASM binaries, APKs, SQLite, pcaps, firmware and websites. Use to explain how a feature works, extract versions/deps, compare builds, or rebuild a feature.
---

# leanrea: fast path

You already know these tools. This file only lists the fastest command for each target, and the traps.

## Rules
- Work on a copy (`cp -c` on APFS is instant). Put each extraction in a new dir under `$TMPDIR/re/<name>`. Reuse an extraction if one exists.
- Route by `file -b T` and the magic bytes first. Run the cheapest inventory next. Only then decompile or read code.
- `rg` skips hidden and ignored files, and bundlers hide code (Electron: `.webpack/`, `.vite/`). Always search extracted trees with `rg -uu`.
- Never `cat` a big or minified file. Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | head`. Dump a disassembly once to a file, then grep that file.
- Batch independent probes into ONE shell call with `;` and `echo '--- name'` markers (quoted: zsh expands a bare `==x`). Cap every output with `head` or `-m`.
- Answer from evidence. In the answer, mark each claim as **seen** (cite file:offset, or a symbol/string) or **inferred**. A fact you did not find is **unknown**, not "absent". Static reading is not observed execution.
- A missing tool is not a blocker. Use the fallback in the same row, or `brew install <x>` if the user allows it.
- On Windows: see the last section. Run the mac/Linux recipes through Git Bash (bash.exe -lc) instead of translating them.
- Turns cost more than bytes. Aim for 2–4 tool calls: one batched recon call, one or two targeted slices, then answer. Stop when every item you were asked has evidence. Do not re-verify what you already saw.

## First move: one call each, paste and run
Native (Mach-O):
```sh
T=./bin; D=$TMPDIR/re/$(basename $T); mkdir -p $D; file $T; lipo -info $T; otool -L $T; echo '--- EXPORTS'; nm -gU $T | head -150; echo '--- IMPORTS'; nm -u $T | rg -v '^__Z|napi_' | tr '\n' ' '; echo; echo '--- STRINGS'; strings -a -n 6 $T | rg -v '^[_$.]' | head -400; otool -tV $T > $D/dis.txt; echo '--- FUNCS'; rg '^[_a-zA-Z].*:$' $D/dis.txt | rg -v '^_?_?Z?N?St3' | head -150
```
Then read one function: `awk '/^FUNC_LABEL:$/{p=1;next} p&&/^[_a-zA-Z].*:$/{exit} p' $D/dis.txt | rg 'bl|b\.|cmp|literal|mov\s+w2'`.

Electron:
```sh
A=./app.asar; X=$TMPDIR/re/asar; rm -rf $X; npx -y @electron/asar extract $A $X && jq '{name,version,main}' $X/package.json; find $X -path '*/node_modules' -prune -o -type f \( -name '*.js' -o -name '*.node' \) -print | head -60; ls ${A}.unpacked/node_modules 2>/dev/null; rg -uu -l --glob '!node_modules' 'exposeInMainWorld' $X
```
Then slice the needle across the bundle: `rg -uu -o --glob '!node_modules' '.{0,250}NEEDLE.{0,250}' $X | head -20`.

Go: `go version -m T` alone usually answers the question.

## Router
| Target (detect) | Fastest path |
|---|---|
| Electron app (`*.app/Contents/Resources/app.asar`) | `npx -y @electron/asar extract app.asar X` (also see `app.asar.unpacked/` for `.node` addons). Entry point: `jq .main X/package.json`. Surface: `rg -n -o '.{0,120}(ipcMain\.(handle|handleOnce|on|once)|ipcRenderer\.(invoke|send|sendSync|on)|contextBridge\.exposeIn(Main|Isolated)World|webPreferences|preload:|nodeIntegration|contextIsolation|sandbox|\.node\b).{0,160}' -uu X --glob '!node_modules'`. App-specific IPC wrappers often hide the channels, so also run `rg -uu -o '"[a-z]+:[a-z0-9:-]+"' X/<main> \| sort -u`. Fuses: `npx -y @electron/fuses read --app A.app`. |
| Web bundle / minified JS | Find `sourceMappingURL`. If the map has `sourcesContent`, dump the sources: `jq -r '.sources[]'`. For webpack, grep the module ids, then slice around the hit. For pretty-print: `npx -y prettier --parser babel F > F.pretty.js`, then read with line ranges. |
| Hermes / bytenode / V8 snapshot | Hermes magic is `c6 1f bc 03` (`index.android.bundle`): use `hermes-dec` / `hbc-decompiler`. `.jsc` (bytenode) cannot be decompiled: use strings and runtime hooks. |
| Mach-O (`file`: Mach-O) | `lipo -info` (thin first: `lipo -thin arm64 -o T1 T`). Then: `otool -L` (libs); `xcrun dyld_info -exports -imports`; `nm -gU` (exports) / `nm -u` (imports = the capability map); `strings -a -n 6`; `otool -l \| rg -A3 'LC_(RPATH\|BUILD_VERSION)'`; `codesign -d --entitlements :- T`; `otool -ov` (ObjC classes/methods); `xcrun swift-demangle --compact`. |
| Native code logic | `otool -tV T > $D/dis.txt` (or `llvm-objdump -d --no-show-raw-insn -C`). Find the function: `rg -n '^_?.*Name.*:$'`. Read the call/string trail: `awk '/^FUNC:/{p=1} p&&/^[_a-zA-Z].*:$/&&!/FUNC/{exit} p' dis.txt \| rg 'bl\|call\|literal\|cmp'`. otool labels string literals and stubs inline, which is often enough. Only for real pseudocode: Ghidra `analyzeHeadless $D p -import T -postScript DecompileAll.java -deleteProject` or `r2 -qc 'aaa; pdc @ sym.X' T`. |
| ELF / PE | `readelf -hlSW`, `readelf -dW` (NEEDED), `nm -D --defined-only`, `objdump -d -M intel`. PE: `objdump -x`, `pefile`/`wrestool` for resources. checksec: `pwn checksec`. |
| Go (`__go_buildinfo`, `.go.buildinfo`) | `go version -m T` gives the toolchain, path, mod, deps and build flags in one call. Without Go: `strings -a T \| rg -m1 -A200 'Go buildinf' `. Symbols survive stripping: `go tool nm T \| rg main\.`. |
| Rust | Deps (cargo-auditable): `cargo audit bin T`, or extract `.dep-v0` / `__DATA,.dep-v0` and zlib-inflate it. Compiler: `strings -a T \| rg -o '/rustc/[0-9a-f]{40}' \| sort -u`. Crates from paths: `strings -a T \| rg -o '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src' \| sort -u`. |
| .NET (`file`: Mono/.Net) | `ilspycmd -p -o X T.dll` (install: `dotnet tool install -g ilspycmd`), then `rg`. P/Invoke: `rg DllImport X`. NativeAOT/IL2CPP are native: use the native rows. |
| Android APK | `jadx -d X --show-bad-code a.apk` then `rg`. Resources/manifest only: `apktool d --no-src -o X a.apk`. Quick look: `unzip -l a.apk`. `lib/*/libflutter.so` means Flutter (Dart AOT: `blutter`); `libhermes.so` means React Native (Hermes row). |
| Flutter snapshot hash | In `libapp.so`, find magic `f5 f5 dc dc`; the 32 hex chars at +20 are the snapshot hash. Map it to a Dart version. |
| WASM | `wasm-objdump -x`, `wasm2wat`, `wasm-decompile` (WABT). |
| SQLite | Copy the db, plus the `-wal` file if present. `sqlite3 'file:C?mode=ro' '.schema'`, then `SELECT * FROM t LIMIT 20`. |
| plist / nib / car | `plutil -p F`. Info.plist holds the bundle id, URL schemes and privacy strings. Asset catalogs: `assetutil --info Assets.car`. |
| pcap / HAR | `tshark -r C -q -z conv,tcp`; `tshark -r C -T fields -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.full_uri \| sort -u`. HAR: `jq -r '.log.entries[].request \| .method+" "+.url'`. |
| Firmware | `binwalk -e F` or `unblob -e X F`. Then route each extracted binary through this table. |
| Website | `curl -sL URL` for the HTML and script srcs, then fetch the JS and slice it. For runtime behavior, use a headless browser with a network log (Playwright `page.on('request')`) or Chrome `--remote-debugging-port`. |
| Running app / runtime | macOS: `lldb -p PID`, `dtrace`/`fs_usage`/`log stream --predicate 'process=="X"'`. Electron main: `--inspect` (only if the RunAsNode/inspect fuses allow it). Android: `adb logcat`, `frida -U -f pkg -l hook.js`. |

## Speed patterns
- Strings and imports first. On a small binary, `nm -u` + `strings` + the export list usually answer "what does it do" with no disassembly.
- To find who uses a string: get its address from `otool -tV` "literal pool for" comments, or `rg -n 'literal pool for: "X'`. Then find the enclosing function label above that line.
- A C++ name in a `bl` target already tells you the protocol (for example `getpeereid`, `write`, `std::hash`). Read the call sequence, not every instruction.
- For JS, go from the native/JS boundary inward: find the native call, then its caller class, then the IPC registration, then the renderer/preload.
- Comparing versions: diff the inventories (`nm`, the module list, `go version -m`) before you diff any code.
- Rebuilding: write the minimal reimplementation, then test it against the original (same inputs, same outputs).

## Install (only on request)
`brew install jadx apktool radare2 binwalk wabt wireshark ghidra` · `npm i -g @electron/asar` · `dotnet tool install -g ilspycmd` · `cargo install cargo-audit`.

## Windows (PowerShell 5.1 / 7, cmd)

Best single move: run the recipes through Git Bash instead of translating them —
`& 'C:\Program Files\Git\bin\bash.exe' -lc 'file -b T; strings -a -n 6 T | head -400'`.
Git for Windows ships real `file`, `strings`, `awk`, `head`, `sed`, `tr`; `C:\msys64\ucrt64\bin` adds `objdump`, `readelf`, `sqlite3`. Use WSL (`wsl -e bash -lc '...'`) for `binwalk`/`unblob` for re-signing Mach-O; static Mach-O parsing needs no WSL - see the Mach-O section below.

| mac/Linux | Windows replacement |
|---|---|
| `file -b T` | `& 'C:\Program Files\Git\usr\bin\file.exe' -b T`; else PS7 `Format-Hex -Path T -Count 16`, PS5.1 `([IO.File]::ReadAllBytes($T))[0..15] \| %{ $_.ToString('X2') }` |
| `strings -a -n 6` | `strings.exe -a -n 6 T` (Git/msys) or `rg -a -o '[\x20-\x7E]{6,}' T` |
| `head` / `awk` / `sed` / `tr` | `Select-Object -First N`, or run the pipe in Git Bash |
| `nm -gU` / `nm -u` | `llvm-nm --defined-only --extern-only T` / `llvm-nm --undefined-only T` |
| `otool -L` / `otool -tV` | `llvm-objdump --macho --dylibs-used T` / `llvm-objdump --macho --disassemble --no-show-raw-insn -C T > dis.txt` |
| `lipo -info` | `llvm-lipo -info T` |
| `readelf` / `objdump` | `llvm-readelf -hlSW`, `llvm-objdump -d -M intel` |
| `$TMPDIR` | `$env:TEMP` |
| `cp -c` (APFS clone) | no clone; `Copy-Item`, `robocopy /B` for locked files |

PE / native Windows target, one call:

```powershell
$T='.\bin\app.exe'; $D="$env:TEMP\re\$((Get-Item $T).BaseName)"; New-Item -ItemType Directory -Force $D | Out-Null
Format-Hex -Path $T -Count 16
llvm-objdump -p $T | Select-String 'DLL Name|Subsystem|Time/Date'     # import map without dumpbin
llvm-readobj --coff-exports $T | Select-Object -First 80
rg -a -o '[\x20-\x7E]{6,}' $T | Select-Object -First 400
```

`dumpbin` exists only inside a Visual Studio Developer shell. Without LLVM either, `python -c "import pefile;pe=pefile.PE('T');print([e.dll for e in pe.DIRECTORY_ENTRY_IMPORT])"` is the cheapest capability map.

Wrappers you meet on Windows, and the unwrap:
- Electron: `resources\app.asar` beside the exe — every Router row applies unchanged. No `jq`? `node -e "const p=require('./package.json');console.log(p.name,p.version,p.main)"`.
- NSIS installer: `7z x setup.exe -oX`, then `X\$PLUGINSDIR\app-64.7z`.
- Inno Setup: `innoextract -e -d X setup.exe`.
- MSI: `lessmsi x setup.msi X\` or `msiexec /a setup.msi /qb TARGETDIR=X`.
- MSIX / APPX: `makeappx unpack /p p.msix /d X` (Windows SDK) or `7z x`.
- .NET: `ilspycmd -p -o X T.dll` (cross-platform `dotnet tool`); dnSpyEx when you must debug a live assembly.

Runtime: Procmon for file/registry (`procmon /AcceptEula /Quiet /Minimized`), `procdump -ma PID d.dmp` then `cdb -z d.dmp`, x64dbg for native, Electron main `--inspect`, `adb` identical to macOS.

Traps:
- Windows PowerShell 5.1 aliases `curl`/`wget` to `Invoke-WebRequest`; call `curl.exe`.
- Put `rg` patterns in single quotes: double quotes expand `$` and backtick.
- `.` is not on `PATH`: `.\tool.exe`. If bare `rg` is missing, DSH ships one at `D:\DeepSeek Harness\resources\app\dsh\node_modules\@vscode\ripgrep-win32-x64\bin\rg.exe`.
- A running exe locks on write but reads fine; extract to `$env:TEMP` and never analyze in `C:\Program Files`.
- Windows bundles store `\\` and `C:/` literals: search both `C:\\` and `C:/`.
- Long paths: prefix `\\?\` when a tool truncates.
- `Format-Hex -Count` / `Get-Content -AsByteStream` need PS7; PS5.1 uses `-Encoding Byte` or `[IO.File]::ReadAllBytes`.

Install (only on request): `winget install LLVM.LLVM Git.Git BurntSushi.ripgrep.MSVC WiresharkFoundation.Wireshark` · `choco install jadx apktool ghidra 7zip lessmsi innoextract jq` · `dotnet tool install -g ilspycmd` · `binwalk`/`unblob` via `wsl`.

## Mach-O on Windows (no codesign, no otool)

`llvm-objdump --macho` is a container parser: it walks load commands and never verifies a signature, so ad-hoc, expired, revoked or hand-patched binaries read exactly like pristine ones. Nothing here needs `codesign`, a keychain, or a Mac — the signature is just bytes at `LC_CODE_SIGNATURE`.

Zero-install first (works with only Git for Windows + python):

```sh
T=lib.dylib
file -b "$T"                                   # thin/universal, arch, MH_ type
strings -a "$T" | rg -m6 'com\.apple\.security|application-identifier|Entitlements|get-task-allow'
python sig.py "$T"                             # identifier, team, flags, cdhash, entitlements
```

`sig.py` — paste once, ~40 lines, stdlib only, thin + fat (exits verified against a linker-signed arm64 dylib, an unsigned x86_64 dylib and a fat wrapper):

```python
import struct, sys, plistlib, hashlib

d = open(sys.argv[1], 'rb').read()

def slices(b):
    if struct.unpack('>I', b[:4])[0] in (0xCAFEBABE, 0xBEBAFECA):
        for i in range(struct.unpack('>I', b[4:8])[0]):
            cpu, sub, off, size, _ = struct.unpack('>5I', b[8+20*i:28+20*i])
            yield {0x01000007: 'x86_64', 0x0100000C: 'arm64'}.get(cpu, hex(cpu)), b[off:off+size]
    else:
        yield 'thin', b

for arch, s in slices(d):
    sig = None
    bits = 32 if struct.unpack('<I', s[:4])[0] == 0xFEEDFACE else 64
    p = 32 if bits == 64 else 28
    for _ in range(struct.unpack('<I', s[16:20])[0]):          # walk load commands
        cmd, size = struct.unpack('<II', s[p:p+8])
        if cmd == 0x1D:                                        # LC_CODE_SIGNATURE
            sig = struct.unpack('<II', s[p+8:p+16])            # dataoff, datasize
        p += size
    print('==', arch, bits, 'bit')
    if not sig:
        print('  unsigned')
        continue
    off = sig[0]
    if struct.unpack('>I', s[off:off+4])[0] != 0xFADE0CC0:     # superblob (big-endian)
        print('  no embedded signature')
        continue
    bl = {}
    for i in range(struct.unpack('>I', s[off+8:off+12])[0]):
        t, o = struct.unpack('>II', s[off+12+8*i:off+20+8*i])
        bl[t] = off + o                                        # slot offsets are superblob-relative
    if 0 in bl:                                                # CodeDirectory
        q = bl[0]; cl = struct.unpack('>I', s[q+4:q+8])[0]; cd = s[q:q+cl]
        ver, fl, ho, io, ns, nc, lim = struct.unpack('>7I', cd[8:36])
        print('  cd v%#x flags %#x cdhash %s' % (ver, fl, hashlib.sha256(cd).hexdigest()[:40]))
        if io:
            print('  ident', cd[io:cd.index(b'\0', io)].decode())
        if ver >= 0x20200 and struct.unpack('>I', cd[48:52])[0]:   # teamOffset needs v>=0x20200
            to = struct.unpack('>I', cd[48:52])[0]
            print('  team', cd[to:cd.index(b'\0', to)].decode())
    if 5 in bl:                                                # XML entitlements
        q = bl[5]; l = struct.unpack('>I', s[q+4:q+8])[0]
        for k, v in sorted(plistlib.loads(s[q+8:q+l]).items()):
            print('  %s = %r' % (k, v))
```

Output shape: `cd v0x20400 flags 0x2 cdhash 707f888a…`, then `ident`/`team`, then one `key = value` per entitlement.

With LLVM installed (`winget install LLVM.LLVM`, or `scoop install llvm`):

| Need | Command |
|---|---|
| all load commands | `llvm-objdump --macho --all-headers T` |
| signature location | `llvm-objdump --macho --private-headers T \| rg -A2 LC_CODE_SIGNATURE` → `dataoff` / `datasize` |
| linked dylibs | `llvm-objdump --macho --dylibs-used T` |
| exported symbols | `llvm-objdump --macho --exports-trie T` |
| ObjC classes/methods | `llvm-objdump --macho --objc-meta-data T` |
| embedded Info.plist | `llvm-objdump --macho --info-plist T` (only when `__TEXT,__info_plist` exists) |
| rpaths / fixups / binds | `--macho --rpaths` · `--macho --chained-fixups` · `--macho --bind` / `--lazy-bind` / `--weak-bind` / `--rebase` |
| function starts | `llvm-objdump --macho --function-starts=names T` |
| fat slices | `llvm-objdump --macho --universal-headers T`; then `--arch=arm64` |
| disassembly | `llvm-objdump -d --no-show-raw-insn -C T > dis.txt`, then `--dis-symname=_main` |

Layout traps (each one cost a debug round while writing the parser above):
- Everything inside the superblob is **big-endian**, while the Mach-O header and load commands are little-endian.
- Slot offsets are relative to the **superblob start**, not the file.
- CodeDirectory header length depends on the version: 44 bytes below `0x20100`, 48 with `scatterOffset` (`>=0x20100`), 52 with `teamOffset` (`>=0x20200`). Fixed-offset reads return empty identifier/team.
- `identOffset`/`teamOffset` point from the CD start, past the header; the strings are NUL-terminated.
- `cdhash` is the first 20 bytes of the CD digest (`sha256` truncated, or a full `sha1`); flags `0x2` adhoc, `0x4` get-task-allow, `0x100` hard, `0x200` kill, `0x800` restrict, `0x10000` runtime, `0x20000` linker-signed.
- Slot 5 is the XML plist under an 8-byte `0xFADE7171` header. Slot 7 (`0xFADE7172`) is DER entitlements: dump that blob and `openssl asn1parse -inform DER -in slot7.bin`.
- Fat slices carry slice-relative offsets, so slice before parsing; never assume the thin header sits at file offset 0.
- A toolchain-built dylib is commonly **linker-signed** (`0x20000|0x2`) or fully unsigned — no slot 5 means "no entitlements blob", not "privileges absent".
