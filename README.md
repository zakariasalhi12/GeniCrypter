# GeniCrypter

Two Rust tools for Windows x64 that package a payload into a single self-contained .exe and run it in memory. The payload never touches disk at runtime.

| Tool | Directory | What it does |
|---|---|---|
| **Evasion** | [`evasion/`](evasion/README.md) | Encrypts a PE executable into a self-contained stub and runs it in memory. |
| **Polymorph** | [`polymorph/`](polymorph/README.md) | Embeds raw x64 shellcode, executes it through indirect syscalls, and mutates its own file signature. |
| **obfuscate_pe.ps1** | [`scripts/`](scripts/obfuscate_pe.ps1) | Post-build helper that strips the Rich header, randomizes the PE timestamp, clears the debug/PDB directory, and fixes the checksum. |

## Repository Layout

```text
GeniCrypter/
├── README.md                 # this overview
├── evasion/
│   ├── README.md             # full Evasion documentation
│   ├── crypter/              # build-machine CLI
│   └── stub/                 # template compiled for each target
├── polymorph/
│   ├── README.md             # full Polymorph documentation
│   ├── engine/               # build-machine CLI
│   └── stub/                 # template compiled for each payload
├── scripts/
│   └── obfuscate_pe.ps1      # post-build PE metadata cleanup
└── resources/                # screenshots used by the docs
```

## Evasion — PE Crypter

**Evasion** takes a Windows x64 executable and produces a new executable that carries the original target encrypted and compressed inside itself. At runtime, the stub decrypts the payload and maps it directly into its own process with `maple-rs`.

Key points:

- AES-256-GCM encryption with an HKDF-SHA256-derived key.
- zstd compression before embedding.
- Payload embedded at compile time via `include_bytes!`.
- In-memory execution — no payload written to disk at runtime.
- Optional execution delay using real CPU/memory work.
- Optional debugger, VM, and sandbox checks.
- Optional user-level persistence — self-copy to `%APPDATA%\Microsoft\Windows\Local Permission Handler.exe`, hidden + system attributes, and restart-on-shutdown via `RegisterApplicationRestart` (`phantom_persist_rs`).

Build and run:

```powershell
cd GeniCrypter\evasion\crypter
cargo build --release

.\target\release\evasion.exe `
  --target-binary C:\lab\hello.exe `
  --output C:\lab\obfuscated_hello.exe `
  --persistence `
  --delay 5 `
  --anti-analysis
```

Requirements: Windows x64, Rust stable with the MSVC toolchain, and Visual Studio Build Tools. The crypter also needs a `.env` file containing `ENCRYPTION_KEY` plus the optional `MAX_*` limits.

See [`evasion/README.md`](evasion/README.md) for the full pipeline, configuration, generated files, and limitations.

## Polymorph — Polymorphic Shellcode Loader

**Polymorph** takes a raw x64 shellcode file and produces a self-contained executable that runs it in memory. On every run, the stub rewrites its own `.counter` section with random bytes, so the file hash changes between executions.

Key points:

- Shellcode embedded at compile time via `include_bytes!`.
- Self-mutating `.counter` section with `self-replace`.
- ETW patching — overwrites `EtwEventWrite` in `ntdll.dll` with `RET` to silence user-mode ETW providers.
- Indirect NT syscalls via `dinvoke_rs`.
- RW → RX allocation instead of an RWX page.
- Native thread creation at the shellcode address.
- Waits for the shellcode thread to exit.

Build and run:

```powershell
cd GeniCrypter\polymorph
cargo build --release

.\engine\target\release\engine.exe `
  --payload C:\lab\calc_shellcode.bin `
  --output C:\lab\polymorphic.exe
```

The payload must be **raw x64 shellcode**, not a PE, and approximately **1 MB or smaller**. Use a benign test payload in the lab.

See [`polymorph/README.md`](polymorph/README.md) for the full engine/stub flow, payload details, and limitations.

## obfuscate_pe.ps1 — PE Metadata Cleanup

[`scripts/obfuscate_pe.ps1`](scripts/obfuscate_pe.ps1) is a small PowerShell post-build helper for Windows executables. Run it on the final `.exe` produced by Evasion or Polymorph (or any PE) to reduce obvious build fingerprints. It performs four cleanup passes:

- **Strips the Rich header** — the undocumented block that `link.exe` writes between the DOS stub and the PE header, which leaks toolchain/compiler details. It locates the encrypted `DanS` marker and zeroes the block up to `Rich`, including the key. Skipped cleanly when no Rich header exists (e.g. GNU toolchain or already stripped).
- **Randomizes `TimeDateStamp`** — instead of the real build time, it writes a random date between **2022-01-01** and **now − 1 day** (clamped so the binary never looks future-dated; there is a safety fallback for machines with clocks set before 2022). A different value is picked on every run.
- **Clears the Debug Directory entry** — zeroes data-directory index 6, which removes the pointer to the CodeView record and therefore the embedded **PDB path/name**. Handles both PE32+ (x64/ARM64) and PE32 (x86) optional headers.
- **Recomputes the PE checksum** — recalculates the standard 16-bit ones-complement checksum after the edits, so `dumpbin /headers` and AV heuristics don't flag a stale or missing checksum as tampering.

It modifies the file **in place**, so copy the binary first if you want to keep the original. The file must be a valid MZ/PE image with a known optional-header magic, otherwise the script exits with an error.

Usage (PowerShell):

```powershell
# Run on a built executable (modifies it in place)
.\GeniCrypter\scripts\obfuscate_pe.ps1 -Path C:\lab\hello.exe
```

Example output:

```text
[OK] Rich header stripped (0x80..0x108)
[OK] TimeDateStamp randomized to 0x63A1F2B4 = 2023-06-28 14:33:24 UTC
[OK] Debug Directory entry cleared (removes PDB path)
[OK] PE checksum recomputed: 0x0003A7C1
[OK] PE obfuscation complete: C:\lab\hello.exe
```

Each step prints a `[--]` notice instead when it doesn't apply (no Rich header, no debug directory). Because the timestamp is random and the checksum follows it, re-running the script on the same file produces a **new hash every time**.

If PowerShell blocks local scripts, run it in a session with `Set-ExecutionPolicy -Scope Process Bypass`, or invoke it as `powershell -ExecutionPolicy Bypass -File .\scripts\obfuscate_pe.ps1 -Path <file>`.

## Requirements

Both tools target **Windows 10/11 x64** and require:

- Rust stable with the MSVC toolchain (`x86_64-pc-windows-msvc`)
- Visual Studio Build Tools with the “Desktop development with C++” workload

## Disclaimer

This project is provided for educational and authorized security research only. The author is not responsible for misuse or damage caused by this software.
