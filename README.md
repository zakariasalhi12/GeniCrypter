# GeniCrypter

Two Rust tools for Windows x64 that package a payload into a single self-contained .exe and run it in memory. The payload never touches disk at runtime.

| Tool | Directory | What it does |
|---|---|---|
| **Evasion** | [`evasion/`](evasion/README.md) | Encrypts a PE executable into a self-contained stub and runs it in memory. |
| **Polymorph** | [`polymorph/`](polymorph/README.md) | Embeds raw x64 shellcode, executes it through indirect syscalls, and mutates its own file signature. |


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
- User-level persistence — self-copy to `%APPDATA%\Microsoft\Windows\Local Permission Handler.exe`, hidden + system attributes, and restart-on-shutdown via `RegisterApplicationRestart` (`phantom_persist_rs`).

Build and run:

```powershell
cd GeniCrypter\evasion\crypter
cargo build --release

.\target\release\evasion.exe `
  --target-binary C:\lab\hello.exe `
  --output C:\lab\obfuscated_hello.exe `
  --persistence`
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

## Requirements

Both tools target **Windows 10/11 x64** and require:

- Rust stable with the MSVC toolchain (`x86_64-pc-windows-msvc`)
- Visual Studio Build Tools with the “Desktop development with C++” workload

## Disclaimer

This project is provided for educational and authorized security research only. The author is not responsible for misuse or damage caused by this software. Running these tools may trigger antivirus or EDR alerts — this is expected behavior, not a bug.
