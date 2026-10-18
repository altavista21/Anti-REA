# AegisForge

A Rust CLI prototype for protecting files with authenticated encryption.

## Status

This repository currently provides a file-encryption prototype using AES-256-GCM. The target and protection-level options are accepted as CLI metadata; they do not yet transform Windows, Web, Android, or iOS binaries. It does not implement anti-debugging, runtime payload loaders, or platform-specific obfuscation.

## Requirements

- Rust stable toolchain

## Build

```sh
cargo build --release
```

## Usage

Set a 32-byte key as 64 hexadecimal characters in `AEGISFORGE_KEY_HEX`, then run:

```sh
cargo run --release -- -i input.bin -o output.afg -t win -l standard
```

Targets: `win`, `web`, `android`, `ios`. Levels: `standard`, `paranoid`.

**Important:** This is a prototype, not a production-grade binary protection suite. Hardware identifiers are not secret key material. Keep encryption keys out of source control and use an appropriate secret store for real deployments.
