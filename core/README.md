# core

Rust workspace for ArchCracker. The M0 skeleton exposes:

- `acx-core`: version marker and (soon) domain/candidates/scheduler/engines.
- `acx-cli`: `acx` binary.
- `acx-ffi`: C ABI (`acx.dll` / `libacx.so` / `libacx.dylib`).

## Build

```powershell
. ..\scripts\env.ps1
cargo build --workspace
cargo test --workspace
cargo run -p acx-cli -- --version
```

Windows uses the GNU toolchain (`x86_64-pc-windows-gnu`) with MinGW-w64 from
`scripts/bootstrap-windows.ps1`. Linux/macOS use their native target.

## License

Apache-2.0. New files need the SPDX header.
