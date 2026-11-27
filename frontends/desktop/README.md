# Desktop frontend (Avalonia 12 / .NET 10)

Planned for P3. Windows first, then Linux/macOS with the same codebase.

## Scope

- Drag/drop or pick archive; show format/encryption/volume info.
- Tabs: dictionary / mask / brute / rules.
- Thread count, fast/strict mode, auto-extract.
- Progress, rate, ETA, pause/resume/stop.
- Result: password, copy, report, auto-extract.
- Error classification: unencrypted/empty/corrupt/missing volume/unsupported/header-encrypted.

## Integration

- P/Invoke `acx.dll`/`libacx.so`/`libacx.dylib` via `[LibraryImport]`.
- Callbacks: progress/hit/log; keep delegates alive; no UI work on native threads.
- Keep a sidecar mode switch for crash isolation (P3).
- Long operations never on the UI thread.

## Packaging

- Windows: MSIX or Inno Setup; EV/OV signing; Defender false-positive check.
- macOS: universal binary, hardened runtime, notarization, DMG; not Mac App Store.
- Linux: AppImage + Flatpak.

## Status

Not scaffolded yet. W3 Windows GUI work is isolated on the local branch `windows-gui`; see `docs/tasks/W3-windows-gui-outline.md` for architecture, modules, interaction rules, and priorities. M0 defines only the minimal C ABI; W3 must freeze C ABI v1 before GUI implementation.
