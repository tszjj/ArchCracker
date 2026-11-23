# HarmonyOS frontend (ArkTS / ArkUI)

Planned for P6.

## Scope

- File Picker (permission is process-scoped; use immediately).
- Archive info, attack mode, thread count, progress/ETA, pause/stop.
- Foreground task + resumable checkpoint (generic compute may be suspended in background).
- `libacx.so` (arm64-v8a) loaded via NAPI (`acx-napi`).
- RAR not bundled in the first release (licensing); UI must say so clearly.

## Integration

- `libacx.so` + `libacx_napi.so` under `entry/libs/arm64-v8a/`.
- NAPI exports: create/start/pause/resume/stop/status; callbacks to ArkTS.
- DevEco Studio signing for HAP.

## Status

Not scaffolded yet. DevEco/SDK installation is P4.
