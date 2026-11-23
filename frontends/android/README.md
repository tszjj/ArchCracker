# Android frontend (Kotlin + Jetpack Compose)

Planned for P5.

## Scope

- Pick archive via SAF (`ACTION_OPEN_DOCUMENT`, persistable permission).
- Pass a `ParcelFileDescriptor` to native via `dup`; never copy the whole archive.
- Choose dictionary/mask/brute; thread count; progress/ETA; pause/stop.
- Foreground service + wake lock; default "foreground + resumable" (Android 15 dataSync quota).
- Auto-extract to a user-selected SAF directory (`CREATE_DOCUMENT`).
- RAR not bundled; optionally hand off to an installed RAR app.

## Integration

- `libacx.so` per ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`) via `acx-jni`.
- JNI thin layer only: handle lifetime, callbacks, error mapping.
- No telemetry, no online lookup.

## Status

Not scaffolded yet. SDK/NDK installation is P3.
