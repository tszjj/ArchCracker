# shared frontend contracts

Everything that must stay identical across desktop/Android/HarmonyOS:

- `acx.h` copy from `core/crates/acx-ffi/include/acx.h` (single source: core).
- Error codes and user-facing messages (zh/en).
- Attack spec schema (mode, charset, min/max, mask, threads, fast/strict).
- Test vectors: same archive + dictionary + options → same result.
- Design tokens: spacing, colors, typography, progress bar.
- i18n keys.

## Rule

Core is the source of truth. Frontends must not redefine enums/structs; generate or copy from `acx.h` in a documented step.

## Status

M0: empty placeholder. P3 will add `error-codes.md`, `attack-spec.schema.json`, `i18n/`.
