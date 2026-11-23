# frontends

三套前端共享同一个 Rust 内核（`core/crates/acx-ffi`），只通过 C ABI / JNI / NAPI 调用。

| 目录 | 技术 | 平台 | 阶段 |
|---|---|---|---|
| `desktop/` | Avalonia 12 + .NET 10 | Windows / Linux / macOS | P3–P4 |
| `android/` | Kotlin + Jetpack Compose | Android 11+ | P5 |
| `harmony/` | ArkTS / ArkUI | HarmonyOS 6+ | P6 |
| `shared/` | 契约、错误码、测试向量、设计 token、i18n | 全部 | P0 起 |

## 共享原则

- 不复制核心算法/错误码；`acx.h` 是唯一契约。
- 进度回调限流 ~10 Hz；UI 线程不做解密。
- 文件访问走平台原生（Windows 路径 / macOS 书签 / Android SAF / HarmonyOS Picker）。
- 三端对同一归档 + 字典 + 参数必须得到一致结果（共享测试向量）。
- 不加入遥测/在线查询；暂不上 Mac App Store（审核/签名成本）。

## 构建顺序

1. 先 Windows 桌面（Avalonia）跑通 C ABI；
2. 再 Linux/macOS（同代码）；
3. Android、HarmonyOS 各自薄胶水。
