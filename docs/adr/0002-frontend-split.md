# ADR-0002：前端拆分——Avalonia + Compose + ArkUI

- 状态：Accepted
- 日期：2026-11-24
- 相关：`docs/architecture.md`、`docs/roadmap.md`

## 背景

同一 Rust 内核需要五个系统的 UI：Windows、Linux、macOS、Android、HarmonyOS。要求界面简洁（拖放/模式/线程/进度/结果），Windows 首发。

候选：

1. Avalonia（桌面三平台）+ Android Compose + HarmonyOS ArkUI
2. Flutter（桌面/Android + OpenHarmony 社区分叉）
3. Tauri 2（桌面/Android + 鸿蒙实验分支）
4. Qt 6.12（桌面/Android + 鸿蒙技术预览）
5. Compose Multiplatform（桌面/Android + 鸿蒙首版）
6. 全原生五套

## 决策

采用 **方案 1**：

- **桌面**：Avalonia 12（.NET 10）一套代码，Windows/Linux/macOS。
- **Android**：Kotlin + Jetpack Compose + JNI。
- **HarmonyOS**：ArkTS/ArkUI + NAPI。
- **共享**：C ABI 头、攻击模式 schema、错误码、测试向量、设计 token、i18n 词条。

## 理由

- **鸿蒙是分水岭**：Avalonia 官方无鸿蒙；Flutter 靠社区分叉；Tauri 鸿蒙仅实验；Qt 6.12 鸿蒙为技术预览；CMP 鸿蒙 2026-09 才首版。把长期维护押在分叉/预览上，风险高于多写一套简单 UI。
- **桌面效率**：Avalonia XAML + MVVM 对 C#/AI Agent 最友好，P/Invoke 调 C ABI 直接；Windows 11 24H2 为 Tier 1。
- **移动原生体验**：Compose 在 Android 是官方一等；ArkUI 是鸿蒙唯一稳定选择；文件选择/前台服务/权限都需原生胶水。
- **成本可控**：三套 UI 各 3–5 屏，90% 复杂度在核心；共享契约与测试向量避免三份逻辑。
- **许可**：Avalonia MIT、Compose Apache-2.0、ArkUI 随 HarmonyOS SDK；与 Apache-2.0 兼容。

## 备选与不选原因

| 方案 | 不选原因 |
|---|---|
| Flutter 全平台 | 鸿蒙依赖 OpenHarmony SIG 分叉，版本落后、插件缺 ohos 实现；长期维护风险 |
| Tauri 2 | 鸿蒙实验分支仅模拟器验证、产物未签名；不可生产 |
| Qt 6.12 单栈 | 鸿蒙技术预览、包体大、移动端原生感弱；QML 曲线 |
| CMP 单栈 | 鸿蒙首版生态薄；桌面 JVM 打包重 |
| 全原生五套 | 体验最好但五套成本过高；本项目 UI 简单，不划算 |

## 后果

**正面**

- 桌面一套代码覆盖三系统；Windows 首发快。
- Android/HarmonyOS 原生文件/后台能力可用。
- C ABI 稳定后，前端可独立迭代/替换。

**负面**

- 三套 UI 需维护；共享设计 token/测试向量来降低漂移。
- .NET 10/Avalonia 12 较新，需锁定版本并验证。
- macOS 当前走官网 + 公证；App Store 后续再评估（审核/签名成本）。
- 鸿蒙 NAPI/打包需真机验证，CI 难自动化。

## 验证方式

- Windows：Avalonia 壳调 C ABI，完成 ZIP/7z 一次恢复（M3）。
- Linux/macOS：同代码构建 + 冒烟（M4）。
- Android：SAF + JNI 真机（M5）。
- HarmonyOS：NAPI + HAP 真机（M6）。
- 共享测试向量：三端对同一归档/字典结果一致。

## 参考

- Avalonia platforms: https://docs.avaloniaui.net/docs/supported-platforms
- Avalonia 12: https://v11.docs.avaloniaui.net/docs/avalonia12-breaking-changes/
- Qt HarmonyOS: https://doc.qt.io/qt-6/harmonyos.html
- OpenHarmony Flutter: https://atomgit.com/oh-flutter/flutter_flutter
- Tauri 2: https://v2.tauri.app/blog/tauri-20/
- Compose Multiplatform: https://kotlinlang.org/docs/multiplatform/compose-multiplatform-and-jetpack-compose.html
