# ArchCracker

跨平台压缩包密码恢复工具：**Rust 内核 + 原生前端**，目标覆盖 Windows、Linux、macOS、Android、HarmonyOS。

> **状态：M0（仓库/工具链/内核骨架）**。Rust workspace 与最小 C ABI 已可构建；攻击流水线与三套前端将在 P1–P6 落地。
>
> **合法使用**：仅用于恢复你本人拥有或已获明确授权的归档密码。不得用于未授权访问、撞库或规避他人安全措施。

## 目标

- **格式**：7z（AES-256、可选头加密）、ZIP（ZipCrypto、WinZip AES-128/256；AES 支持待 P1 实测）、RAR4/RAR5（仅桌面，需用户自装 `unrar`；移动端首发不含 RAR），以及分卷、SFX。
- **攻击方式**：字典、掩码、暴力（数字/大小写字母/符号/自定义字符集 + 长度区间）、字典+掩码混合；规则引擎为 P2。
- **性能**：每 worker 复用归档会话、只测最小加密条目、首块快速判错、命中后官方引擎复核；多核/多进程并行、断点续跑。
- **形态**：同一 Rust 内核 + C ABI；桌面 Avalonia，Android Jetpack Compose，HarmonyOS ArkTS/ArkUI；CLI 可独立运行。
- **隐私**：默认零网络、无遥测、无强制更新。

## 架构

![ArchCracker 跨平台架构](docs/architecture.png)

```text
┌──────────────────────────────────────────────────────────────────┐
│ Frontends                                                        │
│  Avalonia 12 (Win/Linux/macOS) · Compose (Android) · ArkUI (OHOS)│
│  CLI (all desktop platforms)                                     │
└───────────────────────────────┬──────────────────────────────────┘
                                │ C ABI / JNI / NAPI
┌───────────────────────────────▼──────────────────────────────────┐
│ acx-core (Rust)                                                  │
│  jobs · planner · scheduler · resume · stats                     │
│  candidates: dictionary / mask / brute / rules / hybrid          │
│  engines: 7z · ZIP · RAR · volumes · SFX · fast probes           │
│  platform: file access / process / threads (no UI deps)          │
└───────────────────────────────┬──────────────────────────────────┘
                                │
        sevenz-rust2 · zip · unrar-rs(external) · rayon · aes/sha2
```

- **内核**：Rust workspace，纯逻辑、可交叉编译；不依赖任何 UI 框架。
- **前端**：只通过 C ABI（桌面 P/Invoke、Android JNI、HarmonyOS NAPI）调用内核；崩溃隔离可选用 sidecar 进程。
- **引擎边界**：7z/ZIP 使用宽松许可的 Rust 库；RAR 因 unRAR 许可与 GPL-3.0 存在冲突，默认走**外部 `unrar`/可选插件**，不静态链接进 GPL 内核（详见 `docs/licensing.md`）。

## 平台矩阵

| 平台 | 前端 | 内核交付 | 首发阶段 | 备注 |
|---|---|---|---|---|
| Windows 10/11 x64 | Avalonia 12（.NET 10） | `acx.dll` + CLI | P0 | 首要开发/验证平台 |
| Linux x64/arm64 | Avalonia 12 | `libacx.so` + CLI | P2 | AppImage/Flatpak |
| macOS 13+ arm64/x64 | Avalonia 12 | `libacx.dylib` + CLI | P2 | 公证、hardened runtime；不上 Mac App Store |
| Android 11+ | Kotlin + Compose | `libacx.so`（JNI） | P3 | SAF、前台服务、按 ABI 打包 |
| HarmonyOS 6+ | ArkTS/ArkUI | `libacx.so`（NAPI） | P4 | DevEco 签名、前台任务 |

> 版本号（.NET 10、Avalonia 12、HarmonyOS 6+）随调研时间点确定，落地时以实际 SDK 为准。

## 仓库结构

```text
.
├─ core/                 # Rust workspace（M0 起）
│  ├─ crates/acx-core/   # 领域、调度、候选、引擎、探针
│  ├─ crates/acx-cli/    # 跨平台 CLI
│  ├─ crates/acx-ffi/    # C ABI（cdylib/staticlib）+ acx.h
│  ├─ crates/acx-jni/    # Android JNI 薄层
│  └─ crates/acx-napi/   # HarmonyOS NAPI 薄层
├─ frontends/
│  ├─ desktop/           # Avalonia 12
│  ├─ android/           # Kotlin + Compose
│  └─ harmony/           # ArkTS/ArkUI
├─ docs/
│  ├─ architecture.md    # 跨平台总体架构
│  ├─ roadmap.md         # 分阶段开发计划
│  ├─ licensing.md       # GPL-3.0 与第三方许可
│  ├─ adr/               # 架构决策记录
│  ├─ agents/            # 子智能体角色与协作规范
│  └─ analysis/          # 旧工具分析与历史规划（内部研究）
├─ workflows/            # DSH workflow 编排脚本
├─ scripts/              # 环境/语料/构建脚本
├─ tests/                # 跨语言测试向量与语料索引
├─ AGENTS.md             # 所有 Agent 的入口指令
├─ LICENSE               # GPL-3.0
└─ README.md
```

## 快速开始（开发环境）

> 当前 Windows 开发机没有 C++/Rust/.NET SDK；`scripts/bootstrap-windows.ps1` 会以**用户级、免管理员**方式准备工具链。

```powershell
# 1) 检查环境（只读）
powershell -ExecutionPolicy Bypass -File .\scripts\check-env.ps1

# 2) 安装/修复用户级工具链（Rust GNU、MinGW、CMake、Ninja、.NET SDK、GitHub CLI）
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1

# 3) M0 之后：
cargo test --workspace
cargo run -p acx-cli -- --help
```

Android/HarmonyOS 工具链（Android SDK/NDK、DevEco Studio）在 P3/P4 前单独安装，脚本会给出检查项而不是强行下载数 GB 的 IDE。

## 文档

- [总体架构](docs/architecture.md)
- [跨平台开发策略](docs/cross-platform.md)
- [开发路线图](docs/roadmap.md)
- [许可与合规](docs/licensing.md)
- [架构决策记录](docs/adr/)
- [Agent 协作规范](docs/agents/README.md)
- [旧工具分析（内部研究）](docs/analysis/legacy-tools.md)

## 许可

本项目以 **GPL-3.0-only** 发布，见 [LICENSE](LICENSE)。

第三方组件与特殊说明见 [docs/licensing.md](docs/licensing.md)。其中 RAR 支持涉及 unRAR 许可，默认不静态链接进 GPL 内核；在法务结论明确前，发布物不得捆绑 `unrar` 代码或二进制。

## 参与

- 提交前阅读 [AGENTS.md](AGENTS.md) 与 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 任何改动走分支 + PR；核心/前端/测试由不同 Agent 角色分工，详见 `docs/agents/`。
- 禁止提交样本压缩包、破解工具二进制、口令字典或任何未脱敏的用户数据。
