# ArchCracker

跨平台压缩包密码恢复工具：**Rust 内核 + 原生前端**，目标覆盖 Windows、Linux、macOS、Android、HarmonyOS。

> **状态：W1 已签核（2026-11-26），W2 启动**。ZIP/7z/RAR4/RAR5、分卷/SFX、字典、流式、暂停/停止/`--resume`、RAR5 check 快筛均已交付；W1 1M×1GB 基准、ZIP 10M 负例、1GB 暂停/停止矩阵完成。W2 按 [docs/W2-PLAN.md](docs/W2-PLAN.md) 从 mask/brute 开始；**W2-001 GPU/hashcat 已 Deferred，不在 W2 启动**。Windows 只做**单一 Full 版本**：W4 随包未修改的 `UnRAR.exe` 与 hashcat 二进制；hashcat 仅外部进程，不作为 Rust 依赖；无 hashcat/GPU 时 CPU 多线程路径完整可用。Linux/macOS/Android/HarmonyOS 接口保留但**后续排期**。项目结构与文档地图见 [docs/PROJECT-GUIDE.md](docs/PROJECT-GUIDE.md)。
>
> **合法使用**：仅用于恢复你本人拥有或已获明确授权的归档密码。不得用于未授权访问、撞库或规避他人安全措施。

## 目标

- **格式**：7z（AES-256、可选头加密；7-Zip 26.04 差分）、ZIP（ZipCrypto、WinZip AES-128/192/256；7-Zip 差分待补）、RAR4/RAR5（Full 版随包未修改的 `UnRAR.exe`，仅进程调用；解压 RAR 本身符合 unRAR 许可，许可边界见 `docs/licensing.md`），以及分卷、SFX。
- **攻击方式**：字典、掩码、暴力（数字/大小写字母/符号/自定义字符集 + 长度区间）、字典+掩码混合；规则引擎为 P2；字典批量可选 hashcat GPU 后端。
- **性能**：每 worker 复用归档会话、只测最小加密条目、首块快速判错、命中后内置引擎/外部 UnRAR 完整解压复核；CPU 多线程为基线，hashcat/GPU 为可选加速，缺失时自动回落。
- **形态**：同一 Rust 内核 + C ABI；Windows 用 Avalonia 12；CLI 可独立运行。Android/HarmonyOS 前端后续再做。
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
│  engines: 7z · ZIP · RAR · hashcat(GPU) · volumes · SFX · probes   │
│  platform: file access / process / threads (no UI deps)          │
└───────────────────────────────┬──────────────────────────────────┘
                                │
        sevenz-rust2 · zip · 外部 UnRAR（Full 版随包，仅进程） · 外部 hashcat（可选 GPU） · aes/sha2
```

- **内核**：Rust workspace，纯逻辑、可交叉编译；不依赖任何 UI 框架，也不依赖 hashcat/CUDA/HIP/OpenCL 绑定。
- **前端**：Windows 用 Avalonia 12，通过 P/Invoke 调 C ABI；崩溃隔离可选用 sidecar 进程。Android JNI / HarmonyOS NAPI 的接口保留，后续实现。
- **引擎边界**：7z/ZIP 使用宽松许可的 Rust 库；RAR 使用 Full 版随包的未修改 `UnRAR.exe`（仅进程）；hashcat 同样只走外部进程。内核不链接 unRAR/7-Zip RAR 代码，不把 hashcat 作为 Cargo 依赖；无 hashcat/GPU 时 CPU 路径照常工作（详见 `docs/adr/0004-bundled-engines.md`）。

## 当前优先级：Windows 全栈

本迭代按“能装、能用、能卸载”的 Windows 产品推进：

1. Rust 内核 + CLI：ZIP/7z/RAR（外部）+ 字典 + 多线程 + 运行控制/断点 + 基准。
2. W1 已签核：W1-001…W1-010 完成，PR #10–#15 已合并；W2 从 CPU mask/brute 开始（GPU Deferred）。
3. Avalonia 12 桌面：拖放、模式、进度、暂停/停止、结果、自动解压。
4. Windows 交付：单一 Full 安装包、随包 UnRAR/hashcat、代码签名、崩溃转储、zh/en。
5. 测试/基准：1M 字典、1GB 归档、缺卷/损坏/未加密分类、CPU/GPU 对照（GPU 仅 W2 退出后重新评估）。

Linux/macOS/Android/HarmonyOS 的架构与契约在此阶段保留，但**不排期、不引入 SDK**；Windows 发布后再逐平台移植。

## 平台矩阵

| 平台 | 前端 | 内核交付 | 阶段 | 备注 |
|---|---|---|---|---|
| **Windows 10/11 x64** | Avalonia 12（.NET 10） | `acx.dll` + CLI | **当前（W1–W5）** | 唯一排期平台；全栈交付 |
| Linux x64/arm64 | Avalonia 12 | `libacx.so` + CLI | 后续 | Windows 发布后 |
| macOS 13+ arm64/x64 | Avalonia 12 | `libacx.dylib` + CLI | 后续 | 公证；不上 Mac App Store |
| Android 11+ | Kotlin + Compose | `libacx.so`（JNI） | 后续 | SAF、前台服务 |
| HarmonyOS 6+ | ArkTS/ArkUI | `libacx.so`（NAPI） | 后续 | DevEco 签名 |

> 版本号（.NET 10、Avalonia 12）以实际 SDK 为准。Windows Full 版随包 UnRAR/hashcat；GPU 驱动/CUDA/HIP 仍由系统提供。其他平台后续同样走外部引擎，移动端暂不排期。

## 仓库结构

```text
.
├─ core/                 # Rust workspace（M0 起）
│  ├─ crates/acx-core/   # 领域、调度、候选、引擎、探针
│  ├─ crates/acx-cli/    # 跨平台 CLI
│  ├─ crates/acx-ffi/    # C ABI（cdylib/staticlib）+ acx.h
│  ├─ crates/acx-jni/    # [计划] Android JNI 薄层
│  └─ crates/acx-napi/   # [计划] HarmonyOS NAPI 薄层
├─ frontends/            # 目前只有 README 占位
│  ├─ desktop/           # [计划] Avalonia 12
│  ├─ android/           # [计划] Kotlin + Compose
│  └─ harmony/           # [计划] ArkTS/ArkUI
├─ docs/
│  ├─ PROJECT-GUIDE.md   # 项目结构、文档地图、开发进度（先读）
│  ├─ architecture.md    # 跨平台总体架构
│  ├─ roadmap.md         # 分阶段开发计划
│  ├─ windows-plan.md    # Windows 全栈任务/验收
│  ├─ cross-platform.md  # 五平台差异（其他平台 Deferred）
│  ├─ licensing.md       # Apache-2.0 与第三方许可
│  ├─ adr/               # 架构决策记录
│  ├─ tasks/             # 切片任务与验证证据
│  ├─ benchmarks/        # 非正式性能基线
│  ├─ agents/            # 子智能体角色与协作规范
│  └─ analysis/          # 旧工具分析与历史规划（内部研究）
├─ workflows/            # DSH workflow 编排脚本
├─ scripts/              # 环境/构建脚本（语料生成脚本待补）
├─ tests/                # 目前仅 README；语料/向量/差分为 P1 计划
├─ AGENTS.md             # 所有 Agent 的入口指令
├─ LICENSE               # Apache-2.0
└─ README.md
```

## 快速开始（开发环境）

> Windows 工具链由 `scripts/bootstrap-windows.ps1` 以**用户级、免管理员**方式准备；新机器先运行 `check-env.ps1` 检查，缺什么再 bootstrap。

```powershell
# 1) 检查环境（只读）
powershell -ExecutionPolicy Bypass -File .\scripts\check-env.ps1

# 2) 安装/修复用户级工具链（Rust GNU、MinGW、CMake、Ninja、.NET SDK、GitHub CLI）
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1

# 3) 构建与测试（当前可直接运行）：
cd core
cargo test --workspace
cargo run -p acx-cli -- --help

# 4) 可恢复的字典攻击（Ctrl+C 或 TTY 输入 s 停止并写检查点）
cargo run -p acx-cli -- -f <archive> -d <dictionary> -t 8 --checkpoint .\run.acx-checkpoint
cargo run -p acx-cli -- -f <archive> -d <dictionary> -t 8 --checkpoint .\run.acx-checkpoint --resume
```

字典默认按行流式读取，不把大文件整体载入内存；候选水位使用每候选 1 bit 的位图（14.3M 约 1.8MB）。流式路径不做全局去重，重复行可能重复测试。单行上限 1 MiB，批次候选字节上限 8 MiB。

Android/HarmonyOS 工具链（Android SDK/NDK、DevEco Studio）在后续平台启动前单独安装；当前 Windows 阶段不下载数 GB 的 IDE，脚本只给出检查项。

## 文档

- [项目全景与开发指引](docs/PROJECT-GUIDE.md)（结构、文档地图、进度）
- [Windows 全栈开发计划](docs/windows-plan.md)
- [总体架构](docs/architecture.md)
- [跨平台开发策略](docs/cross-platform.md)
- [开发路线图](docs/roadmap.md)
- [许可与合规](docs/licensing.md)
- [架构决策记录](docs/adr/)
- [Agent 协作规范](docs/agents/README.md)
- [旧工具分析（内部研究）](docs/analysis/legacy-tools.md)

## 许可

本项目以 **Apache-2.0** 发布，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

第三方组件与特殊说明见 [docs/licensing.md](docs/licensing.md)。Windows Full 版按 [ADR-0004](docs/adr/0004-bundled-engines.md) 随包**未修改的 `UnRAR.exe`**（附 UnRAR license）与 **hashcat**（MIT/第三方声明）；不随包 WinRAR、CUDA/HIP/GPU 驱动；内核不链接 unRAR，hashcat 不是 Cargo 依赖。

## 参与

- 提交前阅读 [AGENTS.md](AGENTS.md) 与 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 任何改动走分支 + PR；核心/前端/测试由不同 Agent 角色分工，详见 `docs/agents/`。
- 禁止提交样本压缩包、破解工具二进制、口令字典或任何未脱敏的用户数据。
