# 跨平台开发策略（五系统）

> **2026-11-24 修订**：当前只排期 **Windows 全栈（W0–W5）**。本文的 Linux/macOS/Android/HarmonyOS 内容是后续参考，**D1–D3 Deferred**；不引入移动 SDK。

> 目标：同一 Rust 内核覆盖 Windows、Linux、macOS、Android、HarmonyOS；不是五套产品，而是**一套内核 + 三套前端 + 五个打包通道**。

## 1. 需求拆解

| 层 | 需要跨平台的部分 | 允许平台特有的部分 |
|---|---|---|
| 核心 | 格式/加密、候选、调度、断点、错误分类 | 无（`cfg` 小模块除外） |
| 契约 | `acx.h`、错误码、攻击参数、测试向量 | 无 |
| 前端 | 交互流程、设计 token、i18n | UI 框架、文件选择、权限、通知、后台 |
| 打包 | 版本/许可/源码 | 签名、安装器、商店 |
| RAR | Windows Full 随包 `UnRAR.exe` | 其他平台 deferred / 后续 add-on |

**结论**：跨平台成本应集中在“三套 UI + 平台胶水”，而不是复制算法。

## 2. 平台差异矩阵

| 维度 | Windows | Linux | macOS | Android | HarmonyOS |
|---|---|---|---|---|---|
| 文件选择 | 原生对话框/拖放 | 对话框/拖放 | 沙盒书签/拖放 | SAF URI | Picker（授权随进程） |
| 大文件访问 | 路径 | 路径 | 安全书签 | `ParcelFileDescriptor`/`dup` | fd/URI，需即时使用 |
| 后台长任务 | 无限制 | 无限制 | App Nap/省电 | 前台服务；Android 15 dataSync 6h/24h | 长时任务需资质；通用算力易挂起 |
| 线程亲和 | 支持 | 支持 | 基本不支持 | 大小核 | 大小核 |
| 外部进程 | 支持 | 支持 | 支持（沙盒限制） | 基本不可用 | 基本不可用 |
| 签名 | Authenticode/EV | 无/包签名 | Developer ID + 公证 | keystore | DevEco 证书 |
| 商店 | Microsoft Store/官网 | 官网/Flatpak | 官网 DMG（不上 App Store） | Play/侧载 | AppGallery/侧载 |
| RAR | Full 随包 `UnRAR.exe` | 外部 unrar | 外部 unrar | 首发无 | 首发无 |
| GPU 字典 | Full 随包 hashcat | 后续 | 后续 | 暂不 | 暂不 |

## 3. 开发顺序（为什么）

1. **Windows CLI**：工具链最成熟、调试最快、WinRAR 可用于生成 RAR 语料；先把“会话复用 + 快筛 + 断点”打通。
2. **Windows GUI**：验证 C ABI 与交互；桌面 UI 的复杂度主要在这里。
3. **Linux/macOS**：同一 Avalonia 代码；处理路径/权限/公证/包格式。
4. **Android**：SAF/fd、前台服务、JNI；移动端限制最多，放在 C ABI 稳定之后。
5. **HarmonyOS**：NAPI/ArkUI/HAP；Rust OHOS target 为 Tier 2，需真机验证。

**不要**先做五套 UI 再补内核；也不要为每个平台复制一份引擎。

## 4. 技术策略

### 4.1 核心

- Rust workspace，`acx-core` 无 UI/平台 GUI 依赖。
- 平台差异用 `#[cfg(target_os)]` 小模块封装：路径、线程数、进程、locale。
- 文件访问抽象为“可 seek 的只读流 + 长度”；移动端 fd/URI 由前端转成路径或 fd 句柄。
- 外部 `unrar`/`hashcat` 只在 `engines::external`；Windows Full 随包，其他平台 Deferred/后续 add-on；移动端 feature 关闭。

### 4.2 C ABI

- 先冻结 v0（M0），P3 冻结 v1。
- 句柄/回调/错误码稳定；新增字段用 `struct_size`/`version` 向后兼容。
- 前端不复制枚举；头文件是唯一契约。
- 进度回调限流；UI 不阻塞。

### 4.3 前端

- 桌面一套 Avalonia；Android 一套 Compose；HarmonyOS 一套 ArkUI。
- 共享：设计 token、i18n 词条、错误码、测试向量；不共享 UI 代码。
- 移动端默认“前台运行 + 断点续算”，不承诺后台跑完。

### 4.4 功能开关

| Feature | Windows | Linux | macOS | Android | HarmonyOS |
|---|---|---|---|---|---|
| 7z / ZIP | ✅ | ✅ | ✅ | ✅ | ✅ |
| RAR | Full 随包外部引擎 | 外部引擎 | 外部引擎 | ❌ | ❌ |
| GPU 字典 | Full 随包 hashcat | 后续 | 后续 | ❌ | ❌ |
| SFX | ✅ | ✅ | ✅ | 视文件选择 | 视文件选择 |
| 报告导出 | 本地文件 | 本地文件 | 本地文件 | SAF 目录 | Picker 目录 |
| 自动解压 | ✗ | ✗ | ✗ | ✗ | ✗ |
| 规则引擎 | P2 | P2 | P2 | P2 | P2 |

## 5. 构建与测试

### 5.1 本地

- Windows：`scripts/bootstrap-windows.ps1` + `cargo` + .NET 10。
- Linux/macOS：Rust stable + 平台工具链；Avalonia 用 `dotnet publish`。
- Android：Android SDK/NDK + `cargo ndk` + Gradle。
- HarmonyOS：DevEco Studio + OHOS NDK + `cargo` OHOS target + NAPI。

### 5.2 CI

| Job | Runner | 触发 |
|---|---|---|
| core 三平台 | GitHub hosted | 每次 PR |
| desktop 构建 | GitHub hosted | P3 起 |
| Android | ubuntu + NDK | P5，手动/标签 |
| HarmonyOS | 自托管（需 DevEco） | P6，手动 |

移动端 CI 没有官方模拟器/签名环境时，**真机门禁**替代：每次发布前在至少一台 arm64 真机跑通。

### 5.3 测试向量

同一组 `archive + dictionary + options` 在三端必须得到一致结果。测试向量放 `frontends/shared/`，由核心生成/校验。

## 6. 逐步交付（与 roadmap 对应）

| 阶段 | 平台 | 关键验证 |
|---|---|---|
| P1 | Windows CLI | ZIP/7z 字典；1M 字典基准；断点 |
| P2 | Windows CLI | RAR 外部；分卷/SFX；快筛；爆破 |
| P3 | Windows GUI | C ABI v1；拖放/进度/取消；MSIX |
| P4 | +Linux/macOS | 同代码构建；公证；AppImage |
| P5 | +Android | SAF/fd；前台服务；真机 |
| P6 | +HarmonyOS | NAPI；HAP；真机 |

## 7. 风险与降级

| 风险 | 降级方案 |
|---|---|
| HarmonyOS Rust 工具链不稳 | 先做最小 C ABI + NAPI spike；必要时 ArkTS 侧只做 UI，核心用 C++/C ABI 重编 |
| 移动端后台被杀 | 前台服务/常亮/断点；UI 明确“锁屏可能暂停” |
| 商店拒审 | 官网侧载；不内置字典；明确授权使用 |
| RAR 许可/分发 | Windows Full 随包 UnRAR.exe + license；移动首发无 RAR；WinRAR 不随包 |
| GPU/驱动 | hashcat 随包但驱动由系统提供；无 GPU 回落 CPU |
| 多前端漂移 | 共享契约/测试向量；每端 3–5 屏，不做平台特有功能 |
| 性能不达 | M1 基准；按 ROI 优化；不承诺未测数字 |

## 8. Agent 分工

- 平台相关工作按“核心/桌面/Android/HarmonyOS/QA”分派；每个平台一个 owner。
- 跨平台改动必须列出：已验证平台、未验证平台、差异点。
- 平台 SDK 安装/签名由 release-engineer 负责，不让 core-engineer 陷入 IDE 配置。
