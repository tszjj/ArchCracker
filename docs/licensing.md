# 许可与合规

> 本文是工程记录，不是法律意见。发布前需维护者/法务复核。
> 项目许可证：**GPL-3.0-only**（见根目录 `LICENSE`）。

## 1. 项目自身

- 代码：GPL-3.0-only。
- 文档：除特别注明外，与代码同许可（CC BY-SA 4.0 也可，但为简化统一 GPL-3.0-only）。
- 新增源文件建议加 SPDX 头：

```rust
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 ArchCracker contributors
```

- 分发二进制时必须提供对应源码（或书面 offer），并保留版权/许可声明。
- 不得附加 GPL-3.0 之外的额外限制。

## 2. 第三方组件登记

| 组件 | 用途 | 许可 | 与 GPL-3.0 兼容 | 分发方式 | 备注 |
|---|---|---|---|---|---|
| `sevenz-rust2` | 7z 读写 | Apache-2.0 | 是 | 源码依赖 | 支持 AES-256、头加密、PPMd 等；优先引擎 |
| `zip` | ZIP 读写 | MIT | 是 | 源码依赖 | 基础 ZIP；WinZip AES 支持需 P1 实测确认；不支持 multi-disk，由自建容器层补 |
| `rayon` | 并行 | MIT/Apache-2.0 | 是 | 源码依赖 | |
| `aes` / `sha2` / `crc32fast` | 加密/校验 | MIT/Apache-2.0 | 是 | 源码依赖 | |
| `serde` / `thiserror` / `clap` | 序列化/错误/CLI | MIT/Apache-2.0 | 是 | 源码依赖 | |
| `unrar-rs` | RAR 解码（可选） | UnRAR license | **否/受限** | **默认不启用、不分发** | 见 ADR-0003 |
| 7-Zip / p7zip（整体/含 RAR） | 参考/oracle | LGPL-2.1+ + unRAR restriction | 含 RAR 部分否 | 仅本机/CI 工具，不随包 | 官方 7z.dll 含 RAR 代码；Debian `p7zip-rar` 为 non-free |
| 7-Zip / p7zip（RAR-free 构建） | 备用引擎/oracle | LGPL-2.1+ | 是 | 仅测试/可选备用 | 必须剔除 `CPP/7zip/Compress/Rar*`，并做二进制扫描 |
| libarchive | 备用（ZIP/未加密 7z/RAR） | BSD-2-Clause | 是 | 可选依赖 | ZIP AES 可；加密 7z/RAR 不支持 |
| Avalonia | 桌面 UI | MIT | 是 | NuGet 依赖 | |
| .NET Runtime | 桌面运行时 | MIT | 是 | 随自包含发布 | |
| Jetpack Compose | Android UI | Apache-2.0 | 是 | Gradle 依赖 | |
| HarmonyOS ArkUI/SDK | 鸿蒙 UI | 华为开发者条款 | 需遵守 | DevEco 依赖 | 不是 OSI 许可，注意分发条款 |
| GitHub Actions | CI | 各自许可 | 是 | 不随产品分发 | |

> 新增依赖必须在 PR 中更新本表；CI 增加 `cargo deny`（M0 后）。

## 3. RAR 特别说明（重要）

**现状**：GPL-3.0-only 内核**不链接、不随包分发、不自动下载** unRAR/7-Zip RAR 代码。

- RAR 支持仅桌面：调用**用户自行安装**的外部 `unrar`/`UnRAR.exe`；
- 不把 unrar CLI 作为安装包的一部分（即便法理上可作为 aggregate，本项目也从紧）；
- 移动端首发不含 RAR；Android 可引导用户用已安装的 RAR 应用打开；
- 纯 Rust `unrar-rs` 仅本地实验，发布前需法务确认。

理由：UnRAR 许可含“不得用于开发 RAR 兼容压缩器”等额外限制，与 GPL-3.0 §10 冲突；7-Zip 的 RAR 部分同源。详见 `docs/adr/0003-rar-licensing.md`。

**待办**

- [ ] 法务确认“外部进程 + 用户自备”的分发边界。
- [ ] 若未来提供 RAR add-on：单独许可、单独安装包、不与 GPL 内核静态链接，并做分发审查。
- [ ] 发布物扫描：确认无 `unrar` 二进制/源码、无 7-Zip RAR 代码。

## 4. 移动端与商店

### 4.1 GPL-3.0 与 App Store

GPL 与 Apple App Store 条款存在冲突（VLC 2011 先例）。因此：

- macOS 走**官网 DMG + 公证**，不上 Mac App Store；
- iOS 不在首发范围；若未来支持，需单独评估（可能需双许可/例外，但本项目不计划）。

### 4.2 Android / HarmonyOS

- Google Play / AppGallery 对“密码恢复/破解”类工具有审核风险；需明确：
  - 仅用于自有/授权归档；
  - 不内置泄露口令字典；
  - 不提供在线撞库/共享；
  - 说明加密与数据保存方式。
- GPLv3 §6 的 **Installation Information** 对“User Product”可能适用（手机、平板）。分发 Android/HarmonyOS 版本时需评估：
  - 提供源码与构建说明；
  - 不限制用户替换/重装 GPL 组件；
  - 签名/引导加载器限制是否构成额外限制。
- 应用商店的 DRM/签名机制与 GPL 的冲突需逐案评估；必要时仅提供官网 APK/HAP。

## 5. 源码与构建合规

- 发布二进制时附带：
  - `LICENSE`；
  - `THIRD_PARTY_NOTICES.md`（由 `cargo about`/`cargo deny` 生成，M1 后）；
  - 对应 commit 的源码 tag/链接；
  - 构建脚本与工具链说明。
- 不使用“源码仅口头提供”的模糊做法；至少提供稳定下载链接。
- 不把第三方非自由代码复制进仓库（包括反编译/提取的代码）。

## 6. 数据与隐私

- 默认零网络；不收集 MAC/用户名/归档哈希/字典内容。
- 日志默认不记录完整密码；调试模式需显式开启并提示。
- 不上传归档/密码到任何服务。

## 7. 出口/加密合规

- 工具本身使用通用加密算法（AES/SHA/PBKDF2），属于常见密码恢复工具；如在某些司法辖区受限，由分发者自行评估。
- 不提供规避 DRM/版权保护的功能。

## 8. 参考

- GNU GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
- GNU license list: https://www.gnu.org/licenses/license-list.html
- UnRAR license: https://www.rarlab.com/license.htm
- 7-Zip license: https://www.7-zip.org/license.txt
- Debian p7zip-rar: https://packages.debian.org/non-free/p7zip-rar
- Apple App Store / GPL (VLC): https://9to5mac.com/2011/01/07/vlc-for-ios-removed-from-the-app-store/
- Android foreground service limits: https://developer.android.com/develop/background-work/services/fgs/timeout
