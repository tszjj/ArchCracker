# 许可与合规

> 工程记录，不是法律意见。项目许可证：**Apache-2.0**（见根目录 `LICENSE` / `NOTICE`）。

## 1. 项目自身

- 代码与文档：Apache-2.0。
- 新增源文件加 SPDX 头：

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors
```

- 分发二进制/源码时保留 `LICENSE`、`NOTICE`、版权与第三方声明；修改过的文件需保留显著变更说明（Apache-2.0 §4）。
- Apache-2.0 含专利授权与商标条款；不得暗示官方背书。

## 2. 第三方组件登记

| 组件 | 用途 | 许可 | 与 Apache-2.0 兼容 | 分发方式 |
|---|---|---|---|---|
| `sevenz-rust2` | 7z 读写 | Apache-2.0 | 是 | 源码依赖 |
| `zip` | ZIP 读写 | MIT | 是 | 源码依赖 |
| `rayon` / `aes` / `sha2` / `crc32fast` | 并行/加密/校验 | MIT/Apache-2.0 | 是 | 源码依赖 |
| `serde` / `thiserror` / `clap` | 序列化/错误/CLI | MIT/Apache-2.0 | 是 | 源码依赖 |
| Avalonia | 桌面 UI | MIT | 是 | NuGet |
| .NET Runtime | 桌面运行时 | MIT | 是 | 自包含发布 |
| `unrar-rs` | RAR 解码（仅本地实验） | Apache-2.0 + unRAR restriction | 受限 | 不是依赖、默认不启用、不分发 |
| 7-Zip / p7zip（含 RAR） | 差分 oracle | LGPL-2.1+ + unRAR restriction | RAR 部分受限 | 仅本机/CI，不随包 |
| 7-Zip / p7zip（RAR-free） | 差分 oracle | LGPL-2.1+ | 是 | 仅本机/CI，不随包 |

> 新增依赖必须在 PR 中更新本表；CI 用 `cargo-deny` 做许可门禁。M0 依赖仅为 std。

## 3. RAR 与 unRAR

**先澄清**：RAR 解压本身是 unRAR 许可允许的用途，不违反 RAR 协议。

Apache-2.0 没有 GPL 的 copyleft 冲突，但 unRAR 许可自身的限制仍存在（不得开发 RAR 兼容压缩器、反向工程限制等）。为保持组件边界清晰、避免把受限代码混入主项目：

- Windows 首发调用**用户自行安装**的 WinRAR/`UnRAR.exe`（仅进程）；
- 不链接（静态/动态）、不随包、不自动下载 unRAR/7-Zip RAR 代码；
- 密码不写命令行，走 stdin/临时安全通道，日志脱敏；
- 其他平台 Deferred；未来只走外部引擎或独立许可 add-on；
- `unrar-rs` 仅本地实验，不是依赖。

若后续决定“随包 UnRAR.exe 作为独立程序”，按 unRAR 许可单独评审，不改变主项目 Apache-2.0。

## 4. 商店与平台

- Apache-2.0 与 Apple/Google/华为商店条款没有 GPL 式冲突；但“密码恢复”类工具仍可能被按“绕过安全机制”审核。
- 文案需明确：仅恢复自有/授权归档、不内置泄露字典、不提供在线撞库。
- macOS 当前走官网 DMG + 公证；是否上 Mac App Store 后续再评估（审核/签名成本）。
- Android/HarmonyOS 当前 Deferred；未来上架时附 `LICENSE`/`NOTICE` 与第三方声明。

## 5. 发布合规

- 二进制发布附：`LICENSE`、`NOTICE`、`THIRD_PARTY_NOTICES.md`、对应源码 tag/链接、构建说明。
- 不使用“源码仅口头提供”的模糊做法。
- 不把第三方非自由代码（unRAR/7-Zip RAR）复制进仓库。
- 版本发布附 SHA-256；签名证书指纹公开。

## 6. 商标

RAR、WinRAR、WinZip、7-Zip 等名称是其各自权利人的商标。本项目与 RARLAB、WinZip、7-Zip 官方无隶属关系；名称仅用于说明兼容性。

## 7. 参考

- Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
- Apache 许可 FAQ: https://www.apache.org/foundation/license-faq.html
- unRAR license: https://www.rarlab.com/license.htm
- 7-Zip license: https://www.7-zip.org/license.txt
