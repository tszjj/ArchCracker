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
| `lzma-rust2` | 7z LZMA/LZMA2 解密 | Apache-2.0 | 是 | 源码依赖 |
| `aes` 0.8 / `cbc` / `sha2` / `getrandom` / `futures-*` / `version_check` | 7z AES/哈希/异步传递依赖 | MIT OR Apache-2.0 | 是 | 源码依赖 |
| `generic-array` | 7z AES 传递依赖 | MIT | 是 | 源码依赖 |
| `bzip2` / `libbz2-rs-sys` | 7z BZip2 解密 | MIT OR Apache-2.0；`libbz2-rs-sys` 为 bzip2-1.0.6 | 是 | 源码依赖 |
| `ppmd-rust` | 7z PPMd 解密 | CC0-1.0 OR MIT-0 | 是 | 源码依赖 |
| `zip` | ZIP 读写（含 `deflate`） | MIT | 是 | 源码依赖 |
| `zip/aes-crypto` 传递依赖：`aes` / `hmac` / `pbkdf2` / `sha1` / `block-buffer` / `cipher` / `cmov` / `const-oid` / `cpubits` / `cpufeatures` / `crypto-common` / `ctutils` / `digest` / `hybrid-array` / `inout` / `typenum` / `zeroize` / `zeroize_derive` / `getrandom` / `constant_time_eq` | WinZip AES 解密 | MIT OR Apache-2.0；`constant_time_eq` 为 CC0-1.0 OR MIT-0 OR Apache-2.0 | 是 | 源码依赖 |
| `encoding_rs` | 字典编码识别 | (Apache-2.0 OR MIT) AND BSD-3-Clause | 是 | 源码依赖 |
| `crossbeam-channel` | 有界任务队列 | MIT OR Apache-2.0 | 是 | 源码依赖 |
| `crc32fast` / `thiserror` / `clap` | 校验/错误/CLI | MIT OR Apache-2.0 | 是 | 源码依赖 |
| `windows-sys`（仅 Windows） | OEM 代码页转换 | MIT OR Apache-2.0 | 是 | 源码依赖 |
| `UnRAR.exe`（未修改） | RAR4/RAR5 测试/解压 | UnRAR License（非 OSI） | 是（独立组件，不改变主项目许可） | Full 安装包随包，仅进程 |
| hashcat（固定版本） | GPU 字典后端 | MIT + 第三方声明 | 是 | Full 安装包随包，仅进程 |
| Avalonia | 桌面 UI | MIT | 是 | NuGet |
| .NET Runtime | 桌面运行时 | MIT | 是 | 自包含发布 |
| `unrar-rs` | RAR 解码（仅本地实验） | Apache-2.0 + unRAR restriction | 受限 | 不是依赖、默认不启用、不分发 |
| 7-Zip / p7zip（含 RAR） | 差分 oracle | LGPL-2.1+ + unRAR restriction | RAR 部分受限 | 仅本机/CI，不随包 |
| 7-Zip / p7zip（RAR-free） | 差分 oracle | LGPL-2.1+ | 是 | 仅本机/CI，不随包 |

> 新增依赖必须在 PR 中更新本表；CI 用 `cargo-deny` 做许可门禁。`zip` 的 `deflate` 特性会引入 `flate2`/`zlib-rs`/`zopfli` 等 MIT/Apache/BSD 传递依赖；`aes-crypto` 特性引入上表所列 AES/哈希/zeroize/getrandom 传递依赖。`sevenz-rust2` 生产构建只启用 `aes256`/`bzip2`/`ppmd`，不启用 `compress`（writer）；测试通过 dev-dependency 启用 writer，不进入发布二进制。发布前由 `cargo-deny`/`cargo-about` 全量列出。

## 3. RAR、UnRAR 与 Full 版

**先澄清**：RAR 解压本身是 UnRAR 许可允许的用途，不违反 RAR 协议。

Windows 只发布**单一 Full 版本**，不分层。按 [ADR-0004](adr/0004-bundled-engines.md)：

- 随包**未修改的 `UnRAR.exe`** 与完整 `license.txt`；UnRAR 许可明确允许把 utility 放入其他软件包；
- 只通过 `engines::external` 进程调用，不链接（静态/动态）、不调用 `unrar.dll`、不复制 unRAR 源码；
- 不随包 `WinRAR.exe`/`Rar.exe`：WinRAR EULA 对 trial 包 bundling 有独立限制；
- 不自动下载、不静默更新；版本/SHA-256/来源记录在 `third_party/manifest.json`；
- 不用于创建 RAR 归档，不做 RAR 兼容压缩器，不反向工程压缩算法；
- 其他平台当前 Deferred；未来同样只走外部引擎或独立许可 add-on。

UnRAR 许可不是 OSI 自由许可，安装包必须在 NOTICE/THIRD_PARTY_NOTICES 中明确它是独立组件，不能暗示整包都是 Apache-2.0。

### 3.1 hashcat 与 GPU

- 实现时点：W2-001 GPU/hashcat 后端已 **Deferred**，W2 不启动；CPU 路径是 W1/W2 的基线。W4 的 Full 随包策略不变，GPU 是否在 W4 前落地由后续评审决定。
- Full 版随包固定版本 hashcat 二进制，附 MIT 许可与第三方声明；hashcat 只通过外部进程调用。
- hashcat **不是核心 Rust 依赖**：`Cargo.toml`/`Cargo.lock` 不出现 hashcat、CUDA/HIP/OpenCL 绑定。
- 不随包厂商 GPU 运行时/驱动（CUDA Toolkit、HIP SDK、Intel NEO、GPU 驱动）；这些由用户系统提供。hashcat 分发包自带的 OpenCL loader/压缩库随 hashcat 组件按其 MIT/第三方声明分发。
- 无 hashcat、无 GPU 或用户禁用 GPU 时，CPU 多线程路径必须完整可用，功能不降级。
- hashcat 的版本/哈希/来源与 UnRAR 一样固定，运行时不在线更新。

## 4. 商店与平台

- Apache-2.0 与 Apple/Google/华为商店条款没有 GPL 式冲突；但“密码恢复”类工具仍可能被按“绕过安全机制”审核。
- Full 版随包 hashcat/UnRAR 可能提高 AV/SmartScreen 误报概率；发布前做 Defender/VirusTotal 与商店材料评估。
- 文案需明确：仅恢复自有/授权归档、不内置泄露字典、不提供在线撞库。
- macOS 当前走官网 DMG + 公证；是否上 Mac App Store 后续再评估（审核/签名成本）。
- Android/HarmonyOS 当前 Deferred；未来上架时附 `LICENSE`/`NOTICE` 与第三方声明。

## 5. 发布合规

- 二进制发布附：`LICENSE`、`NOTICE`、`THIRD_PARTY_NOTICES.md`、UnRAR license、hashcat MIT/第三方声明、对应源码 tag/链接、构建说明。
- 不使用“源码仅口头提供”的模糊做法。
- 不把第三方非自由代码（unRAR/7-Zip RAR）**源码**复制进仓库；Full 安装包按 ADR-0004 携带未修改二进制与许可文本。
- 版本发布附 SHA-256；签名证书指纹公开。

## 6. 商标

RAR、WinRAR、WinZip、7-Zip 等名称是其各自权利人的商标。本项目与 RARLAB、WinZip、7-Zip 官方无隶属关系；名称仅用于说明兼容性。

## 7. 参考

- Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
- Apache 许可 FAQ: https://www.apache.org/foundation/license-faq.html
- UnRAR License（SPDX；随包以实际 license.txt 为准）: https://spdx.org/licenses/UnRAR.html
- WinRAR EULA（trial bundling 限制）: https://www.rarlab.com/license.htm
- hashcat（MIT）: https://hashcat.net/hashcat/
- 7-Zip license: https://www.7-zip.org/license.txt
