# 第三方组件声明

本文件列出随 ArchCracker 分发或构建时使用的第三方组件。发布前由 CI 生成完整清单（`cargo about` / `cargo deny`），本文件保留人工摘要。许可明细以 [`docs/licensing.md`](docs/licensing.md) 与 [ADR-0004](docs/adr/0004-bundled-engines.md) 为准。

## 当前源码依赖（W1-003）

| 组件 | 用途 | 许可 | 分发方式 |
|---|---|---|---|
| `zip` | ZIP 读写（`deflate` + `aes-crypto`） | MIT | 源码依赖 |
| `aes` / `hmac` / `pbkdf2` / `sha1` / `block-buffer` / `cipher` / `cmov` / `const-oid` / `cpubits` / `cpufeatures` / `crypto-common` / `ctutils` / `digest` / `hybrid-array` / `inout` / `typenum` / `zeroize` / `zeroize_derive` / `getrandom` / `constant_time_eq` | `zip` 的 WinZip AES 传递依赖 | MIT OR Apache-2.0；`constant_time_eq` 为 CC0-1.0 OR MIT-0 OR Apache-2.0 | 源码依赖 |
| `crc32fast` | CRC32 校验 | MIT OR Apache-2.0 | 源码依赖 |
| `thiserror` | 错误类型 | MIT OR Apache-2.0 | 源码依赖 |
| `encoding_rs` | 字典编码识别 | (Apache-2.0 OR MIT) AND BSD-3-Clause | 源码依赖 |
| `crossbeam-channel` | 有界任务队列 | MIT OR Apache-2.0 | 源码依赖 |
| `clap` | CLI 参数解析 | MIT OR Apache-2.0 | 源码依赖 |
| `windows-sys`（仅 Windows） | OEM 代码页转换 | MIT OR Apache-2.0 | 源码依赖 |

## Full 版随包外部程序（W4 落地）

| 组件 | 用途 | 许可 | 分发方式 |
|---|---|---|---|
| `UnRAR.exe`（未修改） | RAR4/RAR5 测试/解压 | UnRAR License（非 OSI） | Full 安装包 `third_party/unrar/`，附 license.txt，仅进程 |
| hashcat（固定版本） | GPU 字典后端 | MIT + 第三方声明 | Full 安装包 `third_party/hashcat/`，仅进程 |

> Full 版只有一个安装包，不分层。UnRAR/hashcat 的版本、来源、SHA-256 记录在 `third_party/manifest.json`；构建/发布按清单获取，运行时不在线更新。hashcat 分发包内的 OpenCL loader/压缩库按其各自许可声明。

## 计划引入（需在 PR 中更新）

| 组件 | 用途 | 许可 | 分发方式 |
|---|---|---|---|
| sevenz-rust2 | 7z | Apache-2.0 | 源码依赖 |
| Avalonia | 桌面 UI | MIT | NuGet |
| .NET Runtime | 桌面运行时 | MIT | 自包含发布 |
| Jetpack Compose | Android UI | Apache-2.0 | Gradle |
| HarmonyOS ArkUI/SDK | HarmonyOS UI | 华为条款 | DevEco |

## 明确不分发

- **WinRAR / `Rar.exe`**：WinRAR EULA 限制 trial bundling；Full 版只随包独立 `UnRAR.exe`。
- **CUDA Toolkit / HIP SDK / Intel NEO / GPU 驱动**：由用户系统提供；hashcat 检测后使用，不随包。
- **7-Zip / p7zip 含 RAR 代码的二进制**：unRAR restriction，不随主项目分发；仅本机/CI 作为 oracle。
- **`unrar-rs`**：默认不启用，不作为依赖。

## 通知与商标

- Apache-2.0 组件：随发布物保留其 `NOTICE`（如有）与许可证文本；MIT 组件保留版权行与许可文本；hashcat 附 MIT 及第三方声明。
- UnRAR 是独立组件，随包附完整 UnRAR license；不得暗示其采用 Apache-2.0。
- RAR、WinRAR、WinZip、7-Zip、hashcat 等名称是其各自权利人的商标；本项目与 RARLAB、WinZip、7-Zip、hashcat 官方无隶属关系；名称仅用于说明兼容性。
- 本项目不随包 WinRAR/7-Zip RAR 代码；不链接 unRAR，不把 hashcat 作为 Rust 依赖。

- Apache-2.0 全文见 `LICENSE`；版权与归属见 `NOTICE`。
- 发布二进制时附本文件、`LICENSE`、对应源码链接/构建说明。
- 如使用 LGPL 组件（未来可选），附其许可证与源码获取方式，并允许重链接。

> 这不是法律意见；正式发布前请做许可审计。
