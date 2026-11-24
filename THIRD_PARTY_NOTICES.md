# 第三方组件声明

本文件列出随 ArchCracker 分发或构建时使用的第三方组件。发布前由 CI 生成完整清单（`cargo about` / `cargo deny`），本文件保留人工摘要。

## 当前（W1-002）

| 组件 | 用途 | 许可 | 分发方式 |
|---|---|---|---|
| `zip` | ZIP 读写（`deflate` + `aes-crypto`） | MIT | 源码依赖 |
| `aes` / `hmac` / `pbkdf2` / `sha1` / `constant_time_eq` / `zeroize` / `getrandom` | `zip` 的 WinZip AES 传递依赖 | MIT OR Apache-2.0 | 源码依赖 |
| `crc32fast` | CRC32 校验 | MIT OR Apache-2.0 | 源码依赖 |
| `thiserror` | 错误类型 | MIT OR Apache-2.0 | 源码依赖 |
| `encoding_rs` | 字典编码识别 | (Apache-2.0 OR MIT) AND BSD-3-Clause | 源码依赖 |
| `crossbeam-channel` | 有界任务队列 | MIT OR Apache-2.0 | 源码依赖 |
| `clap` | CLI 参数解析 | MIT OR Apache-2.0 | 源码依赖 |

## 计划引入（需在 PR 中更新）

| 组件 | 用途 | 许可 | 分发方式 |
|---|---|---|---|
| sevenz-rust2 | 7z | Apache-2.0 | 源码依赖 |
| Avalonia | 桌面 UI | MIT | NuGet |
| .NET Runtime | 桌面运行时 | MIT | 自包含发布 |
| Jetpack Compose | Android UI | Apache-2.0 | Gradle |
| HarmonyOS ArkUI/SDK | HarmonyOS UI | 华为条款 | DevEco |

## 明确不分发

- **unRAR / libunrar / unrar CLI**：unRAR license（非自由），不链接、不随包、不自动下载。RAR 仅调用用户自装的外部程序。见 `docs/adr/0003-rar-licensing.md`。
- **7-Zip / p7zip 含 RAR 代码的二进制**：unRAR restriction，不随主项目分发。仅本机/CI 作为 oracle 时使用。
- **`unrar-rs`**：默认不启用；如未来启用，需单独许可评审。

## 通知与商标

- Apache-2.0 组件：随发布物保留其 `NOTICE`（如有）与许可证文本；MIT 组件保留版权行与许可文本。完整清单由 CI 的 `cargo about`/`cargo deny` 生成。
- RAR、WinRAR、WinZip、7-Zip 等名称是其各自权利人的商标；本项目与 RARLAB、WinZip、7-Zip 官方无隶属关系，名称仅用于说明兼容性。
- 本项目不随包分发 unRAR/7-Zip RAR 代码；RAR 仅调用用户自行安装的 WinRAR/`UnRAR.exe`。

- Apache-2.0 全文见 `LICENSE`；版权与归属见 `NOTICE`。
- 发布二进制时附本文件、`LICENSE`、对应源码链接/构建说明。
- 如使用 LGPL 组件（未来可选），附其许可证与源码获取方式，并允许重链接。

> 这不是法律意见；正式发布前请做许可审计。
