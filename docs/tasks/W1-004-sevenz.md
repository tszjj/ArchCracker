# W1-004：7z AES / 头加密 / 首块探测

- **状态**：完成（本地分支 `feat/w1-004-7z`；按用户要求**未推送 GitHub**，待里程碑确认后统一推送）
- **角色**：core-engineer + reviewer
- **依赖**：`sevenz-rust2` 0.20.2（Apache-2.0；0.25 需要 Rust 1.93，超出本项目 MSRV 1.89）
- **范围**：7z 读取、AES-256 内容解密、`-mhe=on` 头加密、首块快速判错、CLI 分发；不含分卷/SFX、掩码/暴力、GUI

## 1. 目标

在现有 ZIP / 外部 RAR 引擎之外补齐 7z，使同一个 CLI 字典路径可以恢复：

- 普通 7z；
- 7z AES-256（`-mhe=off`）；
- 7z AES-256 + 头加密（`-mhe=on`）；
- LZMA2 与非压缩（COPY）条目；
- solid 归档；
- 正确的“错误密码 = Miss，不是归档错误”语义。

命中必须经过内置 `sevenz-rust2` 完整读取所选条目并校验 CRC32，不能只凭 header CRC 或首块结构返回 Hit。

## 2. 实现

### 2.1 预检与头加密

`SevenZSession::open` 用空密码调用 `Archive::read`：

- 成功：读取文件表、块表、coder；若任一 block 含 `AES256_SHA256`，标记 `Encryption::Aes`；
- `PasswordRequired`：头加密（`-mhe=on`），记录 `ArchiveInfo.header_encrypted = true`，条目表暂不可见；
- 其他错误：按损坏/不支持归档返回 `AcxError::SevenZ`。

`ArchiveInfo` 新增 `header_encrypted` 字段；`has_verification_target()` 把它视为有效目标，因此 scheduler 不会把“头加密、尚未知条目”的归档误判为未加密。

### 2.2 目标选择

只要加密块，选择 **该块第一个文件** 且满足：

- `has_stream`、非目录、`size > 0`、`has_crc`；
- 多个块时选 size 最小的候选。

选择块首文件是为了 solid 归档不再为到达目标而解压前面的文件；要求 CRC 是为了最终命中可验证。没有满足条件的条目时返回 `Unsupported`，不做“猜测命中”。

### 2.3 两级候选验证

1. **首块探测**：`BlockDecoder` 解出所选块第一个文件的前 64 KiB；LZMA/LZMA2 在错误密钥下通常立即报错，映射为 `Miss`。
2. **完整校验**：重新打开归档，`BlockDecoder` 读取目标条目直到 EOF；crate 的 `Crc32VerifyingReader` 校验条目 CRC32，并检查实际读取长度等于声明大小。只有这一层通过才返回 `Hit`。

COPY（stored）条目没有压缩流结构，首块探测无法否决；实现上直接跳过 probe，完整 CRC 校验负责区分（同时避免同一候选做两次 AES KDF）。为避免候选测试变成大文件解压：

- 单条目完整校验上限 **64 MiB**；超过则返回 `Unsupported`；
- 首块探测上限 **64 KiB**。

### 2.4 密码编码

7z 规范密码是 UTF-16LE。调度器候选是 UTF-8 字节（字典加载已统一为 UTF-8），因此：

```text
UTF-8 candidate -> str -> Password::from(str) -> UTF-16LE
```

非 UTF-8 候选在 7z 引擎中直接返回 `Miss`（不能表示为 7z 密码），不误报为归档错误。

### 2.5 错误映射

`is_candidate_rejection` 把以下情况映射为 `Miss`：

- `PasswordRequired`（空候选）；
- `MaybeBadPassword`；
- `ChecksumVerificationFailed` / `NextHeaderCrcMismatch`；
- `Io` 的 `InvalidData` / `InvalidInput` / `UnexpectedEof` / `Other`（crate 把 LZMA 解码失败和 CRC 失败包装为这些 kind）。

`UnsupportedCompressionMethod`、`MaxMemLimited`、`BadSignature`、`UnsupportedVersion` 等仍作为归档/环境错误返回，不吞掉。

### 2.6 CLI 与 factory

- `detect_magic` 识别 `37 7A BC AF 27 1C`，`archive::open` 分发到 `SevenZSession`；
- `SevenZFactory` 缓存 `ArchiveInfo` 和解析后的 `Archive`，worker 不重复解析头；
- 头加密没有可缓存的 `Archive`，worker 按候选重新解头（这是 7z `-mhe=on` 的固有限制）；
- CLI 输出 `Format: 7z`；头加密时输出 `Entries: n/a (encrypted header)` 和 `Selected: first encrypted entry after the password is known`。

## 3. 测试与验证

### 3.1 自动测试

- `acx-core`：**59** 个单测（新增 13 个 7z 用例）：
  - 明文 7z；
  - AES 文件加密（正确/错误/空密码）；
  - AES 头加密（正确/错误/空密码）；
  - stored AES（首块探针不可否决，完整 CRC 判错）；
  - COPY/LZMA/LZMA2/BZip2/PPMd + AES 五种方法；
  - solid AES；
  - 头加密 + solid；
  - 空归档；
  - 损坏 start header；
  - factory 独立会话；
  - `from_info` 拒绝外部归档元数据；
  - 16 个文件加密错误候选不中止；
  - 8 个头加密错误候选不中止。
- `acx-cli`：**19** 个集成测试（新增 6 个 7z 用例；其中 1 个为 `#[ignore]` 的官方 7-Zip 差分，默认不跑）：
  - 字典命中 AES；
  - 字典命中头加密；
  - 错误字典 exit 1；
  - stored 错误字典 exit 1（不能被首块探针误判为错误）；
  - 未加密 7z exit 3；
  - `official_7zip_cli_differential`（`ACX_7Z` 指向官方 7-Zip 时手工运行）。
- `acx-ffi`：2 个测试不变。

### 3.2 命令

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked
cargo build --workspace --release --locked
cargo deny check licenses bans sources

# 可选：官方 7-Zip 差分（Windows 示例）
$env:ACX_7Z = "C:\path\to\7zr.exe"
cargo test -p acx-cli --test w1_sevenz -- --ignored
```

本机结果：全部通过；`cargo deny` 为 `licenses ok, bans ok, sources ok`（仅有重复版本 warning）。`official_7zip_cli_differential` 也已用 7zr 26.04 实际运行通过（`--ignored`）。本机 host 为 `x86_64-pc-windows-gnu`；MSVC 目标待推送后的 CI 覆盖。

### 3.3 与官方 7-Zip 的差分

本机使用官方 **7-Zip 26.04 `7zr.exe`**（`https://www.7-zip.org/a/7zr.exe`，仅本地/CI oracle，不提交、不随包）生成并测试：

| 样本 | 生成方式 | 结果 |
|---|---|---|
| 文件加密 | `7zr a -t7z -p... -mhe=off` | CLI 命中 |
| 头加密 | `7zr a -t7z -p... -mhe=on` | CLI 命中；错误字典 exit 1 |
| stored | `7zr a -t7z -p... -mx=0` | CLI 命中；错误字典 exit 1 |
| solid | writer `push_archive_entries`（多文件 solid 单测） | 命中；错误密码 Miss |
| solid smoke | `7zr a -t7z -p... -ms=on`（单文件） | CLI 命中；验证命令行路径 |
| Unicode 密码 | `7zr a -t7z -p中文密码 -mhe=on` | CLI 命中 `中文密码` |
| 未加密 | `7zr a -t7z` | CLI exit 3 |

反向也验证过：本地 writer 生成的 `file.7z` / `header.7z` 能被官方 `7zr t` 正确测试，说明测试夹具不是“只有自家 reader 能读”的自洽格式。

头加密 100 个错误候选的 smoke test：全部 `Miss`，CLI 正常 `NOT FOUND`、exit 1，没有候选错误中止。

## 4. 结果与限制

**已完成**：

- 7z magic 检测、预检、条目枚举、目标选择；
- AES-256 内容解密；
- `-mhe=on` 头加密；
- 首块探测 + 完整 CRC 两层验证；
- CLI 端到端；
- 工厂缓存解析结果；
- 许可登记（`sevenz-rust2` 及其 bzip2/ppmd 传递依赖已加入 `deny.toml` allow-list）。

**未验证 / 已知边界**：

- 7z 分卷 `.7z.001`、SFX（W1-005 已补；本切片不覆盖）；
- 7z 的 Brotli / LZ4 / ZSTD / Deflate 压缩方法未启用对应 feature（LZMA/LZMA2/COPY/BZip2/PPMd 可用）；
- > 64 MiB 的验证目标（W1 明确拒绝）；
- 7z 条目无 CRC 的归档（选择器要求 CRC；返回 `Unsupported`，不做无校验的 Hit）；
- 重复文件名（目标按文件索引选择，但 `ArchiveReader` 的 name index 不参与验证，当前实现不依赖名字）；
- 7z 性能 p/s 未做正式基准；
- Windows 以外的 7z 运行时未验证（CI 只保证编译/单测）；本机也只验证了 `x86_64-pc-windows-gnu`，MSVC 目标待 CI；
- 损坏 payload 与错误密码在 7z AES 下不可完全区分；完整 CRC 失败按 `Miss`，这是格式限制；
- 7z 畸形流/PPMd 异常可能返回 `Error::Other`，当前按归档错误中止而不是 `Miss`；尚未做 fuzz 验证；
- 头加密归档损坏时可能被当作“头加密”进入字典流程，最终仍是 `NOT FOUND`，没有独立的“损坏”状态。

## 5. 交接

```text
STATUS: done
CHANGED: core/crates/acx-core/src/archive/{info,mod,sevenz}.rs,
         core/crates/acx-core/src/{error,scheduler}.rs,
         core/crates/acx-core/Cargo.toml,
         core/crates/acx-cli/src/main.rs,
         core/crates/acx-cli/tests/w1_sevenz.rs,
         core/crates/acx-cli/Cargo.toml,
         deny.toml, docs/...
VERIFIED: cargo fmt/clippy/test (59 core + 19 CLI incl. 1 ignored + 2 FFI),
          cargo +1.89 test, release build, cargo-deny,
          7zr 26.04 differential (file/header/stored/solid/unicode/plain)
NOT VERIFIED: >64 MiB, no-CRC archives, 7z p/s benchmark,
              non-Windows runtime
NEXT: W1-006 运行控制与断点续跑（合并 epic）
RISKS: 7z AES has no authenticator; corruption and wrong password can look
       identical. The CRC gate prevents false hits but may turn a damaged
       archive into "not found". Documented, not silently accepted as success.
```
