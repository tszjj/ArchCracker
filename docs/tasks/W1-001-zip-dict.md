# W1-001：ZIP + 字典 + 多线程 垂直切片

- 分支：`feat/w1-zip-dict`
- 角色：planner（主对话）、core-engineer ×2、frontend/cli-engineer、qa
- 状态：进行中

## 目标

在 Windows 上打通最小可用链路：

```powershell
acx -f fixture.zip -m dict -d dict.txt -t 4
```

要求：预检 ZIP、选择最小加密文件、流式字典、4 个 worker 并行测试、命中输出密码、退出码正确。

**只做 ZipCrypto**；AES、7z、RAR、掩码/暴力、断点、GUI 不在本切片。

## 当前接口（已由 planner 固定）

```rust
// archive/info.rs
pub struct ArchiveInfo { path, format, encryption, selected: Option<usize>, entries }
pub struct EntryInfo { index, name, uncompressed_size, compressed_size, encryption, crc32, is_dir }
pub enum Encryption { None, ZipCrypto, Aes }
pub enum PasswordTest { Miss, Hit }

// archive/mod.rs
pub trait ArchiveSession: Send {
    fn info(&self) -> &ArchiveInfo;
    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest>;
}
pub trait ArchiveSessionFactory: Send + Sync { fn open(&self) -> Result<Box<dyn ArchiveSession>>; }
```

## 文件所有权

| 角色 | 文件 | 说明 |
|---|---|---|
| core-engineer A | `core/crates/acx-core/src/archive/zip.rs` | 只改这个文件；实现 `ZipSession`/`ZipFactory` + 单元测试 |
| core-engineer B | `core/crates/acx-core/src/candidates/dictionary.rs` | 只改这个文件；实现 `Dictionary` + 单元测试 |
| cli-engineer C | `core/crates/acx-core/src/scheduler.rs`、`core/crates/acx-cli/src/main.rs`、`core/crates/acx-cli/tests/w1_zip_dict.rs` | 调度器 + CLI + 集成测试 |
| qa | 只读评审，最后跑验收 | 不改代码，除非主对话另行指派 |

**不要修改**：`archive/info.rs`、`archive/mod.rs`、`attack.rs`、`lib.rs`、`Cargo.toml`（如需改动先报告 planner）。

## A. ZIP 引擎要求

文件：`archive/zip.rs`

- `ZipSession::open(path)`：
  - `File::open` + `zip::ZipArchive::new`。
  - 遍历条目用 `by_index_raw(i)`（不触发解密）。
  - 记录 `name()`（失败用 `name_raw` lossy）、`size()`、`compressed_size()`、`crc32()`、`is_dir()`、`encrypted()`。
  - AES 判定：扫描 `extra_data()` 中是否有 header id `0x9901`；有则 `Encryption::Aes`，否则加密条目为 `ZipCrypto`。
  - 选择“最小且加密的文件”作为 `selected`；跳过目录。
  - 无条目 → `AcxError::EmptyArchive`；无加密条目 → 返回 info（`encryption=None`, `selected=None`），由 CLI 报“未加密”。
- `test_password`：
  - `selected` 为 `None` → `Err(AcxError::NotEncrypted)`。
  - `archive.by_index_decrypt(idx, password)`：
    - `Err(ZipError::InvalidPassword)` → `Miss`；其他错误可返回 `Miss` 或 `Err`（说明理由）。
    - `Ok(mut file)`：读到 EOF（`Read::read_to_end`），用 `crc32fast` 计算输出 CRC，与 `file.crc32()` 比较；相等 `Hit`，否则 `Miss`（防 ZipCrypto 1/256 误通过）。
  - 大条目可先限制 64 MiB（W1 语料很小），超出返回 `Err(AcxError::Unsupported("entry too large for W1 verification"))`。
- `ZipFactory { path }` 实现 `ArchiveSessionFactory`。
- 单元测试：用 `zip::ZipWriter` + `FileOptionsExt::with_deprecated_encryption` 在临时目录生成 ZipCrypto ZIP（密码 `P@ssw0rd123`），测试：
  - 预检 `encryption=ZipCrypto`、`selected` 是最小加密文件；
  - 正确密码 `Hit`；错误密码 `Miss`；空密码 `Miss`；
  - 未加密 ZIP 的 `selected=None`。
- 若 `zip` writer API 不可用，改用 `std::process::Command` 调 WinRAR 生成**仅测试用** fixture；不要提交二进制样本，不要依赖本机 WinRAR 作为 CI 必需项；优先用 crate writer。

## B. 字典要求

文件：`candidates/dictionary.rs`

- `Dictionary::load(path)`：
  - 读整个文件（W1 允许；W2 改流式）。
  - 编码：BOM（UTF-8/UTF-16LE/BE）优先；否则严格 UTF-8；失败回退 GB18030/GBK（`encoding_rs::GBK`）。
  - 按行切分（`lines()`），去掉行尾 `\r`；跳过空行；保留行内空格。
  - 去重（`HashSet<Vec<u8>>`），保持首次出现顺序。
  - 错误：IO → `AcxError::Io`；解码失败 → `AcxError::Dictionary`。
- `entries()/len()/is_empty()`。
- 单元测试：UTF-8、GBK（用 `encoding_rs::GBK.encode` 生成字节）、UTF-16LE BOM、重复行、空行、含空格密码。

## C. 调度器 + CLI 要求

### scheduler.rs

```rust
pub fn run(
    factory: Arc<dyn ArchiveSessionFactory>,
    passwords: Arc<Vec<Vec<u8>>>,
    threads: usize,
) -> Result<Option<Hit>>
```

- threads clamp 1..=256。
- `crossbeam-channel::bounded(threads * 2)`；producer 按 4096 一批发送 `(start, end)` 索引；worker `factory.open()` **一次**，循环 `test_password`。
- `AtomicBool` 停止标志；命中后设置并发送 `Hit`；其他 worker 在下一个密码检查停止。
- 无命中返回 `None`；session 打开失败/测试错误返回 `Err`（不要吞）。
- 单元测试：FakeSession（正确密码 `secret`）验证命中/未命中/多线程不重复。

### CLI main.rs

- `clap` derive：
  - `-f/--file <PATH>` 必填
  - `-m/--mode <MODE>` 默认 `dict`；本切片只接受 `dict`，其他报错退出 2
  - `-d/--dictionary <PATH>` 必填
  - `-t/--threads <N>` 默认 1（W1 明确；后续自动）
- 流程：
  1. `archive::preflight(&file)`；打印格式/加密/条目数/选中最小的名称与大小。
  2. 若 `selected=None`：打印“未加密/空包”，exit 3。
  3. `Dictionary::load`；打印条数。
  4. `ZipFactory` + `scheduler::run`；打印 hit 密码（UTF-8 lossy）或“未找到”。
- 退出码：`0` 找到、`1` 未找到、`2` 参数/字典错误、`3` 归档错误/未加密。
- 保留 `--version`/`--help`。
- 集成测试 `tests/w1_zip_dict.rs`：临时生成 ZipCrypto ZIP + 字典，调用二进制（`CARGO_BIN_EXE_acx`），断言 stdout/exit 0；错误字典 exit 1。

## 验收命令

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
. .\scripts\env.ps1
cd core
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p acx-core
cargo test -p acx-cli
cargo run -p acx-cli -- --version
```

## 非目标

- 7z/RAR、AES、分卷、SFX、断点、批量、GUI、真机移动端。
- 不引入 `unrar`/GPL 代码；不提交样本/字典。


## 结果（2026-11-24）

- A（ZIP）：`ZipSession`/`ZipFactory` 完成，11 个 zip 单测通过（含 deflated、空条目、AES 字段扫描）。
- B（字典）：UTF-8/UTF-16/GBK、去重、空行处理完成，7 个单测通过；测试临时目录增加 sandbox fallback。
- C（调度/CLI）：有界队列 + 4096 批 + 每 worker 单会话 + 停止/错误传播；CLI 退出码 0/1/2/3；3+1 个集成测试。
- 独立 reviewer 发现 2 个阻塞问题并已修复：
  1. deflate 错误密码的 `InvalidInput` 被当成 I/O 错误导致整轮退出 → 映射为 Miss；
  2. 零长度加密条目 CRC=0 造成假命中 → 跳过空条目；仅有空条目时明确报 Unsupported。
- 手工复测 reviewer 语料：deflated 正确密码 exit 0、5000 错误密码 exit 1；空条目 exit 3。
- 验证：`cargo test --workspace`（24 core + 4 CLI + 4 集成 + 2 FFI）通过；`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --check` 通过。
- 未覆盖：真实 AES ZIP、>64 MiB 条目、非 Windows 平台、1M 字典 p/s 基准（W1 后续）。
