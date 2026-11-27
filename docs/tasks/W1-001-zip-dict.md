# W1-001：ZIP + 字典 + 多线程垂直切片

- 分支：`feat/w1-zip-dict`
- 角色：planner、core-engineer ×2、cli-engineer、qa
- 状态：完成（PR #1，独立评审通过，CI 6/6）

## 设计目标

解决「从零打通一条可运行的恢复链路」的问题。面向 Windows CLI 首发场景，用最小实现验证 ZIP 传统加密（ZipCrypto）+ 字典 + 多线程的组合可用：给一个加密 ZIP 和一本字典，程序能并行试密码、输出命中结果、返回正确退出码。本切片只验证链路，不做 AES、7z、RAR、断点或界面。

## 目标命令

`acx -f fixture.zip -m dict -d dict.txt -t 4`

要求：预检 ZIP、选最小加密文件、流式读字典、4 个线程并行测试、命中输出密码、退出码正确。

## 接口（已固定）

```rust
pub struct ArchiveInfo { path, format, encryption, selected: Option<usize>, entries }
pub struct EntryInfo { index, name, uncompressed_size, compressed_size, encryption, crc32, is_dir }
pub enum Encryption { None, ZipCrypto, Aes }
pub enum PasswordTest { Miss, Hit }

pub trait ArchiveSession: Send {
    fn info(&self) -> &ArchiveInfo;
    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest>;
}
pub trait ArchiveSessionFactory: Send + Sync {
    fn open(&self) -> Result<Box<dyn ArchiveSession>>;
}
```

## 实现要点

**ZIP 引擎**（`archive/zip.rs`）：用 `zip::ZipArchive` 打开，遍历条目选最小的加密文件；加密类型看本地头扩展字段 `0x9901`（AES）与否（ZipCrypto）。验证密码时完整读取条目并计算 CRC32 与声明值比对，避免 ZipCrypto 的 1/256 误通过。零长度加密条目无校验数据，跳过；仅有空条目时报不支持。

**字典**（`candidates/dictionary.rs`）：整文件读入（W2 改流式），按 BOM → 严格 UTF-8 → GBK 顺序识别编码；去行尾 `\r`、跳空行、保留行内空格、去重并保持首次顺序。

**调度与 CLI**：有界队列（容量 `线程数×2`），按 4096 一批分发索引；每个线程只开一次归档会话；命中后设停止标志，其他线程在下一个候选检查停止。CLI 参数 `-f/-m/-d/-t`，退出码 0 命中 / 1 未找到 / 2 参数或字典错误 / 3 归档错误或未加密。

## 验收

```powershell
cd core
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p acx-core
cargo test -p acx-cli
cargo run -p acx-cli -- --version
```

集成测试用 `zip` writer 生成 ZipCrypto 样本（密码 `P@ssw0rd123`），验证预检、命中、错误密码、未加密 ZIP 路径。

## 结果（2026-11-24）

ZIP 引擎 11 个单测、字典 7 个单测、调度/CLI 3+1 个集成测试通过。`cargo test --workspace`（24 core + 4 CLI + 4 集成 + 2 FFI）、clippy、fmt 全绿。手工复测：deflate 正确密码 exit 0、5000 错误密码 exit 1、空条目 exit 3。基线见 `docs/benchmarks/w1-zipcrypto.md`。

## 许可与引用

不引入 unRAR/GPL 代码，不提交样本归档或字典。测试样本由 `zip` writer 在临时目录生成；若 writer 不可用才改用本机 WinRAR 生成测试样本，CI 不依赖本机安装。

## 评审与对照意见

独立评审发现两个阻塞问题并已修复：deflate 错误密码的 `InvalidInput` 曾被当作 I/O 错误中止整轮（改为未命中）；零长度加密条目 CRC=0 造成假命中（跳过空条目）。
