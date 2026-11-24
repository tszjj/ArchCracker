# W1-003b：RAR 预检缓存

- 分支：`feat/w1-003b-rar-preflight-cache`
- 角色：core-engineer（主对话实现）、reviewer（独立评审）
- 状态：实现完成，待 PR/评审
- 前置：[W1-003](W1-003-rar-external.md)（RAR 外部引擎）

## 背景

W1-003 的 `RarFactory::open()` 为每个 scheduler worker 重新执行
`unrar t -p-`（加密归档还要再跑 `unrar l -p-`），而 CLI 在创建 factory 前
已经通过 `archive::preflight` 探测过一次。`-t N` 因此会多出约 `2N` 次
UnRAR 进程，纯属重复工作。

## 目标

- 归档元数据只在 factory 创建时探测一次，worker 的 `open()` 只克隆缓存。
- CLI 复用 `archive::preflight` 的结果，不再启动第二次预检。
- 不改变候选密码验证路径：仍是整包 `unrar t`，密码走 stdin。
- 不改变退出码、错误文本或加密判定。

## 范围

- `core/crates/acx-core/src/archive/rar.rs`
  - `RarFactory` 增加 `info: ArchiveInfo` 缓存与 `info()` 访问器。
  - `RarFactory::new()` / `with_engine()` 创建时预检一次。
  - `RarFactory::from_info()` 接收已探测的 `ArchiveInfo`，只重新发现引擎路径，不启动进程。
  - `RarFactory::with_cached_info()` 供测试/诊断注入元数据。
  - `ArchiveSessionFactory::open()` 不再调用 `detect_format` / `preflight`，只复制缓存。
- `core/crates/acx-cli/src/main.rs`
  - RAR 分支改用 `RarFactory::from_info(cli.file, info)`。
- 文档：本任务、W1-003 优化记录、架构/路线图/Windows 计划/AGENTS 当前阶段。

## 非目标

- 不改变“每候选一次整包 `unrar t`”的验证成本（W2 用 clean-room 头/KDF + hashcat 优化）。
- 不改超时策略、退出码 1/3 分类、头加密字段（W2/后续）。
- 不引入随包引擎路径（W4）。
- 不引入 hashcat/Cargo 依赖。

## 设计

```text
CLI
  archive::preflight(path)          # 1 次 t -p-（加密再 1 次 l -p-）
    -> ArchiveInfo
  RarFactory::from_info(path, info) # 只 find_unrar，不启动进程
    -> RarFactory { path, engine, info }
  scheduler -t N
    worker open()                   # clone info，0 次 UnRAR
    test_password()                 # 每候选 1 次 unrar t（原有行为）
```

`RarFactory::new()` / `with_engine()` 仍会自行预检一次，供不经 CLI 的
调用方使用；两条构造路径都不会让 worker 重复预检。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

- [x] 加密 RAR、`-t N`：预检进程数从约 `2 + 2N` 降为 `2`（与 N 无关）。
- [x] `RarFactory::open()` 不再启动 UnRAR；用不存在的 engine 路径 + 缓存元数据打开两个 session 仍成功。
- [x] `from_info()` 拒绝非 RAR 元数据。
- [x] CLI RAR 命中/未命中/未加密、Unicode 密码集成测试保持通过。
- [x] 现有 ZIP/FFI/CLI 测试全部通过。
- [x] 无 Cargo 依赖、无许可边界变化。

## 验证结果

- `cargo fmt --all -- --check`：通过。
- `cargo clippy --workspace --all-targets -- -D warnings`：通过。
- `cargo test --workspace --locked`：
  - `acx-core` 单元 41（原 39，新增 2）；
  - CLI 单元 4；
  - 集成 8（ZIP 6 + RAR 2，本机 WinRAR 7.22 可用，未跳过）；
  - FFI 2。
- 本机 RAR 集成实际执行 `local_rar_external_cli` 与 `local_rar_unicode_password`，均通过。
- 同机前后对比（debug，172 B RAR5，1 条错误密码，5 次中位数）：`-t 4` 206→136 ms，`-t 16` 243→135 ms，`-t 32` 376→135 ms；W1-003b 基本不随线程数增长。详见 [w1-rar-preflight.md](../benchmarks/w1-rar-preflight.md)。
- 未验证：RAR4 真实样本、超大归档预检耗时、release 构建、冷文件缓存、杀毒软件干扰。

## 风险

- `from_info()` 信任调用方传入的元数据；目前只有 CLI 在 `archive::preflight`
  之后立即调用，路径一致。若后续增加调用方，应改为返回 `(ArchiveInfo, EnginePath)`
  的预检结果，避免重复发现引擎或元数据错配。
- 预检本身仍可能因损坏/大归档失败；错误分类优化仍在 W2。
