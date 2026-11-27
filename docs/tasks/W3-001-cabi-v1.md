# W3-001：C ABI v1 冻结 — 实现记录

- 状态：完成（2026-11-28，`windows-gui`；本地验证通过；reviewer/architect/release 最终复审 APPROVE）
- 角色：core-engineer（FFI）、frontend-engineer（C# smoke）、architect（ABI 边界）、reviewer/release（复核通过）
- 分支：`windows-gui`
- 依赖：W2 已签核（`docs/W2-SIGNOFF.md`）；`acx-core` 的 `run_job`/`validate_job`/`RunControl`/W2 攻击与统计能力
- 依据：`docs/W3-PLAN.md` §3、`docs/tasks/W3-windows-gui-outline.md` §4、`docs/architecture.md` §5

## 设计目标

在 `acx-ffi` 中冻结稳定的 C ABI v1：GUI 通过 P/Invoke 创建句柄、启动后台攻击、暂停/继续/停止、查询状态、接收回调并读取最后错误。`acx-ffi` 只做类型转换、错误码、回调生命周期与 panic 隔离，业务逻辑仍由 `acx-core` 提供。

## 实现要点

### 1. ABI 表面

- `include/acx.h` 提升至 `ACX_ABI_VERSION 1`；全部结构体带 `struct_size`/`version` 与 `reserved[]`。
- 函数：`acx_abi_version`、`acx_product`、`acx_version`、`acx_status_name`、`acx_create`、`acx_destroy`、`acx_start`、`acx_pause`、`acx_resume`、`acx_stop`、`acx_status`、`acx_estimate`、`acx_last_error`。
- `AcxInput` 冻结 `path/fd/uri` 完整抽象；Windows 桌面使用 `path`，`fd`/`uri` 返回 `ACX_ERR_UNSUPPORTED`，为 JNI/NAPI 保留 ABI 槽位。
- `AcxAttackSpec` 覆盖字典/掩码/暴力/混合、线程、encoding、strict、`rar_no_fast_reject`、checkpoint/resume、`report_stats`。
- `AcxCallbacks` 含 `on_progress`、`on_hit`、`on_log`、`on_finished`；`AcxStatusInfo` 暴露状态、tried/total、rate、ETA 与最后状态码。
- 一个 handle 只承载一个 job；销毁前不可重复 start。`acx_stop` 返回后不再启动新的 progress/hit/log 回调，`on_finished` 作为终态通知仍触发一次。

### 2. Rust FFI（`core/crates/acx-ffi/src/lib.rs`）

- C 字符串与数组在 `acx_start` 阶段拷贝为 Rust-owned 值，调用返回后不依赖调用方内存。
- `struct_size`/`version`/布尔字段/输入 kind/攻击模式均校验；布局不足或版本不符返回 `ACX_ERR_INVALID_ARG`。
- 每个公开入口使用 `catch_unwind`：Rust panic 转成 `ACX_ERR_PANIC`，不跨 FFI 传播。
- `CallbackGate` 跟踪进行中的回调；`acx_stop`/`acx_destroy` 关闭 gate 并等待活动回调结束。
- worker 线程通过 `job::run_job_with_progress` 执行；进度回调约 10 Hz，由 `acx-core::job::PROGRESS_INTERVAL = 100ms` 驱动。
- `acx-core` 新增 `run_job_with_progress`、`ProgressHook` 与 `ProgressReporter`，不改 CLI/batch 的既有 `run_job` 调用。
- 错误映射：`Io → ACX_ERR_IO`、`MissingVolume → ACX_ERR_MISSING_VOLUME`、`Cancelled → ACX_ERR_CANCELLED`、`Unsupported → ACX_ERR_UNSUPPORTED`、归档类 → `ACX_ERR_ARCHIVE`、参数/字典/批量 → `ACX_ERR_INVALID_ARG`、内部 → `ACX_ERR_INTERNAL`。
- `acx_last_error(handle)` 返回句柄最近错误；handle 为 null 时返回线程级错误。

### 3. 测试

- `acx-ffi/src/lib.rs` 单元测试：元数据、句柄创建销毁、错误布局拒绝、fd 输入拒绝、callback gate。
- `acx-ffi/tests/cabi.rs`：真实 ZipCrypto 归档 + 字典，经 `acx_create → acx_start → acx_status → on_hit/on_finished → acx_destroy` 完整链路，断言命中密码与最终状态。
- `core/crates/acx-ffi/tests/header_smoke.c`：C99/C++17 编译检查全部 v1 结构体与函数签名。
- `frontends/desktop/tests/AcxFfiSmoke`：.NET 10 `LibraryImport` smoke，加载 `acx.dll` 验证 ABI 版本、`acx_create/status/destroy` 与结构体布局。

## 验证结果（本机 Windows x64）

| 命令 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 通过 |
| `cargo test --workspace --locked` | 通过；FFI 8 单测 + 5 个 C ABI E2E（命中、最终进度、stop 回调、pause/resume/重复 start、stop-before-start、错误映射分列） |
| `cargo +1.89 test --workspace --locked` | 通过 |
| `cargo deny check licenses bans sources` | 通过 |
| `cargo build --workspace --release --locked` | 通过 |
| `gcc -std=c99 -Wall -Wextra -Werror ... header_smoke.c` | 通过 |
| `g++ -std=c++17 -Wall -Wextra -Werror ... header_smoke.c` | 通过 |
| `dotnet run --project frontends/desktop/tests/AcxFfiSmoke ... acx.dll` | 输出 `ABI=1 state=0 status=ACX_OK` |

## 影响范围与风险

- 影响：新增 dev-dependency `zip`（已在依赖登记中，非生产依赖）与 `acx-core` 的进度钩子；不改命中复核路径。
- ABI：v1 尚未发布；本切片冻结后 W3-002 GUI 必须按 `acx.h` 对接，不得复制参数/错误码。
- 平台：Windows x64 本地等价门禁全绿；Linux/macOS 仅由 Rust job 的 CI 编译/单测覆盖并需在评审前重跑确认，本分支未持有独立远端绿灯；Android fd 与 HarmonyOS uri 仍为预留，未运行时验证。
- 生命周期：用户指针/回调必须在 `acx_destroy` 前保持有效，回调内不得重入 `acx_*`；已写入头文件注释。
- sidecar：未实现真实进程，仅保留后续 P2 开关设计；自动解压不在项目范围内。

## 交接

```text
STATUS: done
BRANCH: windows-gui
CHANGED: core/crates/acx-ffi/{include/acx.h,src/lib.rs,tests/header_smoke.c,tests/cabi.rs,Cargo.toml}、
         core/crates/acx-core/src/job.rs、
         frontends/desktop/tests/AcxFfiSmoke/*、
         docs/architecture.md、docs/W3-PLAN.md、docs/PROJECT-GUIDE.md、本文
ROLE: core-engineer + frontend-engineer；architect/release 复核待下一次评审
NEXT: W3-002 Avalonia 工程与 NativeBridge
RISKS: 回调模型 C# 实测选择、fd/uri 后续 JNI/NAPI 生命周期、v1 冻结后的兼容性门禁
```
