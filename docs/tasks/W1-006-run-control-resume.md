# W1-006：运行控制与断点续跑（合并 epic）

- **状态**：**进行中（本地实现完成，reviewer APPROVE；待用户大语料/矩阵测试）**
- **门禁**：属于 W1 准出项；W2-001 GPU 不在此 epic，且 W2 不启动
- **角色**：core-engineer + reviewer
- **分支**：`feat/w1-006-run-control`
- **合并来源**：原 W1-006（断点续跑）+ 原 W1-007 中的暂停/停止
- **依赖**：W1-001…W1-005；`engines::external` 的进程封装
- **范围**：运行中暂停/继续、优雅/强制停止、检查点、跨进程续跑、CLI `--resume`；不含 GUI 按钮、流式字典、GPU

## 1. 为什么合并

暂停/停止和断点续跑共享同一套底层控制流：

- 都需要把当前单一的 `AtomicBool stop` 改为可表达的 `RunControl` 状态；
- 都需要 worker 在批次/候选边界响应；
- 都需要“连续完成批次”的水位来避免并发下漏候选；
- 停止写检查点、恢复读检查点，天然是同一状态机的两个出口。

但两者**不是同一个功能**：

| 能力 | 生命周期 | 是否落盘 | 恢复方式 |
|---|---|---|---|
| 暂停/继续 | 当前进程 | 不要求 | 清 pause 标志，原地继续 |
| 停止 | 当前进程 | 可选（检查点） | 进程退出；无检查点则从头开始 |
| 断点续跑 | 跨进程 | 必须 | 新进程校验指纹后从水位继续 |

因此本 epic 内部分两层实现，不把暂停、停止、续跑混成一个不可测试的状态机。

## 2. 目标

### 2.1 运行控制

- `RunControl` 状态：`Running`、`Paused`、`Stopping`、`Stopped`、`Finished`；
- `pause()`：停止派发新批次；worker 在当前候选边界停下；保留 worker、归档会话、内存字典；暂停时 `run` 阻塞等待 `resume()`/`stop()`；
- `resume()`：清暂停，继续派发；同一进程、同一会话，不重开归档；
- `stop()`：停止派发；worker 不再开始新候选；外部 UnRAR 子进程被 kill；
- `force_stop()`：当前与 `stop()` 相同；CPU 候选在当前调用返回后退出；
- `RunOutcome`：`Found`、`Exhausted`、`Stopped(RunProgress)`；暂停不是终态；
- 进度查询：`tried`、`total`、`completed_through`、elapsed；`completed_through` 是连续完成候选前缀。

### 2.2 检查点与续跑

- `Checkpoint` 至少包含：
  - schema 版本、工具版本；
  - 归档指纹：规范化路径、大小、mtime、分卷列表、首尾 64 KiB CRC32；
  - 字典指纹：路径、大小、mtime、首尾 64 KiB CRC32；
  - 攻击参数：模式、`threads`；
  - **连续完成水位** `completed_through`（不是 `tried` 的最大值）；
  - 统计：tried、创建时间；p/s 只由 CLI 输出，不持久化；
- 原子写：临时文件 + fsync + rename；写锁防止双开；
- `--resume` 加载并校验；指纹不匹配明确拒绝，不静默从头跑；
- 硬杀恢复误差 ≤ 1 个 4096 候选窗口；允许重放，不允许漏候选；
- 命中结果必须先记录再停止；续跑不能把已命中的密码丢掉。

## 3. 非目标

- GUI 暂停/停止按钮（W3）；
- 流式字典/批处理（W1-007）；
- 多任务队列、包间密码复用（W2）；
- GPU/hashcat（W2-001，已延后）；
- 自研 KDF/AES 中断点；
- 精确到候选内部的抢占式取消（CPU 候选在调用返回后停下）。

## 4. 设计约束

### 4.1 水位必须按候选连续完成

N 个 worker 完成顺序不确定。不能把“最大已尝试索引”作为续跑点，否则会跳过仍在执行中的候选。实现要求：

- producer 控制总 in-flight 候选 ≤4096；per-batch = `floor(4096 / (threads + queue + 1))`；
- 每个候选完成后标记 bit，并推进**连续完成前缀** `completed_through`；
- 命中候选本身**不推进**水位：这样即使在“命中后、删除检查点前”被强杀，续跑也会重放该候选而不是跳过密码；
- 检查点只写该前缀；强杀时最多重放当前 4096 候选窗口；
- 暂停时停止派发，worker 在候选边界等待；恢复后继续使用原来的 session。

### 4.2 外部引擎取消

RAR 的 `UnRAR t` 是阻塞进程。`RunControl` 必须把取消句柄传给 `engines::external`：

- 停止时 kill 子进程，避免等 60 秒超时；
- 清理 stdin/stdout/stderr 管道和临时文件；
- 终止后不把“被取消”误判为密码错误。

### 4.3 暂停不是持久化

- 暂停默认只保留内存状态；关机/崩溃后不可恢复；
- 如用户选择“暂停并写检查点”，才落盘；
- 文档/CLI 提示必须区分“暂停”和“停止并保存进度”。

## 5. 验收标准

- [x] `pause()` 在 ≤200 ms 内被 scheduler 观察到；CPU 候选在下一个候选边界停下（fake session 测试）；
- [x] 暂停后 `resume()` 原地继续，不重开归档/会话；
- [x] 优雅 `stop()` 结束并返回安全水位；外部 `CancelToken` 有独立测试；
- [x] `force_stop()` 走同一停止路径；
- [x] 检查点临时文件 + fsync + rename；崩溃后不半写；
- [x] 硬杀恢复 `completed_through` 不跳过候选（本机 2 s kill：checkpoint 11/200，`--resume` 从 11 继续）；
- [x] 归档/字典指纹不匹配时拒绝续跑（CLI 测试）；
- [ ] ZIP、7z、RAR 外部分别覆盖暂停、停止、恢复测试（当前只有 fake session + ZIP resume；7z/RAR 的停止矩阵待补）；
- [x] CLI：`--checkpoint`、`--resume`、TTY `p/r/s`、Ctrl+C 停止、退出码 0/1/2/3/4；
- [x] `cargo fmt`、`clippy -D warnings`、`cargo test --workspace`、MSRV 1.89、release build、cargo-deny 全绿；
- [x] 文档记录暂停/停止/续跑的语义、检查点位置、未验证项。

## 5.1 本地实现与验证

- 运行控制：[scheduler.rs](../../core/crates/acx-core/src/scheduler.rs) 的 `RunControl`/`RunContext`/`RunOutcome`；
- 外部取消：[external.rs](../../core/crates/acx-core/src/engines/external.rs) 的 `CancelToken`/`run_cancellable`；`ArchiveSession::set_cancel_token` 接入 RAR；
- 检查点：[checkpoint.rs](../../core/crates/acx-core/src/checkpoint.rs)（无 JSON 依赖的 key=value 格式、原子写、锁、指纹）；
- CLI：`--checkpoint`、`--resume`、TTY `p/r/s`、Ctrl+C 停止、退出码 4；
- 测试：core 84（新增 scheduler 3、checkpoint 3、external cancel 1），CLI 37（含 1 ignored；新增 resume 3）；
- 命中后若检查点删除失败：CLI 先打印 `FOUND: <password>`，再以 3 退出并报错，不静默留下可续跑检查点；
- 本机验证：fmt/clippy、`cargo test --workspace`、MSRV 1.89、release build、cargo-deny；硬杀后 `--resume` 从 checkpoint 水位继续。

## 6. 风险

- `ArchiveSession::test_password` 目前是阻塞调用；1GB 条目完整 CRC 可能让“停止”超过 2 秒。验收按“控制请求被观察 ≤200 ms、当前候选结束后停止”定义，不承诺抢占式中断。
- 并发水位若实现成 `tried` 计数会导致漏候选；当前用逐候选 bit + 连续前缀。
- 归档可能在暂停期间被修改；续跑前必须校验指纹。
- RAR 外部进程的取消/管道清理是平台相关代码，需要 Windows 实测。
- 暂停时保留内存字典；1M 字典可接受，更大字典需等 W1-007 流式化。
- 检查点锁是 W1 单进程 advisory lock；硬杀后由 `--resume` 清理，不做多用户并发保证。

## 7. 交接

```text
STATUS: partial（本地实现 + reviewer APPROVE；待用户大语料/矩阵测试）
CHANGED: core/crates/acx-core/src/{scheduler,checkpoint,error,archive/mod,archive/rar,engines/external}.rs,
         core/crates/acx-cli/src/main.rs, core/crates/acx-cli/tests/w1_resume.rs,
         docs/tasks/W1-006-run-control-resume.md
VERIFIED: 84 core + 37 CLI（1 ignored）+ 2 FFI; fmt/clippy/MSRV 1.89/release/cargo-deny;
          hard-kill checkpoint 11/200 -> --resume from 11
NOT VERIFIED: TTY p/r/s 自动化; RAR stop matrix; 1GB/1M user corpus; MSVC CI
NEXT: 用户用测试文件跑 ZIP/7z/RAR pause/stop/resume；reviewer 复核；再做 W1-007
RISKS: in-flight candidate latency; external child cancellation; checkpoint lock is single-process
```
