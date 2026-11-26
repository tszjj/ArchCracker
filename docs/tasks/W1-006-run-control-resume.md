# W1-006：运行控制与断点续跑（合并 epic）

- **状态**：待开始
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

- `RunControl` 状态：`Running`、`Pausing`、`Paused`、`Stopping`、`Stopped`；
- `pause()`：停止派发新批次；worker 在当前候选/批次边界停下；保留 worker、归档会话、内存字典；
- `resume()`：清暂停，继续派发；
- `stop()`：停止派发；worker 不再开始新候选；外部 UnRAR 子进程可被取消；
- `force_stop()`：立即请求终止；外部子进程 kill；CPU 候选在当前调用返回后退出；
- `RunOutcome`：`Found`、`Exhausted`、`Paused(Checkpoint?)`、`Stopped(Checkpoint?)`、`Error`；
- 进度查询：`tried`、`total`、`completed_through`、p/s、ETA、暂停/停止请求状态。

### 2.2 检查点与续跑

- `Checkpoint` 至少包含：
  - schema 版本、工具版本；
  - 归档指纹：规范化路径、大小、mtime、分卷列表；可选首尾块哈希；
  - 字典指纹：大小、哈希、编码；恢复用候选索引；
  - 攻击参数：模式、`threads`、严格/快速、引擎路径/版本；
  - **连续完成水位** `completed_through`（不是 `tried` 的最大值）；
  - 统计：tried、耗时、p/s、创建时间；
- 原子写：临时文件 + fsync + rename；写锁防止双开；
- `--resume` 加载并校验；指纹不匹配明确拒绝，不静默从头跑；
- 硬杀恢复误差 ≤ 1 批（4096）；允许重放，不允许漏候选；
- 命中结果必须先记录再停止；续跑不能把已命中的密码丢掉。

## 3. 非目标

- GUI 暂停/停止按钮（W3）；
- 流式字典/批处理（W1-007）；
- 多任务队列、包间密码复用（W2）；
- GPU/hashcat（W2-001，已延后）；
- 自研 KDF/AES 中断点；
- 精确到候选内部的抢占式取消（CPU 候选在调用返回后停下）。

## 4. 设计约束

### 4.1 水位必须按批次连续完成

N 个 worker 完成顺序不确定。不能把“最大已尝试索引”作为续跑点，否则会跳过仍在执行中的批次。实现要求：

- producer 为批次编号；
- worker 完成批次后 ack；
- 只把**连续完成前缀**写入 `completed_through`；
- 暂停时先停止派发，等在途批次完成/取消后再写检查点；
- 强杀时最多丢失一个未 ack 批次，恢复时重放 ≤1 批。

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

- [ ] `pause()` 在 ≤200 ms 内被 scheduler 观察到；CPU 候选在下一个候选边界停下；
- [ ] 暂停后 `resume()` 原地继续，不重开归档、不丢候选；
- [ ] 优雅 `stop()` 在 ≤2 s 内结束（外部 UnRAR 子进程被 kill），退出后无残留进程；
- [ ] `force_stop()` 在 ≤2 s 内结束；
- [ ] 检查点原子写；崩溃后文件不半写；
- [ ] 硬杀恢复 `completed_through` 误差 ≤1 批；不重复已命中结果、不漏候选；
- [ ] 归档/字典/参数指纹不匹配时拒绝续跑并给出具体差异；
- [ ] ZIP、7z、RAR 外部分别覆盖暂停、停止、恢复测试；
- [ ] CLI：`--resume`、暂停/停止提示、退出码与现有 0/1/2/3 约定一致；
- [ ] `cargo fmt`、`clippy -D warnings`、`cargo test --workspace`、MSRV 1.89、release build、cargo-deny 全绿；
- [ ] 文档记录暂停/停止/续跑的语义、检查点位置、未验证项。

## 6. 风险

- `ArchiveSession::test_password` 目前是阻塞调用；7z 64 MiB 完整 CRC 可能让“停止”超过 2 秒。验收按“控制请求被观察 ≤200 ms、当前候选结束后停止”定义，不承诺抢占式中断。
- 并发水位若实现成 `tried` 计数会导致漏候选；必须用连续批次 ack。
- 归档可能在暂停期间被修改；续跑前必须校验指纹。
- RAR 外部进程的取消/管道清理是平台相关代码，需要 Windows 实测。
- 暂停时保留内存字典；1M 字典可接受，更大字典需等 W1-007 流式化。

## 7. 交接

```text
STATUS: planned
CHANGED: docs/tasks/W1-006-run-control-resume.md, docs/{PROJECT-GUIDE,roadmap,windows-plan}.md
VERIFIED: documentation only
NOT VERIFIED: implementation
NEXT: implement RunControl + external cancellation, then CheckpointStore + --resume
RISKS: in-flight candidate latency; concurrent watermark correctness; external child cancellation
```
