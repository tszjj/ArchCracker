# W2-003a：空间估算公共函数与回填

- **状态**：首版实现完成（2026-11-27，PR 待合并）
- **日期**：2026-11-27
- **角色**：core-engineer + reviewer
- **分支**：与 W2-004 同一 PR（`feat/w2-004-hybrid-rules`）
- **依赖**：W2-002 `MaskEstimate`、W2-003 `BruteEstimate`、W1-006 scheduler 批次窗口
- **范围**：`acx-core` 公共空间估算函数、mask/brute 回填、hybrid 复用；**不含**字典模式 `--estimate`

> 本切片是 W2-004 的前置：W2-002/003 的空间复杂度只写在文档里，程序没有输出。W2-004 的水位位图会被 `V` 放大，必须在攻击前让用户看到真实内存成本。

## 1. 问题

- `RunContext::new` 按 `ceil(total/64)` 个 `AtomicU64` 预分配完成位图，即 **`ceil(total/8)` 字节**，没有 `try_reserve`；
- 现有 `MaskEstimate`/`BruteEstimate` 只有 keyspace，没有内存字段；`--estimate` 不打印空间；
- `?d`×10 = 10¹⁰ 个候选可以通过 `usize` 检查，但位图约 **1.25 GB**，足以在启动时 OOM；
- 调度器同时可能持有 `threads + 3` 个批次，W2-004 文档里的“一个 8 MiB 批次”低估多线程场景。

## 2. 决策（2026-11-27）

| 决策 | 内容 |
|---|---|
| “三个模式” | 指 W2 的 **mask / brute / hybrid**；字典模式不新增 `--estimate`，继续只走攻击路径 |
| API 签名 | `MaskSet::estimate(threads)`、`BruteSet::estimate(threads)`、`HybridSet::estimate(threads)` 直接带线程数，不保留无参版本 |
| 超阈值行为 | **只警告，不拒绝执行**；位图 >128 MB 时打印警告。是否拒绝留给后续切片评审 |
| 单位 | 十进制 MB（`182.9 MB`），与 W2-004 §7.1 示例一致 |
| 估算口径 | 单候选用**最大长度**（不是平均值），批次按 `threads+3` 个在飞 + 源自身 8 MiB cap，加上位图与源缓冲；**不含归档会话**，输出标注 `(+ archive sessions)` |
| 归档会话 | ZIP 中央目录、7z header、外部 UnRAR 进程无法从核心侧精确估算，不纳入 |

## 3. API

```text
acx_core::estimate::SpaceInput
  total: u128
  threads: usize
  max_candidate_bytes: u128
  batch_bytes_cap: Option<u128>
  source_bytes: u128

acx_core::estimate::SpaceEstimate
  total: u128
  watermark_bytes: u128            // ceil(total/8)
  candidates_per_batch: u128       // 与 scheduler 共用 batch_candidates()
  in_flight_batches: u128          // threads + 3
  in_flight_bytes: u128
  source_bytes: u128
  estimated_peak_bytes: u128
  warnings: Vec<SpaceWarning>      // 位图 >128 MB

acx_core::estimate::estimate_space(&SpaceInput) -> SpaceEstimate
```

公式：

```text
watermark   = ceil(total / 8)
per_batch   = min(cap, batch_candidates(threads) × (24 + round16(max_candidate + 16)))
in_flight   = (threads + 3) × per_batch
peak        = watermark + in_flight + source_bytes
```

`batch_candidates()` 与 scheduler 共用（[scheduler.rs](../../core/crates/acx-core/src/scheduler.rs)），避免公式漂移。

## 4. 各模式输入

| 模式 | total | max_candidate_bytes | batch cap | source_bytes |
|---|---:|---:|---|---:|
| mask | keyspace | 最大 positions（≤128） | 无 | 4 KiB |
| brute | Σ keyspace(L) | `max_len`（≤128） | 无 | 4 KiB |
| hybrid | dict_lines × V | 最大行 + 前缀/后缀 positions | 8 MiB | 2 MiB + 2×最大行 |

## 5. 验收

- [x] 位图 = `ceil(total/8)`；t=1/14/256 时 `candidates_per_batch` 与 scheduler 一致；
- [x] 8 MiB cap 生效；`8 MiB × (threads+3)` 的上界；
- [x] 位图 >128 MB 产生警告；`--estimate` 打印位图与峰值；
- [x] mask/brute/hybrid 三个模式输出相同字段；
- [x] `--estimate` 不启动攻击、不写检查点；
- [x] 估算不影响调度行为（`batch_candidates` 原公式不变）；
- [x] 无新依赖、无许可变化。

## 6. 实现记录（2026-11-27）

- 新增 `core/crates/acx-core/src/estimate.rs`；
- `scheduler.rs` 暴露 `batch_candidates()`，`run_with_source` 改为调用它（行为不变）；
- `MaskEstimate`/`BruteEstimate` 增加 `space: SpaceEstimate`，`estimate()` 改为 `estimate(threads)`；
- CLI `--estimate` 与攻击启动前都打印 `Watermark bitmap` / `Estimated peak (core) (+ archive sessions)`，空间警告与 ETA 警告并列；
- 测试：`estimate` 单测 5 个；mask/brute/hybrid 估算与 CLI 空间输出覆盖；`cargo test --workspace` 141 core / 68 CLI passed（1 ignored）/ 2 FFI 全绿。

## 7. 交接

```text
STATUS: done
CHANGED: core/crates/acx-core/src/estimate.rs, scheduler.rs, candidates/{mask,brute,hybrid}.rs, acx-cli/src/main.rs
VERIFIED: fmt / clippy -D warnings / cargo test --workspace
NOT VERIFIED: 估算不含归档会话；未做 RSS 实测对比
NEXT: 合并后更新 PROJECT-GUIDE 测试计数；W2-004 复用同一 SpaceEstimate
RISKS: 位图随 total 线性增长；只警告不拒绝，超大 keyspace 仍可能 OOM
```
