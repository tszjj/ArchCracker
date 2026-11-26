# W1-007：流式字典与候选源

- **状态**：**进行中（本地实现完成，reviewer APPROVE；待 500MB/1M 正式基准）**
- **门禁**：属于 W1 准出项；W2 不启动
- **角色**：core-engineer + reviewer
- **分支**：`feat/w1-007-streaming-dictionary`
- **依赖**：W1-006 的候选项水位、暂停/停止、检查点
- **范围**：有界内存字典读取、候选批次源、CLI 流式接入、检查点续跑、编码兼容；不含掩码/暴力/规则、GPU、GUI

## 1. 为什么需要

W1-001…W1-006 的 `Dictionary::load` 一次性把文件读入 `String`，再把每行复制成 `Vec<u8>`，并用 `HashSet<Vec<u8>>` 全局去重。CLI 还会 `entries().to_vec()` 再复制一遍。

实际内存约为文件大小的数倍；500 MB 组合字典可能占用数 GB，不能把“500 MB 文件”当成“500 MB 内存”。W1-007 把 CLI 切到有界内存的流式候选源。

## 2. 目标

- 读取字典时只保留：
  - 一个 64 KiB 解码块；
  - 当前未完成的一行（上限 1 MiB）；
  - 当前 scheduler 批次（≤4096 个候选，且 ≤8 MiB 候选字节）；
  - **每候选 1 bit 的连续水位位图**（O(N/8)，14.3M 候选约 1.8 MB，50M 约 6.3 MB；不是候选字符串数组）；
- 不把整个文件或全部候选常驻内存；
- 支持 UTF-8（含 BOM）、UTF-16LE/BE（BOM）、GBK/GB18030 回退；
- 保留 CR/LF/CRLF、空行跳过、行首尾空格；
- 文件顺序即候选顺序；`completed_through` 是稳定候选索引；
- `--resume` 时顺序跳过到水位，重新校验归档/字典指纹；
- 暂停/停止/检查点语义与 W1-006 一致。

## 3. 非目标

- 全局去重（流式默认不做；重复行可能重复测试）；
- 按字节偏移随机 seek（当前 resume 用顺序 skip；后续可加稀疏 offset 索引）；
- 掩码/暴力/混合/规则（W2）；
- 物理核数默认值调整（仍用 `-t`，后续 W1-008/调优处理）；
- GPU/hashcat。

## 4. 设计

### 4.1 候选源

```text
DictionaryStream --next_batch(4096)--> CandidateBatch
                                      { start_index, Vec<Vec<u8>> }
scheduler producer --bounded channel--> workers
```

- `CandidateSource` 只暴露 `total()` 和 `next_batch(max)`；
- 内存路径 `MemorySource` 保留给旧 `run`/`run_with_context` API；
- worker 不再拿到整个字典 `Arc<Vec<Vec<u8>>>`，只处理当前批次；
- 批次的 `start_index` 由源维护，scheduler 校验连续性。

### 4.2 两遍读取

1. `count_lines`：流式解码计数，得到精确 `total`；
2. 重新打开并可选跳过 `skip` 行，`next_batch` 逐行产出。

这样 checkpoint 的 `total`、进度百分比和续跑校验不需要“不完整总数”的特殊分支。代价是启动时多读一遍文件；500 MB 级别可接受。

### 4.3 编码与行

- BOM 优先：UTF-8 / UTF-16LE / UTF-16BE；
- 无 BOM：前 64 KiB 像 UTF-8 则按 UTF-8；否则 GBK；
- 若前段是 ASCII、后面才出现非法 UTF-8（rockyou 常见），计数阶段报错后**重扫为 GBK**；
- 按 `\n` 或 `\r` 切行，空行跳过，行首尾空格保留；
- 单行超过 1 MiB 报错，避免无界 `pending`。

### 4.4 检查点

- `completed_through` 仍是候选索引；流式源按行顺序计数；
- 流式不做全局去重，因此索引不会因去重集合变化而漂移；
- `--resume` 顺序跳过 `completed_through` 行；不存字节偏移，代价是 O(N) 跳过；
- 字典指纹仍覆盖原始文件大小/mtime/首尾 CRC；
- W1-006 的旧检查点如果来自去重后的 `Dictionary::load`，可能因 `total` 与流式原始行数不同而被拒绝（明确报错，不静默续跑）。

## 5. 验收

- [x] CLI 不再 `Dictionary::load` 全量字典，也不再 `entries().to_vec()` 深拷贝；
- [x] 500 MB 级文件不按文件大小分配候选内存（133 MB rockyou 实测进程 RSS 约 **11 MB**；候选总数 14,344,390；另含约 1.8 MB 水位位图）；
- [x] 60k 字典 + 1.3 GB ZIP AES 命中，退出码 0（流式路径，约 3.2 s，8 线程，冒烟非正式基准）；
- [x] UTF-8/UTF-8 BOM/UTF-16LE/BE/GBK、CRLF、空行、行首尾空格测试；
- [x] 前段 ASCII、后段 GBK 的 fallback 测试；
- [x] `--resume` 从水位继续（`w1_resume` 3 个测试）；
- [x] 暂停/停止/命中水位语义沿用 W1-006；
- [x] 单行 1 MiB 上限；批次候选字节上限 8 MiB；
- [ ] 500 MB 正式文件 + 内存峰值自动化测试；
- [ ] 1M × 1GB 正式基准（W1-008）。

## 6. 风险与已知限制

- 启动多读一遍文件；大文件上的 `--resume` 还要顺序 skip，最坏 O(N)；
- 水位位图是 O(N/8)，不是严格 O(1)；500 MB/约 50M 行约 6.3 MB，1B 行约 125 MB；
- 流式默认**不做全局去重**，重复行会重复测试；这是保持索引稳定和内存有界的取舍；
- 无 BOM 且前 64 KiB 全为 ASCII、后段为 GBK 的字典会先按 UTF-8 扫描一遍再回退，启动变慢但结果正确；
- 真正的 UTF-8 文件中偶发非法字节会按 GBK 解释，和旧 `Dictionary::load` 的回退策略一致，不保证原文密码；
- 行上限 1 MiB 是新的硬限制；超长行会报错而不是占满内存；
- 文件在“计数”和“读取”之间被修改时可能总数/内容不一致；字典指纹只能发现首尾/大小/mtime 变化；
- 物理核数默认值和 1M/1GB 正式 p/s 仍属 W1-008。

## 7. 交接

```text
STATUS: partial（本地实现 + reviewer APPROVE；待 500MB/1M 正式基准）
CHANGED: core/crates/acx-core/src/candidates/{mod,dictionary}.rs,
         core/crates/acx-core/src/scheduler.rs,
         core/crates/acx-cli/src/main.rs
VERIFIED: 94 core + 38 CLI（1 ignored）+ 2 FFI; fmt/clippy;
          133MB rockyou RSS ~11MB, total 14,344,390; resume at 767;
          1.3GB ZIP + 60k dictionary hit; UTF-8/UTF-16/GBK tests
NOT VERIFIED: 500MB automated peak-RSS test; 1M/1GB benchmark; MSVC CI
NEXT: reviewer；W1-008 1M/1GB 基准与内存峰值
RISKS: two-pass startup; O(N) skip; no global dedupe; 1 MiB line cap
```
