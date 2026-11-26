# W2-003：暴力/键空间

- **状态**：任务定义稿（未实现）
- **日期**：2026-11-27
- **门禁**：属于 W2 准出项；W3 GUI 之前完成
- **角色**：core-engineer + reviewer；接口/断点决策需 architect 复核
- **分支**：`feat/w2-003-brute-keyspace`
- **依赖**：W1-006 调度与断点、W1-007 `CandidateSource`、W2-002 字符集解析器与 schema v2 checkpoint
- **范围**：字符集 + 长度区间的暴力候选源、短密码优先、CLI 攻击模式、checkpoint/resume、估算；不含掩码表达式（W2-002）、混合/规则（W2-004）、GPU/hashcat、GUI

> 本文是 W2-003 的正式任务定义。W2-PLAN §3 中“按 `UInt128` 键空间分区”的表述以本文 §4.3 为准：**估算用 `u128`，执行侧维持 `usize`，分片复用 scheduler 的批次窗口，不做独立键空间分区器**。

## 1. 为什么需要

W2-002 的掩码攻击要求用户写出固定长度的表达式（`?d?d?d?d`）。当密码长度未知、或只有“由小写字母和数字组成、1–8 位”这类模糊线索时，逐条写掩码很笨重。

暴力模式提供不依赖字典的通用兜底：用户给字符集和长度区间，内核按短密码优先遍历整个键空间。它与掩码共用 `CandidateSource`/scheduler/checkpoint，不新增第二套并发或断点逻辑。

## 2. 需求结论

- 采用**内核候选源**，不生成完整字典文件；
- 长度区间用 `--min-len`/`--max-len` 表达，按长度递增（短密码优先）遍历；
- 字符集复用 W2-002 的内置集合与自定义集合语法，不引入第二套字符集定义；
- 键空间用 `u128` 估算并展示，执行侧维持 `usize`；超出 `usize::MAX` 的组合硬错误拒绝；
- checkpoint 复用 W2-002 定义的 schema v2 `AttackFingerprint`，`mode = "brute"`；
- 小键空间可选导出字典（后续功能，非首版）。

## 3. 参考与约定

参考：W2-002 掩码需求（`?d ?l ?u ?s ?a ?1..?4`、字面量、去重、ASCII 限制）、W1-007 流式候选源、W1-006 断点水位。

本项目约定：

| 项 | 约定 |
|---|---|
| 字符集表达式 | 与 W2-002 掩码 position 语法相同：`?d ?l ?u ?s ?a ?1..?4` + 字面量；`?b` 不实现；非 ASCII 字面量报错 |
| 自定义字符集 | `--custom-charset1..4`，规则同 W2-002（可含内置集合与字面量、展开去重、不允许递归、≤256 字节） |
| 长度区间 | `--min-len N --max-len M`，均 ≥1；`min > max` 报错；上限 128（与 W2-002 掩码长度一致） |
| 遍历顺序 | 长度从小到大；同一长度内按字符集顺序做 odometer 递增；固定位置按字面量处理 |
| 单长度键空间 | 各位置字符集长度的乘积（含字面量位置，贡献因子 1） |
| 总键空间 | `Σ_{L=min}^{max} keyspace(L)`，用 `u128` 估算；执行侧要求 ≤ `usize::MAX` |
| 最大执行键空间 | **`usize::MAX`**（与 W2-002 一致；当前 `CandidateBatch.start_index` 与 `CandidateSource.total()` 是 `usize`） |
| 进度/断点索引 | 全局索引跨长度累计；恢复时按累计划分区间映射到 `(len, local_index)` |

## 4. 框架设计

### 4.1 类型

```text
BruteSpec
  charset: Vec<u8>              // 展开、去重后的候选字符集合
  charset_text: String          // 规范化文本，用于指纹
  min_len: usize
  max_len: usize

BruteSource : CandidateSource
  spec: BruteSpec
  len_prefix: Vec<usize>        // len_prefix[i] = Σ_{L=min}^{min+i-1} keyspace(L)
  current_len: usize
  digits: Vec<usize>            // 当前长度下的 odometer 位
  next_index: usize
  total: usize

BruteEstimate
  keyspace: u128                // 可超过 usize，仅展示
  fits_usize: bool
  per_format_eta: ...
  warnings: Vec<BruteWarning>
```

字符集来自 `--brute` 表达式和 `--custom-charset1..4`；解析后展开为单一字节集合。若表达式含字面量位置，按 W2-002 的 `MaskSpec` 思路保留位置信息，避免把固定字符混入可变字符集。

### 4.2 生成算法

- 按长度 `L = min_len..=max_len` 依次处理；
- 每个长度把 `start_index` 减去该长度的累计前缀，解码成 `digits`（base = `charset.len()`）；
- 按 odometer 递增生成候选字节串，固定位置直接填字面量；
- 候选写入复用的输出 buffer，遵守 W1 的 4096 in-flight 与 8 MiB/批上限；
- 一个长度耗尽后切到下一个长度，`next_index` 保持全局连续；
- 不按候选做除法/分配；批次边界不重不漏。

### 4.3 与 W1 scheduler 的集成（关键取舍）

**不做独立键空间分区器**。W2-PLAN 早期的“UInt128 键空间分区”在落地时替换为：

- `BruteSource` 实现 W1 `CandidateSource`，暴露 `total()` 与 `next_batch(max)`；
- 分片由 scheduler 的 producer 按批次完成，worker 只拿当前批次；
- 批次 `start_index` 必须连续，scheduler 已校验；
- 暂停/停止沿用 W1 的 20 ms 轮询和 4096 in-flight 窗口；
- 好处：与 W2-002 掩码共用同一条调度/断点路径，无第二套并发逻辑。

### 4.4 usize vs u128 决策（已定）

**维持 `usize`，不扩到 `u128`。** 理由：

- 64 位 `usize::MAX ≈ 1.84e19`；按 W1-010 实测 ZIP 25,423/s，24h 可尝试 2.2e9，`usize` 上限对应约 2.3 万年，比任何实际可完成的攻击高约 9 个数量级；
- 扩到 `u128` 会改动 `CandidateBatch.start_index`、`CandidateSource.total()`、scheduler 的 `Vec<AtomicU64>` 水位位图索引、`Checkpoint` 三个 u64 字段、CLI 转换和全部 scheduler 单测，并需重跑 W1-010 的 1 GB 暂停/停止/硬杀矩阵；收益极低、回归风险集中在最不能出错的模块；
- `u128` 只用于 `--estimate` 展示完整键空间与 ETA；超出 `usize::MAX` 时打印“超出可执行上限，仅估算”并拒绝实际攻击。

此决策同时关闭 W2-002 §7 待定问题 #2；W2-004 混合攻击沿用同一执行上限。

### 4.5 Checkpoint 指纹（复用 schema v2）

复用 W2-002 §4.6 定义的 `AttackFingerprint`，不新增 schema 版本：

```text
schema=2
attack_mode=brute
attack_signature=<sha256 hex>   // canonical(charset_text, min_len, max_len)
dictionary 行缺失 -> None
completed_through=<全局索引 u64>
tried=<u64>
total=<u64>
```

- 签名输入：`charset_text`（含 `--custom-charset*` 定义与顺序）+ `min_len` + `max_len`，用固定分隔符连接后取 SHA-256；
- 字符集、长度区间任一变化都会拒绝 `--resume`；
- 全局 `completed_through` 按 `len_prefix` 二分定位到 `(len, local_index)`；落在长度边界时，从下一长度的第 0 个候选继续；
- 旧 schema=1 检查点直接拒绝，与 W2-002 策略一致。

### 4.6 CLI

建议参数（具体拼写实现时定）：

```text
--brute <charset>              字符集表达式；可重复？首版给单一集合，保留扩展位
--min-len <N>                  最小长度（≥1）
--max-len <M>                  最大长度（≤128）
--custom-charset1..4 <set>     自定义字符集（同 W2-002）
--estimate                     只解析/估算，不攻击
```

- `--brute` + `--min-len`/`--max-len` 与 `-d/--dictionary`、`--mask` 互斥；
- `--estimate` 可按归档格式选择实测候选率；
- 输出字段与 W2-002 §4.5 一致，增加 `charset`、`min_len`、`max_len`、`per-length keyspace`。

## 5. 需求验收

- 解析：内置/自定义字符集、字面量、去重、ASCII 限制、长度区间校验；
- 键空间：与手算一致；`u128` 估算；`Σ keyspace(L)` 超过 `usize::MAX` 明确报错；
- 生成：跨长度边界不重不漏；短密码优先顺序稳定；1M 候选生成无异常；
- 恢复：暂停/停止/checkpoint，`--resume` 从全局 `next_index` 继续；长度边界续跑不跳过候选；
- 估算：ETA、24h 容量、警告文本；`--estimate` 不启动攻击；
- 指纹：字符集或长度区间变化拒绝续跑；schema v2 与 W2-002 互通；
- 性能：生成开销不成为 ZIP/7z/RAR 验证瓶颈；批次内存遵守 W1 上限；
- 文档：参数、限值、顺序、警告与示例可复现。

## 6. 可选/后续功能

非首版必需：

- 导出字典（小键空间，`--export-dictionary`）；
- 多字符集集合并行（首版单一集合）；
- hashcat 式 `--increment`（W2 用 `--min-len`/`--max-len` 表达区间）；
- `--estimate --json`（与 W2-002 一起做）；
- 运行时 ETA/已尝试数/剩余量进度。

## 7. 风险与已知限制

- 总键空间超过 `usize::MAX` 时拒绝执行，用户需缩小字符集或长度区间；
- 短密码优先意味着长密码排在后面，超长区间可能实际不可完成；
- 水位位图为 O(N/8)，与 W1-007 相同；大键空间下仍是主要内存项；
- 字符集顺序固定，用户无法指定“常用字符优先”之类的权重；
- RAR 外部进程每候选成本高，暴力模式在 RAR 上实际可尝试量远小于 ZIP；
- `sha2` 已是 `acx-core` 既有依赖，无新增许可登记；
- 与 W2-002 共用解析器，若 W2-002 的字符集定义变化，本文需同步。

## 8. 待定问题

1. `--brute` 是否允许多个集合（首版单一集合，保留扩展位）；
2. 字符集权重/常用字符优先是否值得做（首版不做）；
3. 与 W2-004 混合模式的字符集复用方式（W2-004 任务文档确定）。

## 9. 交接

```text
STATUS: planned
CHANGED: docs/tasks/W2-003-brute-keyspace.md
VERIFIED: 文档结构对齐 W1-007/W2-002；决策引用 W1-010 实测数字
NOT VERIFIED: 无代码实现；u128 线性外推基于 14 线程 i5-14600K，未实测更高核心数
NEXT: W2-002 实现并合并后，从 main 开 feat/w2-003-brute-keyspace 分支
RISKS: usize 执行上限；短密码优先的长尾；跨长度断点映射
```
