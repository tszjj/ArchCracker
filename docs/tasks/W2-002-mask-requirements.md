# W2-002 掩码攻击：需求分析与框架设计

- **状态**：实现完成（2026-11-27；待 reviewer）
- **日期**：2026-11-26
- **范围**：W2-002 掩码表达式、空间/时间估算、警告策略、内核候选源框架
- **关联**：[W2-PLAN](../W2-PLAN.md)、[W1-010 基准](../benchmarks/W1-010.md)、[W1-009 基准](../benchmarks/W1-009.md)
- **约束**：只做 CPU 路径；不做 GUI；不启动 GPU/hashcat

> **实现状态（2026-11-27）**：已落地 `MaskSpec`/`MaskSet`/`MaskSource`、`--mask`/`--custom-charset1..4`/`--estimate`、schema v2 checkpoint；`--mask-file`、`?b`、GUI 字典生成仍按本文后续范围处理。实现文件：`core/crates/acx-core/src/candidates/mask.rs`、`checkpoint.rs`、`acx-cli/src/main.rs`。

> “目前性能最高”在本稿中按**本项目当前实测机器**（i5-14600K，14 线程）理解；对更高核心数 CPU 只给线性上界，不作为实测结论。

## 1. 需求结论

W2-002 采用**内核候选源 + CLI 攻击模式**，不把掩码完整展开成字典文件。

- CLI 用掩码表达式描述候选集合；
- 内核按批次生成候选，交给 W1 的 scheduler；
- 支持暂停/停止/checkpoint/resume；
- 攻击前先做空间/时间估算，过长或过大的表达式先给警告；
- GUI 的“规则描述 → 字典文件”不属于 W2：放 W3 或另建工具。

## 2. 参考与约定

参考：

- hashcat mask attack：`?l ?u ?d ?s ?a ?b`、自定义 `?1..?4`、固定长度掩码；hashcat 4.0 起密码/盐上限 256 字节。见 [hashcat mask wiki](https://hashcat.net/wiki/doku.php?id=mask_attack)、[hashcat 256 字节说明](https://securityaffairs.com/64929/hacking/hashcat-4-0-0-release.html)。
- John the Ripper 的 mask/incremental 支持长度范围；见 [John mask 示例](https://www.openwall.com/lists/john-users/2025/06/04/2)。
- WinRAR 文件加密密码最大 127 字符；见 [WinRAR password length](https://www.win-rar.com/password-length.html)。

本项目约定：

| 项 | 约定 |
|---|---|
| 表达式字符集 | ASCII；非 ASCII 字面量报错 |
| 最大掩码长度 | **128 个位置**（硬上限） |
| 推荐长度 | ≤16 个位置；>16 产生警告 |
| 表达式原始长度 | ≤512 字节（含 `?1` 等 token 写法） |
| 内置字符集 | `?d` 0-9；`?l` a-z；`?u` A-Z；`?s` 33 个 ASCII 符号；`?a` 可打印 ASCII 95 个 |
| 自定义字符集 | `?1..?4`，每个最多 256 字节；由 `--custom-charset1..4` 定义 |
| `?b` | W2-002 不实现；0x00-0xff 与 CLI/外部 RAR 行输入冲突，后续单独评审 |
| 转义 | `??` 表示字面 `?`；未知 `?x` 报错 |
| 长度范围 | 单个 mask 固定长度；首版用多条 `--mask` 表达，`--mask-file` 为后续功能（见 §6）；不做隐式 increment |
| 位置集合 | 每个 token 占一个位置；固定字符是单字节 literal，`?1` 是自定义集合 |
| 最大键空间 | **`usize::MAX`**（当前 `CandidateBatch.start_index` 是 `usize`）；估算用 `u128`，超出可攻击范围报错 |

### 2.1 内置字符集

```text
?d = 0123456789                                  (10)
?l = abcdefghijklmnopqrstuvwxyz                  (26)
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ                  (26)
?s = space ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~   (33)
?a = ?l ?u ?d ?s                                 (95)
```

`?s` 包含空格；shell 中必须整体引用。`?a` 是 95 个可打印 ASCII，不是任意字节。

### 2.2 表达式语法

```text
mask      := position+
position  := literal | escape | charset | custom
literal   := 任意 ASCII 可打印字符（除 ? 外）
escape    := "??"                 -> literal '?'
charset   := "?d" | "?l" | "?u" | "?s" | "?a"
custom    := "?1" | "?2" | "?3" | "?4"
```

示例：

```text
?d?d?d?d                 4 位数字
?u?l?l?l?d?d             首字母大写 + 3 小写 + 2 数字
PREFIX-?1?1?1            固定前缀 + 3 个自定义字符
??d?d?d                  字面 '?' + 'd' + 两位数字
```

自定义字符集：

```text
--mask "?1?1?1?1" --custom-charset1 "?d?l"
```

`--custom-charset1` 可以包含内置字符集和字面量，展开后去重；不允许引用 `?1` 自身或其他未展开的 `?n`，不做递归。最多 4 个自定义集，每个展开后 ≤256 字节。

### 2.3 警告/错误

**警告（继续执行前打印）**

- 掩码长度 >16；
- 估算键空间 >2³²（约 42.9 亿）；
- 估算 24h 内无法完成（ETA >24h）；

**硬错误（拒绝执行）**

- 长度 >128；
- 表达式 >512 字节；
- 非法 `?x`、未定义自定义集、自定义集 >256 字节、递归引用；
- 键空间 >`usize::MAX`，或多 mask 合计 >`usize::MAX`；
- 空 mask、纯空白、非 ASCII 字面量。

警告不改变退出码；`--estimate` 只打印估算，不启动攻击。`--max-runtime` 可在运行中按用户设定主动停止（可选）。

## 3. 空间复杂度与时间估算

### 3.1 空间复杂度

设掩码位置数为 `L`，自定义字符集总字节数为 `C`，批次候选数为 `B`：

- 表达式/解析：`O(L + C)`，L≤128、C≤1024，可忽略；
- 候选批次：`O(B × L)`；复用 W1 的 4096 in-flight 候选和 8 MiB/批次上限；
- 不分配完整键空间；不生成完整字典；
- 预计常驻内存增量：≤1 MB（不含归档/引擎会话）+ W1 既有批次内存。

**不生成** `95^8` 这种数组；只保存当前位置/索引。

### 3.2 时间复杂度

单个候选的验证成本由格式决定；掩码生成本身是 `O(L)`：

```text
总时间 ≈ keyspace / 实测候选率
24h 最大候选数 ≈ 实测候选率 × 86,400
```

候选率按 W1 的 1.3 GB / 14 线程实测基准，不是理论峰值：

| 格式 | 实测候选率 | 24h 最大尝试量 |
|---|---:|---:|
| ZIP AES | 25,409/s | **2,195,337,600**（约 2.20e9） |
| 7z AES | 967.9/s | **83,626,560**（约 8.36e7） |
| RAR5 + check 快筛 | 1,727.2/s | **149,230,080**（约 1.49e8） |
| RAR5 外部 `UnRAR t` | 221.5/s | **19,137,600**（约 1.91e7） |

说明：

- 这是“**可尝试验证**的候选数”，不是保证命中的密码数；
- ZIP 是当前 CPU 路径最高吞吐；7z 的 AES/完整 CRC 成本高；RAR 外部 oracle 最慢；
- 换更高核心数只能做线性上界估算：以 14 线程 i5-14600K 为基线，32 线程线性外推约 **58,078/s**（ZIP），24h 约 **5.02e9**；该数字未实测，只用于容量规划；
- 非 ASCII、RAR 外部、CPU 降频/后台负载都会让实际值低于上表。

### 3.3 常见掩码的 ZIP 时间

| 掩码 | 键空间 | ZIP ETA（25,409/s） |
|---|---:|---:|
| `?l?l?l?l?l?l`（6 小写） | 308,915,776 | 约 3.4 小时 |
| `?d?d?d?d?d?d?d?d`（8 数字） | 100,000,000 | 约 1.1 小时 |
| `?l?l?l?l?l?l?l?l`（8 小写） | 208,827,064,576 | 约 95 天 |
| `?d`×10 | 10,000,000,000 | 约 4.6 天 |
| `?a`×8 | 6.63e15 | 约 8,274 年 |

这些只作数量级参考；实际以 `--estimate` 输出为准。

## 4. 框架设计

### 4.1 类型

```text
MaskSpec
  positions: Vec<MaskPosition>     // literal 或 charset
  custom: [Option<Vec<u8>>; 4]
  source_text: String              // 诊断/指纹
  length: usize

MaskPosition
  Literal(u8)
  Charset(CharsetId)               // builtin 或 custom index

MaskSource : CandidateSource
  spec: MaskSpec
  next_index: usize
  total: usize
  next_batch(max) -> CandidateBatch

MaskEstimate
  keyspace: u128                   // 估算可超过 usize
  fits_usize: bool
  warnings: Vec<MaskWarning>
  per_format_eta: ...
```

### 4.2 生成算法

- 解析 mask 为 `Vec<MaskPosition>`；
- 每个位置的有效字符集为 `Vec<u8>`（去重、顺序稳定）；
- 键空间为各位置长度的乘积；用 `u128` 估算，超过 `usize` 时拒绝实际攻击；
- 批次起点 `start_index` 解码成各位置 digit，再按 odometer 递增；
- 每个批次最多 `max` 个候选，遵守 W1 的 8 MiB/批上限；
- 不按候选做除法/分配；只维护 digit 向量和输出 buffer。

### 4.3 与 W1 scheduler

- `MaskSource` 实现 W1 `CandidateSource`，不修改 scheduler API；
- `total` 必须准确；批次 `start_index` 连续；
- 检查点记录 mask 指纹 + `next_index`，不记录密码；指纹方案见 §4.6；
- 暂停/停止沿用 W1 的 20 ms 轮询和 4096 in-flight 窗口。

### 4.4 CLI

建议参数（具体拼写实现时定）：

```text
--mask <expr>               可重复；每条固定长度
--mask-file <path>          每行一条 mask；# 注释（后续功能，首版不实现）
--custom-charset1..4 <set>  自定义字符集
--estimate                  只解析/估算，不攻击
--max-runtime <duration>    可选；到时停止
--yes                       非交互确认超长/超 24h 计划（可选）
```

`--mask`/`--mask-file` 与 `-d/--dictionary` 互斥；`--estimate` 可配合 `-f` 使用，按归档格式选择实测候选率。

### 4.5 估算输出

示例字段：

```text
mask: ?u?l?l?l?d?d
positions: 6
keyspace: 26^3 * 10^2 = 1,757,600
fits_usize: true
format: zip (25,409/s measured)
eta: 69.2 s
24h capacity: 2,195,337,600 candidates
warnings: none
```

超过 24h 时明确打印：

```text
WARNING: estimated 95.1 days at 25,409/s; 24h capacity is 2.20e9
```

### 4.6 Checkpoint 指纹与恢复

**决策（2026-11-27）**：把 W1 的 `Checkpoint` 扩展为 schema v2，新增通用攻击指纹；W2-003 暴力、W2-004 混合复用同一结构，不再逐切片改格式。

现状约束：`Checkpoint.dictionary` 是必填 `FileFingerprint`，`validate()` 校验字典指纹；掩码攻击没有字典文件，且 W2-004 需要同时表达“字典 + 规则”，因此不能把掩码指纹塞进 `mode` 字符串。

类型（规划）：

```text
Checkpoint (schema=2)
  archive: ArchiveFingerprint
  dictionary: Option<FileFingerprint>   // 掩码/暴力为 None，混合为 Some
  attack: AttackFingerprint             // 新增
  completed_through: u64                // 保持 u64，执行侧维持 usize
  tried: u64
  total: u64
  ...

AttackFingerprint
  mode: String                          // "dict" | "mask" | "brute" | "hybrid"
  signature: String                     // 规范化描述的 SHA-256 hex
```

编码新增两行：`attack_mode=mask`、`attack_signature=<hex>`；`dictionary` 行缺失时解码为 `None`。`sha2` 已是 `acx-core` 既有依赖（0.10），无需新增依赖或许可登记。

多 mask 规范化：把每条 mask 的 `source_text` 按 CLI 出现顺序拼接，附 4 个自定义字符集定义，用固定分隔符连接后取 SHA-256。`total = Σ keyspace_i`，`completed_through` 是全局索引；恢复时按累计划分区间二分定位到 `(mask_i, local_index)`。命令行中多条 `--mask` 的出现顺序即为顺序；`--mask-file` 不在首版（见 §6）。

兼容性：schema=1 的 W1 检查点在 v2 下直接拒绝并提示重新运行；W2 处于 beta 阶段，不做半兼容读取。

验收补充：

- 字典模式写出的 v2 检查点可被 v2 读取并续跑；
- 掩码表达式、自定义字符集或多条 mask 的顺序任一变化都会拒绝 `--resume`；
- 全局 watermark 落在 mask 边界时，恢复后从下一条 mask 的第 0 个候选继续，不重不漏；
- 旧 schema=1 检查点被明确拒绝，错误信息可读。

## 5. 需求验收

- 解析：合法/非法 token、`??`、自定义字符集、重复字符去重、ASCII 限制；
- 键空间：与手算一致；`u128` 估算；超过 `usize` 明确报错；
- 生成：批次边界不重不漏；已知 mask 的候选顺序稳定；1M 候选生成无异常；
- 恢复：暂停/停止/checkpoint，`--resume` 从 `next_index` 继续；
- 估算：ETA、24h 容量、警告文本；`--estimate` 不启动攻击；
- 性能：生成开销不成为 ZIP/7z/RAR 验证的瓶颈；批次内存遵守 W1 上限；
- 文档：表达式约定、限值、警告和示例可复现。

## 6. 可选/后续功能

这些不是 W2-002 首版必需，但可作为后续迭代：

- `--estimate --json`：给 GUI/脚本输出键空间、ETA、警告；
- `--mask-file`：一行一条 mask，支持注释和空行；
- 自定义字符集预设（如 `digits+lower`），减少重复输入；
- 运行时 ETA/已尝试数/剩余量进度；
- 小键空间 `--export-dictionary`，供离线/外部工具复用；
- `--max-runtime` 到时自动停止并保存 checkpoint；
- 长度范围/隐式 increment（W2 先用多条 mask 表达；是否做类似 hashcat `-i` 另行评审）；
- GUI 的规则描述/字典生成器（W3 或独立工具）。

## 7. 待定问题

1. `?b`（0x00-0xff）与 CLI/外部 RAR 行输入的兼容方案；
2. 是否把 `CandidateBatch.start_index`/`CandidateSource.total` 从 `usize` 扩到 `u128`（当前限制由 W1 接口决定）；
3. 是否支持 hashcat 式 `--increment`；W2 先用多条 mask/`--mask-file` 表达长度范围；
4. GUI 的“规则描述 → 字典文件”放 W3 还是独立 `acx-dictgen` 工具；
5. 高核心数 CPU 的实测基线（当前 32 线程仅为线性外推，未实测）。

## 8. 实现记录（2026-11-27）

- `MaskSpec`/`MaskSet`/`MaskSource`：解析、去重、odometer 批次、多 mask 全局索引、resume。
- CLI：`--mask`（可重复）、`--custom-charset1..4`、`--estimate`；`--mask` 与 `-d` 互斥。
- Checkpoint：schema v2，`dictionary: Option<_>` + `attack_mode`/`attack_signature`；schema 1 明确拒绝。
- 测试：`cargo test --workspace` 107 core / 44 CLI passed（另有 1 ignored）/ 2 FFI；`--estimate` 与 mask 命中/续跑有集成测试。
- 1M 掩码回归：[W2-002 基准](../benchmarks/W2-002.md)（40.458 s / 约 24,717/s，ZIP 对照 2.8% 开销）。
- 未实现：`--mask-file`、`?b`、GUI 字典生成（按 §6/§7 后续）。
