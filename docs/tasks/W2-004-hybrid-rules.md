# W2-004：混合/规则攻击

- **状态**：首版完成（2026-11-27，PR #28 已合并）
- **日期**：2026-11-27
- **门禁**：属于 W2 准出项；W3 GUI 之前完成
- **角色**：core-engineer + reviewer；规则语法与复合指纹需 architect 复核
- **分支**：`feat/w2-004-hybrid-rules`
- **依赖**：W1-007 流式字典、W2-002 掩码字符集与解析器、W2-003 `usize` 决策、schema v2 `AttackFingerprint`
- **范围**：字典 × 规则链 × 掩码前后缀的候选源、二维断点、复合指纹、CLI、估算；不含独立字典生成器（W3/`acx-dictgen`）、GPU、GUI、通用规则引擎

> 本文是 W2-004 的正式任务定义，也是规则语法与复合指纹的唯一事实源。W2-PLAN §3 "最小规则子集"的具体语法以本文 §5 为准。

---

## 1. 要实现什么功能（一句话）

**给用户一本字典，让他用"每条词做几种变形 + 加固定/掩码前后缀"的方式生成候选密码，而不是手写一个巨大的字典文件。**

典型场景：

- 用户知道密码可能是公司名 + 两位数字，如 `ACME42`、`ACME07`：
  - `--rule identity --rule capitalize --suffix-mask '?d?d'`
- 用户有一本常见密码字典，想试首字母大写 + 常见后缀：
  - `--rule 'capitalize|append:123' --rule 'capitalize|append:2024'`
- 用户想试每个词的反转与大小写变体：
  - `--rule identity --rule lower --rule upper --rule reverse --rule toggle`

这些场景的共同点是：**候选集由"字典中的一行"和"对该行施加的一个变换"共同决定**。W2-004 就是把这类组合变成内核候选源。

## 2. 需求 → 功能对照（为什么每条需求都存在）

| 需求 | 要实现的功能 | 为什么需要 |
|---|---|---|
| 流式读取字典 | 处理 500 MB / 1400 万行字典而不占满内存 | W1-007 已证明全量加载会占数 GB；真实字典常常很大 |
| 规则链（大小写/反转/追加/前缀） | 一条命令行表达十几种常见变形 | 用户不会为每种变形单独造一本字典；这是真实攻击中最常用的手段 |
| 掩码前后缀 | 每条词展开为 `?d?d` 等键空间 | 固定后缀只能试 `123`；掩码后缀能试 `00`–`99`，覆盖率大幅提升 |
| 字典为外层、变体为内层 | 断点只记"字典行号 + 变体索引" | 与 W1-007 的顺序跳过一致；不需要记录字节偏移，恢复简单可靠 |
| 复合指纹（字典 + 规则 + 掩码 + 自定义集） | 任一输入变化都拒绝旧断点 | 否则改了规则却从旧位置续跑，会静默跳过本应测试的候选 |
| schema v2 不升版 | W2-002/003 的检查点代码不用改 | 混合只是又一种 `attack_mode`，`AttackFingerprint` 已能表达 |
| `u128` 估算 / `usize` 执行 | 大组合能展示估算值，但拒绝不可执行的攻击 | 与 W2-002/003 决策一致；避免改 scheduler 位图索引 |
| **时间预估（`--estimate`）** | 攻击前输出键空间、ETA、24h 容量、超限/超 24h 警告 | 沿用 W2-002/003 已实现的能力；用户必须在启动前知道任务要跑多久 |
| **空间预估（本切片补齐）** | 攻击前输出字典行数、V、总候选数、水位位图字节数、峰值内存估算 | W2-002/003 只有理论分析、程序不输出空间估算；混合的位图随 V 放大（500 万行 ×100 变体≈62.5 MB），是最需要提前告警的切片 |
| 可选导出字典 | 小组合可以导出给外部工具复用 | 混合候选本身有价值；但大组合落盘会占满磁盘，所以只做小键空间 |

---

## 3. 核心概念（先把术语说清楚）

理解 W2-004 的关键是三层索引：

```text
全局候选索引 (0..total)
   │
   ├─→ 字典行索引 (dict_line)          ← 外层，来自 W1-007 的流式行号
   │
   └─→ 变体索引 (variant_index)        ← 内层，对该行施加的某个变换
          │
          └─→ (变体生成器, 局部索引)   ← 再细分：规则链 or 掩码前后缀展开
```

**定义**：

- **字典行**：W1-007 的流式行读取（`LineReader`，与 `DictionaryStream` 共用编码探测/GBK 回退）读出的非空行，原样保留首尾空格；行号即索引，与 W1-007 完全一致。
- **变体生成器**：一个能"对一行字典词产生零个或多个候选"的函数。有两种：
  1. `RuleChain`：固定的变换链，对每行产生**恰好 1 个**候选（如 `capitalize|append:123`）；
  2. `AffixMask`：前缀/后缀掩码，对每行产生 **prefix_ks × suffix_ks** 个候选；只给一侧时另一侧因子为 1，两侧都不给时该生成器不存在。候选 = `prefix + word + suffix`，后缀变化最快。
- **变体索引**：对某一行，所有变体生成器按顺序串接后的连续索引。
- **每词变体数** `V = 规则数 + affix_keyspace`。若只有规则链，`V = 规则条数`；若有一条 `?d?d` 后缀掩码，`V = 规则条数 + 100`；若同时给前缀 `?d` 和后缀 `?d?d`，`affix_keyspace = 10 × 100 = 1000`。
- **总候选数** `total = 字典行数 × V`。
- **全局索引** `index = dict_line × V + variant_index`。

**为什么字典放外层**：字典行是流式顺序读取的，外层按行推进可以"读一行、生成该行所有变体、再读下一行"，内存里始终只有一行字典词。反过来（变体放外层）就要为同一个变体重读整本字典，或者把字典缓存下来——两者都不可接受。

## 4. 规则语法（首版最小集，不做通用规则引擎）

### 4.1 设计原则

不做 hashcat 那样的通用规则语言（如 `$a`、`T0`、`?` 等单字符操作符组合）。理由：

- 通用规则引擎解析复杂、调试困难，且 W2 的准出要求是"最小规则子集可用"；
- 真实用户最常用的就是大小写、反转、追加固定串这几种，固定函数列表已覆盖；
- 固定语法便于生成稳定的指纹字符串，不会有"两条等价规则产生不同签名"的问题。

首版采用**命名变换 + `|` 串联**的可读语法。

### 4.2 变换函数（首版全集）

| 函数 | 作用 | 例子（输入 `paSS`） |
|---|---|---|
| `identity` | 原样输出 | `paSS` |
| `lower` | 全部转小写（仅 ASCII A–Z） | `pass` |
| `upper` | 全部转大写（仅 ASCII a–z） | `PASS` |
| `capitalize` | 首字母大写，其余小写 | `Pass` |
| `toggle` | 大小写逐字符反转 | `PAss` |
| `reverse` | 字节反转 | `SSap` |
| `append:<literal>` | 末尾追加字面量 | `append:123` → `paSS123` |
| `prepend:<literal>` | 开头前置字面量 | `prepend:x` → `xpaSS` |

**边界约定**：

- 大小写/反转只处理 ASCII 字节；不解码 UTF-8、不做 Unicode 大小写映射。密码是字节（项目全局约定），Unicode 变形属于 W2-006 编码变体范畴；
- `<literal>` 只允许 ASCII 可打印字符（0x20–0x7E），`??` 转义一个字面 `?`（与 W2-002 掩码一致）；其他 `?x` 报错；
- 单个 `<literal>` 展开后 ≤64 字节（防止一行生成超长候选）；
- 规则链长度 ≤8 个函数（防止一条规则生成超大对象）。

### 4.3 规则链

- 语法：`func1|func2|...|funcN`，按从左到右顺序应用；
- 例：`capitalize|append:123` 对 `paSS` → 先 `Pass` → 再 `Pass123`；
- `--rule` 可重复，每条规则是一个独立的变体生成器，产生 1 个候选/行；
- 若用户不传 `--rule`，默认使用一条 `identity`（否则"混合"退化为只加前后缀，不符合直觉）。

### 4.4 掩码前后缀

- `--prefix-mask <expr>` / `--suffix-mask <expr>`，语法与 W2-002 `--mask` 完全相同（`?d ?l ?u ?s ?a ?1..?4`、字面量、`??`）；
- 两侧同时给出时合成**一个** affix 变体生成器，候选 = `prefix_bytes + 词 + suffix_bytes`，键空间为两侧乘积，后缀变化最快；只给一侧时退化为该侧单掩码；
- 掩码前后缀生成的候选字节数上限沿用现有约束：字典行 ≤1 MiB、每个掩码 ≤128 个位置；首版不额外引入 256 字节候选上限（W2-002 `?b` 与候选长度上限留待 W2-006/后续评审）。

### 4.5 一个完整例子

命令：

```text
acx -f secret.zip -d words.txt \
    --rule identity \
    --rule 'capitalize|append:123' \
    --suffix-mask '?d?d' \
    --custom-charset1 '?d?l'
```

对字典行 `acme` 产生的变体（按变体索引顺序）：

| 变体索引 | 来源 | 候选 |
|---:|---|---|
| 0 | `identity` | `acme` |
| 1 | `capitalize|append:123` | `Acme123` |
| 2–101 | `suffix-mask ?d?d` | `acme00` … `acme99` |

`V = 1 + 1 + 100 = 102`。若字典有 5000 行，`total = 510,000`。

## 5. 类型与生成算法

### 5.1 类型

```text
HybridSpec
  dictionary_path: PathBuf
  scan: DictionaryScan             // lines + max_line_bytes + 编码
  rules: Vec<RuleChain>            // 每条包含 Vec<Transform>；默认 identity
  prefix: Option<MaskSpec>         // 复用 W2-002 解析器
  suffix: Option<MaskSpec>
  suffix_keyspace: u128            // 无后缀时为 1；仅 into_source 转 usize
  variants_per_line: u128          // V = rules.len() + prefix_ks × suffix_ks
  total: Option<usize>             // None = 超过 usize，仅估算
  total_u128: u128

HybridSource : CandidateSource
  reader: LineReader               // 定位在 dict_line
  word: bytes
  line_index: usize
  variant_index: usize
  next_index: usize
  total: usize

HybridEstimate                     // --estimate 输出
  dict_lines: usize
  variants_per_line: u128          // V；可超过 usize
  total: u128                      // 可超过 usize，仅展示
  fits_usize: bool
  space: SpaceEstimate             // W2-003a 公共类型：位图 + 在飞批次 + 源缓冲
  warnings: Vec<HybridWarning>
```

`space` 复用 W2-003a 的 `SpaceEstimate`（[W2-003a](W2-003a-space-estimate.md)），不再自定义 `watermark_bytes`/`estimated_peak_rss`。

### 5.2 初始化（两遍走）

1. 解析规则与前后缀掩码，得到 `V = rules.len() + affix_keyspace`；
2. 用 `scan_dictionary(path)` 扫描一遍得到 `dict_lines` 与 `max_line_bytes`（复用 W1-007 的编码探测与 GBK 回退）；
3. `total = dict_lines × V`，用 `checked_mul` 计算 `u128`；超过 `usize::MAX` 时执行侧为 `None`，`--estimate` 仍展示；
4. 攻击时按 `dict_line` 顺序跳过并读取当前行，不重复整本扫描。

### 5.3 生成流程

```text
next_batch(max):
  while 收集候选数 < max:
    若 variant < rules.len():
      candidate = rules[variant].apply(word)
    否则:
      local = variant - rules.len()
      (prefix_index, suffix_index) = 解码 local（后缀最快）
      candidate = prefix_bytes + word + suffix_bytes
    输出 candidate；variant + 1
    variant == V 时：读下一行，variant 归零
```

- `Rule` 是纯字节变换；affix 把 `local` 解码成前缀/后缀字节再拼接；
- 批次候选数由 scheduler 的 4096 窗口决定；字节上限由 `HybridSource` 自己实现（复用 `MAX_BATCH_BYTES = 8 MiB`），scheduler 本身不做字节检查；
- 不整本缓存字典；始终只有当前行在内存。

### 5.4 二维索引映射

```text
dict_line    = global_index / V
variant_index = global_index % V
```

恢复时：

- 用 `scan_dictionary(path)` 得到的行数与编码，`LineReader::open` 顺序跳过 `dict_line` 行；
- `variant_index < rules.len()` 时选对应规则；否则 `local = variant_index - rules.len()`，按后缀最快分解为 `(prefix_index, suffix_index)`；
- 落在行边界（`variant_index == 0`）时，从该行的第一个变体开始，不跳过；
- `next_index == total` 时返回 `None`。

**为什么不用字节偏移**：W1-007 明确选择行号而非字节偏移——字典编码可能变化（UTF-8/GBK），字节偏移会漂移；行号稳定，代价是恢复时 O(N) 顺序跳过。混合攻击沿用这一取舍。

## 6. Checkpoint 复合指纹（schema v2 不升版）

### 6.1 为什么需要复合指纹

混合攻击的输入比 W2-002/003 多：字典文件、规则链、前后缀掩码、自定义字符集。只要其中任何一个变化，旧的 `completed_through` 就不再对应同一个候选序列——从旧位置续跑会静默跳过候选或测试错误的候选。

- 字典文件变化：由 `Checkpoint.dictionary: Option<FileFingerprint>` 覆盖（W1 已有 size/mtime/首尾 CRC）；
- 其余四项：由 `AttackFingerprint.signature` 覆盖。

### 6.2 签名格式

```text
attack_mode=hybrid
attack_signature = SHA256(canonical_string)
```

`canonical_string`（固定顺序、固定分隔符，编码为 UTF-8）：

```text
hybrid\n
rule[i]=<rule chain text>\n      // i 按 CLI 出现顺序
prefix=<prefix mask text>\n      // 未给出则空字符串
suffix=<suffix mask text>\n      // 未给出则空字符串
custom0=<text>\n ... custom3=<text>\n
```

**为什么包含顺序**：`--rule A --rule B` 与 `--rule B --rule A` 产生的候选序列不同，必须视为不同攻击。自定义集的顺序同理（W2-002/003 已有此约定）。

**为什么不含字典路径**：字典已由 `FileFingerprint` 覆盖（含绝对路径）；重复记录无意义。但路径变化导致 `FileFingerprint.path` 变化，仍会被拒绝——这是正确的行为。

### 6.3 与 W2-002/003 的互通

- `AttackFingerprint` 结构不变，只是 `mode="hybrid"`；
- `Checkpoint` 结构不变，`dictionary = Some(FileFingerprint)`（混合有字典）；
- 三类模式的检查点不能互相续跑：`mode` 不同即拒绝（如 `mask` 检查点不能用于 `hybrid` 攻击）；
- 旧 schema=1 检查点仍直接拒绝。

## 7. CLI 参数

```text
-d, --dictionary <path>             字典文件（必需）
--rule <chain>                      规则链，可重复（默认 identity）
--prefix-mask <expr>                前缀掩码（可选）
--suffix-mask <expr>                后缀掩码（可选）
--custom-charset1..4 <set>          自定义字符集（供前后缀掩码）
--estimate                          只解析/估算，不攻击
```

- `--rule`/`--prefix-mask`/`--suffix-mask` 与 `--mask`、`--brute` 互斥；
- 不给任何 `--rule`、前后缀时：退化为纯字典攻击（与 `-m dict` 等价），此时应提示用户使用 dict 模式而不是静默接受；
- `--estimate` 输出：见 §7.1（时间 + 空间两类估算）。

### 7.1 `--estimate` 输出规范（沿用 W2-002/003 + 本切片补齐空间）

这是 W2-002/003 已确立的约束：**攻击前必须预估任务的时间与空间复杂度**，用户在启动前就能判断任务是否可执行。W2-004 必须沿用并补齐空间部分。

**时间预估（W2-002/003 已实现，直接沿用）**：

```text
总时间 ≈ total / 实测候选率
24h 最大候选数 ≈ 实测候选率 × 86,400
```

候选率按 W1-010 实测值（ZIP 25,423/s、7z 967.9/s、RAR5 check 1,727.2/s、RAR 外部 221.5/s），不是理论峰值。ETA >24h、键空间 >2³² 时打印警告；`--estimate` 只打印不启动攻击。

**空间预估（W2-003a 已实现，本切片直接复用）**：

```text
watermark 位图 = ceil(total / 8) 字节
峰值(core) ≈ 位图 + (threads + 3) × 每批字节 + 源缓冲
每批字节 = min(8 MiB, batch_candidates × (24 + round16(最大候选 + 16)))
```

关键：`total = dict_lines × V`，位图随 V 线性放大。W1-007 的 1400 万行字典单模式位图约 1.8 MB；混合模式若 V=100，位图约 **175 MB**——必须提前告知用户。公式与常量见 [W2-003a](W2-003a-space-estimate.md)；估算**不含归档会话**。

输出示例（十进制 MB）：

```text
Dictionary lines: 14,344,390
Variants per line: 102
Total candidates: 1,463,127,780
Fits executable index: true
Watermark bitmap: 182.9 MB (1463127780 candidates)
Estimated peak (core): ~184.0 MB (+ archive sessions, 17 batches in flight)
Format: zip (25,409/s measured)
ETA: 16.0 h
24h capacity: 2,195,337,600 candidates
WARNING: completion bitmap is 182 MB, above the 128 MB warning threshold; reduce the keyspace or length range
```

**为什么现在补**：位图在 `RunContext::new` 立即分配，混合攻击是第一个位图可能达到数百 MB 的切片；等用户跑到一半 OOM 才发现就晚了。W2-003a 已把 `SpaceEstimate` 抽成公共函数，本切片只负责把 hybrid 的 `dict_lines`、`V`、最大行与 8 MiB cap 填进去。

## 8. 验收标准

每条验收都写明它验证的是哪个功能。

### 8.1 规则变换功能

- [ ] 8 个变换函数各有单测，输出与 §4.2 表格一致（`identity/lower/upper/capitalize/toggle/reverse/append/prepend`）；
- [ ] 规则链按左到右顺序应用（`capitalize|append:123` 得到 `Acme123`，不是 `acme123Cap...`）；
- [ ] 大小写与反转只作用于 ASCII 字节；含非 ASCII 字节的字典行原样保留该字节，不变形、不报错；
- [ ] 非法函数、非法 `<literal>`、超长 literal（>64 B）、超长规则链（>8）均报错。

### 8.2 掩码前后缀功能

- [ ] `--suffix-mask '?d?d'` 在显式规则之外额外产生 100 个候选（默认 `identity` 时为 101，含原词），顺序 `00`…`99`；
- [ ] 前缀 + 后缀同时给出时拼接顺序为 `prefix + word + suffix`；
- [ ] 掩码复用 W2-002 解析器：自定义集、`??` 转义、去重、长度上限行为一致；
- [ ] 前后缀掩码与 `--custom-charset*` 组合正确。

### 8.3 候选生成功能

- [ ] 小样本（3 行字典 × 3 变体）逐候选比对预期序列，验证 §4.5 的变体索引顺序；
- [ ] 批次边界不重不漏（`next_batch` 任意 `max` 下 `start_index` 连续）；
- [ ] 1M 候选生成单测通过；
- [ ] 已知密码端到端命中（ZIP，退出码 0，`FOUND:`）。

### 8.4 断点与恢复功能

- [ ] 对全部全局索引 `0..=total`（小样本）逐一验证：`into_source(i)` 的输出等于完整序列的第 `i` 项起的后缀；
- [ ] 字典行边界（`index = k×V`）恢复时从该行变体 0 开始，不跳过；
- [ ] `--resume` 端到端：先跑出检查点，改 watermark 到某行边界，恢复后命中该行之后的密码；
- [ ] 改规则顺序、改前后缀掩码、改自定义集、改长度区间任一情况，`--resume` 均因 `attack signature changed` 拒绝；
- [ ] 字典文件内容变化，`--resume` 因 `dictionary fingerprint changed` 拒绝。

### 8.5 估算功能（时间 + 空间）

- [ ] `--estimate` 打印字典行数、V、总候选数（`u128`）、逐生成器分解；
- [ ] **时间预估**：ETA 与 24h 容量按归档格式实测速率计算，与 W2-002/003 口径一致；
- [ ] **空间预估**：打印 `SpaceEstimate` 的水位位图字节数与峰值（十进制 MB，标注不含归档会话）；
- [ ] 位图超过 128 MB 时打印警告，ETA >24h 时打印警告；
- [ ] `--estimate` 不启动攻击（无 `FOUND:`、不写检查点）；
- [ ] 总候选数超过 `usize::MAX` 时，`--estimate` 仍展示 `u128` 值并标注不可执行，实际攻击拒绝。

### 8.6 性能与内存

- [ ] 500 MB 级字典不整本进内存（RSS 参考 W1-007 的 ~11 MB + 位图）；
- [ ] 1M 候选生成开销不成为 ZIP 验证瓶颈（参考 W2-002 的 2.8% 开销）；
- [ ] 水位位图内存按 `total/8` 字节计算并记录（大组合下可能很大，见 §9 风险）。

## 9. 风险与已知限制

- **水位位图放大**：`total = 字典行数 × V` 可能远大于字典行数。500 万行 × 100 变体 = 5 亿候选 → 位图约 62.5 MB。W1-007 的 O(N/8) 位图在这里被 V 放大，是本切片最大的内存风险。缓解：首版不做优化，但在基准中记录实际 RSS；若成为瓶颈，留给 W2-008 后单独评审（可能改为按字典行水位 + 行内变体位图的两级结构）。
- **恢复 O(N) 跳过**：与 W1-007 相同，`--resume` 要顺序跳过到目标行；大字典 + 大 watermark 时启动较慢。
- **规则是字节级**：非 ASCII 字典行不会被大小写/反转变形；用户若需要 Unicode 变形，属于 W2-006 编码变体范畴。
- **不做通用规则引擎**：用户无法表达"跳过前 3 个字符"等复杂变换；这是首版范围决定，不是缺陷。
- **掩码前后缀与固定前后缀的重复**：`append:123` 与 `suffix-mask '123'` 功能重叠；前者是规则链（1 个变体），后者是掩码（1 个变体）。文档需说明推荐用 `append`（更直观），掩码用于产生多个候选。
- **`sha2` 已是既有依赖**，无新增许可登记；无 RAR/hashcat 边界变化。

## 10. 已定问题

1. ~~默认 `identity` 的触发条件~~ **已定（2026-11-27）：无 `--rule` 时插入一条 `identity`，并在指纹中记为 `rule[0]=identity`**；
2. ~~空规则链~~ **已定：`--rule ''` 报错**；
3. **字典行超长**：首版沿用 W1-007 的 1 MiB 行上限与 W2-002 的 128 位置上限；不额外引入 256 字节候选上限（hashcat 4.0+ 的口径留待 W2-006/后续评审，避免因个别超长行破坏 `V` 的均匀性与全局索引）。

## 11. 实现记录（2026-11-27）

- **规则**：`core/crates/acx-core/src/candidates/rules.rs`（8 个变换、`|` 链、ASCII 字节语义、literal `??`、≤64 B、≤8 段）。
- **候选源**：`candidates/hybrid.rs`（`HybridSet`/`HybridSource`/`HybridEstimate`）。字典外层、变体内层，`index = dict_line × V + variant`；流式读取，恢复按 `dict_line` 顺序跳过；批内 8 MiB 上限由源自身实现。
- **变体顺序**：`--rule` 按 CLI 顺序，然后一个合并 affix 生成器（`prefix + word + suffix`，后缀最快）；无 `--rule` 时默认 `identity`。
- **u128 路径**：affix keyspace、`V`、`total` 全程 `u128`；`into_source` 在 total 确认可执行后才转 `usize`，超过 `usize::MAX` 时只允许 `--estimate`。
- **Checkpoint**：schema v2 不升版，`attack_mode=hybrid`、`dictionary=Some`；签名 = 规则原文（含默认 identity）+ 前后缀原文 + 4 个自定义集原文。
- **空间估算**：复用 W2-003a 的 `SpaceEstimate`（位图 + `threads+3` 个在飞批次 + 源缓冲；8 MiB cap；不含归档会话）。
- **CLI**：`--rule`（可重复）、`--prefix-mask`、`--suffix-mask`、`-m hybrid`；与 `--mask`/`--brute` 互斥，必须给 `-d`。
- **测试**：`cargo test --workspace` 144 core / 69 CLI passed（1 ignored）/ 2 FFI；规则单测 7、hybrid 单测 9、hybrid 端到端 10。
- **跨平台**：Windows x64 已验证；Linux/macOS 仅 CI 编译/单测，未做运行时验证。

## 12. 交接

```text
STATUS: done
CHANGED: core/crates/acx-core/src/candidates/{rules,hybrid,dictionary,mask,mod}.rs、estimate.rs、acx-cli/src/main.rs、acx-cli/tests/w2_004_hybrid.rs、docs/tasks/W2-004-hybrid-rules.md
VERIFIED: fmt / clippy -D warnings / cargo test --workspace（144 core / 69 CLI +1 ignored / 2 FFI）/ MSRV 1.89；PR #28 CI 6/6
NOT VERIFIED: 1M×1GB hybrid 基准；7z/RAR hybrid 端到端；RSS 实测；Linux/macOS 运行时；未新增 256 字节候选上限
NEXT: W2-005 批量任务/包间复用、W2-006 编码变体与严格模式、W2-007 CPU 快筛补全
RISKS: 水位位图随 V 放大（W2-003a 已告警）；恢复 O(N) 跳过；字节级规则不覆盖 Unicode
```
