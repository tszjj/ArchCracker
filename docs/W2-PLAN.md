# W2 阶段目标划分（计划）

- **状态**：**已批准启动（W1 signoff 2026-11-26）；从 W2-002/003 开始**
- **准入意见**：W1 已签核（[W1-SIGNOFF](W1-SIGNOFF.md)），按本计划进入 W2；W2-001 GPU 继续 Deferred
- **周期**：2–3 周
- **首发平台**：Windows 10/11 x64 CLI；GUI 仍属 W3
- **GPU**：W2-001 已 **Deferred**，W2 不启动 hashcat/GPU

## 1. W2 目标

在 W1 的 ZIP/7z/RAR + 字典 + 流式 + 断点基础上，补齐 CPU 攻击面、批量和编码变体，使 Windows CLI 达到 beta 可用：

- 掩码、暴力、混合/规则；
- 批量任务/包间复用；
- ZIP/RAR4/7z 的 CPU 快筛和严格模式；
- 编码变体、错误分类和 CLI 状态输出；
- 可复现的差分/负例/基准证据。

**不包含**：GUI、安装包/签名、GPU/hashcat、RAR 解压器/压缩器。

## 2. 工作包

### W2-001 GPU/hashcat spike — Deferred

- 不启动、不阻塞 W2 准入/退出；
- W2 退出后单独评审，更新 ADR/任务再决定；
- 当前 Cargo 依赖不得出现 hashcat/CUDA/HIP/OpenCL。

### W2-002 掩码攻击

- 语法：`?d ?l ?u ?s ?a ?b ?1..?4` + 固定字符 + 位置集合；
- 键空间计算、长度区间、短密码优先、UInt128 分区；
- 与 W1 `CandidateSource` 批次/检查点/暂停停止复用；
- 验收：已知密码 100%、键空间不重不漏、越界/非法掩码错误、1M 级 p/s。

### W2-003 暴力/键空间

- 字符集 + 长度区间；短密码优先；
- UInt128 键空间分区，按 worker/断点分配；
- 支持 `--resume` 键空间水位；
- 验收：小键空间穷举、分区不重不漏、暂停/停止/恢复。

### W2-004 混合/规则

- 字典 × 前后缀掩码；
- hashcat 风格最小规则集（P2 子集）；
- 规则错误/长度上限/编码；
- 验收：与字典/mask 组合的命中、规则去重语义、差分。

### W2-005 批量任务/包间复用

- 多归档队列、串行/并行策略、失败隔离；
- 已找到密码的包间复用（仅授权语料）；
- 每任务独立 checkpoint/指纹/进度；
- 验收：批量 100 包、单包失败不拖垮队列、密码复用正确。

### W2-006 编码变体与严格模式

- ZIP 无 UTF-8 标志的 CP437/GBK 变体；RAR4 OEM/UTF-8；7z UTF-8；
- 密码编码矩阵与差分；
- `--strict`/`--rar-no-fast-reject`（禁用 RAR5 check 快筛做差分/排障）；
- 验收：非 ASCII 已知密码、假阴性 0、严格模式与外部 oracle 一致。

### W2-007 CPU 快筛补全

- ZIP verifier/结构判据；RAR4 头加密首头校验（仅评审通过后）；7z 头 CRC/首块；
- 快筛只否决，命中仍由内置引擎/`UnRAR t` 复核；
- RAR5 ASCII 快筛边界沿用 ADR-0005；非 ASCII 回退；
- 验收：错误候选 0 误报、严格模式 0 漏报、性能记录。

### W2-008 语料/差分/基准

- ZIP/7z/RAR 差分 oracle、10⁷ ZIP 负例、1GB 归档、分卷/SFX 负例；
- W2 各攻击模式 p/s、CPU、内存、ETA；
- 结果写入 `docs/benchmarks/W2-*.md`，样本/字典不入库。

## 3. 依赖与顺序

```text
W1 signoff
   │
   ├─ W2-002 mask ──► W2-004 hybrid/rules
   ├─ W2-003 brute ─┘
   ├─ W2-006 encoding/strict ──► W2-007 fast filters
   └─ W2-005 batch/jobs ──► W2-008 evidence
W2-001 GPU: Deferred（不在关键路径）
```

建议先做 **W2-002/003**（候选源复用 W1 接口），再做 W2-004/005/006/007，最后 W2-008 收口。W2-006 的编码差分最好在 W2-002/003 前建立最小矩阵，避免后面返工。

## 4. W2 退出标准

- 掩码/暴力/混合/规则全部可用，已知密码 100%；
- 批量/包间复用/编码变体/严格模式通过语料；
- CPU 快筛 0 误报、严格模式 0 漏报；
- 1M 级基准、p/s/CPU/内存/ETA 记录；无 P0/P1；
- `cargo fmt/clippy/test`、MSRV 1.89、release、cargo-deny、CI 全绿；
- 许可边界不变：RAR 只外部/独立 check，hashcat 不是 Cargo 依赖，GUI 不引入。

## 5. 角色

- core-engineer：候选源/调度/引擎；
- qa-engineer：语料/差分/基准；
- reviewer：正确性/许可；
- architect：攻击接口/ADR；
- release-engineer：CI/许可门禁。
