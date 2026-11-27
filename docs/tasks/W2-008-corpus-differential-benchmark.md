# W2-008：语料 / 差分 / 基准 — 设计目标

- 状态：预期目标已定稿（2026-11-28），**尚未实现**
- 日期：2026-11-28
- 门禁：W2 准出项；为 W3 GUI 与 W2 退出提供可复现证据
- 角色：qa-engineer 主责；core-engineer 支持计数/工具接口；reviewer 复核正确性与口径；architect 复核边界；release 复核许可与平台标注
- 分支：`feat/w2-008-corpus-evidence`（本地待创建）
- 依赖：W2-007 已合入（PR #36、`c4cdbc2`）；W1-008 / W1-010 基准；W2-002/003/004/005/006 攻击模式；本机 7-Zip 26.04 与 WinRAR/UnRAR 6.24
- 开发模式：**本地开发**（GitHub Actions 额度耗尽，见 `docs/DEV-ARCHIVE-2026-11-28.md` §3）；CI 证据待额度恢复后补

> 本文只定义**预期目标与验收**；`docs/W2-PLAN.md` §3「W2-008 语料/差分/基准」为实现目标参考，准出按 §4 和本文 §8。W2-007 已完成的判据与计数在本切片作为验证对象，不重新设计。

## 设计目标

在 W1 基线与 W2-007 快筛判据之上，建立**可复现、可审计、不入库样本**的本地验证体系：用生成脚本构造覆盖多格式/多编码/多负例的小型语料，用 7-Zip/UnRAR 做 oracle 做差分，证明快筛 0 误杀、严格模式 0 漏报、命中 0 误报；再以 1M 级矩阵记录各攻击模式的吞吐、CPU、RSS 与 ETA 误差，形成 W2 退出与 Windows 全栈验证的证据包。

## 1. 目标用户与使用场景

| 用户 | 场景 | 本切片为其解决什么 |
|---|---|---|
| QA / reviewer | 验证 W2-007 快筛是否误杀、strict 是否漏报 | 可重跑的差分脚本 + 小型语料清单 + 计数公式断言 |
| 终端用户 | 大字典 × 多归档的真实恢复 | 1M 级吞吐与 ETA 误差有本机实测，不用估算 |
| 后续 W3 GUI 开发者 | 需要可信的进度/统计口径 | 统一统计字段的实测量级与边界说明 |
| release-engineer | W2 准出与发布审计 | 报告含机器、工具版本、语料哈希、未验证项 |

## 2. 与 W2-007 / W1 基线的关系

- **不重新实现** W2-007 判据；本切片验证 `zip_verifier` / `sevenz_first_block` / `rar5_check_value` 与 `full_attempted` / `external_attempts` 的真实表现。
- W2-007 已给出的结论保持有效：ZIP 不新增重复判据（crate 已内置 verifier，无吞吐 before/after 可宣称）、RAR4 `-hp` no-go（外部调用不下降，只量化调用次数）。
- 复用 W1-010 的 4096 in-flight 窗口与准出数字（ZIP 25,423/s、7z 967.9/s、RAR5 1,727.2/s）作为"同机同口径"对照；不引用 W1-008 旧口径。
- 复用 `tests/README.md` 的语料矩阵与规则；语料只提交脚本、manifest、哈希与小型文本向量。

## 3. 核心功能目标（可衡量）

| # | 功能目标 | 衡量方式 |
|---|---|---|
| F1 | 建立语料生成脚本与 manifest | `tests/corpus/` 下按格式/加密/分卷/SFX/非 ASCII/负例生成；每条记录命令行、工具版本、大小、SHA-256；仓库内无归档/字典二进制 |
| F2 | 建立差分 oracle 脚本 | ZIP/7z 用内置完整验证、RAR 用外部 `UnRAR t`；与 7-Zip 26.04 / UnRAR 6.24 对照，命中/未命中/错误分类逐项一致 |
| F3 | 覆盖 W2-007 判据 | 负例差分证明 0 误杀；`--strict` 与默认在已知密码语料上命中率一致（0 漏报）；按判据桶、`full_attempted`、`external_attempts` 满足 §4.4 公式 |
| F4 | 1M 级基准矩阵 | 字典/掩码/暴力/混合 × ZIP/7z/RAR；记录 p/s、CPU、RSS、ETA 误差；报告写入 `docs/benchmarks/W2-008.md`，与 W1 同机口径对照 |
| F5 | Windows 全栈本地验证 | 完成 `docs/DEV-ARCHIVE-2026-11-28.md` §4 的 WV-1…WV-8；每项写结论与证据路径 |
| F6 | 证据包自洽 | 所有报告可复现（脚本 + 版本 + 哈希 + 命令）；不提交样本、字典、密钥；未验证项显式标注 |

## 4. 非功能性目标

### 4.1 计数与正确性口径（沿用 W2-007 §4.4）

```text
attempts       = fast_rejected + full_attempted
variant_slots  = attempts + skipped
candidates <= variant_slots
external_attempts ⊆ full_attempted（不与 full_attempted 相加）
误杀 = 0；漏报 = 0；误报由完整复核保证 0
```

### 4.2 可复现性

- 固定机器、电源模式、杀软状态、线程数、语料哈希；报告记录 rustc/cargo、7-Zip、WinRAR 版本。
- 生成脚本可重复产出相同语料（或记录随机种子）。
- 差分脚本以退出码与结构化输出判定，不靠人工看日志。

### 4.3 兼容性 / 许可 / 平台

- 不新增 Cargo 依赖；hashcat 仍非依赖；RAR 仍只外部未修改 UnRAR，不解压、不链接、不复制源码。
- 断点 schema v2 不因本切片升版（除非发现缺陷，另开 fix 分支并评审）。
- Windows x64 本地验证；Linux/macOS 仅编译/CI 可用时补，移动端 Deferred；未验证的一律写明。

### 4.4 规模与时间上限

- 小型差分语料：每个维度可选 1–2 个代表，总量控制在本地可重复执行（分钟级）。
- 1M 基准：每种组合一次完整运行；若总时长超出本机预算，按优先级裁剪并在报告中说明，不虚构数字。

## 5. 预期交付成果

1. `tests/corpus/` 生成脚本 + manifest + 哈希清单（无二进制）；
2. `tests/differential/` 差分脚本与小型向量，覆盖 ZIP/7z/RAR4/RAR5、分卷/SFX、非 ASCII、负例；
3. 差分报告：0 误杀 / 0 漏报 / 0 误报，含默认与 `--strict` 对照、按判据计数公式断言；
4. 1M 基准报告 `docs/benchmarks/W2-008.md`：各攻击模式 p/s、CPU、RSS、ETA 误差与 W1 对照；
5. Windows 全栈验证记录（WV-1…WV-8）写入归档文档或基准报告；
6. `tests/README.md` 从"M0 仅目录说明"更新为实际的语料/脚本索引；
7. CI 恢复后的 6/6 绿灯链接（本地开发模式下待补，不阻塞目标定稿）。

## 6. 关键约束与假设

- 正确性优先：差分 oracle 不一致即为失败，不以"本项目能解压"为准。
- 7z 无认证器：候选级 CRC 失败统一按 Miss，不承诺区分密码错与 payload 损坏；损坏归档可能表现为 `NOT FOUND`。
- RAR4 `-hp` 仅第三方语料验证，快筛仍 no-go；RAR5 非 ASCII 仍回退外部。
- 编码变体：每个可表示变体独立验证；不可表示计 `skipped`，不进入 `attempts`。
- 本地开发模式：不 push / 不开 PR，直到 CI 通道恢复；所有"已验证"只指本机 Windows x64。
- 不提交样本归档、字典、明文密码；不执行来源不明的归档。

## 7. 里程碑规划

| 里程碑 | 内容 | 依赖 | 完成标志 |
|---|---|---|---|
| M1 语料与脚本 | 生成脚本、manifest、小型向量清单 | W2-007 已合入 | 脚本可重复生成；哈希入库、二进制不入库 |
| M2 差分 | oracle 对照、默认/strict 对照、计数公式断言 | M1 | 0 误杀/0 漏报/0 误报，报告可复现 |
| M3 判据证据 | ZIP/7z/RAR5 判据桶、外部调用计数、RAR4 no-go 复核 | M2 | 计数公式与 W2-007 验收逐条对应 |
| M4 1M 与 Windows 全栈 | 基准矩阵 + WV-1…WV-8 | M2/M3 | `docs/benchmarks/W2-008.md` 完成；W2 准出证据齐 |

## 8. 验收标准（可衡量）

1. 语料脚本覆盖 §矩阵的格式、加密、分卷、SFX、非 ASCII、负例；manifest 有命令行、版本、大小、SHA-256；仓库无样本二进制。
2. 差分脚本可重复执行；ZIP/7z/RAR 命中与错误分类与 oracle 一致；不一致项有明确判定与处理。
3. 0 误杀：被快筛否决的候选经完整验证确认无正确密码；0 漏报：`--strict` 与默认命中率一致；0 误报：命中均经完整复核。
4. 计数满足 §4.1 公式，`variant_slots >= candidates`，`external_attempts ⊆ full_attempted`。
5. 1M 基准至少覆盖字典/掩码/暴力/混合各一种格式组合；记录 p/s、CPU、RSS、ETA 误差，无未实测百分比。
6. Windows 全栈验证 WV-1…WV-8 全部给出结论与证据路径；未完成项明确标注，不写"已完成"。
7. 本地门禁：fmt、clippy `-D warnings`、`cargo test --workspace`、MSRV 1.89、release、cargo-deny 全绿。
8. 许可边界不变：无新依赖、无 RAR 源码、hashcat 非 Cargo 依赖、无 GUI。
9. 平台标注：Windows x64 已验证；其他平台写明未验证。
10. 报告与任务文档状态同步；CI 恢复后补绿灯链接（不阻塞本地目标定稿）。

## 许可与评审意见

无新增依赖预期；RAR 仍只通过外部未修改 UnRAR，hashcat 不是 Cargo 依赖。差分脚本调用的 7-Zip / WinRAR 为本机工具，不随仓库分发、不纳入许可登记，但报告须记录版本与来源。任何因验证发现的缺陷走独立 `fix/*` 分支与评审，不在证据切片内夹带功能改动。

## 9. 预期交接格式

```text
STATUS: planned（本地开发模式）
BRANCH: feat/w2-008-corpus-evidence（本地待创建）
CHANGED（预期）: tests/corpus/、tests/differential/、tests/README.md、
                 docs/benchmarks/W2-008.md、docs/PROJECT-GUIDE.md
ROLE: qa-engineer + review；architect/release 按边界参与
NEXT: M1 语料生成脚本与 manifest 定稿；随后 M2 差分 oracle
RISKS: 语料生成耗时、第三方 RAR 语料不足、CI 额度未恢复导致跨平台证据缺失
```
