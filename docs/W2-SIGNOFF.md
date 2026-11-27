# W2 阶段签核

- 日期：2026-11-28
- 评审编号：W2-EXIT-REVIEW-2026-11-28
- 签核范围：`docs/W2-PLAN.md` §4 六条准出标准；`docs/W2-EXIT-PLAN.md` G1–G7
- 功能基线：`feat/w2-008-corpus-evidence @ da3adf7`；公开仓库主基线 `main @ e3854c1`
- CI 证据：仓库转公开后重跑 `main` run [`46025110880`](https://github.com/tszjj/ArchCracker/actions/runs/46025110880)，**6/6 成功**；W2-008 分支的远端验证见合并 PR（合并后回填 run id）。
- 结论：**GO（有条件签核）**。条件仅为"列为未验证的证据项"，不再是功能开发阻塞项；无 P0/P1 缺陷。

## 1. 准出清单

| 门 | 标准 | 结论 | 证据 |
|---|---|---|---|
| G1 功能 | 掩码/暴力/混合/规则可用；批量/编码变体/严格模式通过语料 | ✅ 通过（限定已测语料） | PR #23/#26/#28/#30/#33/#36；`docs/benchmarks/W2-008.md` §4/§5 |
| G2 正确性 | 快筛 0 误杀、strict 0 漏报、完整复核 0 误报 | ✅ 通过（限定证据范围） | W2-007 小型差分 + `docs/benchmarks/W2-007.md`；W2-008 oracle 差分 5/5；计数公式 4/5 用例断言 |
| G3 性能 | 1M 级 p/s、CPU、内存、ETA；无 P0/P1 | ✅ 通过（限定 ZIP 单格式） | `docs/benchmarks/W2-008.md` §4；W1-010 基线；ETA 仅 hybrid 可比 |
| G4 质量 | fmt/clippy/test/MSRV/release/cargo-deny/CI 全绿 | ✅ 通过 | 本地六项全绿（`W2-008.md` §6）；main CI 6/6（run `46025110880`） |
| G5 许可 | RAR 外部、hashcat 非依赖、无 GUI、无新依赖 | ✅ 通过 | ADR 0003/0004/0005；`docs/licensing.md`；release 复核 |
| G6 文档 | 任务文档、基准报告、CL、归档、签核文件齐备 | ✅ 通过 | 本文件；`docs/CL-W2-007.md`；`docs/DEV-ARCHIVE-2026-11-28.md`；`docs/benchmarks/W2-008.md` |
| G7 平台 | Windows x64 验证；其他平台标注未验证 | ✅ 通过 | `W2-008.md` §5/§7；CI 覆盖 Windows/Linux/macOS 编译，运行时仅 Windows x64 |

## 2. 评审角色意见

- **reviewer（正确性/证据）**：无 P0/P1；要求修正 1M 统计行对 0 误杀的过度推断、oracle 表格、公式断言范围、WV-1 措辞与路径。本次签核前已修正 `docs/benchmarks/W2-008.md`。
- **architect（范围/边界）**：W2 范围清晰；GPU/GUI/`?b`/`--mask-file`/通用规则引擎等为后续阶段或明确排除项；架构边界保持；要求修正 `architecture.md` 的 `?b`/规则状态与 roadmap 复选框。已修正。
- **release-engineer（质量/许可/平台）**：本地门禁不能替代 CI；转公开后重跑 CI 6/6 已满足硬前置；许可边界与平台标注合格；要求统计行格式扩展写入发布说明。

## 3. 已知限制与未验证项（签核时显式保留）

1. 1M 规模未做默认/strict 全量命中率对照；0 误杀证据来自小语料差分与 oracle 用例。
2. 1M 基准仅 ZIP 一种格式；7z/RAR 1M、编码变体 1M p/s 未测。
3. ETA 仅 hybrid 有可比样本；字典模式不支持 `--estimate`。
4. 本次 W2-008 语料无分卷/SFX、非 ASCII 归档、1 GB 条目；头加密 7z 负例差分未构造。
5. RAR4 `-hp` 第三方语料不足，维持 no-go；RAR5 非 ASCII 仍回退外部。
6. Linux/macOS/Android/HarmonyOS 运行时、非 Windows OEM 回退 CP437 未验证。
7. 水位位图实际常驻内存对比未做；1 GB 尾延迟沿用 W1-010 结论，本次未重测。
8. `Stats:` 行新增判据桶与计数字段；按字段位置解析的下游需适配（发布说明中标注）。
9. GitHub 分支保护未启用；本仓库以 `main` 不可直接 push 的流程/本地钩子约束为准（见 `docs/GITHUB.md`）。

## 4. 后续行动项

| # | 行动 | 责任角色 | 完成标志 |
|---|---|---|---|
| A1 | 合并 W2-008 分支并回填合并 PR/run id 到本文件 | release-engineer | 本文件 §头部 CI 证据含合并 PR 链接 |
| A2 | 合并后清理公开仓库旧分支，仅保留 W2 基线 `main` | release-engineer | `git branch -r` 仅 `origin/main`（与 HEAD） |
| A3 | 发布说明标注 `Stats:` 行扩展与非 Windows 平台未验证 | release-engineer | W4/发布清单引用本文件 |
| A4 | RAR5 校验器 ADR-0005 附条件复核 | release-engineer | W4 发布前复核记录 |
| A5 | 1M strict 对照与 7z/RAR 基准 | qa-engineer + core-engineer | 新基准报告；不阻塞 W2 签核 |

## 5. 签核结论

W2 的功能目标与准出标准在已声明的证据范围内达成，CI 硬前置已满足。允许进入 W3（C ABI v1 + Avalonia GUI）准备；上述未验证项作为 W3/W4 与后续基准的输入，不得表述为"已完成"。

**STATUS: GO（有条件签核）**
