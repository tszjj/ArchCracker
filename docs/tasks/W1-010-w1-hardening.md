# W1-010：W1 准出硬化与证据收口

- **状态**：**完成（PR #10–#15 已合并，W1 signoff 2026-11-26）**
- **分支**：`feat/w1-009-rar5-fast-check`（W1-010 证据文档随 W1-009 PR；硬化代码如再开展另开分支）
- **角色**：qa-engineer + core-engineer + release-engineer
- **依赖**：W1-001…W1-009
- **范围**：补齐 W1 准出剩余证据，不新增攻击能力

## 任务

1. **ZIP 10⁷ 负例长跑**：✅ 393.569 s / 25,409/s，0 误报；详见 [W1-010 基准](../benchmarks/W1-010.md)。
2. **当前 4096 窗口复测**：✅ ZIP 39.335 s/25,423/s；7z 1033.040 s/967.9/s；RAR5 578.958 s/1727.2/s。
3. **暂停/停止时延矩阵**：✅ pause 状态立即置位；stop→退出 ZIP 0.709 ms、7z 11.581 ms、RAR 5.545 ms；1 GB 正确候选尾延迟 ZIP 1091.804 ms、7z 5036.663 ms、RAR 5.686 ms；硬杀重放 1242 候选。详见 [W1-010 基准](../benchmarks/W1-010.md)。
4. **PR 合并/签核**：#10→#11→#12→#13→#14→#15，CI 全绿；待里程碑签核。
5. **第三方 `-hp` 语料**：本机 fixture 已验证；更广泛第三方样本未测，按用户停止测试指令保留风险。
6. **物理核数默认值**（可选）：仍默认 1；文档要求显式 `-t`。

## 验收

- [x] ZIP 10⁷ 0 误报；
- [x] 当前窗口 1M ZIP/7z/RAR 数据；
- [x] 暂停/停止/1 GB 尾延迟矩阵；
- [x] PR 合并/W1 signoff；
- [x] 98 core / 39 CLI（1 ignored）/ 2 FFI；CI/MSRV/release/cargo-deny；
- [x] W1 正式签核（[W1-SIGNOFF](../W1-SIGNOFF.md)）。

## 交接

```text
STATUS: done
CHANGED: docs/W1-SIGNOFF.md, docs/W1-ASSESSMENT.md, docs/W2-PLAN.md,
         docs/tasks/W1-010-w1-hardening.md, docs/benchmarks/W1-010.md,
         core/crates/acx-cli/examples/w1_latency.rs
VERIFIED: PR #10-#15 merged; ZIP 10M 393.569s/25,409/s/0 false;
          1M ZIP/7z/RAR current window; pause/stop 1GB matrix; hard-kill 1242
NOT VERIFIED: broader third-party -hp; physical core default
NEXT: W2-002/W2-003 per W2-PLAN
RISKS: 7z 1GB stop tail 5.04s; RAR non-ASCII fallback; third-party -hp corpus
```
