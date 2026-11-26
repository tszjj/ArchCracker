# W1-010：W1 准出硬化与证据收口

- **状态**：**证据完成，待 PR 合并/W1 signoff**
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
- [ ] PR 合并/W1 signoff；
- [x] 98 core / 39 CLI（1 ignored）/ 2 FFI；CI/MSRV/release/cargo-deny；
- [ ] W1 正式准出签核。

## 交接

```text
STATUS: partial（证据完成，待 PR 合并/W1 signoff）
CHANGED: docs/W1-ASSESSMENT.md, docs/W2-PLAN.md, docs/tasks/W1-010-w1-hardening.md,
         docs/benchmarks/W1-010.md, core/crates/acx-cli/examples/w1_latency.rs
VERIFIED: ZIP 10M 393.569s/25,409/s/0 false; 1M ZIP/7z/RAR current window;
          pause/stop 1GB matrix; hard-kill replay 1242
NOT VERIFIED: broader third-party -hp; physical core default; PR signoff
NEXT: W1 signoff / merge PRs; then W2
RISKS: 7z 1GB candidate stop tail 5.04s (documented, not ≤2s); third-party -hp corpus
```
