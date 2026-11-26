# W1 里程碑签核

- **签核日期**：2026-11-26
- **签核对象**：W1-001…W1-010
- **基线**：`main` 合并 PR #10–#15 后（W1-009 merge `d9fa679`；签核文档单独提交）
- **结论**：**W1 通过，允许进入 W2 规划/实现**
- **W2 准入意见**：**GO**（见 [W1 评估](W1-ASSESSMENT.md)）

## 1. 合并记录

| PR | 内容 | 状态 |
|---|---|---|
| #10 | W1-004 7z AES/头加密 | 已合并 |
| #11 | W1-005 分卷/SFX | 已合并 |
| #12 | W1-006 运行控制/断点 | 已合并 |
| #13 | W1-007 流式字典 | 已合并 |
| #14 | W1-008 1M×1GB 基准 | 已合并 |
| #15 | W1-009 RAR5 快筛 + W1 评估/矩阵 | 已合并 |

- `main` 合并后 CI（6 job）全绿。
- 本地：98 core / 39 CLI（1 ignored）/ 2 FFI；fmt/clippy/MSRV 1.89/release/cargo-deny 通过。

## 2. 关键证据

- ZIP 1M：39.335 s / 25,423/s；ZIP 10M：393.569 s / 25,409/s，0 误报。
- 7z 1M：1033.040 s / 967.9/s。
- RAR5 1M：check 快筛 578.958 s / 1727.2/s（外部整包基线 4515.104 s）。
- 暂停/停止 1 GB 矩阵：pause 状态立即置位；stop 退出 ZIP 0.709 ms/7z 11.581 ms/RAR 5.545 ms；1 GB 正确候选尾延迟 ZIP 1.092 s/7z 5.037 s/RAR 0.006 s；硬杀重放 1242 ≤4096。
- ADR-0005 完成法务复核（附条件）；RAR5 快筛不复制/链接 UnRAR，不做解压/压缩，命中仍外部 `UnRAR t`。

## 3. 已知限制（不阻塞 W2）

- RAR5 非 ASCII 快筛未启用，回退外部，性能提升有限；RAR4 1M 不在 W1 性能承诺内。
- 1 GB 7z 候选停止尾延迟约 5.04 s，超过 2 s；文档已记录，不承诺抢占式中断。
- RAR5 `-hp` 只有本机 fixture，第三方语料仍待扩。
- CPU 线程默认值仍为 1，需要 `-t`；物理核数默认调优进入 W2/后续。
- RAR4 损坏仍部分走 External；前端错误码未映射（W3）。

## 4. 交接

```text
STATUS: done
CHANGED: docs/W1-SIGNOFF.md, docs/W1-ASSESSMENT.md, docs/W2-PLAN.md,
         docs/PROJECT-GUIDE.md, docs/GITHUB.md, README.md, AGENTS.md
VERIFIED: PR #10-#15 merged; main CI 6/6 green; 98 core / 39 CLI / 2 FFI
NOT VERIFIED: broader third-party -hp corpus; physical-core default
NEXT: W2-002/W2-003（CPU 攻击面）按 W2-PLAN 开分支
RISKS: RAR non-ASCII fallback; 1GB 7z stop tail; third-party -hp corpus
```
