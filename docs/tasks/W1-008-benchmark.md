# W1-008：正式基准与 W1 收口证据

- **状态**：**完成（三格式 1M×1GB 实测；W1 正确性长跑另列）**
- **门禁**：W1 准出/W2 准入前的最后证据切片
- **角色**：qa-engineer + release-engineer
- **分支**：`feat/w1-008-benchmark`
- **依赖**：W1-001…W1-007
- **范围**：1M 字典、1GB+ 归档、p/s、CPU、内存、ETA；不含新算法/GPU/GUI

## 1. 目标

- 用 release CLI 和可复现脚本测 ZIP / 7z / RAR；
- 记录 wall time、吞吐、进程 RSS、CPU、退出码；
- 明确已知密码命中率、错误候选、错误分类和未验证项；
- 用结果决定 W1 是否准出，必要时调整口径，不把“未跑”写成“通过”。

## 2. 已确认的硬限制

- RAR 当前每个候选启动外部 `UnRAR t` 整包测试；1M 实测约 75 min，成本最高；
- 7z 每个候选都有 AES KDF；1M 实测约 21 min（14 线程）；
- ZIP AES 1M 实测 42.247 s；
- 用户的大归档/字典不提交仓库；基准记录文件大小/条目数/命令，不记录密码。

## 3. 基准矩阵

| 格式 | 归档 | 候选 | 状态 |
|---|---|---|---|
| ZIP AES | 1.3 GB `zip加密.zip` | 1M 错误 | ✅ 42.247 s，约 23,670/s，RSS 3.1 MB |
| 7z AES | 1.3 GB `新建压缩.7z` | 1M 错误 | ✅ 1271.049 s，约 786.8/s，RSS 3.1 MB，CPU 约 11.2 核 |
| RAR5 | 1.3 GB `rar单个压缩.rar` | 1M 错误 | ✅ 4515.104 s，约 221.5/s，RSS 3.1 MB（父进程） |
| 已知密码 | W1 测试夹具 | 各格式 | 既有集成测试 100% |

## 4. 验收与口径

- [x] release binary + 可复现脚本 [bench-w1.ps1](../../scripts/bench-w1.ps1)；
- [x] ZIP 1M 实际完成并记录 p/s/RSS/CPU；
- [x] 7z 1M 实际完成；
- [x] RAR 100 候选采样 + 单候选成本；
- [x] RAR 1M 实际完成（4515.104 s / 221.5/s）；
- [x] 结果写入 [W1-008 基准报告](../benchmarks/W1-008.md)；
- [x] 明确 W1 准出口径：三格式 1M 性能已实测，RAR 成本最高；
- [x] CI/MSRV/release/cargo-deny 与基准同 commit。

**准出判断**

- 1M × 1GB ZIP/7z/RAR 性能门禁：**实测全部通过**；
- RAR 约 75 min，主要成本是每候选一个外部 `UnRAR t`；W2 快筛仍是后续优化；
- ZIP 10⁷ 长跑、7z/RAR 10⁵ 差分矩阵、暂停/停止时延矩阵仍需在 W1 准出评审中逐项确认，不能用本基准替代。

## 5. 交接

```text
STATUS: done（W1-008 三格式 1M×1GB 实测）
CHANGED: scripts/bench-w1.ps1, docs/benchmarks/W1-008.md, docs/tasks/W1-008-benchmark.md
VERIFIED: ZIP 42.247s/23,670/s; 7z 1271.049s/786.8/s; RAR 4515.104s/221.5/s
NOT VERIFIED: ZIP 10^7 long run; pause/stop latency matrix; 7z/RAR 10^5 full differential
NEXT: W1 准出评审/里程碑推送
RISKS: RAR 75 min; ZIP correctness long run remains
```
