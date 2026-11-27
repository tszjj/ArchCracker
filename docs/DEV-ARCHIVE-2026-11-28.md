# 开发进度归档（2026-11-28）

> 用途：冻结 W1 → W2-007 的交付状态，作为切换到**本地开发模式**后的起点。
>
> 归档基线：`main` @ `e3854c1`（merge PR #37）。
>
> 本地复核：在 `core/` 下执行 `cargo test --workspace --locked`，core 165 / CLI 各文件通过（1 ignored）/ FFI 2，全绿。

---

## 1. 归档时的阶段快照

| 阶段 | 状态 | 证据 |
|---|---|---|
| W0 Bootstrap | 基本完成 | 仓库、Apache-2.0、CI 配置、用户级工具链脚本、Rust workspace、ADR 0001–0005、最小 C ABI |
| W1 核心 CLI | **已签核（2026-11-26）** | W1-001…W1-010；PR #10–#15；`W1-SIGNOFF.md` |
| W2-002 掩码 | 已合并 | PR #23 |
| W2-003 暴力 | 已合并 | PR #26 |
| W2-003a 空间估算 | 已合并 | PR #28 |
| W2-004 混合/规则 | 已合并 | PR #28 |
| W2-005 批量任务 | 已合并 | PR #30 |
| W2-006 编码变体/严格模式 | 已合并 | PR #33 |
| **W2-007 CPU 快筛补全** | **已合并** | PR #36 / merge `c4cdbc2`；功能提交 `e9b33b1`；CL 见 `docs/CL-W2-007.md` |
| 状态同步 | 已合并 | PR #37 / merge `e3854c1` |
| W2-008 语料/差分/基准 | **本地验证完成，已签核** | `docs/tasks/W2-008-corpus-differential-benchmark.md`、`docs/W2-SIGNOFF.md` |
| W2-001 GPU/hashcat | Deferred | W2 不启动 |
| W3 GUI / W4 安装包 / W5 Beta | 未开始 | 前端目录仅 README 占位 |
| D1–D3 其他平台 | Deferred | 仅保留接口 |

## 2. W2-007 交付归档

**交付物**

- 统一判据契约：`core/crates/acx-core/src/archive/filters.rs`（`FastFilterKind` / `FilterCounts`）。
- 计数：`ArchiveStats` / `JobStats` 新增 `full_attempted`、`external_attempts`、`by_filter`；接入 `--report-stats` 与 batch 报告。
- ZIP：确认 `zip` crate 已内置 verifier，只接入计数，不新增重复判据；该精确判据是 `--strict` 唯一例外（已登记在任务文档 §2/F2/F5）。
- 7z / RAR5：内部判据保留，以适配器接入统一统计；RAR 每次外部进程调用计 `external_attempts`。
- `ArchiveSession::was_variant_skipped()`：修复 7z 非 UTF-8 / RAR OEM 跳过变体的计数双重计入，守恒 `attempts = fast + full`。
- RAR4 `-hp` 首头校验结论：**no-go**，继续外部 `UnRAR t`；证据 `docs/analysis/rar4-hp-header-feasibility.md`。
- 测试：`tests/w2_007_filters.rs` 5 个 E2E、`w1_rar_external.rs` RAR 计数 1 个（本机 UnRAR 6.24 实跑）、若干单测。
- 证据与变更记录：`docs/benchmarks/W2-007.md`、`docs/CL-W2-007.md`、`docs/tasks/W2-007-cpu-fast-filters.md` §实现记录。

**审阅结论**：reviewer 首轮 REQUEST_CHANGES（skip 路径计数公式、RAR 测试覆盖、strict 契约）→ 修复后复审 APPROVE；architect 契约补丁后放行；release APPROVE。

**已知非阻塞项**：ZipCrypto 1/256 检查头碰撞会影响 fast/full 分配但不影响命中；头加密 7z 无首块 probe；`Stats:` 行对位置敏感的解析器不兼容；全量差分与 1M 基准留给 W2-008。

## 3. 切换到本地开发模式（2026-11-28 起）

**原因**：GitHub Actions 计费账户的月度额度耗尽，6 个 job 全部未启动（非代码失败）。为避免阻塞验证，后续开发先在本地完成。

**约定**

1. 仍从 `main` 开本地分支（`docs/*` / `feat/*` / `fix/*`），保留提交历史；**不在 `main` 上直接提交**。
2. 本地分支暂不 push / 不开 PR；待额度恢复或切换 CI 通道后，再按 `AGENTS.md` 流程补齐评审与合并。
3. 每次改动后必须在本地跑等价门禁，并把命令与结果写入对应 `docs/benchmarks/` 或任务文档：

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force; . .\scripts\env.ps1
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked
cargo deny check licenses bans sources
cargo build --workspace --release --locked
```

4. 跨平台结论一律写"Windows x64 本地验证 / Linux·macOS·移动端未验证"，不得把本地结果写成 CI 结果。
5. 样本归档、字典、明文密码不入库；只提交生成脚本、manifest、哈希与报告。
6. 本归档文件与 W2-008 目标文档提交在本地分支 `docs/local-dev-w2-008`，未推送远端。

## 4. Windows 全栈验证（当前优先）

范围：在 Windows x64 上把已交付的 CLI 栈端到端跑通，**不含 GUI / 安装包**（属 W3/W4）。Oracle 为本机 7-Zip 26.04 与 WinRAR/UnRAR 6.24。

| 编号 | 验证项 | 完成标准 |
|---|---|---|
| WV-1 | 格式与加密：ZIP ZipCrypto / AES-128/192/256、7z AES / `-mhe=on`、RAR4 `-ma4` / `-hp`、RAR5 | 已知密码 100% 命中；错误密码 0 命中；与 oracle 差分一致 |
| WV-2 | 分卷/SFX：ZIP/7z `.001`、RAR `.partN`/`.r00`、简单 SFX；缺卷/截断/损坏分类 | 预检分类 100% 正确；PKZIP `.z01` 明确报不支持 |
| WV-3 | 攻击模式：字典、掩码、暴力、混合/规则 + `--estimate` | 各模式已知密码命中；索引/断点水位一致 |
| WV-4 | 编码变体与严格模式：ZIP GBK/CP437、RAR4 OEM、7z 中文；`--strict` / `--rar-no-fast-reject` | 默认/严格命中率一致（0 漏报）；变体计数与快筛计数满足公式 |
| WV-5 | 运行控制与断点：暂停/继续/停止、Ctrl+C、`--resume`、硬杀恢复 | 控制观察 ≤200 ms；硬杀重放 ≤4096；不丢候选 |
| WV-6 | 批量任务：`acx batch jobs.toml`、失败隔离、独立断点、有限并行、密码复用 | 单包失败不影响其他任务；每任务报告计数正确 |
| WV-7 | 快筛与计数：ZIP/7z/RAR5 判据、`full_attempted`/`external_attempts`、按判据桶 | 0 误杀；公式成立；external ⊆ full |
| WV-8 | 基准：1M 级各模式 p/s、CPU、RSS、ETA 误差 | 同机同语料同电源；结果写 `docs/benchmarks/W2-008.md`；不引用未实测数字 |

其中 WV-1/3/4/5/6/7 已有自动化用例或本机实测，WV-2 的第三方 SFX / `-hp` 语料与 WV-8 的全量 1M 矩阵由 W2-008 补齐。

## 5. 恢复线上流程的条件

- GitHub 计费恢复或改用自托管 runner / 公开仓库等替代通道；
- 重跑 `main` 合并后的 CI（当时 run `46025110880`），确认 6/6 绿；
- 把本地分支按 `AGENTS.md` 流程补 PR + reviewer/architect/release 评审；
- 更新 `docs/PROJECT-GUIDE.md` §2 状态与 CL/任务文档中的 CI 证据链接。
