# ArchCracker 项目全景与开发指引

> 最后更新：2026-11-27 · 阶段：**W1 已准出并签核；W2 已启动（Windows 全栈优先）**
>
> 本文是项目结构、文档地图和开发进度的**单一入口**。它不替代架构/许可/任务文档；
> 具体设计、验收证据和决策以链接文档为准。每次完成一个切片或调整排期时，先更新本文的状态。

## 1. 项目是什么

ArchCracker 是一个**只做授权恢复**的压缩包密码恢复工具：

- **内核**：Rust workspace，负责归档预检、候选密码、调度、引擎适配和结果复核；
- **前端**：Windows 首发，计划 Avalonia 12；CLI 已可用；Android/HarmonyOS 只保留接口；
- **格式目标**：7z、ZIP（ZipCrypto / WinZip AES）、RAR4/RAR5（外部 UnRAR）、分卷、SFX；
- **攻击目标**：字典已可用；掩码/暴力/混合在后续阶段；
- **交付形态**：Windows 只做**单一 Full 版本**，不分 Lite/Full；
- **边界**：默认离线、无遥测；不链接/复制 unRAR/7-Zip RAR 源码；hashcat 只作为外部进程，
  不是 Cargo 依赖；无 hashcat/GPU 时 CPU 多线程路径必须完整可用。

合法使用边界见 [README](../README.md) 与 [SECURITY.md](../SECURITY.md)：仅处理本人拥有或已获明确授权的归档。

## 2. 当前状态快照

| 维度 | 状态 | 证据 / 说明 |
|---|---|---|
| 当前阶段 | **W2 进行中** | W1 signoff 2026-11-26；W2-002 掩码、W2-003 暴力、W2-003a 空间估算、W2-004 混合/规则（PR #23/#26/#28）、W2-005 批量（PR #30）、W2-006 编码/严格模式（PR #33）已合入；W2-001 GPU Deferred；GUI 未开始 |
| 已完成切片 | W1-001…W1-010；W2-002、W2-003、W2-003a、W2-004、W2-005、W2-006 | W1 PR #10–#15；W2 PR #23、#26、#28、#30、#33 已合入 `main` |
| 内核能力 | ZIP、7z、RAR（外部）、RAR5 check 快筛、分卷、SFX、流式字典、掩码/暴力/混合候选源、规则链、空间估算、批量任务编排、编码变体/严格模式、多线程调度、运行控制/检查点 | W1-009 RAR5 快筛 completed（reviewer APPROVE + 法务复核附条件通过）；W1-006/007、W2-002/003/003a/004 reviewer APPROVE；W1-008 三格式 1M×1GB 实测 |
| CLI | 单任务：字典/掩码/暴力/混合；批量：`acx batch <manifest>` | `--encoding-variants`/`--strict`/`--rar-no-fast-reject`/`--report-stats`；退出码 0/1/2/3/4；`--estimate` 输出时间 + 空间 + 变体倍数；批量退出码停止 4 > 失败 3 > 校验 2 > 有命中 0 > 全未命中 1 |
| C ABI | 最小 `acx_product` / `acx_version` / `acx_status_name` | `acx.h` ABI v0；攻击 API 未实现 |
| GUI / 前端 | 只有目录与 README 占位 | Avalonia/JNI/NAPI 工程尚未创建 |
| Full 随包 | 策略已定（ADR-0004），**尚未落地** | 无 `third_party/manifest.json`、无二进制、无安装包 |
| 测试 | core 157、CLI 96（1 ignored）、FFI 2 | 本机 Windows GNU + WinRAR 6.24 + 7-Zip 26.04 oracle；MSVC 待 CI |
| CI | `rust (win/linux/mac)`、Windows GNU、MSRV 1.89、cargo-deny | `.github/workflows/ci.yml`；PR #33 6/6 全绿（2026-11-27） |
| 平台 | Windows x64 为唯一排期平台 | Linux/macOS 只保证编译/测试；RAR 运行时未验证；移动端 Deferred |

> 最近一次全绿：`main` CI 6/6（PR #33，2026-11-27；W1 签核基线见 [W1-SIGNOFF](W1-SIGNOFF.md)）。本地 fmt/clippy/test、MSRV 1.89 全通过。

## 3. 实际目录结构

```text
.
├─ core/                                  # Rust workspace（当前真正有代码的部分）
│  ├─ Cargo.toml                          # workspace 成员/共享包元数据；依赖见各 crate Cargo.toml；许可策略在 deny.toml + docs/licensing.md
│  └─ crates/
│     ├─ acx-core/                        # 内核库
│     │  └─ src/
│     │     ├─ archive/                   # 归档抽象与引擎
│     │     │  ├─ mod.rs                  # magic 检测、open/preflight、Factory trait
│     │     │  ├─ info.rs                 # ArchiveInfo/ArchiveFormat/Encryption
│     │     │  ├─ source.rs               # 分卷拼接、SFX payload 偏移、缺卷检测
│     │     │  ├─ zip.rs                  # ZipCrypto + WinZip AES 会话
│     │     │  ├─ sevenz.rs               # 7z AES/头加密/首块探测会话
│     │     │  └─ rar.rs                  # 外部 UnRAR 会话、factory 预检缓存
│     │     ├─ candidates/dictionary.rs   # 流式字典：BOM/UTF-8/UTF-16/GBK、行/批
│     │     ├─ checkpoint.rs              # 断点指纹/原子写/续跑校验
│     │     ├─ engines/external.rs        # 外部进程边界：发现/stdin/超时/取消/截断
│     │     ├─ scheduler.rs               # 有界队列 + 多 worker + 暂停/停止/水位
│     │     ├─ attack.rs                  # AttackMode/AttackSpec（目前仅 Dictionary）
│     │     └─ error.rs / lib.rs
│     ├─ acx-cli/                         # CLI（直接依赖 acx-core）
│     │  ├─ src/main.rs
│     │  └─ tests/                        # cli.rs、w1_zip_dict.rs、w1_sevenz.rs、w1_rar_external.rs、w1_volumes_sfx.rs、w1_resume.rs
│     └─ acx-ffi/                         # 最小 C ABI
│        ├─ include/acx.h                 # ABI v0，仅 product/version/status
│        └─ src/lib.rs
│
├─ frontends/                             # 目前只有 README 占位，尚无工程文件
│  ├─ desktop/                            # [计划] Avalonia 12
│  ├─ android/                            # [计划] Kotlin + Compose
│  ├─ harmony/                            # [计划] ArkTS/ArkUI
│  └─ shared/                             # [计划] token/i18n
│
├─ docs/
│  ├─ PROJECT-GUIDE.md                    # 本文：结构/文档地图/进度
│  ├─ architecture.md                     # 跨平台总体架构（Accepted）
│  ├─ roadmap.md                          # W0–W5 阶段路线图
│  ├─ windows-plan.md                     # Windows 全栈任务/验收
│  ├─ cross-platform.md                   # 五平台差异与后续策略（Deferred）
│  ├─ licensing.md                        # Apache-2.0 + 第三方 + RAR/hashcat 边界
│  ├─ GITHUB.md                           # 仓库设置手册
│  ├─ adr/                                # 0001 Rust、0002 前端拆分、0003 RAR、0004 Full 随包
│  ├─ tasks/                              # W1-001/002/003/003b/003c/004/005/006、W2-001 任务与证据
│  ├─ benchmarks/                         # ZIP 基线、RAR 预检缓存基准
│  ├─ agents/                             # Agent 协作规范 + 7 个角色提示词
│  └─ analysis/legacy-tools.md            # 三款旧工具的静态分析（内部研究，不执行样本）
│
├─ scripts/                               # bootstrap/check-env/env/make-architecture
├─ tests/                                 # 目前仅 README；语料/向量/差分/模糊测试为 P1 计划
├─ workflows/                             # DSH workflow 脚本（research/feature-cycle）
├─ third_party/                           # 目前仅 README；只登记策略，不提交二进制
├─ .github/                               # ci.yml、PR 模板、issue 模板
├─ 解密1/ 解密2/ 解密3/                    # 旧工具样本，已 gitignore；禁止执行
├─ AGENTS.md                              # 所有 Agent 的入口指令
├─ CONTRIBUTING.md / SECURITY.md
├─ LICENSE / NOTICE / THIRD_PARTY_NOTICES.md
├─ deny.toml
└─ README.md
```

**尚未创建但文档中已规划的目录/工程**：`core/crates/acx-jni`、`core/crates/acx-napi`、
`frontends/desktop` 的实际 .NET 工程、`frontends/android` 的 Gradle 工程、
`frontends/harmony` 的 DevEco 工程、`tests/corpus`/`vectors`/`differential`/`fuzz`、
`third_party/manifest.json` 与随包二进制。看到文档里的这些路径时，先确认是否已落地。

## 4. 说明文件地图

### 4.1 根目录入口

| 文件 | 作用 | 何时读/更新 |
|---|---|---|
| [README.md](../README.md) | 产品目标、架构图、平台矩阵、快速开始 | 第一次进入项目；目标/平台/状态变化时 |
| [AGENTS.md](../AGENTS.md) | Agent 必须遵守的边界、决策表、构建/评审规则 | 任何 Agent 开工前；流程变化时 |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | 人类贡献者环境、分支、测试、PR 规范 | 提交 PR 前 |
| [SECURITY.md](../SECURITY.md) | 漏洞报告渠道、安全边界、不收录范围 | 发现安全问题；发布前 |
| [LICENSE](../LICENSE) / [NOTICE](../NOTICE) | Apache-2.0 与项目声明 | 发布/再分发 |
| [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | 第三方组件与许可摘要 | 新增依赖/随包组件时 |

### 4.2 架构与计划

| 文件 | 作用 | 何时读/更新 |
|---|---|---|
| [docs/architecture.md](architecture.md) | 分层、引擎/验证、C ABI、模块、安全、许可、风险 | 改接口/引擎边界/跨平台设计时；本文件是技术事实源 |
| [docs/roadmap.md](roadmap.md) | W0–W5 阶段目标和退出标准 | 排期变化；阶段验收 |
| [docs/windows-plan.md](windows-plan.md) | Windows 全栈的交付物、W1–W5 任务、RAR 实现细节 | 做 Windows 功能/打包时 |
| [docs/cross-platform.md](cross-platform.md) | Linux/macOS/Android/HarmonyOS 差异与后续策略 | Windows 发布后启动 D1–D3 时；当前**不排期** |

### 4.3 决策与合规

| 文件 | 作用 |
|---|---|
| [ADR-0001](adr/0001-rust-core.md) | 为什么用 Rust 内核 |
| [ADR-0002](adr/0002-frontend-split.md) | Avalonia / Compose / ArkUI 的前端拆分 |
| [ADR-0003](adr/0003-rar-licensing.md) | RAR/UnRAR 许可边界；进程隔离；不链接/不复制源码 |
| [ADR-0004](adr/0004-bundled-engines.md) | 单一 Full 版本；随包未修改 UnRAR + hashcat；CPU 回退；发现顺序 |
| [docs/licensing.md](licensing.md) | 依赖登记、RAR/hashcat 边界、商店/发布合规 |
| [docs/GITHUB.md](GITHUB.md) | 仓库/分支保护/Actions/发布设置手册 |

### 4.4 任务、证据与研究

| 文件 | 内容 | 状态 |
|---|---|---|
| [W1-001 ZIP + 字典 + CLI](tasks/W1-001-zip-dict.md) | ZipCrypto、字典、多线程 CLI | 完成 |
| [W1-002 WinZip AES](tasks/W1-002-aes-zip.md) | AES-128/192/256、AE-1/AE-2 验证 | 完成 |
| [W1-003 RAR 外部引擎](tasks/W1-003-rar-external.md) | UnRAR 进程调用、整包 `t`、错误映射 | 完成 |
| [W1-003b RAR 预检缓存](tasks/W1-003b-rar-preflight-cache.md) | factory 缓存 `ArchiveInfo`，去掉每 worker 预检 | 完成 |
| [W1-003c RAR4 `-ma4`](tasks/W1-003c-rar4-ma4.md) | RAR4 预检/退出码适配与端到端验证 | 完成 |
| [W1-004 7z AES/头加密/首块](tasks/W1-004-sevenz.md) | `sevenz-rust2`、AES-256、`-mhe=on`、首块探测、CLI | 完成（PR #10 已合并） |
| [W1-005 分卷/SFX](tasks/W1-005-volumes-sfx.md) | `.001/.0001`、`.partN.rar`、SFX、缺卷/截断/损坏分类 | 完成（PR #11 已合并） |
| [W1-006 运行控制与断点续跑](tasks/W1-006-run-control-resume.md) | 暂停/继续、停止/取消、检查点、`--resume` | 完成（PR #12 已合并；1 GB 矩阵已测） |
| [W1-007 流式字典](tasks/W1-007-streaming-dictionary.md) | 有界内存、编码、CandidateSource、resume | 完成（PR #13 已合并；reviewer APPROVE） |
| [W1-008 正式基准](tasks/W1-008-benchmark.md) | 1M × 1GB ZIP/7z/RAR | 完成（PR #14 已合并；准出数字见 W1-010） |
| [W1-009 RAR5 快筛](tasks/W1-009-rar5-fast-check.md) | 进程内 check + 外部确认 | 完成（PR #15 已合并；法务复核附条件通过） |
| [W1-010 准出硬化](tasks/W1-010-w1-hardening.md) | ZIP 10⁷、暂停/停止矩阵、签核 | 完成（[W1-SIGNOFF](W1-SIGNOFF.md)） |
| [W1 评估](W1-ASSESSMENT.md) | W1 交付物与 W2 准入意见 | GO（已签核） |
| [W2 计划](W2-PLAN.md) | W2 工作包/顺序/退出标准 | 已批准启动（W1 signoff 2026-11-26） |
| [W2-002 掩码需求](tasks/W2-002-mask-requirements.md) | 表达式约定、限值、空间/时间估算、24h 容量、checkpoint 指纹 | 首版完成（PR #23） |
| [W2-002 基准](benchmarks/W2-002.md) | 1M 掩码 / ZIP 回归 | 已记录 |
| [W2-003 暴力/键空间](tasks/W2-003-brute-keyspace.md) | 字符集 + 长度区间、短密码优先、`usize` 决策、schema v2 复用 | 首版完成（PR #26） |
| [W2-003a 空间估算](tasks/W2-003a-space-estimate.md) | 水位位图/在飞批次/峰值估算、mask/brute 回填、hybrid 复用 | 首版完成（PR #28） |
| [W2-004 混合/规则](tasks/W2-004-hybrid-rules.md) | 规则语法、字典×变体二维候选源、复合指纹、schema v2 复用 | 首版完成（PR #28） |
| [W2-005 批量任务/包间复用](tasks/W2-005-batch-jobs.md) | 任务清单、失败隔离、独立断点、有限并行、授权密码复用 | 首版完成（PR #30 已合并） |
| [W2-006 编码变体与严格模式](tasks/W2-006-encoding-strict.md) | 非 ASCII 编码变体、严格模式开关、编码/快筛计数 | 首版完成（PR #33 已合并） |
| W2-007 CPU 快筛补全 | 统一快筛接口、ZIP/7z 判据、RAR4 可行性、严格模式全覆盖、快筛计数 | 设计目标已定义（实现未开始） |
| [W2-001 hashcat GPU spike](tasks/W2-001-hashcat-spike.md) | ZIP AES/RAR5 提 hash + 外部 hashcat + CPU 回退 | **Deferred（W2 不启动）** |
| [docs/benchmarks/w1-zipcrypto.md](benchmarks/w1-zipcrypto.md) | ZIP 字典吞吐非正式基线 | 已记录 |
| [docs/benchmarks/w1-rar-preflight.md](benchmarks/w1-rar-preflight.md) | RAR 预检缓存前后对比 | 已记录 |
| [docs/analysis/legacy-tools.md](analysis/legacy-tools.md) | 三款旧工具的静态分析、历史架构参考 | 内部研究；不执行样本 |
| [docs/agents/README.md](agents/README.md) | 多 Agent 角色、任务包、交接、反模式 | 协作入口 |
| [docs/agents/POOL.md](agents/POOL.md) | 角色槽位、复用/新建判据、上下文预算、并发与生命周期 | 派发子智能体前 |
| [tests/README.md](../tests/README.md) | 语料/向量/差分/模糊测试计划 | 目前仅目录说明 |
| [third_party/README.md](../third_party/README.md) | 随包二进制 manifest/哈希策略 | 无实际二进制 |

## 5. 开发进度

### 5.1 阶段总表

| 阶段 | 状态 | 已完成 | 主要缺口 |
|---|---|---|---|
| **W0 Bootstrap** | **基本完成** | 仓库、Apache-2.0、CI、用户级工具链脚本、Rust workspace、ADR 0001–0004、最小 C ABI | 语料生成器/校验清单/差分向量（`tests/README` 仍为 P1 计划） |
| **W1 核心 CLI** | **✅ 已签核** | ZIP/7z/RAR/分卷/SFX/流式/断点/暂停停止/RAR5 快筛 | 已知限制见 [W1-SIGNOFF](W1-SIGNOFF.md)（不阻塞 W2）：RAR5 非 ASCII 回退、7z 停止尾延迟、`-hp` 第三方语料、物理核数默认值 |
| **W2 引擎/攻击** | **进行中** | W2-002 掩码、W2-003 暴力、W2-003a 空间估算、W2-004 混合/规则、W2-005 批量任务、W2-006 编码/严格模式（PR #33 已合并） | CPU 快筛补全（W2-007 设计目标已定义、实现未开始）、W2-008 语料/差分；**W2-001 GPU 已 Deferred**；见 [W2-PLAN](W2-PLAN.md) |
| **W3 桌面 GUI** | 未开始 | — | C ABI 攻击 API、Avalonia 工程、进度/暂停、自动解压 |
| **W4 全栈交付** | 未开始 | ADR-0004 策略 | 单一 Full 安装包、UnRAR/hashcat 随包、签名、崩溃转储、zh/en |
| **W5 Windows Beta** | 未开始 | — | 性能/模糊/兼容性/AV/文档 |
| **D1–D3 其他平台** | **Deferred** | 接口保留 | Linux/macOS/Android/HarmonyOS 前端与打包 |

### 5.2 W1 切片明细

| 切片 | 状态 | 说明 |
|---|---|---|
| ZIP ZipCrypto + 字典 + 多线程 CLI | ✅ 完成 | W1-001；命中由 ZIP 引擎完整验证 |
| ZIP WinZip AES-128/192/256 | ✅ 完成 | W1-002；AE-1/AE-2；7-Zip 差分待补 |
| RAR5 外部 UnRAR | ✅ 完成 | W1-003；整包 `t`，密码走 stdin；RAR5 已端到端验证 |
| RAR4 外部 UnRAR | ✅ 完成 | W1-003c；WinRAR 6.24 生成 `-ma4` 样本；文件加密/未加密自动测试，`-hp` 头加密手工验证 |
| RAR 预检缓存 | ✅ 完成 | W1-003b；`-t N` 不再产生 `2N` 次重复预检 |
| 7z（AES/头加密/首块） | ✅ 完成 | W1-004；`sevenz-rust2` 0.20.2；AES-256、`-mhe=on`、首块 64 KiB 探测 + 完整 CRC；7-Zip 26.04 差分 |
| 分卷/SFX + 预检完整化 | ✅ 完成 | W1-005；ZIP/7z `.001` 拼接、RAR `.partN`/`.r00`、7z/ZIP/RAR SFX、缺卷/截断/损坏分类；PKZIP `.z01` 明确不支持 |
| 运行控制 + 断点续跑 | ✅ W1-006 | 暂停/继续、优雅/强制停止、检查点、`--resume`；reviewer APPROVE；1 GB 矩阵与硬杀窗口（1242 ≤4096）实测通过 |
| 字典/调度补全 | ✅ W1-007 | 流式字典（reviewer APPROVE）：有界候选、编码、批次源、resume；物理核数默认值属调优项，不阻塞 W2 |
| 错误分类完整化 | ⏳ 部分 | 缺卷/截断/损坏/未加密已有预检分类（W1-005）；RAR 损坏仍走 External，前端错误码未映射（W3） |
| 1M 字典 / 1GB 归档基准 | ✅ W1-008/W1-010 | **准出数字以 [W1-010](benchmarks/W1-010.md) 的 4096 窗口复测为准**：ZIP 39.335s / **25,423/s**、7z 1033.040s / **967.9/s**、RAR5 check 578.958s / **1727.2/s**、RAR 外部整包 4515.104s / 221.5/s；[W1-008](benchmarks/W1-008.md) 的 23,670/s、786.8/s 为旧口径，不再作为准出数字 |
| RAR5 快速校验 | ✅ W1-009 | 进程内 check 快筛（ASCII-only，只否决；命中仍外部 `UnRAR t`）；reviewer APPROVE + 法务复核附条件通过 |

### 5.3 当前可交付与不可交付

**可用（Windows CLI：字典/掩码/暴力/混合/批量/编码变体）**：

```powershell
cd core
# 字典
cargo run -p acx-cli -- -f <archive> -m dict -d <dictionary> -t 4
# 掩码（可重复 --mask）
cargo run -p acx-cli -- -f <archive> --mask "P@ssw0rd?d?d?d" -t 4
# 暴力：字符集 + 长度区间
cargo run -p acx-cli -- -f <archive> --brute "?l?d" --min-len 1 --max-len 8 --estimate
# 混合：字典 × 规则/前后缀掩码；--estimate 同时输出时间与空间
cargo run -p acx-cli -- -f <archive> -d <dictionary> --rule "capitalize|append:123" --suffix-mask "?d?d" --estimate
# 非 ASCII 编码变体 + 严格模式 + 计数
cargo run -p acx-cli -- -f <archive> -d <dictionary> --encoding-variants auto --strict --report-stats
# 批量：TOML 清单，失败隔离、每任务断点、有限并行
cargo run -p acx-cli -- batch jobs.toml --dry-run
cargo run -p acx-cli -- batch jobs.toml --max-parallel 2 --reuse-found
```

- ZIP：ZipCrypto、WinZip AES-128/192/256；`.zip.001` 分卷、简单 SFX；
- 7z：AES-256、`-mhe=on` 头加密、LZMA/LZMA2/COPY/BZip2/PPMd；`.7z.001` 分卷、SFX；
- RAR4/RAR5：本机安装 WinRAR/UnRAR，或设置 `ACX_UNRAR`；`.partN.rar`/`.r00` 分卷；
- 攻击模式：字典（流式）、掩码（`?d ?l ?u ?s ?a ?1..?4`、固定长度、多条 `--mask`）、暴力（字符集 + `--min-len`/`--max-len`，短密码优先）、混合（`--rule` + `--prefix-mask`/`--suffix-mask`）；
- 编码变体：`--encoding-variants auto|utf8|gbk|cp437|oem`（可组合）；ZIP 默认 UTF-8/GBK/CP437，RAR4 默认 UTF-8/OEM（外部引擎内部转换），7z 默认 UTF-8（引擎内部转 UTF-16LE）；不可表示字符跳过该变体；
- 严格/统计：`--strict` 关闭所有可能漏报的快筛，`--rar-no-fast-reject` 只关 RAR5，`--report-stats` 输出编码/快筛计数；
- `--estimate` 只估算不攻击：keyspace/ETA/24h 容量 + 水位位图/峰值（十进制 MB，不含归档会话）；位图 >128 MB 警告；
- 批量：`acx batch jobs.toml [--max-parallel N] [--reuse-found] [--fail-fast] [--dry-run]`，单任务失败隔离、每任务独立断点、复用仅内存；清单 `[[jobs]]` 支持 `encoding_variants`/`strict`/`rar_no_fast_reject`/`report_stats`；
- 退出码：单任务 0 命中，1 未找到，2 参数/字典/续跑校验错误，3 归档/引擎/缺卷错误（含命中后检查点清理失败），4 已停止并保存检查点；批量按停止 4 > 失败 3 > 校验 2 > 有命中 0 > 全未命中 1；
- 暂停/继续、优雅/强制停止、`--resume` 断点续跑（W1-006，退出码 4 = 已停止并保存检查点）。

**尚不可用 / 未验证**：

- PKZIP spanned `.z01/.z02`（明确报不支持）；
- 异常 SFX 布局、stub 超过 32 MiB；
- CPU 快筛补全（W2-007，设计目标已定义、实现未开始）；
- `--mask-file`、`?b`、`--export-dictionary`、`--increment`；
- 跨运行跳过已命中的批量任务（首版无批量状态文件；中断任务按各自断点续跑）；
- GPU/hashcat 加速（W2-001 Deferred，W2 不启动）；
- GUI、安装包、自动解压；
- Full 随包 UnRAR/hashcat（W4）；
- Linux/macOS/Android/HarmonyOS 的实际产品交付。

### 5.4 W1 准出标准

W1 不能只用“能跑”收口。以下全部满足才算 W1 准出：

**功能**

- W1-001…W1-010 完成；PR #10–#15 已合并，W1 signoff 2026-11-26（[W1-SIGNOFF](W1-SIGNOFF.md)）；
- CLI 字典模式覆盖 ZIP（ZipCrypto/AES）、7z（AES/头加密）、RAR4/RAR5（外部）、分卷、SFX；
- 暂停/继续、优雅/强制停止、`--resume` 可用；暂停/停止后无残留外部进程；
- `--resume` 能校验归档/字典/参数指纹，不匹配时拒绝而不是静默重跑。

**正确性**

- 语料上已知密码 100% 命中；命中必须由 ZIP/7z 内置引擎完整解压或外部 UnRAR 完整 `t` 复核；
- ZIP/ZipCrypto 10⁷ 错误候选 0 误报；7z/RAR5 抽样 ≥10⁵ 错误候选 0 误报 + 差分；
- 缺卷/截断/损坏/未加密/不支持/头加密分类在语料上 100% 正确；
- 暂停/停止不会把“未测试”记成“已测试”；硬杀恢复不跳过候选。

**性能与可恢复性**

- 1M 字典 × 1GB ZIP/7z/RAR（已知密码）完成，并记录 p/s、CPU、内存、ETA 误差；
- 暂停/停止请求被 scheduler 观察 ≤200 ms；外部 UnRAR 子进程 ≤2 s 内 kill；CPU 候选在测试调用返回后停止（1GB 候选的实际停止时延在基准中记录，不承诺 ≤2 s）；
- 强杀恢复误差 ≤1 批（4096）；恢复后仍在合理时间内完成；
- 1M 字典不出现无界内存增长；大字典路径由 W1-007 流式化收口（reviewer APPROVE）。

**质量与交付**

- `cargo fmt --check`、`clippy -D warnings`、`cargo test --workspace`、MSRV 1.89、release build、cargo-deny 全绿；
- `docs/benchmarks/` 记录机器/电源模式/语料哈希/线程数；
- 无 P0/P1 未关闭缺陷；无样本归档、密钥、未登记依赖；
- README、PROJECT-GUIDE、任务文档与真实状态一致。

### 5.5 W2 准入标准

W1 已完成签核（[W1-SIGNOFF](W1-SIGNOFF.md)，2026-11-26）；W2 按 [W2 计划](W2-PLAN.md) 启动。W2 准入条件：

- W1 准出清单全部勾选，且有一个里程碑评审记录（reviewer/architect）；
- W2 范围已写入任务文档：快筛、掩码/暴力/混合、批量/编码变体；每项有验收；
- 语料/差分 oracle 可用：ZIP/7z/RAR 差分、10⁷ 负例、1GB 归档、分卷/SFX 负例；
- W1 性能基线稳定；scheduler 的运行控制/断点接口不再大改；
- 许可与 CI 门禁保持绿色；hashcat 仍只允许外部进程，不是 Cargo 依赖；
- **W2-001 GPU 不阻塞准入**：该切片 Deferred，W2 先完成 CPU 快筛/攻击/批量；GPU 需在 W2 退出后单独重新评审并更新任务/ADR；
- 前端/移动端 SDK 不提前引入；GUI 仍属于 W3。

## 6. 推荐开发顺序

> 以下 `W1-007` 等编号是**建议切片**，正式开工时在 `docs/tasks/` 新建任务文档并写清验收；
> 已有正式任务文档的切片（W1-001/002/003/003b/003c/004/005/006/007/008/009/010、W2-001）以任务文档为准。

按依赖和风险排序：

1. **W1-004：7z 引擎** — ✅ 已完成（见 [W1-004](tasks/W1-004-sevenz.md)）
   - `sevenz-rust2` 读取、AES-256、可选头加密；
   - 选择最小可验证块/首块探测；
   - CLI 按 magic 分发；与 7-Zip CLI 做差分 oracle；
   - 测试：明文、AES、头加密、错误密码、空包、损坏。
2. **W1-005：分卷/SFX 与预检完整化** — ✅ 已完成（见 [W1-005](tasks/W1-005-volumes-sfx.md)）
   - ZIP `.zip.001`、7z `.7z.001`、RAR `.partN`/`.r00`；
   - PE overlay 扫描与数据偏移；
   - 缺卷/截断/损坏分类，CLI 明确提示；
   - PKZIP `.z01` 明确报不支持。
3. **W1-006：运行控制与断点续跑（合并 epic）** — ✅ 已完成（见 [W1-006](tasks/W1-006-run-control-resume.md)）
   - `RunControl`：暂停/继续、优雅/强制停止、外部子进程取消；
   - 连续完成批次水位；检查点原子写；`--resume` 指纹校验；
   - 归档/字典/参数不一致拒绝续跑；硬杀恢复 ≤4096 候选窗口。
4. **W1-007：流式字典与候选源** — ✅ 已完成（见 [W1-007](tasks/W1-007-streaming-dictionary.md)）
   - 有界内存、编码识别、批次源、检查点续跑；reviewer APPROVE。
5. **W1-008：正式基准（已完成）**
   - 1M 字典 × 1GB ZIP/7z/RAR；记录 p/s、CPU、内存、ETA 误差；
   - 结果写入 [W1-008 基准报告](benchmarks/W1-008.md)；准出数字以 [W1-010](benchmarks/W1-010.md) 为准。
6. **W1-009：RAR5 快速校验（已完成：reviewer + 法务复核）**
   - 进程内 check 快筛，外部 `UnRAR t` 复核；报告见 [W1-009](benchmarks/W1-009.md)。
7. **W1-010：准出硬化** — ✅ 已完成：ZIP 10⁷、暂停/停止矩阵、当前窗口复测、PR 签核；见 [W1-010](tasks/W1-010-w1-hardening.md) 与 [W1-SIGNOFF](W1-SIGNOFF.md)。
8. **W2：CPU 攻击面（进行中）** — W2-002 掩码、W2-003 暴力、W2-003a 空间估算、W2-004 混合/规则、W2-005 批量、W2-006 编码/严格模式已完成（PR #23/#26/#28/#30/#33）；下一步 W2-007 快筛；W2-001 GPU Deferred。
9. **W3：C ABI v1 + Avalonia GUI**；之后 W4 Full 安装包、W5 Beta。

## 7. 开发工作流

### 7.1 Agent 分配（先复用）

- 派发前先 `list_agents`，同角色/同领域且有相关上下文的 inactive agent 优先用 `send_message` 续用。
- 领域 reviewer 是常驻槽位，不为每个 PR 新建；同一 PR 不并行开两个 reviewer。
- 只有无合适槽位、需要独立评审（现有 reviewer 参与实现）、或需要隔离上下文时，才新建。
- `workflow` 每次新建 agent，只用于一次性 fan-out，不用于同域小步迭代。
- 新建 label 用 `角色:领域`；复用消息只给变更点，不重贴仓库全文。
- 完整规则：[`docs/agents/POOL.md`](agents/POOL.md)。

### 7.2 分支与评审

- 从 `main` 开分支：`feat/<id>-<slug>`、`fix/...`、`docs/...`、`chore/...`；
- 所有改动走 PR；禁止直接 push `main`、禁止 force-push 共享分支；
- 每个 PR 至少 1 个 reviewer；核心/许可/安全改动加 architect/release 角色；
- PR 描述必须写：改了什么、怎么验证、风险/许可影响、未验证项。

### 7.3 提交前命令

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked        # MSRV
cargo deny check licenses bans sources
```

### 7.4 CI 门禁

`.github/workflows/ci.yml` 当前 6 个 job：

1. `rust (windows-latest)`：fmt/clippy/test/release build；
2. `rust (ubuntu-latest)`：同上 + C header smoke；
3. `rust (macos-latest)`：同上；
4. `rust (windows-latest, gnu)`：GNU target 测试；
5. `rust (msrv 1.89)`：最低 Rust 版本；
6. `cargo-deny`：licenses/bans/sources。

### 7.5 Definition of Done

- 代码 + 测试 + 文档（至少更新对应 `docs/tasks/` 或本文）；
- fmt/clippy/受影响测试通过；
- 新依赖/许可已登记；hashcat 不是 Cargo 依赖；无 unRAR/7-Zip RAR 源码；
- 跨平台影响说明；性能改动有前后数据；
- 无样本归档/密钥/用户数据；PR 写清未验证项。

## 8. 文档维护规则

| 变更类型 | 必须更新 |
|---|---|
| 完成/推进一个切片 | 对应 `docs/tasks/*.md` 的“结果/验证”，以及本文 §5 |
| W1/W2 范围或顺序变化 | `docs/roadmap.md`、`docs/windows-plan.md`、本文 §5–6 |
| 架构/接口/引擎边界变化 | `docs/architecture.md`；必要时新增 ADR |
| 新依赖/随包二进制 | `docs/licensing.md`、`THIRD_PARTY_NOTICES.md`、`third_party/README.md`、ADR |
| 平台排期变化 | `README.md` 平台矩阵、`docs/cross-platform.md`、本文 §5 |
| 测试/基准结论 | `docs/benchmarks/`、任务文档；不要只写在 PR 里 |
| CI/分支/发布流程变化 | `CONTRIBUTING.md`、`docs/GITHUB.md`、`.github/` |

**避免状态漂移**：README 只保留一段“当前阶段”摘要；详细状态以本文为准；
roadmap 的复选框保留阶段级口径，切片级完成情况看 §5.2。

## 9. 约束与风险

1. **RAR 许可**：只通过外部未修改 `UnRAR.exe`；不链接 `unrar.dll`、不复制源码；
   WinRAR 不随包。Full 随包在 W4 落地，当前开发机使用本机 WinRAR。
2. **hashcat**：只通过外部进程；不是 Cargo 依赖；无 hashcat/GPU 时 CPU 路径必须完整可用。
3. **Windows 优先**：其他平台 Deferred；CI 的 Linux/macOS 通过只代表可编译/可跑单测，
   RAR 运行时与 GUI 未验证。
4. **RAR4 退出码语义**：RAR4 的缺密码/错误密码/部分损坏都可能返回 3；当前 3 按 Miss
   （RAR5 的 3 仍按 External），损坏归档还没有独立状态，W2 继续完善。
5. **前端缺失**：`frontends/*` 目前只有 README；W3 之前不要按“已有 GUI”排期。
6. **语料缺失**：没有提交样本归档/字典；`tests/` 仍是计划。正式基准前必须补生成脚本和清单。
7. **旧工具样本**：`解密1/2/3` 只做静态分析，禁止执行；已被 `.gitignore` 排除。
8. **7z 无认证器**：错误密码与损坏 payload 在 CRC 之前不可完全区分；完整 CRC 失败按 Miss，损坏归档可能表现为 `NOT FOUND`，没有独立“损坏”状态。头加密损坏也可能被当作头加密进入字典流程。
9. **分卷/SFX 边界**：PKZIP spanned `.z01` 明确不支持；最后卷缺失对 ZIP/7z 靠“最后两卷等大”启发式，RAR 单卷靠 archive flags、多卷靠 UnRAR 诊断；SFX 扫描上限 32 MiB，异常偏移的第三方 SFX 未验证；RAR4 SFX `-hp` 未单独验证。
10. **性能数字**：现有 `docs/benchmarks/` 是非正式单机结果，不能外推到 7z/RAR KDF 或大归档。

## 10. 快速阅读路径

- **新人类开发者**：README → 本文 §2–§3 → CONTRIBUTING → `cargo test` → 选 §6 一个切片。
- **新 Agent**：AGENTS.md → 本文 §5–§7 → 对应角色 `docs/agents/roles/*.md` → 任务文档。
- **Reviewer**：本文 §5 → PR 对应任务文档 → `docs/architecture.md` 相关章节 →
  `docs/licensing.md`（涉及 RAR/hashcat 时）→ 验证命令。
- **Release**：README 平台矩阵 → `docs/windows-plan.md` §7 → `docs/licensing.md` →
  `third_party/README.md` → ADR-0004。
- **只想跑一下**：README“快速开始” → 本文 §5.3 命令。
