# ArchCracker 项目全景与开发指引

> 最后更新：2026-11-24 · `main` @ `b0129d9` · 阶段：**W1 进行中（Windows 全栈优先）**
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
| 当前阶段 | **W1 进行中** | Windows 全栈优先；W2–W5 未开始 |
| 已验收切片 | W1-001、W1-002、W1-003（RAR5；RAR4 待真实样本）、W1-003b | PR #1–#5 已合并（#4 为 Full 随包文档）；详见 §5 |
| 内核能力 | ZIP、RAR（外部）、字典、多线程调度 | 7z、分卷、SFX、断点、暂停/停止未完成 |
| CLI | `acx -f <archive> -m dict -d <dict> -t N` | 仅字典模式；退出码 0/1/2/3 |
| C ABI | 最小 `acx_product` / `acx_version` / `acx_status_name` | `acx.h` ABI v0；攻击 API 未实现 |
| GUI / 前端 | 只有目录与 README 占位 | Avalonia/JNI/NAPI 工程尚未创建 |
| Full 随包 | 策略已定（ADR-0004），**尚未落地** | 无 `third_party/manifest.json`、无二进制、无安装包 |
| 测试 | core 42、CLI 4、集成 8、FFI 2 | 本机 Windows + WinRAR 7.22；CI 6/6 通过 |
| CI | `rust (win/linux/mac)`、Windows GNU、MSRV 1.89、cargo-deny | `.github/workflows/ci.yml` |
| 平台 | Windows x64 为唯一排期平台 | Linux/macOS 只保证编译/测试；RAR 运行时未验证；移动端 Deferred |

> 最近一次全绿：`main` CI run `45406249615`（2026-11-24，合并 PR #5 后）。

## 3. 实际目录结构

```text
.
├─ core/                                  # Rust workspace（当前真正有代码的部分）
│  ├─ Cargo.toml                          # workspace 成员/依赖版本；许可策略在 deny.toml + docs/licensing.md
│  └─ crates/
│     ├─ acx-core/                        # 内核库
│     │  └─ src/
│     │     ├─ archive/                   # 归档抽象与引擎
│     │     │  ├─ mod.rs                  # magic 检测、open/preflight、Factory trait
│     │     │  ├─ info.rs                 # ArchiveInfo/ArchiveFormat/Encryption
│     │     │  ├─ zip.rs                  # ZipCrypto + WinZip AES 会话
│     │     │  └─ rar.rs                  # 外部 UnRAR 会话、factory 预检缓存
│     │     ├─ candidates/dictionary.rs   # 字典加载：BOM/UTF-8/UTF-16/GBK、去重
│     │     ├─ engines/external.rs        # 外部进程边界：发现/stdin/超时/截断
│     │     ├─ scheduler.rs               # 有界队列 + 多 worker + 命中仲裁
│     │     ├─ attack.rs                  # AttackMode/AttackSpec（目前仅 Dictionary）
│     │     └─ error.rs / lib.rs
│     ├─ acx-cli/                         # CLI（直接依赖 acx-core）
│     │  ├─ src/main.rs
│     │  └─ tests/                        # cli.rs、w1_zip_dict.rs、w1_rar_external.rs
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
│  ├─ tasks/                              # W1-001/002/003/003b、W2-001 任务与证据
│  ├─ benchmarks/                         # ZIP 基线、RAR 预检缓存基准
│  ├─ agents/                             # Agent 协作规范 + 6 个角色提示词
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
| [W2-001 hashcat GPU spike](tasks/W2-001-hashcat-spike.md) | ZIP AES/RAR5 提 hash + 外部 hashcat + CPU 回退 | 只有规格，未实现 |
| [docs/benchmarks/w1-zipcrypto.md](benchmarks/w1-zipcrypto.md) | ZIP 字典吞吐非正式基线 | 已记录 |
| [docs/benchmarks/w1-rar-preflight.md](benchmarks/w1-rar-preflight.md) | RAR 预检缓存前后对比 | 已记录 |
| [docs/analysis/legacy-tools.md](analysis/legacy-tools.md) | 三款旧工具的静态分析、历史架构参考 | 内部研究；不执行样本 |
| [docs/agents/README.md](agents/README.md) | 多 Agent 角色、任务包、交接、反模式 | 协作入口 |
| [tests/README.md](../tests/README.md) | 语料/向量/差分/模糊测试计划 | 目前仅目录说明 |
| [third_party/README.md](../third_party/README.md) | 随包二进制 manifest/哈希策略 | 无实际二进制 |

## 5. 开发进度

### 5.1 阶段总表

| 阶段 | 状态 | 已完成 | 主要缺口 |
|---|---|---|---|
| **W0 Bootstrap** | **基本完成** | 仓库、Apache-2.0、CI、用户级工具链脚本、Rust workspace、ADR 0001–0004、最小 C ABI | 语料生成器/校验清单/差分向量（`tests/README` 仍为 P1 计划） |
| **W1 核心 CLI** | **进行中** | ZIP（ZipCrypto/AES）、RAR5（外部 + 预检缓存）、字典编码/去重、有界多线程调度、CLI 字典模式 | 7z、RAR4 真实样本、分卷/SFX、暂停/停止、断点、完整错误分类、1M/1GB 基准、流式字典/批处理 |
| **W2 引擎/攻击** | 未开始 | RAR 外部引擎已由 W1-003 提前交付；W2-001 只有规格 | hashcat spike、快筛、掩码/暴力/混合、分卷/SFX、批量/编码变体 |
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
| RAR4 外部 UnRAR | ⏳ 待真实样本 | 代码路径/magic/预检已覆盖；WinRAR 7.22 无法生成 `-ma4` 样本，端到端未验证 |
| RAR 预检缓存 | ✅ 完成 | W1-003b；`-t N` 不再产生 `2N` 次重复预检 |
| 7z（AES/头加密/首块） | ⏭ **下一步** | `sevenz-rust2`；与 7-Zip CLI 差分 |
| 分卷/SFX + 预检完整化 | ⏳ 未开始 | `.001`/`.z01`/`.partN`、PE overlay、缺卷检测 |
| 暂停/停止 | ⏳ 未开始 | scheduler 目前只有命中/错误停止，没有用户暂停 |
| 断点续跑 | ⏳ 未开始 | 归档指纹 + 字典偏移 + 原子写盘；强杀恢复 ≤ 1 批 |
| 错误分类完整化 | ⏳ 部分 | 未加密/缺失引擎/格式已有；损坏/缺卷/头加密提示仍待补 |
| 1M 字典 / 1GB 归档基准 | ⏳ 部分 | 已有 ZIP 微基准 + RAR 启动基准；未做正式 p/s 矩阵 |
| 流式字典/批处理 | ⏳ 未开始 | 当前 `Dictionary::load` 全量读入内存 |

### 5.3 当前可交付与不可交付

**可用（Windows CLI，字典模式）**：

```powershell
cd core
cargo run -p acx-cli -- -f <archive> -m dict -d <dictionary> -t 4
```

- ZIP：ZipCrypto、WinZip AES-128/192/256；
- RAR4/RAR5：本机安装 WinRAR/UnRAR，或设置 `ACX_UNRAR`；
- 退出码：0 命中，1 未找到，2 参数/字典错误，3 归档/引擎错误。

**尚不可用**：

- 7z；
- 分卷/SFX；
- 掩码/暴力/混合；
- GUI、安装包、自动解压；
- 断点续跑、暂停/停止；
- Full 随包 UnRAR/hashcat（W4）；
- Linux/macOS/Android/HarmonyOS 的实际产品交付。

### 5.4 W1 关闭条件

W1 不能只用“能跑”收口；满足以下条件才进入 W2：

- 1M 字典 × 1GB ZIP/7z/RAR（已知密码）完成，并记录 p/s（格式/线程/硬件）；
- 取消 < 200 ms；强杀恢复误差 ≤ 1 批（4096）；
- 缺卷/损坏/未加密/不支持/头加密分类在语料上 100% 正确；
- 性能基线写入 `docs/benchmarks/`，并注明机器/电源模式/语料哈希。

## 6. 推荐开发顺序

> 以下 `W1-004` 等编号是**建议切片**，正式开工时在 `docs/tasks/` 新建任务文档并写清验收；
> 已有正式任务文档的切片（W1-001/002/003/003b、W2-001）以任务文档为准。

按依赖和风险排序，下一步建议：

1. **W1-004：7z 引擎**
   - `sevenz-rust2` 读取、AES-256、可选头加密；
   - 选择最小可验证块/首块探测；
   - CLI 按 magic 分发；与 7-Zip CLI 做差分 oracle；
   - 测试：明文、AES、头加密、错误密码、空包、损坏。
2. **W1-005：分卷/SFX 与预检完整化**
   - ZIP `.z01`/`.zip.001`、7z `.7z.001`、RAR 交外部引擎；
   - PE overlay 扫描与数据偏移；
   - 缺卷/截断/损坏分类，CLI 明确提示。
3. **W1-006：断点续跑**
   - 归档指纹（大小/哈希/卷列表）+ 字典偏移 + 参数哈希；
   - 原子写盘；强杀恢复误差 ≤ 1 批。
4. **W1-007：调度与字典补全**
   - 暂停/停止；物理核数默认；流式字典/批处理，避免 1M 全量常驻。
5. **W1-008：正式基准**
   - 1M 字典 × 1GB ZIP/7z/RAR；记录 p/s、CPU、内存、ETA 误差；
   - 结果写入 `docs/benchmarks/`，再关闭 W1。
6. **W2-001：hashcat GPU spike**
   - 仅外部进程；ZIP AES 13600 + RAR5 13000；CPU 回退证据；
   - 不在 W1 提前引入 hashcat 依赖。
7. **W3：C ABI v1 + Avalonia GUI**；之后 W4 Full 安装包、W5 Beta。

## 7. 开发工作流

### 7.1 分支与评审

- 从 `main` 开分支：`feat/<id>-<slug>`、`fix/...`、`docs/...`、`chore/...`；
- 所有改动走 PR；禁止直接 push `main`、禁止 force-push 共享分支；
- 每个 PR 至少 1 个 reviewer；核心/许可/安全改动加 architect/release 角色；
- PR 描述必须写：改了什么、怎么验证、风险/许可影响、未验证项。

### 7.2 提交前命令

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked        # MSRV
cargo deny check licenses bans sources
```

### 7.3 CI 门禁

`.github/workflows/ci.yml` 当前 6 个 job：

1. `rust (windows-latest)`：fmt/clippy/test/release build；
2. `rust (ubuntu-latest)`：同上 + C header smoke；
3. `rust (macos-latest)`：同上；
4. `rust (windows-latest, gnu)`：GNU target 测试；
5. `rust (msrv 1.89)`：最低 Rust 版本；
6. `cargo-deny`：licenses/bans/sources。

### 7.4 Definition of Done

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
4. **RAR4 未验证**：WinRAR 7.22 无法生成 `-ma4` 样本；代码路径有 magic/预检覆盖，
   但缺真实端到端样本。
5. **前端缺失**：`frontends/*` 目前只有 README；W3 之前不要按“已有 GUI”排期。
6. **语料缺失**：没有提交样本归档/字典；`tests/` 仍是计划。正式基准前必须补生成脚本和清单。
7. **旧工具样本**：`解密1/2/3` 只做静态分析，禁止执行；已被 `.gitignore` 排除。
8. **性能数字**：现有 `docs/benchmarks/` 是非正式单机结果，不能外推到 7z/RAR KDF 或大归档。

## 10. 快速阅读路径

- **新人类开发者**：README → 本文 §2–§3 → CONTRIBUTING → `cargo test` → 选 §6 一个切片。
- **新 Agent**：AGENTS.md → 本文 §5–§7 → 对应角色 `docs/agents/roles/*.md` → 任务文档。
- **Reviewer**：本文 §5 → PR 对应任务文档 → `docs/architecture.md` 相关章节 →
  `docs/licensing.md`（涉及 RAR/hashcat 时）→ 验证命令。
- **Release**：README 平台矩阵 → `docs/windows-plan.md` §7 → `docs/licensing.md` →
  `third_party/README.md` → ADR-0004。
- **只想跑一下**：README“快速开始” → 本文 §5.3 命令。
