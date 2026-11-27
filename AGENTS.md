# AGENTS.md — ArchCracker 开发入口

本文件对所有进入本仓库的 AI Agent 生效（DSH / Codex / Claude Code / 其他支持 `AGENTS.md` 的运行时）。
目标不是“写得快”，而是**在五平台约束下持续交付可验证、可维护、许可干净的代码**。

---

## 1. 使命与边界

ArchCracker 是一个跨平台压缩包密码恢复工具：Rust 内核 + 原生前端，覆盖 Windows、Linux、macOS、Android、HarmonyOS。

必须坚持：

1. **只做授权恢复**：仅处理用户本人拥有或已获明确授权的归档；不实现在线撞库/共享密码/绕过 DRM。
2. **内核/前端分离**：核心不得依赖 UI、不得调用平台 GUI API；前端只通过 C ABI / JNI / NAPI 调用核心。
3. **默认离线**：无遥测、无强制更新、无静默网络请求。
4. **许可干净**：Apache-2.0；第三方组件逐个登记；Full 版按 ADR-0004 随包**未修改的 UnRAR.exe 与 hashcat 二进制**，仅进程调用；内核不链接 unRAR/7-Zip RAR 代码，不复制其源码；WinRAR 与 GPU 运行时（CUDA/HIP/驱动）不随包。
5. **可验证**：每个功能有测试或可复现的验证步骤；性能结论必须有基准数据。

---

## 2. 已确定的决策（改动需 ADR）

| 决策 | 内容 | 记录 |
|---|---|---|
| 许可证 | Apache-2.0 | `LICENSE` |
| 内核语言 | Rust（workspace + C ABI） | `docs/adr/0001-rust-core.md` |
| 前端拆分 | Avalonia 12（桌面三平台）/ Compose（Android）/ ArkUI（HarmonyOS） | `docs/adr/0002-frontend-split.md` |
| RAR 策略 | **单一 Windows Full 版**随包未修改 `UnRAR.exe`（仅进程）；不链接/不调用 `unrar.dll`；WinRAR 不随包；其他平台 Deferred | `docs/adr/0003-rar-licensing.md`、`docs/adr/0004-bundled-engines.md` |
| GPU/字典加速 | Full 版随包 hashcat 二进制，**仅外部进程**；hashcat 不是 Rust/Cargo 依赖；无 hashcat/GPU 时 CPU 多线程完整可用；实现时点 W2-001 **Deferred** | `docs/adr/0004-bundled-engines.md`、`docs/tasks/W2-001-hashcat-spike.md` |
| 发布形态 | 不分 Lite/Full，直接开发单一 Full 版本 | `docs/adr/0004-bundled-engines.md` |
| 首发平台 | Windows 10/11 x64，先 CLI 后 GUI | `docs/roadmap.md` |
| 开发方式 | 多 Agent 分工 + 分支/PR + 评审门禁 | 本文件第 6 节 |

> 决策变更流程：新增 `docs/adr/NNNN-*.md` → 在 PR 中说明影响 → 更新本表与 `docs/architecture.md`。

---

## 3. 当前阶段

> 项目结构、文档地图和切片进度见 [`docs/PROJECT-GUIDE.md`](docs/PROJECT-GUIDE.md)。开工前先读该页的“当前状态”和“推荐开发顺序”。

**W1 已签核；W2 进行中（Windows 全栈优先）**：

- 仓库、许可证、文档、ADR、Agent 协作规范已建立；
- Windows 用户级工具链（Rust GNU/MinGW、.NET 10、CMake、Ninja、gh）已装好；
- `core/` 已有可编译的 Rust workspace + C ABI 最小实现，`cargo test` 通过；
- W1-001（ZIP + 字典 + 多线程 CLI）已完成并通过评审；W1-002 已补 WinZip AES-128/192/256（AE-1/AE-2）候选验证；W1-003 已接入外部 UnRAR（整包 `t`，密码走 stdin/OEM 编码）；W1-003b 已将预检缓存进 `RarFactory`，worker 不再重复探测；W1-003c 已在 WinRAR 6.24 下补验 RAR4 `-ma4` 端到端（RAR4/RAR5 均已验证）；W1-004 已补 7z（AES-256、`-mhe=on` 头加密、首块探测 + 完整 CRC，`sevenz-rust2` 0.20.2），并用 7-Zip 26.04 做差分；W1-005 已补 ZIP/7z/RAR 分卷与 SFX payload 定位，缺卷/截断/损坏分类在预检阶段给出；W1-006（运行控制 + 断点续跑合并 epic）已通过 reviewer APPROVE 并完成 1GB 矩阵；W1-007 流式字典已通过 reviewer APPROVE；W1-008 三格式 1M×1GB 基准已完成（ZIP 42.247s、7z 1271.049s、RAR 外部 4515.104s）；W1-009 RAR5 check 快筛已实现并通过 reviewer APPROVE + 法务复核附条件通过（RAR5 1M 578.958s）。W2-002 掩码（PR #23）、W2-003 暴力（PR #26）、W2-003a 空间估算 + W2-004 混合/规则（PR #28）已合入 `main`（`--mask`/`--brute`/`--rule`/`--prefix-mask`/`--suffix-mask`、`--estimate` 时间+空间、schema v2 checkpoint）。W2-005 批量任务（`acx batch jobs.toml`、失败隔离、每任务断点、有限并行、内存内命中复用）PR #30 待合并。下一步按 [W2 计划](docs/W2-PLAN.md) 推进 W2-006 编码/严格模式、W2-007 CPU 快筛；W2-001 GPU/hashcat 已 Deferred，不在 W2 启动。Windows GUI 尚未开始。Full 版的 UnRAR/hashcat 随包按 ADR-0004 在 W4 落地；其他平台 Deferred。

W1 已完成；W2 不提前铺 GUI，移动端 SDK 一律不引入；不要提交未经证实的性能数字。

---

## 4. 仓库地图

```text
core/                 Rust workspace
  crates/acx-core/    领域模型、候选源、调度、引擎、探针、断点（部分模块仍为计划）
  crates/acx-cli/     CLI
  crates/acx-ffi/     C ABI + include/acx.h（当前仅最小 v0）
  crates/acx-jni/     [计划] Android JNI 薄层
  crates/acx-napi/    [计划] HarmonyOS NAPI 薄层
frontends/desktop/    [计划] Avalonia 12（当前只有 README）
frontends/android/    [计划] Kotlin + Compose（当前只有 README）
frontends/harmony/    [计划] ArkTS / ArkUI（当前只有 README）
docs/                 架构、路线图、许可、ADR、Agent 角色
workflows/            DSH workflow 编排脚本
scripts/              环境/构建脚本（语料生成脚本待补）
tests/                跨语言测试向量与语料索引（当前仅 README；不提交大文件）
```

**边界规则**

- `acx-core` 不得依赖 `clap`、`serde_json` 之外的 UI/平台库；不得 `use std::process::Command` 直接跑 `unrar`/`hashcat`（由 `engines::external` 抽象）。
- hashcat 只能通过外部进程/`engines::external` 接入，**不得**成为 Cargo 依赖、不得把 CUDA/HIP/OpenCL 绑定或 hashcat 内核复制进核心。
- `acx-ffi` 只做类型转换、错误码、回调生命周期；不得承载业务逻辑。
- 前端不得复制核心的攻击参数/错误码定义；以 `acx.h` 与 `docs/architecture.md` §5 为准。

---

## 5. 构建与测试

> 当前可直接运行；先加载 `scripts/env.ps1`。

```powershell
# Windows 环境检查（只读，仓库根目录）
Set-ExecutionPolicy -Scope Process Bypass -Force
powershell -ExecutionPolicy Bypass -File .\scripts\check-env.ps1

# Rust（以下在 core/ 下执行；仓库根目录没有 Cargo.toml）
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p acx-cli -- --help

# 前端（M1 后，回到仓库根目录）
cd ..
dotnet test frontends/desktop/ArchCracker.Desktop.sln
```

提交前至少跑：`cargo fmt`、`cargo clippy -D warnings`、受影响 crate 的测试。跨平台改动必须说明在哪些目标上验证过；未验证的写“未验证”，不要假装跑过。

---

## 6. 多 Agent 协作

### 6.1 角色

| 角色 | 职责 | 禁止 |
|---|---|---|
| `architect` | 架构、ADR、接口、跨平台约束、任务拆分 | 直接写业务代码 |
| `researcher` | 技术调研、方案对比、许可/依赖证据、未验证项 | 直接写产品代码；把未复现数字当结论 |
| `core-engineer` | Rust 内核、引擎、调度、FFI、测试 | 改前端/移动端工程 |
| `frontend-engineer` | Avalonia / Compose / ArkUI、打包 | 改核心算法/许可策略 |
| `qa-engineer` | 语料、差分测试、模糊测试、基准 | 修产品代码（只提 issue/PR 建议） |
| `reviewer` | 正确性、许可、性能、跨平台、可维护性 | 顺手重构无关代码 |
| `release-engineer` | CI、签名、安装包、发布说明 | 绕过测试/许可检查 |

角色提示词在 `docs/agents/roles/`。派发任务时把对应角色文件内容 + 仓库 `AGENTS.md` 一起给子智能体。

### 6.2 何时用 subagent / workflow / 复用

**先复用，后新建**。完整规则见 [`docs/agents/POOL.md`](docs/agents/POOL.md)。

- 派发前先 `list_agents`：同角色/同领域且有相关上下文的 inactive agent，优先用 `send_message` 续用。
- 同类工作（同格式 reviewer、同模块实现、同文档复核）不为每个 PR 新建 agent；领域 reviewer 是槽位，不是一次性。
- 只有无合适槽位、需要独立评审（现有 reviewer 参与了实现），或需要隔离上下文时，才用 `subagent`。
- 1–2 个独立子任务：用 `subagent`（或 `subagent_fork`），不要上 workflow；
  但若已有同域 agent，先复用，不要为了“独立”重复开同角色。
- 3 个以上独立方向、需要并行汇总：用 `workflow`；workflow 每次都会新建 agent，不适合同域后续迭代。
- 每个任务必须写清：**目标、范围、输入文件、验收标准、禁止事项**；复用消息只给变更点，不重贴整份仓库。
- 新建 `subagent` 不共享本对话上下文，prompt 必须自包含；`subagent_fork` 继承已完成轮次，prompt 只补变更点。新建 label 用 `角色:领域`，便于下次找回。
- 同一 PR 不并行开两个 reviewer；需要第二意见时，串行换一个未参与该改动的已有 reviewer。

### 6.3 任务包格式

```markdown
## Task <id>: <一句话>
Role: core-engineer
Branch: feat/<id>-<slug>
Scope: core/crates/acx-core/src/...
Inputs: docs/..., issue link
Acceptance:
- [ ] ...
- [ ] cargo test ... 通过
Out of scope: ...
```

### 6.4 分支 / 提交 / 评审

- `main` 保护（当前私有免费仓库无法启用 GitHub 分支保护，暂由流程约束；转公开/Pro 后开启）；所有改动走 `feat/`、`fix/`、`docs/`、`chore/` 分支 + PR。
- 提交信息：`type(scope): summary`，例如 `feat(core): add zipcrypto probe`。
- PR 描述必须包含：改了什么、怎么验证、风险/许可影响、未验证项。
- 评审门禁：至少 1 个 reviewer agent；核心/许可/安全改动需要 architect 或 release 角色复核。
- 不 Force-push 共享分支；不提交生成物、样本档案、密钥。

### 6.5 交接

每个 Agent 结束时输出：

```text
STATUS: done | blocked | partial
CHANGED: <files>
VERIFIED: <commands + results>
NOT VERIFIED: <items>
NEXT: <one concrete step>
RISKS: <licensing/perf/cross-platform>
```

---

## 7. 编码规范

### Rust

- Edition 2021（或团队确认后的 2024）；`rustfmt` + `clippy -D warnings`。
- 错误用 `thiserror`；库层不 `unwrap`/`expect` 用户输入路径；CLI 层可 `anyhow`。
- 公开 API 有文档注释；`unsafe` 必须写 `// SAFETY:` 并覆盖测试。
- 平台相关代码放 `#[cfg(target_os = ...)]` 小模块，不污染核心逻辑。
- 候选密码以字节处理；不假设 UTF-8。
- 热路径避免每候选分配：`ArrayPool` 等价物用 `Vec` 复用/`SmallVec`，批量 4096。
- 不引入与 Apache-2.0 不兼容的依赖；新增依赖必须在 PR 中登记到 `docs/licensing.md`。

### 前端

- 桌面：Avalonia 12 + MVVM；进度回调限流（约 10 Hz）；UI 线程不做解密。
- Android：Compose + ViewModel；SAF URI → `ParcelFileDescriptor` → `dup` 给 native；不整包拷贝。
- HarmonyOS：ArkTS/ArkUI + NAPI；文件 Picker 授权即时使用；长任务用前台任务/断点。
- 共享设计 token、错误码、i18n 词条放 `frontends/shared/`（M1 建立）。

### 跨平台

- 新增功能先问：Windows/Linux/macOS 能否同一实现？Android/HarmonyOS 的差异是否只在胶水层？
- 文件路径、换行、编码、权限、线程数、进程创建都必须抽象；不准在核心硬编码 `C:\` 或 `\\?\`。
- 每个平台特性在 `docs/architecture.md` 的平台矩阵中注明“已支持/未验证/不支持”。

---

## 8. Definition of Done

- [ ] 代码 + 测试 + 文档（至少更新相关 `docs/`）
- [ ] `cargo fmt --check`、`clippy -D warnings`、受影响测试通过
- [ ] 新依赖/许可已登记；无 unRAR/7-Zip RAR 源码违规引入；hashcat 未成为 Cargo 依赖
- [ ] 跨平台影响已说明（Windows 验证 / 其他平台未验证）
- [ ] 性能改动有基准数据（before/after，同机同语料）
- [ ] 无样本档案、无密钥、无用户数据
- [ ] PR 描述含验证命令与未验证项

---

## 9. 安全、许可、隐私

- **不执行** `解密1/2/3` 目录中的二进制；它们只作静态分析样本，且已被 `.gitignore` 排除。
- 不运行来源不明的压缩包/字典；测试语料必须由仓库脚本生成或来自可信公开数据集。
- 不把 `unrar`/7-Zip RAR **源码**、破解版工具提交进仓库；Full 版按 ADR-0004 随包**未修改的 UnRAR.exe 与 hashcat 二进制**（发布流水线按 manifest 获取，不提交二进制），RAR 只通过外部进程调用，不链接/不复制源码；边界见 `docs/licensing.md`。
- 不加入遥测、崩溃上报、在线密码查询；日志默认不记录完整密码。
- 解压路径做规范化，防 Zip Slip；DLL/so 从程序目录加载并校验哈希。
- 发现安全问题时走私密渠道（`SECURITY.md`），不要在公开 issue 贴利用细节。

---

## 10. 性能与正确性

- 正确性优先：任何“找到密码”必须由 ZIP/7z 内置引擎完整解压，或由外部 UnRAR 完整测试复核；CI 再用 7-Zip/unrar 做差分 oracle。快筛只用于否决候选。
- 快筛的分层：结构判据（verifier/压缩流头/CRC）可靠；文件签名启发式可能漏，必须标注“未确认”，并提供严格模式。
- 基准：同机、同语料、同电源模式；报告 p/s、CPU、内存、ETA 误差；不引用未复现的第三方数字作为本项目结论。
- 移动端 ETA 用滑动窗口，不假设可持续满载。

---

## 11. 常用命令

> 以下命令在 `core/` 下执行。

```text
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p acx-cli -- -f <archive> -m dict -d <dict> -t 14
```

---

## 12. Agent 反模式（不要做）

- 在 `main` 上直接提交；跨多个角色边界“顺手重构”。
- 为了跑通而 `unwrap()`、吞错误、跳过测试。
- 引入 `unrar`/7-Zip RAR **源码或链接**“先跑起来再说”；把 hashcat 写成 Cargo 依赖或复制其内核。
- 把“未验证”写成“已完成”；把估算写成实测。
- 复制许可不兼容代码或从破解版工具提取资源。
- 在 UI 线程做解密；每候选新建归档会话；无界 `Parallel.ForEach`。
- 提交大文件/样本/字典；把令牌写进仓库。
