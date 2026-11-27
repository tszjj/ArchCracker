# W3 阶段目标划分（计划）

- 状态：计划稿（2026-11-28），从 W2 签核基线 `fe02141` 开始
- 开发分支：`windows-gui`；**所有 Windows GUI 相关实现与文档只在该分支进行**，W3 签核前不并入 `main`
- 周期建议：3–4 周，按依赖串行推进；每个切片完成后更新本文状态与对应任务文档
- 前置：W1/W2 已签核（`docs/W1-SIGNOFF.md`、`docs/W2-SIGNOFF.md`）；C ABI v0 仅有 `product/version/status`
- 平台：Windows 10 22H2 / 11 24H2 x64；Linux/macOS/Android/HarmonyOS 不在 W3 实现
- 设计依据：`docs/tasks/W3-windows-gui-outline.md`、`docs/adr/0002-frontend-split.md`、`docs/windows-plan.md` §6、`docs/architecture.md` §5

> 本文沿用 `docs/W2-PLAN.md` 的切片方式：§3 是阶段目标参考，**准出只按 §4 和 W3 签核文件**。每个切片的实现目标、依赖、验收与禁止事项按 W1-001/W2-008 的任务文档格式展开。

## 1. W3 目标

在 Windows x64 上交付可用的 Avalonia 12（.NET 10）GUI，并冻结 C ABI v1：用户能拖放归档、选择攻击参数、后台恢复、实时查看进度并控制运行、查看/复制命中密码、获得可审计报告。GUI 只通过 `acx-ffi` 调 `acx-core`，不复制业务算法、参数定义或错误码。

## 2. 切片总览

```text
W3-001 C ABI v1 ──► W3-002 Avalonia 骨架 ──► W3-003 Setup/Run/Result 垂直切片
                                                     │
                                                     ▼
                                      W3-004 攻击模式/编码/严格/续跑
                                                     │
                                                     ▼
                                      W3-005 统计/报告/交互与诊断
                                                     │
                                                     ▼
                                      W3-006 稳定性/崩溃隔离/W3 签核
```

| 切片 | 状态 | 交付核心 |
|---|---|---|
| W3-001 C ABI v1 | 待启动 | `acx.h` v1、句柄/攻击参数/回调/错误码/panic 隔离 |
| W3-002 Avalonia 骨架 | 待启动 | .NET 10 工程、MVVM、NativeBridge、主题/i18n 基础 |
| W3-003 垂直切片 | 待启动 | Setup/Run/Result、ZIP 字典攻击、暂停/停止/命中复制 |
| W3-004 攻击模式扩展 | 待启动 | 掩码/暴力/混合、编码变体、strict/resume、估算 |
| W3-005 报告与体验 | 待启动 | 统计/报告导出、错误分类、键盘/高 DPI/脱敏日志 |
| W3-006 稳定与签核 | 待启动 | sidecar 开关预留、性能与 UI 冒烟、W3-SIGNOFF |

---

## 3. 阶段化目标（任务包格式）

### W3-001：C ABI v1 冻结

- Role: core-engineer + architect + release-engineer
- Branch: `windows-gui`
- Scope: `core/crates/acx-ffi/`、`core/crates/acx-core` 最小稳定入口、`docs/architecture.md` §5
- Inputs: `docs/tasks/W3-windows-gui-outline.md` §4、`docs/architecture.md:121-181`、W2 已实现参数与统计
- Acceptance:
  - `acx.h` 带 `ACX_ABI_VERSION`、结构体 `struct_size/version`、不透明句柄；
  - `acx_create/acx_destroy/acx_start/acx_pause/acx_resume/acx_stop/acx_status/acx_version/acx_last_error` 可用；
  - `AcxAttackSpec` 覆盖字典/掩码/暴力/混合、线程、encoding、strict、`rar_no_fast_reject`、checkpoint/resume、`report_stats`；
  - `AcxInput` 在 v1 冻结完整 `path/fd/uri` 抽象：判别式、字段、生命周期、错误语义与 `reserved` 全部定义；Windows 桌面先使用 `path`，Android/HarmonyOS 后续接入不破坏 ABI；
  - `on_progress/on_hit/on_log` 回调在 `stop` 返回后不再触发；Rust panic 转 `ACX_ERR_PANIC`；
  - C/C++ header smoke 与 C# P/Invoke smoke 通过；不引入 hashcat/UI 依赖。
- Out of scope: GUI 界面、Android JNI、HarmonyOS NAPI、安装包、W4 随包二进制。

### W3-002：Avalonia 工程与 NativeBridge

- Role: frontend-engineer + core-engineer（接口支持）
- Branch: `windows-gui`
- Scope: `frontends/desktop/`、`frontends/shared/`、`scripts/`（可选 .NET 验证脚本）
- Inputs: W3-001 冻结的 `acx.h`、ADR-0002、W3 GUI 大纲 §3/§5
- Acceptance:
  - .NET 10 + Avalonia 12 工程可在 Windows x64 构建启动；
  - MVVM 分层：Views / ViewModels / Models / Services / NativeBridge，NativeBridge 不引用 Avalonia 控件类型；
  - `[LibraryImport]` 从程序目录加载 `acx.dll`，校验版本/ABI；句柄生命周期有单测；
  - `UnmanagedCallersOnly` 与 `Marshal.GetFunctionPointerForDelegate` 在 C# smoke 中实测生命周期、稳定性与性能后择一，文档阶段不预设；native 回调封送到 UI 线程并限流 ~10 Hz；错误码映射与 `frontends/shared/` 词条统一；
  - zh/en 与浅色/深色基础可切换；日志默认无完整密码。
- Out of scope: 完整 Setup/Run/Result 业务流程、攻击模式扩展、sidecar 实装、安装包。

### W3-003：Setup → Run → Result 垂直切片

- Role: frontend-engineer + qa-engineer
- Branch: `windows-gui`
- Scope: 三屏 View/ViewModel、Services 主流程、运行控制、结果展示
- Inputs: W3-001/002、W1 ZIP 字典 CLI 行为、`docs/windows-plan.md` §6
- Acceptance:
  - Setup 可拖放/选择 ZIP，显示预检信息（格式/加密/条目/错误分类）；
  - 只开放字典模式；点击开始后后台线程调用 C ABI，Run 屏显示进度/速度/ETA；
  - 暂停/继续/停止可用，停止语义与 CLI 一致；UI 不冻结；
  - Result 屏显示并复制密码，展示命中复核方式；错误归档给出明确分类；
  - ZIP 已知密码命中、错误密码未命中、未加密/损坏/缺卷提示三类 E2E 用例通过；
  - GUI 与 CLI 对同一归档/字典结果一致。
- Out of scope: 掩码/暴力/混合、strict/encoding/resume、统计报告导出、自动解压（项目整体不做）、RAR。

### W3-004：攻击模式与恢复选项

- Role: frontend-engineer + core-engineer
- Branch: `windows-gui`
- Scope: Setup 高级参数、Services 参数映射、C ABI 参数扩展验证、checkpoint/resume
- Inputs: W2-002/003/004/005/006 任务文档、W3-003 垂直切片
- Acceptance:
  - 掩码/暴力/混合三种模式可选择，参数校验与 CLI 等价；
  - encoding variants、strict、`rar_no_fast_reject` 可设置，签名变化导致旧断点拒绝时给出明确提示；
  - `--estimate` 等价能力展示 keyspace/ETA/24h 容量/变体倍数与空间警告；
  - 暂停/停止后可选择续跑，GUI 与 CLI 对同一 checkpoint 行为一致；
  - ZIP/7z/RAR 各选一个已知密码样本做 GUI↔CLI 差分。
- Out of scope: 新攻击算法、批量 GUI 队列（P2）、GPU/hashcat。

### W3-005：报告、统计与交互体验

- Role: frontend-engineer + qa-engineer + reviewer
- Branch: `windows-gui`
- Scope: Result 报告、Stats 展示/导出、错误呈现、日志、键盘/高 DPI/无障碍
- Inputs: W2-007/W2-008 计数口径、`docs/W2-SIGNOFF.md` 未验证项、W3 GUI 大纲 §6
- Acceptance:
  - 报告展示耗时、tried、按判据快筛否决、`full_attempted`、`external_attempts`；公式与 CLI 一致；
  - 错误区分归档级分类与候选级 Miss，不承诺逐候选"密码错/损坏"二分；
  - `Ctrl+O`/`F5`/`Esc`、Tab 焦点、可访问名称可用；高 DPI 与深色/zh-en 冒烟通过；
  - 运行中不弹模态；日志/报告/崩溃转储默认不含完整密码；
  - 结果页明确"不提供自动解压"；只提供打开归档目录与导出报告，RAR 仅保留 `UnRAR t` 复核语义。
- Out of scope: W4 安装包与签名、随包 UnRAR/hashcat、跨前端 i18n 全量迁移。

### W3-006：稳定性、崩溃隔离与 W3 签核

- Role: release-engineer + frontend-engineer + reviewer + architect
- Branch: `windows-gui`
- Scope: sidecar 开关、崩溃诊断、性能/UI 冒烟、CI、W3-SIGNOFF、状态同步
- Inputs: W3-001…005 全部产物、`docs/W2-EXIT-PLAN.md` 的签核模板
- Acceptance:
  - 进程内 DLL 为主路径；sidecar 只预留开关与配置，W3 不实现真实进程，P2 再实现；
  - 长任务 UI 不卡，取消请求观察 ≤200 ms，进度刷新 ~10 Hz；连续运行/大归档冒烟有记录；
  - Windows CI 增加 .NET 构建/测试（或明确记录未加入原因），Rust 6 job 不回归；
  - 许可复核：RAR 外部边界、hashcat 非依赖、无新增不兼容依赖；
  - `docs/W3-SIGNOFF.md` 逐条勾选准出项，结论 GO / NO-GO；未验证项显式列出；
  - W3 分支合并回 `main` 前完成 reviewer/architect/release 评审与 CI。
- Out of scope: W4 安装包、代码签名、随包引擎、W5 Beta 验收。

---

## 4. W3 准出标准（唯一）

> §3 的每个切片目标只是任务参考；W3 是否准出只按本节与 `docs/W3-SIGNOFF.md`。

1. C ABI v1 已冻结：`acx.h` 版本化、攻击参数/错误码/回调/统计覆盖 W2 全能力，C/C# smoke 通过；
2. Avalonia GUI 在 Windows 10/11 x64 可启动，Setup/Run/Result 主流程可用；
3. ZIP/7z/RAR 各至少一个已知密码样本可由 GUI 找回，结果与 CLI 一致；字典/掩码/暴力/混合可用；
4. 暂停/继续/停止、进度/ETA、错误分类、断点续跑、统计报告符合 W2 语义；
5. UI 不阻塞；取消 ≤200 ms；进度限流 ~10 Hz；zh/en、高 DPI、键盘/可访问名称可用；
6. 日志/报告/崩溃信息默认不含完整密码；RAR 仅外部 UnRAR；hashcat 非 Cargo 依赖；无新不兼容依赖；
7. Rust 6 job CI 与 .NET Windows 构建/测试全绿（若 .NET 未入 CI，必须在签核中列为阻塞或例外批准）；
8. `docs/W3-SIGNOFF.md` 完成并给出 GO；所有未验证项写明，不把 W4/W5 事项写成完成。

## 5. 顺序与角色

```text
W3-001 C ABI v1
   │
   ▼
W3-002 Avalonia 骨架
   │
   ▼
W3-003 垂直切片 ──► W3-004 攻击模式 ──► W3-005 报告体验 ──► W3-006 稳定签核
```

角色：frontend-engineer 主责 GUI；core-engineer 支持 C ABI；qa-engineer 做 GUI↔CLI 差分与冒烟；reviewer 审正确性；architect 审 ABI/边界；release-engineer 审 CI/许可/签核。

## 6. 与 W4/W5 的边界

- **W3 不做**：安装包、代码签名、随包 UnRAR/hashcat、Defender/SmartScreen、完整崩溃转储交付、W5 Beta 验收。
- **W3 必须提供**：可被 W4 打包的目录/文件清单假设、DLL 加载与版本校验、sidecar 配置开关、许可边界复核记录。
- **W4 才做**：MSIX/Inno Setup、单一 Full 版随包引擎、签名与哈希、卸载升级、AV 检查。
- 为避免与旧文档冲突：`docs/roadmap.md` §W3 中"Windows 打包：MSIX/Inno + 代码签名"属于 W4，实施时以 `docs/windows-plan.md` §7 和本文为准。

## 7. 风险与待确认

1. C ABI v1 若 Q3 之前未冻结，W3-002/003 会被接口变更反复返工；
2. Avalonia 12 / .NET 10 版本需锁定，CI 机器需验证 SDK；
3. 回调生命周期与 delegate 存活是 P0 风险，必须在 W3-001/002 单测覆盖；
4. 项目不实现自动解压；`windows-plan.md` 中 `UnRAR.exe x` 的历史描述仅作旧资料，与 W3/W4 交付无关；
5. W3 本地验证先于 CI 扩展，但正式签核必须有 CI 证据；
6. `windows-gui` 分支是隔离分支；不得从 `main` 直接提交 GUI 文件，PR 目标在 W3 签核前不得指向 `main`。
