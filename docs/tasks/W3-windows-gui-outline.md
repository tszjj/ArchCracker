# W3：Windows GUI 设计大纲

- 状态：设计大纲（2026-11-28），尚未实现
- 分支：`windows-gui`（从 W2 基线 `main @ fe02141` 创建）；**所有 Windows GUI 相关工作只在本分支进行**，合并回 `main` 前不得从 `main` 直接改动 GUI 文件
- 前置：W1/W2 已签核（`docs/W1-SIGNOFF.md`、`docs/W2-SIGNOFF.md`）
- 平台：Windows 10 22H2 / 11 24H2 x64（ARM64 另评）
- 依据：`docs/adr/0002-frontend-split.md`、`docs/windows-plan.md` §6、`docs/architecture.md` §5、`docs/W2-SIGNOFF.md`

> 本文只定义 W3 Windows GUI 的设计大纲与开发顺序，不作为 W3 准出标准。阶段化切片与准出标准见 [`docs/W3-PLAN.md`](../W3-PLAN.md)；正式任务文档需为 C ABI v1、Avalonia 工程、各屏幕/组件分别建立验收。

## 1. 目标与非目标

### 1.1 目标

在 Windows x64 上提供可安装的 Avalonia 12（.NET 10）桌面壳：用户拖放归档 → 选择攻击模式与参数 → 后台恢复 → 实时进度/运行控制 → 查看并复制命中密码、导出报告。GUI 只通过稳定 C ABI 调用 `acx-core`，不复制核心算法、错误码或攻击参数定义。

### 1.2 非目标

- 不重新实现 ZIP/7z/RAR 引擎、快筛、候选源、调度器或断点逻辑；
- 不在本分支做 W4 安装包、签名、随包 UnRAR/hashcat（但设计需预留接口与路径）；
- 不在本分支引入 Linux/macOS/Android/HarmonyOS SDK；同一套 Avalonia 代码后续复用即可；
- 不做在线查询、遥测、自动更新、共享密码库；
- **不实现自动解压**；命中后只展示/复制密码、导出报告，用户可自行解压；
- 不在 UI 线程执行解密，不把完整密码写入日志或普通诊断输出。

## 2. 整体架构

```text
┌──────────────────────────────────────────────────────────────┐
│ ArchCracker.exe — Avalonia 12 / .NET 10                      │
│ Views (3 screens) ↔ ViewModels ↔ Services / Domain Models    │
│ NativeBridge (P/Invoke, callback marshalling, handle lifetime)│
└───────────────────────────┬──────────────────────────────────┘
                            │ C ABI v1（W3 冻结）
┌───────────────────────────▼──────────────────────────────────┐
│ acx.dll — Rust cdylib                                        │
│ C ABI 薄层：类型转换 / 错误码 / 回调生命周期 / panic 捕获      │
│ acx-core：job / scheduler / candidates / archive / checkpoint │
└───────────────────────────┬──────────────────────────────────┘
                            │ 外部进程（仅进程边界）
                UnRAR.exe（RAR t）  ·  hashcat（Deferred/可选）
```

### 2.1 进程模型

- **默认进程内**：GUI 通过 `[LibraryImport]` 加载随程序目录的 `acx.dll`；DLL 从程序目录加载并校验哈希。
- **可选 sidecar**：只预留开关与配置，W3 不启动真实进程；实现推迟到 P2。
- 所有原生长任务在后台线程；UI 线程只接收限流后的进度（约 10 Hz）。
- `acx.dll` 回调不得直接操作 UI 控件；经 `Dispatcher.UIThread.Post`/`InvokeAsync` 封送。
- C# 回调委托/函数指针生命周期由 `NativeBridge` 持有，直到 `stop`/`destroy` 完成且回调不再触发。

### 2.2 与 CLI 的关系

GUI 不调用 `acx.exe` 文本输出作为主路径；CLI 继续独立存在，供脚本与差分验证。二者共用 `acx-core` 语义与 C ABI v1 定义的攻击参数/错误码；禁止在 GUI 复制一套参数字符串或退出码解释。

## 3. 主要模块划分

| 模块 | 目录建议 | 职责 |
|---|---|---|
| App Bootstrap | `frontends/desktop/src/App.axaml*` | 应用启动、主题/i18n、DI、全局异常与日志初始化 |
| Views | `Views/` | 主界面、运行、结果三屏；对话框与错误提示 |
| ViewModels | `ViewModels/` | 表单状态、命令、状态机、进度/报告映射；不持有原生线程逻辑 |
| Domain Models | `Models/` | `ArchiveInfo`、`AttackConfig`、`JobReport`、`ErrorInfo`；与 C ABI schema 对齐 |
| Services | `Services/` | 归档预检、任务启动/暂停/停止/续跑、设置、报告导出 |
| NativeBridge | `Native/` | P/Invoke 声明、回调封送、句柄生命周期、错误码转换、版本/能力探测 |
| Diagnostics | `Diagnostics/` | 脱敏日志、崩溃转储开关、性能计数；默认不记录完整密码 |
| Shared UI | `frontends/shared/` | 设计 token、错误码映射、i18n 词条、测试向量（跨前端复用） |

模块边界：ViewModels 只依赖 Services/Models；Services 只通过 NativeBridge 访问内核；NativeBridge 不引用 Avalonia 类型。

## 4. C ABI v1 接口约定（W3 前置）

`core/crates/acx-ffi/include/acx.h` 已冻结 ABI v1：句柄/攻击/回调/状态/估算函数与完整 `AcxInput{path|fd|uri}` 均已实现；`docs/W3-PLAN.md` 与 `docs/CL-W3-001.md` 记录实现和评审。W3-003 需按当前 v1 对接，不得引用旧的 v0 草案：

- 结构体带 `struct_size`/`version`；未知字段忽略；破坏性布局变更才提升 ABI 版本。
- 句柄不透明，`create`/`destroy` 成对；一个 handle 同时只允许一个 `start`；`pause`/`resume`/`stop` 可跨线程调用。
- 回调：`on_progress`、`on_hit`、`on_log`、`on_finished`；`stop` 返回后不再启动 progress/hit/log，`on_finished` 作为终态通知仍触发一次。
- **C ABI v1 必须冻结完整 `AcxInput{path|fd|uri}` 抽象**（项目支持多平台）：Windows 桌面主用 `path`，Android 走 `fd`，HarmonyOS 走 `uri`；v1 即定义判别式、字段、生命周期与错误语义，避免后续平台接入时破坏 ABI。
- 字符串：v1 路径/URI 用 UTF-8 NUL 结尾；二进制密码用 `ptr + len`；fd 用平台原生整数句柄；C# 侧不做隐式截断。
- Rust panic 必须 `catch_unwind` 转为 `ACX_ERR_PANIC`，不得跨 FFI。
- 错误码登记表与前端映射统一放 `docs/architecture.md`/`frontends/shared/`，GUI 不得自定义一套数值。
- 需暴露 W2 已实现的：`--encoding-variants`、`strict`、`rar_no_fast_reject`、`report_stats`、checkpoint/resume、攻击模式（字典/掩码/暴力/混合）、估算（keyspace/ETA/空间）、统计字段（按判据桶、`full_attempted`、`external_attempts`）。

> 风险：C ABI v1 是 W3 的硬前置；未冻结前不得把 GUI 的控件字段直接映射到临时 ABI，否则后续破坏性改动会波及整个 UI。

## 5. 关键组件设计

### 5.1 NativeBridge

- 用 `LibraryImport`/`DllImport` 加载程序目录 `acx.dll`；启动时校验 `acx_version()` 与 ABI v1 兼容，不满足则进入不可用状态并提示。
- 回调模型已在 W3-001/002 smoke 中实测：生产路径使用 `UnmanagedCallersOnly`，`Marshal.GetFunctionPointerForDelegate` 仅作为 smoke 对照。
- NativeBridge 持有回调生命周期；封送 `AcxAttackSpec` 与回调；把 native `uint8_t*` 密码复制为 `byte[]` 后交 ViewModel。
- 所有 native 调用返回统一 `Result<T, ErrorInfo>`；`AcxStatus` → `ErrorInfo` 映射集中在 `frontends/shared/`。
- 回调线程与 UI 线程解耦；日志默认脱敏，密码只在结果对象中存在。

### 5.2 主界面（Setup）

- 拖放或文件选择器选择归档（含分卷首卷/SFX）；调用预检展示格式、加密、条目、分卷、头加密、错误分类。
- 攻击模式 Tab：字典（路径）、掩码（表达式）、暴力（字符集/长度）、混合（字典 + 规则/前后缀）；高级参数折叠。
- 运行选项：线程数、`fast/strict`（显示为"严格模式"与"快筛"）、`rar_no_fast_reject`、编码变体、checkpoint/resume、`report_stats`。
- 点击"开始"前展示估算：keyspace、ETA、24h 容量、变体倍数、空间警告；超长 ETA 需二次确认。

### 5.3 运行界面（Run）

- 显示进度条、已试/总数、p/s、ETA；快筛/完整验证/外部调用计数待 W3-005 的结构化统计 ABI 通道后接入。当前候选默认不显示。
- 暂停/继续/停止/强制停止；停止须给出明确语义（是否写断点）；取消请求观察 ≤200 ms，外部进程 ≤2 s kill 继承 W1 指标。
- 日志折叠面板：只记录阶段与错误分类，不记录明文密码。
- 运行中禁止模态弹窗；错误以横幅/状态栏呈现。

### 5.4 结果界面（Result）

- 大字展示密码、复制按钮、编码(bytes → 显示文本)说明；命中来源与完整复核方式（内置解压 / `UnRAR t`）。
- 报告：耗时、尝试数、统计字段、归档/攻击指纹、checkpoint 状态；导出文本报告不含明文密码日志之外的额外敏感信息。
- 提供“打开归档所在目录”和“导出报告”；不提供自动解压。

### 5.5 设置与持久化

- 本地设置：默认线程、主题、语言、日志级别、sidecar 开关、UnRAR 路径（用户显式指定）、输出目录。
- 不保存字典内容、密码、未脱敏日志；checkpoint 由内核管理，GUI 仅展示与选择。
- 配置变更影响断点签名的选项时，提示用户"继续将拒绝旧断点"。

## 6. 交互规范

| 项 | 规范 |
|---|---|
| 屏幕结构 | 三屏：Setup / Run / Result；一屏完成 90% 常用操作，高级项折叠 |
| 拖放 | 接受首卷或单文件；多文件仅提示首卷；不支持格式给出分类提示 |
| 键盘 | `Ctrl+O` 选择归档、`F5` 开始、`Esc` 停止/返回；Tab 顺序与焦点可见 |
| 进度刷新 | native 回调可在 worker 线程高频触发；UI 限流 ~10 Hz，避免过载 |
| 长任务 | 不在 UI 线程做解密/IO；禁用阻塞式对话框；窗口关闭需先确认停止 |
| 高 DPI | Avalonia 高 DPI 缩放；图标与文本随缩放；布局最小宽度约束 |
| 主题/i18n | 深色/浅色；zh/en 词条放 `frontends/shared/`；回退英文 |
| 无障碍 | 控件名称/自动化 ID；状态变化可访问；不只靠颜色表达错误 |
| 错误呈现 | 归档级分类（缺卷/损坏/未加密/不支持/头加密）与引擎错误分开；候选级统一 Miss，不宣称"密码错/损坏"二分 |
| 隐私 | 日志/崩溃转储默认不含完整密码；结果页密码复制需用户显式操作 |

## 7. 许可与安全边界

- RAR 仍只通过外部未修改 `UnRAR.exe` 进程命中复核；不链接/复制 unRAR 源码，不做自研 RAR 解压。
- 项目决策：**不实现自动解压**。`windows-plan.md:83` 中 `UnRAR.exe x` 的历史描述仅作旧资料，不是 W3/W4 交付内容；RAR 继续只用 `UnRAR.exe t` 做完整复核，不解压。
- hashcat 仅外部进程、不是 Cargo 依赖；W2-001 Deferred 状态下 GUI 不暴露 GPU 后端开关。
- 默认零网络；不自动下载 UnRAR/hashcat 或更新。
- DLL/so 从程序目录加载并校验哈希；sidecar 进程只接受本地受控参数。

## 8. 开发优先级与里程碑

| 优先级 | 工作包 | 完成标志 |
|---|---|---|
| P0 | C ABI v1 冻结（attack API、回调、错误码、统计/估算） | `acx.h` 版本化，C/C# smoke 通过，panic 不跨 FFI |
| P0 | Avalonia 工程骨架 + NativeBridge + 主题/i18n | Windows 构建启动，能显示版本/能力探测 |
| P0 | Setup：归档选择/预检 + 字典攻击 + 运行控制 + Result 命中 | 拖放 ZIP/7z，字典已知密码命中，暂停/停止/复制可用 |
| P1 | 掩码/暴力/混合/编码变体/strict/resume/checkpoint | 四种模式可运行；续跑拒绝不匹配配置 |
| P1 | 统计/估算/报告导出与日志脱敏 | 计数与 CLI 一致；报告可复核；日志无完整密码 |
| P2 | 批量队列、sidecar 真实进程隔离 | 独立验收；不阻塞 W3 首版；自动解压不在项目范围内 |
| W4 交接 | 安装包、签名、随包 UnRAR/hashcat、崩溃转储、AV | W4 任务文档验收 |

建议切片顺序：ABI v1 → 工程骨架 → Setup/预检 → Run/字典 → Result → 控制/断点 → 攻击模式扩展 → 统计/报告 → P2 项。每个切片必须可独立构建与验证。

## 9. 验收条件（大纲级，非最终准出）

1. Windows 10/11 x64 上可启动、预检、运行四种攻击模式；已知密码 100% 命中；
2. UI 线程不被长任务阻塞；进度刷新 ~10 Hz；暂停/停止语义与 CLI 一致；
3. C ABI v1 稳定：版本探测、句柄成对、回调生命周期、panic 捕获、错误码映射均有测试；
4. 统计/估算与 CLI 对齐；默认与 strict/encoding 选项可解释；
5. 日志、崩溃转储、报告默认不包含完整密码；RAR 边界与 hashcat 非依赖不变；
6. zh/en、高 DPI、深色模式可用；键盘操作与错误分类清晰；
7. 本分支所有改动可追溯；合并回 `main` 前完成 reviewer + architect/release 评审与 CI。

## 10. 分支与工作流约束

- 分支名：`windows-gui`；从 `main @ fe02141`（W2 签核基线）创建。
- 所有 Windows GUI 相关代码、测试、文档与 PR 目标分支都指向 `windows-gui`；不得在 `main` 上直接提交 GUI 变更。
- 本仓库未启用服务端分支保护，但本地 `pre-push` 钩子禁止直接 push `main`；所有合并通过 PR。
- 与核心/ABI 相关的改动需在 PR 中说明跨语言影响，并由 architect/release 复核许可与接口稳定性。

## 11. 已确认决策（2026-11-28）

1. **C ABI v1 需要完整 `AcxInput{path|fd|uri}` 抽象**。项目支持多平台，v1 必须一次性冻结判别式、字段、生命周期与错误语义；Windows 桌面先使用 `path`，Android/HarmonyOS 后续接入不再破坏 ABI。
2. **sidecar 首版仅预留开关**，W3 不实现真实进程；真实进程隔离推迟到 P2。
3. **项目不实现自动解压**。命中后只展示/复制密码与导出报告；RAR 继续只用 `UnRAR.exe t` 做复核。
4. **NativeBridge 回调模型由实测决定**。在 W3-001/002 的 C# smoke 中按 .NET 10 下的生命周期、稳定性与性能选择 `UnmanagedCallersOnly` 或 `Marshal.GetFunctionPointerForDelegate`，不在文档阶段预设。
