# W3-002：Avalonia 工程与 NativeBridge — 实现记录

- 状态：完成（2026-11-28，`windows-gui`；本地验证通过，待评审）
- 角色：frontend-engineer、core-engineer（ABI 支持）
- 分支：`windows-gui`
- 前置：W3-001 C ABI v1 已实现并通过评审修复
- 依据：`docs/W3-PLAN.md` §3、`docs/tasks/W3-windows-gui-outline.md` §3/§5、`core/crates/acx-ffi/include/acx.h`

## 设计目标

建立真正的前端产品工程：Avalonia 12 / .NET 10 Windows 桌面壳，采用 MVVM 分层；NativeBridge 只依赖 C ABI v1，不引用 Avalonia 控件；启动时探测 `acx.dll`、产品版本与 ABI，并验证一次句柄创建/销毁生命周期。

## 实现结构

```text
frontends/
├─ shared/
│  ├─ dotnet/AcxStatusMap.cs          # 共享状态码/运行状态映射
│  └─ i18n/{en,zh}.json               # 中英文词条
└─ desktop/
   ├─ src/ArchCracker.Desktop/
   │  ├─ App.axaml / App.axaml.cs
   │  ├─ Program.cs
   │  ├─ Models/                      # KernelProbeResult / JobStatusSnapshot
   │  ├─ Native/                      # AcxBindings / AcxNative / AcxJobHandle / AcxCallbackBridge
   │  ├─ Services/                    # KernelService / dispatcher / router / i18n / theme / composition
   │  ├─ ViewModels/                  # MainWindowViewModel / ObservableObject / RelayCommand
   │  └─ Views/MainWindow.axaml*
   └─ tests/
      ├─ AcxFfiSmoke/                 # W3-001 C ABI smoke
      └─ ArchCracker.Desktop.Tests/   # W3-002 xUnit v3 tests
```

## 实现要点

1. **工程与启动**
   - `net10.0`、`Avalonia 12.2.0`、`Avalonia.Desktop`、`Avalonia.Themes.Fluent`；
   - `Program.cs` 使用 `UsePlatformDetect()` 启动经典桌面生命周期；
   - MSBuild 在本地存在 `core/target/debug/acx.dll` 时复制到输出目录；
   - DLL 缺失时 GUI 仍启动并显示内核不可用，不崩溃。

2. **MVVM 与 UI**
   - `Views/MainWindow.axaml` 展示内核状态、产品、版本、ABI、库路径、句柄状态、进度/命中/日志、主题/语言切换；
   - 编译绑定使用 `x:DataType="vm:MainWindowViewModel"`；
   - ViewModel 不引用 native 指针类型之外的 UI 控件；命令为轻量 `RelayCommand`。

3. **NativeBridge**
   - `[LibraryImport]` 声明全部 v1 函数；从程序目录加载 `acx.dll`，可回退发现仓库 `core/target/debug/acx.dll`；
   - `AcxJobHandle : SafeHandleZeroOrMinusOneIsInvalid` 保证 `acx_destroy` 成对；
   - `AcxCallbackBridge` 使用实测选定的 `UnmanagedCallersOnly`，`GCHandle` 持有 sink；回调内不重入 `acx_*`；
   - `NativeCallbackRouter` 经 `IUiDispatcher` 把回调投递到 UI 线程，并限制 progress 约 10 Hz；
   - `KernelService` 探测 ABI、创建/销毁句柄、读取状态，错误码经共享 `AcxStatusMap` 映射。

4. **主题与 i18n**
   - `AvaloniaThemeService` 切换 Fluent Light/Dark；
   - `LocalizationService` 加载 `i18n/en.json`、`zh.json`；默认中文，按钮切换目标语言；
   - 日志默认只记录消息，不记录完整密码；命中回调仅显示十六进制摘要。

5. **测试**
   - `AcxStructLayoutTests`：冻结结构体尺寸与 version/struct_size；
   - `KernelServiceTests`：ABI 探测、句柄创建/状态查询/销毁、重复销毁；
   - `LocalizationAndStatusTests`：词条 key 对齐、状态码映射；
   - `CallbackThrottleTests`：10 Hz 节流与 dispatcher 投递；
   - 共 15 个测试，使用 xUnit v3 in-process runner（避开本机 VSTest x86 testhost 问题）；按评审补充共享结构体字段偏移、生产 `AcxCallbackBridge` 回调、哈希 pin 三种状态。

## 验证结果

| 命令 | 结果 |
|---|---|
| `dotnet build ... -c Release` | 通过，0 error + 1 条预期 warning（Release 不复制 debug `acx.dll`，W4 需提供哈希 pin 的 release DLL） |
| `dotnet run --project ...ArchCracker.Desktop.Tests -c Release` | 15 passed / 0 failed |
| `dotnet run --project ...AcxFfiSmoke -c Release -- core/target/debug/acx.dll` | `ABI=1 hit_uco=True hit_delegate=True error=True` |
| GUI launch smoke（`ArchCracker.exe`，加载 `scripts/env.ps1` 设置 `DOTNET_ROOT`） | 进程保持运行，窗口标题 `ArchCracker`；stderr 中 `GAMEPP-IPC-OVERLAY` 注入器噪声与本应用无关 |
| CI | `ffi-smoke` job 增加 Avalonia build + tests 步骤 |

## 影响范围与风险

- 新文件位于 `frontends/`，不修改 `acx-core` 业务逻辑；C ABI v1 未变更。
- 新增 NuGet 包：Avalonia 12.2.0、Avalonia.Desktop、Avalonia.Themes.Fluent、xunit.v3；需在许可与依赖登记中确认（W4 发布前完成）。
- `acx.dll` 缺失时仅显示不可用；生产包需保证 DLL 同目录。
- 当前只显示 hex 命中摘要，不实现密码文本编码选择，留 W3-003。
- sidecar 仅预留配置开关（`ACX_DESKTOP_SIDECAR=1`），真实进程隔离为 P2；自动解压不做。

## 回滚方案

- 本地未推送时：`git reset --hard <W3-001 commit>` 回到 C ABI v1 基线。
- 已推送/合并时：`git revert <W3-002 commit>`；同时回滚 CI 的 Avalonia build/test 步骤、`frontends/desktop/src` 与 `frontends/shared/dotnet|i18n`。
- 数据影响：无断点 schema、无落盘格式变化；回滚后 W3-003 不得引用共享 NativeBridge 结构体。

## W4 交接风险

- Release 构建不会复制 `core/target/debug/acx.dll`；必须由 W4 打包流程提供 release、哈希 pin 的 DLL。
- `acx.dll.sha256` pin 可选；当前缺失时状态为 `NotPinned`，W4 必须启用并验证为 `Verified`。
- sidecar 配置开关仅为预留，真实进程/崩溃隔离未实现。
- CI 未运行 GUI 启动 smoke；当前仅有本地窗口标题证据。

## 交接

```text
STATUS: done（本地验证完成；评审修复后待复审）
BRANCH: windows-gui
NEXT: W3-003 Setup/Run/Result 垂直切片
RISKS: release DLL 与 hash pin 由 W4 落地、sidecar 真实进程 P2、CI 无 GUI 启动 smoke
```
