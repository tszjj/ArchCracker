# W1-003：RAR 外部引擎

- 分支：`feat/w1-rar-external`
- 角色：planner（主对话）、core-engineer（主对话实现）、reviewer（独立评审）
- 状态：进行中

## 目标

在 Windows 上通过用户自行安装的 WinRAR/`UnRAR.exe` 恢复 RAR4/RAR5 密码：

```powershell
acx -f encrypted.rar -m dict -d dict.txt -t 4
```

要求：进程调用边界清晰、密码不进入 argv、超时/取消可控、错误分类正确、未安装引擎时明确提示。

## 范围

- 新增 `engines::external`：发现 `ACX_UNRAR` / PATH / `%ProgramFiles%\WinRAR\UnRAR.exe`，统一进程执行、stdin 密码、输出截断、超时与 kill。
- 新增 `archive::rar`：RAR4/RAR5 magic、预检、`ArchiveSession`/`Factory`。
- `ArchiveInfo` 增加 `whole_archive`：RAR 当前以整包 `unrar t` 验证，不解析本地化条目列表；不以“最小条目”伪装。
- 预检：
  - `unrar t -p- -idq` 退出 0 → 未加密；
  - 退出 11 → 加密；再 `unrar l -p- -idq` 区分非头加密/头加密；
  - 其他退出码 → 归档/引擎错误。
- 候选验证：`unrar t -idq -p archive`，密码写 stdin；退出 0 → Hit，11 → Miss，其他 → `AcxError::External`。
- CLI 按 `ArchiveFormat` 选择 ZIP/RAR factory；未安装引擎时退出 3 并提示安装/`ACX_UNRAR`。
- 测试：
  - 纯函数：预检/测试退出码分类；
  - 本地集成（仅当 `UnRAR.exe` + `Rar.exe` 可用时运行，CI 无则跳过）：生成 RAR4/RAR5 文件加密样本，验证 CLI 正确/错误字典、头加密预检；
  - 缺失引擎错误路径（使用不存在的显式路径）。

## 非目标

- 不链接/随包/自动下载 unRAR；不做自研 RAR 解码器。
- 不解析 `unrar` 本地化输出以选择最小条目；W2 用 clean-room 头/KDF 快筛优化。
- 分卷/SFX、断点、RAR 头加密的单独快筛、性能基准不在本切片。
- 非 Windows 平台 RAR 能力仍 Deferred；Linux/macOS 只保证代码可编译，不宣称可用。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- 现有 ZIP 测试全部保持通过；
- RAR 本地集成测试在本机通过（CI 无引擎时跳过并明确输出）；
- `cargo-deny` 通过；无 unRAR 二进制/源码进入仓库；
- 手工确认密码不在 argv、缺引擎提示正确。

## 结果

- 新增 `engines::external`：`ACX_UNRAR` / PATH / `%ProgramFiles%\WinRAR` 发现；stdin 单行密码；stdout/stderr 截断；超时 kill；`CREATE_NO_WINDOW`。
- 新增 `archive::rar`：RAR4/RAR5 magic、`RarSession`/`RarFactory`、整包 `unrar t` 验证；预检用 `t -p-` 区分未加密/加密，再用 `l -p-` 覆盖头加密；退出码 0/11/其他映射为 Hit/Miss/External。
- `ArchiveInfo` 增加 `whole_archive`，CLI 显示 “whole archive (external RAR test)”；按格式选择 ZIP/RAR factory。
- 密码不进 argv：参数只为 `-p`（无值），密码写 stdin；单测断言参数不含测试密码；日志/错误只带 UnRAR stderr 摘要。
- 测试：core 36（含 RAR magic、参数安全、缺失引擎、external 截断）+ CLI 4 + 集成 7（ZIP 6 + RAR 1）+ FFI 2。RAR 集成测试仅在本地存在 `UnRAR.exe` + `Rar.exe` 时运行，CI 无引擎时明确 skip。
- 手工验证（WinRAR 7.22 / RAR5）：文件加密命中/错误字典、头加密命中、未加密 exit 3、缺失引擎 exit 3、密码不在 argv。
- 验证命令：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、`cargo +1.89 test --workspace --locked`、`cargo deny check licenses bans sources`。
- 未验证：RAR4 真实样本、RAR5 非 ASCII/含换行密码、缺卷/损坏分类、大归档、真实超时 kill、Linux/macOS 实际 RAR（CI 无引擎）。
