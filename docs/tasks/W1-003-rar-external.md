# W1-003：RAR 外部引擎

- 分支：`feat/w1-rar-external`
- 角色：planner、core-engineer、reviewer
- 状态：完成（RAR5 端到端；RAR4 见 [W1-003c](W1-003c-rar4-ma4.md)；PR #3，评审通过，CI 6/6）

## 设计目标

解决「内核不实现 RAR 解码但要支持 RAR 恢复」的问题。面向 Windows 上持有 RAR4/RAR5 加密包的用户，通过外部 UnRAR 进程完成候选验证，保持清晰的进程边界与许可边界：密码不进命令行参数、超时与取消可控、错误分类明确、缺引擎时给出可操作提示。

## 实现要点

**进程边界**（`engines::external`）：按 `ACX_UNRAR` → PATH → WinRAR 安装目录的顺序发现引擎；密码走标准输入单行；输出截断与超时终止；Windows 下按 OEM 代码页编码非 ASCII 密码（不可表示时报不支持，不静默算错）。

**RAR 会话**（`archive::rar`）：识别 RAR4/RAR5 文件标识；预检用 `t -p-`（0=未加密、11=加密）与 `l -p-` 区分文件加密/头加密；候选测试退出码 0=命中、11=未命中、其他=引擎错误。整包测试，不伪装成「最小条目」选择。

CLI 按格式分发 ZIP/RAR 会话；缺引擎退出 3 并提示配置路径。

## 后续补验与优化

RAR4 已由 [W1-003c](W1-003c-rar4-ma4.md) 用真实样本补验，预检重复已由 [W1-003b](W1-003b-rar-preflight-cache.md) 解决。优化评估结论：需要优化但不阻塞收口——逐候选整包测试留 W2 用密钥派生与快筛优化；固定 60 秒超时和退出码 1/3 分类留 W2；头加密/文件加密区分属低优先，不影响正确性。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

覆盖预检参数、路径绝对化、缺引擎、超时截断；本机有 UnRAR + Rar 时跑 RAR5 集成（ASCII/中文密码、文件/头加密、未加密），CI 无引擎则跳过。

## 结果

core 39 + CLI 4 + 集成 8 + FFI 2 通过。手工（WinRAR 7.22）验证命中/错误字典、头加密、中文密码、未加密 exit 3、密码不在命令行参数。

## 许可与引用

代码不链接、不复制 unRAR；不做自研 RAR 解码。随包策略按 ADR-0004 在 W4 落地（未修改的 UnRAR.exe + 许可证，仅进程调用）。无 unRAR 二进制或源码入仓。

## 评审与对照意见

独立评审通过。当时未验证：RAR4 真实样本、其他代码页/emoji 密码、缺卷/损坏分类、大归档、真实超时终止、Linux/macOS 运行时。
