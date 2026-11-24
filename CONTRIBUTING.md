# 贡献指南

ArchCracker 以 **Apache-2.0** 发布。提交代码即表示你同意以该许可证分发你的贡献。

## 1. 环境

```powershell
# Windows（用户级、免管理员）
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check-env.ps1

# 当前 shell
Set-ExecutionPolicy -Scope Process Bypass -Force
. .\scripts\env.ps1
```

要求：Git、Rust stable（GNU host + MinGW）、.NET 10 SDK（桌面前端阶段）、CMake/Ninja（原生依赖阶段）。

## 2. 构建与测试

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p acx-cli -- --version
```

提交前必须跑 fmt/clippy/受影响测试。跨平台改动注明在哪验证、哪些未验证。

## 3. 分支与提交

- 分支：`feat/<topic>`、`fix/<topic>`、`docs/<topic>`、`chore/<topic>`。
- 提交信息：`type(scope): summary`，例如 `feat(zip): add aes verifier probe`。
- 一个 PR 只做一件事；不混入无关格式化/重构。
- 不 force-push `main`；不提交生成物、样本、密钥。

## 4. 代码规范

- Rust：edition 2021；`rustfmt`；`clippy -D warnings`；库层不 `unwrap` 用户输入；`unsafe` 写 `// SAFETY:`。
- 新文件头：

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors
```

- 依赖：新增前说明用途/许可/体积；更新 `docs/licensing.md`。
- 不引入 unRAR/7-Zip RAR 源码或链接；RAR 只走外部进程（见 ADR-0004）。
- hashcat 只能作为外部进程，不得加入 Cargo 依赖；CPU 路径必须保持可独立运行。
- 不加入遥测/在线查询；不记录完整密码。

## 5. 测试与证据

- 修复 bug 附最小复现；新功能附测试/语料。
- 性能改动附同机 before/after（命令、样本哈希、线程数）。
- 不把“估算”写成“实测”；不引用未复现的第三方数字。

## 6. PR

- 填写 `.github/pull_request_template.md`。
- 至少 1 名 reviewer；核心/许可/安全改动需要 architect/release 角色复核。
- CI 必须绿；未验证项写清楚。

## 7. 多 Agent 协作

- 阅读 `AGENTS.md` 与 `docs/agents/README.md`。
- 用任务包（目标/范围/验收/禁止）派发；实现者与评审者分离。
- 子 Agent 不共享上下文；prompt 自包含。

## 8. 安全问题

不要公开 issue 贴利用细节，见 `SECURITY.md`。
