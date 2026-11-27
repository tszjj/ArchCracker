# GitHub 仓库设置

仓库已创建并推送到 GitHub（**当前为公开仓库**，`origin` = `https://github.com/tszjj/ArchCracker.git`）；`gh` 已登录。本文保留首次建仓与推荐设置步骤，当前状态见 §5。

## 1. 登录

```powershell
gh auth login
# 选择 GitHub.com → HTTPS → Login with a web browser
```

或使用已有 token（不要写进仓库）：

```powershell
$env:GH_TOKEN = '<token>'
gh auth status
```

## 2. 创建远端并推送

在仓库根目录：

```powershell
# 建议先私有，确认无敏感内容后再转公开
gh repo create ArchCracker --private --source=. --remote=origin --push
```

如果远端已存在：

```powershell
git remote add origin https://github.com/<owner>/ArchCracker.git
git push -u origin main
```

> 公开前检查：`git ls-files` 不应包含 `解密1/2/3`、样本归档、字典、密钥。
> `.gitignore` 已排除这些目录，但仍建议 `git status --ignored` 复核。

## 3. 推荐设置

- **默认分支**：`main`。
- **分支保护**（Settings → Branches）：当前决策为**不启用**服务端分支保护；以"禁止直接 push `main`"的流程 + 本地 `.githooks/pre-push` 钩子约束（安装：`powershell -ExecutionPolicy Bypass -File .\scripts\install-push-guard.ps1`）。该钩子是本地保护，其他克隆仍可绕过；若后续启用分支保护，再要求 PR + approve + 6 个 CI job + 禁止 force push/删除。
- **Actions**：允许 GitHub Actions；fork PR 默认只读 token。
- **Security**：启用 Private vulnerability reporting、Dependabot alerts、secret scanning。
- **Topics**：`archive`、`password-recovery`、`rust`、`cross-platform`、`android`、`harmonyos`。
- **Releases**：附源码归档、SHA-256、第三方 notices、LICENSE/NOTICE。

## 4. 公开发布前清单

- [ ] 仓库无样本/破解工具/字典/密钥
- [ ] `LICENSE`、`THIRD_PARTY_NOTICES.md` 完整
- [ ] RAR/hashcat 策略与 ADR-0004 一致（Full 随包未修改二进制 + 许可；无 WinRAR/GPU 运行时）
- [ ] README 的“授权使用”声明
- [ ] CI 三平台绿
- [ ] macOS 不上 App Store 的说明
- [ ] 移动端首发无 RAR 的说明

## 5. 当前状态

- 远端：**已创建并转为公开（2026-11-28）**，`origin` 指向 `tszjj/ArchCracker`；默认分支 `main`。
- 已合并 ZIP、AES、RAR、Full 随包文档、RAR 预检缓存等 PR（详见 `docs/PROJECT-GUIDE.md` §5）。
- W1-004（7z）PR #10、W1-005（分卷/SFX）PR #11、W1-006（运行控制/断点）PR #12、W1-007（流式字典）PR #13、W1-008（1M×1GB 基准）PR #14、W1-009（RAR5 快筛 + W1 评估/矩阵）PR #15。**均已合并到 `main`**；W1 signoff 2026-11-26（[W1-SIGNOFF](W1-SIGNOFF.md)）。
- 合并顺序：#10 → #11 → #12 → #13 → #14 → #15；已按顺序合并，`main` 合并后 CI 6/6 全绿。
- CI：6 个 job（Windows MSVC/GNU、Ubuntu、macOS、MSRV 1.89、cargo-deny），最近一次 main 全绿。
- **分支保护决策**：转公开后仍**不启用**服务端分支保护；`main` 禁止直接 push 由流程与本地 `.githooks/pre-push` 钩子执行（见 §3）。钩子只保护已安装的克隆，其他客户端/API 仍可绕过。
- CI：公开后重跑 `main` run `46025110880`，6/6 全绿（2026-11-28）。
- W2 签核见 [`W2-SIGNOFF.md`](W2-SIGNOFF.md)；准出后公开仓库只保留 W2 基线 `main`，旧分支删除。
- Vulnerability alerts / Dependabot / secret scanning 需在 Settings 中逐项核对；公开仓库不再使用 Private vulnerability reporting。
