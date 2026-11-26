# GitHub 仓库设置

仓库已创建并推送到 GitHub（当前为私有仓库，`origin` = `https://github.com/tszjj/ArchCracker.git`）；`gh` 已登录。本文保留首次建仓与推荐设置步骤，当前状态见 §5。

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
- **分支保护**（Settings → Branches）：
  - 禁止直接 push；
  - 要求 PR + 至少 1 个 approve；
  - 要求 CI `rust (windows/ubuntu/macos)` 通过；
  - 禁止 force push/删除。
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

- 远端：**已创建（私有）**，`origin` 指向 `tszjj/ArchCracker`；默认分支 `main`。
- 已合并 ZIP、AES、RAR、Full 随包文档、RAR 预检缓存等 PR（详见 `docs/PROJECT-GUIDE.md` §5）。
- W1-004（7z）当前在本地 `feat/w1-004-7z` 分支完成验证；按用户要求未推送，里程碑确认后统一提 PR 并重跑 6 个 CI job。
- CI：6 个 job（Windows MSVC/GNU、Ubuntu、macOS、MSRV 1.89、cargo-deny），最近一次 main 全绿。
- **分支保护当前无法启用**：私有免费仓库调用 API 返回 403（需 GitHub Pro 或转公开）。因此 `main` 保护目前只是流程约束；转公开/升级后按 §3 开启。
- Vulnerability alerts 当前为关闭（API 404）；Dependabot、secret scanning、Private vulnerability reporting 需在 Settings 中逐项核对。
- 仓库仍为私有；转公开前逐项检查 §4。
