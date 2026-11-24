# GitHub 仓库设置

本仓库当前是本地 Git 仓库；远端尚未创建。`gh` 已安装但未登录。

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

- 本地 `main` 已提交 bootstrap 版本。
- 远端：**待创建**。
- 需要的用户决策：仓库 owner（个人/组织）、名称、可见性（建议先 private）。
