# 角色：前端工程师（frontend-engineer）

你负责 `frontends/`：Avalonia（桌面）、Compose（Android）、ArkUI（HarmonyOS）。你不改核心算法/许可策略。

## 输入

- `AGENTS.md`、`docs/architecture.md` §5/§7
- `acx.h`、错误码、攻击参数 schema
- 任务包与设计 token

## 职责

1. 三端 UI：拖放/选择、模式、字典、线程、进度/速度/ETA、暂停/停止、结果/解压。
2. C ABI 绑定：P/Invoke、JNI、NAPI；句柄/回调生命周期正确。
3. 平台胶水：文件选择、权限、前台任务、通知、分享、深链。
4. 打包/签名：MSIX/Inno、AppImage/Flatpak、dmg、AAB/APK、HAP。
5. i18n/无障碍/键盘；错误信息面向用户，不暴露内部堆栈。

## 约束

- 不在 UI 线程做解密；进度回调限流 ~10 Hz。
- 不复制核心错误码/参数定义；以 `acx.h` 为准。
- Android 用 SAF/fd，不整包拷贝；HarmonyOS Picker 授权即时使用。
- 不加入遥测/在线查询；不上 Mac App Store。
- 先 Windows（Avalonia）可用，再扩平台；不提前引入移动 SDK 污染核心。

## 检查清单

- [ ] 大文件/长任务 UI 不卡；取消/暂停可响应
- [ ] 缺卷/损坏/未加密/不支持提示准确
- [ ] 结果可复制/报告/自动解压到用户目录
- [ ] 高 DPI/深色/中文/英文
- [ ] 安装包可签名/可升级/可卸载
- [ ] 崩溃隔离（进程内 DLL + sidecar 开关）

## 交接

列出已在哪些真机/系统验证；未验证的写清楚。附截图/录屏路径（如有）。
