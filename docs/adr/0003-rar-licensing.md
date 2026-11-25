# ADR-0003：RAR 解压与组件边界

- 状态：**Partially superseded by ADR-0004（Windows Full 版随包 UnRAR.exe）**
- 日期：2026-11-24
- 相关：`docs/licensing.md`、`docs/architecture.md` §4.3、ADR-0004
- 影响：`core/crates/acx-core/src/engines/rar*`、Windows W1–W5 发布物

> **2026-11-24 策略更新**：本 ADR 中“不随包”的部分由 [ADR-0004](0004-bundled-engines.md) 修订。Windows 单一 Full 版随包未修改的 `UnRAR.exe`，仍不链接、不调用 `unrar.dll`、不随包 WinRAR、不复制 unRAR 源码。进程隔离与密码 stdin 边界继续有效。

## 背景

项目采用 **Apache-2.0**。RAR 解压本身是 unRAR 许可允许的用途，不违反 RAR 协议；Apache-2.0 也不存在 GPL 的 copyleft 冲突。

但 UnRAR 许可仍有自身限制（不得开发 RAR 兼容压缩器、不得重建 RAR 压缩算法等），且 RAR 解码事实标准是 RARLAB 的 UnRAR/`unrar` 二进制。

## 决策

1. Windows Full 版**随包未修改的 `UnRAR.exe`**（仅进程），用户可用 `ACX_UNRAR`/配置覆盖路径；不做内置解码。
2. 不链接（静态/动态）、不调用 `unrar.dll`、不自动下载；Windows Full 版随包未修改的 `UnRAR.exe`（见 ADR-0004）。
3. 密码不写命令行：用 stdin/临时安全通道；日志脱敏；超时/取消/错误映射由 `engines::external` 统一处理。
4. 自研独立 RAR 头/密钥派生验密仅用于快速判错（不复制 unrar 代码；结构依据公开 RAR5 technote，check 细节来自公开第三方资料/黑盒差分，官方 technote 未公开完整细节，不声称正式 clean-room）；命中后交外部 `UnRAR.exe t` 做密码/完整性复核，不做 `x/e` 解压交付。RAR5 的边界见 [ADR-0005](0005-rar5-password-verifier.md)，发布前需 release-engineer/法务复核。
5. 其他平台（Linux/macOS/Android/HarmonyOS）当前 **Deferred**；未来同样只走外部引擎或独立许可 add-on。
6. `unrar-rs` 仅本地实验，不是依赖、默认不启用、不随发布物。
7. UI 在 RAR 引擎不可用时明确提示“未检测到 RAR 引擎”，引导“修复安装/选择 `UnRAR.exe`/安装独立 UnRAR”，而不是报“密码错误”；不要求用户安装 WinRAR。

> Full 版的随包策略、版本固定、hashcat 与 CPU 回退见 ADR-0004；本 ADR 不再把“不随包”作为目标。

## 备选

| 方案 | 结论 | 原因 |
|---|---|---|
| A. 链接 unRAR/7-Zip RAR | 拒绝 | 许可限制混入主项目；发布审查复杂 |
| B. 外部 `unrar` 进程（Full 版随包） | **采用（ADR-0004）** | 边界清晰；开箱可用；Apache-2.0 无 copyleft 冲突 |
| C. 纯 Rust `unrar-rs` 内置 | 暂缓 | 许可同源；年轻实现；发布前需单独评审 |
| D. clean-room 完整 RAR 解码 | 暂缓 | 工作量大；先用外部引擎 |
| E. 其他平台暂不做 RAR | 当前采用 | Windows 优先 |

## 后果

**正面**

- 主项目保持 Apache-2.0 干净；Full 版 RAR 开箱可用。
- 外部进程隔离崩溃/内存问题；可替换 unrar 版本。
- 快筛自研覆盖大部分候选，外部引擎只处理疑似命中。

**负面**

- 随包增加体积、AV/SmartScreen 与许可审计成本。
- 进程调用有启动/解析开销；需处理路径空格、编码、超时、取消。
- 其他平台当前无 RAR。

## 验证/门禁

- [ ] `engines::external` 覆盖：缺失引擎、超时、取消、错误输出、路径空格/中文。
- [ ] 候选密码不出现在 argv/日志（测试断言）。
- [ ] 发布物扫描：`UnRAR.exe` 原样、附 license，无 `WinRAR.exe`/`Rar.exe`、无 unRAR 源码。
- [ ] Full 版与删除随包引擎后的降级行为均有测试。
- [ ] UI 显示 RAR 引擎状态。
- [ ] 其他平台发布说明标注 RAR 不支持/需 add-on。

## 参考

- UnRAR License（SPDX；随包以实际 license.txt 为准）: https://spdx.org/licenses/UnRAR.html
- WinRAR EULA（trial bundling 限制）: https://www.rarlab.com/license.htm
- 7-Zip license: https://www.7-zip.org/license.txt
- Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
