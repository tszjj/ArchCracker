# ADR-0003：RAR 解压与组件边界

- 状态：**Accepted（Windows 外部引擎）**
- 日期：2026-11-24
- 相关：`docs/licensing.md`、`docs/architecture.md` §4.3
- 影响：`core/crates/acx-core/src/engines/rar*`、Windows W1–W5 发布物

## 背景

项目采用 **Apache-2.0**。RAR 解压本身是 unRAR 许可允许的用途，不违反 RAR 协议；Apache-2.0 也不存在 GPL 的 copyleft 冲突。

但 unRAR 许可仍有自身限制（不得开发 RAR 兼容压缩器、反向工程限制等），且 RAR 解码事实标准是 RARLAB 的 UnRAR/`unrar` 二进制。

## 决策

1. Windows 首发**调用用户自行安装的 WinRAR/`UnRAR.exe`**（仅进程），不做内置解码。
2. 不链接（静态/动态）、不随包、不自动下载 unRAR/7-Zip RAR 代码。
3. 密码不写命令行：用 stdin/临时安全通道；日志脱敏；超时/取消/错误映射由 `engines::external` 统一处理。
4. 自研 clean-room RAR 头/密钥派生验密仅用于快速判错（不复制 unrar 代码）；命中后交外部 `unrar` 完整解压确认。
5. 其他平台（Linux/macOS/Android/HarmonyOS）当前 **Deferred**；未来同样只走外部引擎或独立许可 add-on。
6. `unrar-rs` 仅本地实验，不是依赖、默认不启用、不随发布物。
7. UI 在 RAR 引擎不可用时明确提示“未检测到 RAR 引擎”，引导安装 WinRAR/指定 `UnRAR.exe`，而不是报“密码错误”。

> 如果未来要“零依赖/随包 UnRAR.exe”，按 unRAR 许可单独评审（独立程序、独立许可、独立安装包）。这不改变主项目的 Apache-2.0。

## 备选

| 方案 | 结论 | 原因 |
|---|---|---|
| A. 链接 unRAR/7-Zip RAR | 拒绝 | 许可限制混入主项目；发布审查复杂 |
| B. 外部 `unrar` 进程（用户提供） | **采用** | 边界清晰；Windows 功能不受影响；Apache-2.0 无 copyleft 冲突 |
| C. 纯 Rust `unrar-rs` 内置 | 暂缓 | 许可同源；年轻实现；发布前需单独评审 |
| D. clean-room 完整 RAR 解码 | 暂缓 | 工作量大；先用外部引擎 |
| E. 其他平台暂不做 RAR | 当前采用 | Windows 优先 |

## 后果

**正面**

- 主项目保持 Apache-2.0 干净；RAR 可用性取决于用户环境。
- 外部进程隔离崩溃/内存问题；可替换 unrar 版本。
- 快筛自研覆盖大部分候选，外部引擎只处理疑似命中。

**负面**

- 开箱即用性下降：用户需安装 WinRAR/unrar。
- 进程调用有启动/解析开销；需处理路径空格、编码、超时、取消。
- 其他平台当前无 RAR。

## 验证/门禁

- [ ] `engines::external` 覆盖：缺失引擎、超时、取消、错误输出、路径空格/中文。
- [ ] 候选密码不出现在 argv/日志（测试断言）。
- [ ] 发布物扫描：无 `unrar` 二进制/源码、无 `Rar*` 代码。
- [ ] UI 显示 RAR 引擎状态。
- [ ] 其他平台发布说明标注 RAR 不支持/需 add-on。

## 参考

- unRAR license: https://www.rarlab.com/license.htm
- 7-Zip license: https://www.7-zip.org/license.txt
- Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
