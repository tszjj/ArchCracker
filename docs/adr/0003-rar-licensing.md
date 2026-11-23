# ADR-0003：RAR 解压与 GPL 分发边界

- 状态：**Accepted（Windows 外部引擎；分发法务复核待办）**
- 日期：2026-11-24
- 相关：`docs/licensing.md`、`docs/architecture.md` §4.3
- 影响：`core/crates/acx-core/src/engines/rar*`、Windows W1–W5 发布物

## 背景

项目采用 GPL-3.0-only。RAR4/RAR5 的解码事实标准是 RARLAB 的 UnRAR 源码/`unrar` 二进制；7-Zip 的 RAR 部分也源自同一许可约束。

**先澄清**：解压 RAR 本身是 unRAR 许可允许的用途，不违反 RAR 协议。本 ADR 只解决“GPL-3.0 内核如何分发 RAR 能力”，不是限制 RAR 解压功能。

已知约束（需法务确认）：

- UnRAR 许可允许免费使用源码处理 RAR，但**禁止用于开发 RAR 兼容压缩器**，并有反向工程等限制；这属于 GPL-3.0 §10 不允许的“额外限制”。
- 7-Zip 主体是 LGPL-2.1+，但 RAR 代码带 unRAR restriction；Debian 将 `p7zip-rar` 放在 non-free，而 `p7zip` 在 main。
- 因此，把 UnRAR/7-Zip RAR 代码**静态/动态链接进 GPL 内核并分发**存在许可冲突风险。

## 决策

1. **内核不链接（静态/动态）、不随包分发、不自动下载 unRAR/7-Zip RAR 代码或二进制。**
2. **Windows 首发**通过用户自行安装的外部程序完成 RAR 确认/解压：
   - 检测 WinRAR 安装目录下的 `UnRAR.exe`，或用户指定 `unrar.exe`；
   - 核心只做进程调用、参数转义、输出解析、超时/取消/错误映射；
   - 密码不放在命令行参数里（用 stdin/临时安全通道），避免进程列表/日志泄密。
3. **自研 clean-room RAR 头/密钥派生验密**用于快速判错（仅解析公开格式，不复制 unrar 代码）；命中后仍交外部 `unrar` 完整解压确认。
4. `unrar-rs` 等纯 Rust 实现只作为**本地实验 feature**，默认关闭；任何发布物启用前必须单独评审。
5. 其他平台（Linux/macOS/Android/HarmonyOS）当前 Deferred；未来同样只走外部引擎或独立许可 add-on，不污染 GPL 内核。
6. UI 在 RAR 引擎不可用时明确提示“未检测到 RAR 引擎”，而不是报“密码错误”。

> 补充结论（2026-11 许可调研）：即便把 unrar CLI 作为“独立程序”捆绑在法理上可能构成 aggregate，本项目也从紧选择**不随包分发**；GPL FAQ 对 fork/exec + 简单通信的独立程序较宽松，但共享复杂结构可能被视为单一作品。详见 `docs/licensing.md`。

## 备选

| 方案 | 结论 | 原因 |
|---|---|---|
| A. 链接 unRAR/7-Zip RAR | 拒绝 | GPL-3.0 §10 额外限制冲突；分发风险 |
| B. 外部 `unrar` 进程（用户提供） | **采用** | 不链接、不分发；Windows 功能不受影响；分发边界仍待法务复核 |
| C. 纯 Rust `unrar-rs` 内置 | 暂缓 | 许可同源；年轻实现；发布前需法务 + 差分测试 |
| D. clean-room 完整 RAR 解码 | 暂缓 | 工作量巨大；RAR4/5 压缩算法复杂；先用外部引擎 |
| E. 其他平台暂不排期 | 当前采用 | Windows 优先；避免在 APK/HAP 中分发受限代码 |

## 后果

**正面**

- GPL 内核保持许可干净；RAR 可用性取决于用户环境。
- 外部进程天然隔离崩溃/内存问题；可替换不同 unrar 版本。
- 快筛自研可覆盖大部分候选，外部引擎只处理疑似命中，性能可接受。

**负面**

- 开箱即用性下降：用户需自行安装 WinRAR/unrar。
- 进程调用有启动/解析开销；需处理路径空格、编码、超时、取消。
- 其他平台当前无 RAR（Deferred），需在 UI/文档明确。
- “外部进程是否仍构成衍生/聚合”需法务确认；本 ADR 不是法律意见。

## 验证/门禁

- [ ] 法务/维护者书面确认方案 B 的分发方式（不随包、不自动下载）。
- [ ] `engines::external` 有单元测试：缺失引擎、超时、取消、错误输出、路径空格/中文。
- [ ] 发布检查：`cargo deny`/二进制扫描确认无 unRAR 代码；安装包不含 `unrar`。
- [ ] UI 明确“RAR 引擎状态”。
- [ ] 其他平台发布说明标注 RAR 不支持/需 add-on。

## 参考

- UnRAR license: https://www.rarlab.com/license.htm
- 7-Zip license: https://www.7-zip.org/license.txt
- Debian p7zip-rar (non-free): https://packages.debian.org/non-free/p7zip-rar
- GNU GPL-3.0 §10: https://www.gnu.org/licenses/gpl-3.0.html#section10
- GNU license list: https://www.gnu.org/licenses/license-list.html
