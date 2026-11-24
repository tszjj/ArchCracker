# ADR-0004：Full 版随包外部引擎（UnRAR + hashcat）

- 状态：**Accepted（2026-11-24）**
- 日期：2026-11-24
- 相关：ADR-0003、`docs/licensing.md`、`docs/architecture.md`、`docs/windows-plan.md`
- 影响：Windows W2–W5 发布物、`engines::external`、安装器、许可清单

## 背景

Windows 最终成品的目标是**开箱可用**，不再提供“基础版/Full 版”分层。用户不应先安装 WinRAR，也不应自行寻找 hashcat。

已确认：

- **UnRAR 许可第 3 条**允许将未修改的 UnRAR utility 放入其他软件包分发；限制是不得开发 RAR 兼容压缩器、不得反向工程 RAR 压缩算法。
- **hashcat 为 MIT**，允许随包，但必须附版权/许可文本并审计其第三方组件。
- **WinRAR 的 EULA**禁止把试用版安装包塞进其他软件包；因此只随包独立 `UnRAR.exe`，不随包 `WinRAR.exe`/`Rar.exe`。
- CUDA/HIP/GPU 驱动属于系统环境，不能随包；hashcat 随包不等于 GPU 在所有机器上可用。

ADR-0003 的“不随包”是当时的保守边界，已不满足开箱目标。本 ADR 修订该部分；**进程隔离、不链接、不复制 unRAR 源码**仍有效。

## 决策

1. **单一 Full 版本**：Windows 只发布一个 Full 安装包，不分层、不做 Lite；安装包默认包含 RAR 与 GPU 后端所需的外部程序。
2. **随包未修改的 `UnRAR.exe`**：放在安装目录的 `third_party/unrar/`，附完整 `license.txt`；只通过 `engines::external` 进程调用，不链接（静态/动态），不调用 `unrar.dll`。
3. **随包 hashcat 二进制**：放在 `third_party/hashcat/`，附 MIT 许可与第三方声明；只通过外部进程调用。
4. **hashcat 不是核心 Rust 依赖**：`Cargo.toml`/`Cargo.lock` 不出现 hashcat、CUDA、HIP、OpenCL 绑定；不把 hashcat 源码/内核复制进 `acx-core`。
5. **CPU 是一等路径**：hashcat 缺失、损坏、无可用 GPU、驱动不满足或用户禁用 GPU 时，必须自动回落现有多线程 CPU 调度；CPU 的 ZIP/7z/外部 RAR 功能与不带 hashcat 时完全一致。
6. **不随包**：`WinRAR.exe`、`Rar.exe`、CUDA Toolkit、HIP SDK、Intel NEO、GPU 驱动。仅提示用户安装/升级系统驱动。
7. **固定版本与可验证**：UnRAR 与 hashcat 固定版本、SHA-256、来源 URL 记入 `third_party/manifest.json`；发布流水线按清单取包，不在运行时自动下载。
8. **许可与安装器**：`THIRD_PARTY_NOTICES.md`、`LICENSE`、`NOTICE`、UnRAR license、hashcat MIT/第三方声明随安装包分发；默认不启用遥测/联网。
9. **发现顺序**：随包路径优先，其次 `ACX_UNRAR`/`ACX_HASHCAT`、PATH、用户手动指定；不得静默使用来源不明的同名程序。
10. **发布门禁**：Full 安装包必须通过 Defender/SmartScreen 检查、许可审计、无 GPU 环境冒烟、`cargo tree` 无 hashcat/GPU 依赖检查。

## 备选

| 方案 | 结论 | 原因 |
|---|---|---|
| 基础版/Full 分层 | 拒绝 | 用户明确要求不分层、开箱即用 |
| 只随包 UnRAR，不随包 hashcat | 拒绝 | GPU 能力无法开箱；与 Full 目标不符 |
| 随包 WinRAR | 拒绝 | WinRAR EULA 禁止 bundling |
| 链接 `unrar.dll`/`7z.dll` | 拒绝 | 许可边界与崩溃隔离；继续外部进程 |
| 自研 GPU 内核 | 暂缓 | 后端/驱动矩阵与维护成本；先外置 hashcat |
| 随包 CUDA/HIP 运行时 | 拒绝 | 体积、EULA、驱动耦合；由用户系统提供 |

## 后果

**正面**

- RAR 与 GPU 功能开箱可用；用户无需额外安装 WinRAR/hashcat。
- hashcat 留在进程边界外，核心 Rust 依赖保持干净，CPU 路径不被 GPU 绑架。
- 版本固定、许可文本随包，发布可审计。

**负面**

- 安装包变大；hashcat/UnRAR 可能触发 AV/SmartScreen 误报，需要签名与提交白名单。
- UnRAR 许可不是 OSI 自由许可，需在 NOTICE 中明确独立组件与限制。
- 仍需用户驱动/GPU 满足 hashcat 要求，不能承诺所有机器 GPU 加速。
- 随包版本更新需要重新做许可/哈希/回归验证。

## 验证/门禁

- [ ] `cargo tree`/`Cargo.lock` 不包含 hashcat/CUDA/HIP/OpenCL 绑定。
- [ ] 删除/改名 `third_party/hashcat` 后，`cargo test` 与 CLI 字典攻击全部走 CPU 并通过。
- [ ] 删除/改名 `third_party/unrar` 后，非 RAR 功能不受影响，RAR 给出明确引擎缺失错误。
- [ ] 随包 `UnRAR.exe` 原样、许可证文本存在；没有 `WinRAR.exe`/`Rar.exe`。
- [ ] hashcat MIT/第三方声明存在；GPU 运行时未被随包。
- [ ] Full 安装包在无 GPU、无 hashcat、无 UnRAR 三种降级场景冒烟。
- [ ] Defender/SmartScreen/许可审计通过。

## 参考

- UnRAR License（SPDX，含“allowed to distribute UnRAR inside of other software packages”）：https://spdx.org/licenses/UnRAR.html
- WinRAR EULA（trial 包禁止 bundling）：https://www.rarlab.com/license.htm
- hashcat（MIT、GPU 后端、驱动要求）：https://hashcat.net/hashcat/
- hashcat requirements：https://github.com/hashcat/hashcat/blob/master/docs/hashcat-requirements.md
- Apache-2.0：https://www.apache.org/licenses/LICENSE-2.0
