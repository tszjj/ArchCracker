# ArchCracker 开发路线图

> 目标：**先完成 Windows 全栈**（内核 + CLI + GUI + 安装包 + 自动解压），再把同一 Rust 内核扩展到 Linux/macOS/Android/HarmonyOS。
> 时间以“1 名人类维护者 + 多个 AI Agent 并行”估算；Agent 吞吐高但评审/集成仍是瓶颈。
>
> Windows 的具体任务/验收见 [`docs/windows-plan.md`](windows-plan.md)。

## 0. 阶段总览（2026-11-24 修订：Windows 优先）

| 阶段 | 周期 | 交付 | 平台 |
|---|---|---|---|
| W0 Bootstrap | 1–2 周 | 仓库/CI/工具链/语料/C ABI 草案 | Windows |
| W1 核心 CLI | 2–3 周 | CLI：ZIP/7z/RAR（外部）+ 字典 + 多线程 + 断点 | Windows |
| W2 引擎/攻击 | 2–3 周 | 快筛/分卷/SFX/掩码/暴力/批量/编码 + hashcat GPU spike | Windows |
| W3 桌面 GUI | 3–4 周 | Avalonia 12 主界面 + C ABI v1 | Windows |
| W4 全栈交付 | 2–3 周 | 单一 Full 安装包（随包 UnRAR/hashcat）/签名/自动解压/崩溃转储/zh-en | Windows |
| W5 Windows Beta | 2–4 周 | 性能/模糊测试/文档/兼容性/AV | Windows |
| D1–D3 其他平台 | — | Linux/macOS、Android、HarmonyOS | **Deferred** |
| P7 持续 | 持续 | 许可审计、性能、发布 | Windows 优先 |

> **当前只排期 W0–W5。** P4–P6（原 Linux/macOS/Android/HarmonyOS）改为 Deferred，保留技术参考；Windows 发布后再启动。
>
> 并行原则：核心与前端可并行；但 **C ABI 契约**必须先冻结（W3 前），前端只依赖契约，不依赖核心内部实现。

---

## W0 Bootstrap（1–2 周）

**目标**：让任何 Agent 在新机器上 30 分钟内跑起 `cargo test`。

- [ ] 仓库初始化：Apache-2.0、README、AGENTS.md、ADR、目录骨架
- [ ] 用户级工具链脚本：Rust GNU + MinGW + CMake/Ninja + .NET SDK + gh
- [ ] Rust workspace：`acx-core`/`acx-cli`/`acx-ffi` 空壳，`cargo test` 通过
- [ ] `acx.h` v0 草案 + 错误码
- [ ] 语料生成脚本（7z/WinRAR CLI 可用时）+ 校验清单
- [ ] CI：windows/ubuntu/macos 的 fmt/clippy/test/build
- [ ] 首个 ADR 评审：Rust、前端拆分、RAR 许可

**退出标准**

- 任意 Agent 按 README 能构建/测试；
- CI 三平台绿；
- `acx --version` 可运行；
- 许可/依赖清单无红旗。

**Agent 分工**：architect（骨架/ADR）+ core-engineer（workspace/CI）+ qa（语料脚本）。

---

## W1 核心 CLI（2–3 周）

**目标**：在 Windows 上，用 1M 字典跑通 ZIP/7z/RAR 的单包恢复，且性能可测。

- [ ] 归档预检：格式/加密类型/条目/最小加密条目/缺卷
- [x] ZIP：ZipCrypto + WinZip AES（W1-001/W1-002）
- [ ] 7z：`sevenz-rust2`；AES/头加密；首块探测
- [x] RAR：外部 UnRAR.exe、stdin 密码、整包验证（W1-003）
- [ ] 字典：流式、编码识别、去重、批处理
- [ ] 调度：物理核数、有界队列、暂停/停止、命中仲裁
- [ ] 会话复用：每 worker 打开一次；不每候选重开
- [ ] 断点：归档指纹 + 字典偏移；强杀恢复
- [ ] 错误分类：未加密/空包/损坏/缺卷/不支持/头加密
- [ ] 基准语料与 p/s 报告

**退出标准**

- 1M 字典 × 1GB ZIP/7z/RAR（已知密码）完成，并记录 p/s（格式/线程/硬件）；"可接受"不作为验收措辞；
- 取消 < 200 ms；强杀恢复误差 ≤ 1 批；
- 错误分类 100% 正确（语料）；
- 性能基线记录在 `docs/benchmarks/`。

**Agent 分工**：core-engineer（引擎/调度）+ qa（语料/基准）+ reviewer（每 PR）。

---

## W2 引擎与攻击（2–3 周）

**目标**：覆盖 RAR/分卷/SFX/快筛/爆破，Windows CLI 达到 beta。

- [x] RAR 外部引擎：检测 `UnRAR.exe`/`unrar`；调用协议；错误映射；许可说明（W1-003；Full 随包 W4）
- [ ] hashcat GPU 后端 spike：ZIP AES 13600 + RAR5 13000 提 hash；外部进程；CPU 回退（见 `docs/tasks/W2-001-hashcat-spike.md`）
- [ ] 分卷：7z/ZIP `.001` 拼接；RAR 交外部引擎；缺卷检测
- [ ] SFX：PE overlay 扫描；数据区偏移
- [ ] 快筛：ZIP verifier、RAR 头/密钥、7z 头 CRC/首块；严格模式
- [ ] 命中确认：参考引擎完整解压 + CRC
- [ ] 掩码/暴力/混合：字符集、长度、UInt128 键空间、分区
- [ ] 批量队列 + 包间密码复用
- [ ] 成本估算 + “未确认”语义
- [ ] 编码变体（UTF-8/GBK）

**退出标准**

- 已知密码 100% 命中；ZIP/ZipCrypto 10⁷ 错误候选 0 误报，7z/RAR5 抽样（≥10⁵）0 误报 + 差分；
- 缺卷/损坏/未加密分类正确；
- RAR 只通过外部 `UnRAR.exe`；hashcat 只通过外部进程，不是 Cargo 依赖；无 hashcat/GPU 时 CPU 多线程功能完整；
- 快筛/严格模式结果差异可解释。

**Agent 分工**：core-engineer ×2（引擎/候选）+ qa（差分测试）+ reviewer（许可）。

---

## W3 桌面 GUI（3–4 周）

**目标**：Windows 图形界面可用，C ABI 冻结 v1。

- [ ] `acx-ffi`：句柄/错误码/回调/JSON 配置；panic 隔离；C 头稳定
- [ ] Avalonia 12 工程：MVVM、拖放、模式页、进度/ETA、暂停/停止
- [ ] 结果：密码展示/复制、报告、自动解压
- [ ] 预检/错误提示：缺卷/损坏/未加密/不支持
- [ ] 进度回调限流 10 Hz；UI 不卡
- [ ] 崩溃隔离：进程内 DLL + sidecar 开关
- [ ] Windows 打包：MSIX/Inno + 代码签名（EV 可选）
- [ ] zh/en i18n、键盘/读屏基础

**退出标准**

- 双击安装/免安装可运行；
- 拖放→开始→找到→解压全流程；
- UI 取消/暂停不阻塞；
- 崩溃转储可定位。

**Agent 分工**：frontend-engineer（Avalonia）+ core-engineer（FFI）+ qa（UI 冒烟）。

---

## W4 Windows 全栈交付（2–3 周）

**目标**：从“能跑”到“能装、能卸载、能自动解压”。

- [ ] 安装包：单一 Full 版（MSIX 或 Inno Setup）；卸载/升级/便携模式
- [ ] Full 随包：未修改 `UnRAR.exe` + license，hashcat + MIT/第三方声明；版本/SHA 清单
- [ ] 不随包：WinRAR、CUDA/HIP/OpenCL 运行时、GPU 驱动
- [ ] 代码签名：OV/EV；SmartScreen/Defender 误报提交
- [ ] 自动解压：目标目录、覆盖策略、磁盘空间检查、Zip Slip 防护
- [ ] 崩溃转储/日志脱敏（不记完整密码）；sidecar 隔离开关
- [ ] zh/en、键盘、读屏基础；高 DPI/深色
- [ ] 首次启动授权提示；GPU/引擎检测与 CPU 回落提示
- [ ] 发布检查：无 RAR 样本、`THIRD_PARTY_NOTICES`/manifest 最新

**退出标准**

- 干净 Windows 11 上安装→拖放→恢复→解压→卸载全流程；
- 普通用户权限可运行；
- 安装包已签名（或明确标注测试签名）；
- 崩溃有可定位的 dump/日志。

---

## W5 Windows Beta（2–4 周）

**目标**：性能、兼容性、稳定性达标，可以对外 beta。

- [ ] 基准矩阵：格式 × 加密 × KDF × 线程 × 硬件，记录 p/s
- [ ] 1M 字典 / 1GB 归档 / 分卷 / SFX 语料
- [ ] 差分测试（7-Zip/unrar oracle）+ 模糊测试（头/分卷/SFX）
- [ ] 兼容性：Windows 10 22H2、Windows 11 24H2；x64（ARM64 另评）
- [ ] 安全评审：路径穿越、恶意归档、DLL 加载、日志泄密
- [ ] 许可审计：UnRAR/hashcat 版本/许可/哈希齐全，无 RAR 源码；无 WinRAR/CUDA/HIP 随包
- [ ] AV/SmartScreen：Defender/VirusTotal、安装包签名、误报处理流程
- [ ] 文档/FAQ/已知问题/回滚

**退出标准**

- 已知密码 100% 命中；错误候选按格式抽样 0 误报；
- 缺卷/损坏/未加密/不支持分类 100% 正确；
- 强杀恢复误差 ≤ 1 批；
- 性能达到 `docs/benchmarks/` 基线；
- beta 安装包 + 发布说明。

---

## D1 桌面跨平台（Deferred）

> 以下 D1–D3 是 Windows 发布后的技术参考，**当前不排期、不引入 SDK**。


**目标**：Linux/macOS 同一 Avalonia 代码可构建、可分发。

- [ ] Linux：AppImage/Flatpak；glibc 兼容；文件对话框
- [ ] macOS：universal（arm64+x64）、hardened runtime、公证；官网 DMG
- [ ] 线程数/亲和性平台差异（macOS 无线程亲和）
- [ ] 路径/大小写/编码/换行测试
- [ ] CI：三平台构建 + 冒烟
- [ ] 暂不上 Mac App Store（审核/签名成本；后续再评估）

**退出标准**

- 三平台同一功能集；
- macOS 公证通过；
- Linux 主流发行版可运行；
- 跨平台差异记录在 architecture.md。

---

## D2 Android（Deferred）

**目标**：Compose + JNI，能选 SAF 文件、前台跑、断点续算。

- [ ] `acx-jni`：handle 生命周期、回调、错误码
- [ ] Compose：文件选择、模式、进度、暂停/停止、结果
- [ ] SAF：`ACTION_OPEN_DOCUMENT` + 持久化权限；fd `dup` 给 native
- [ ] 输出：`CREATE_DOCUMENT`/目录；自动解压
- [ ] 前台服务 + 常亮 + 通知；Android 15 配额适配
- [ ] 按 ABI 打包 `libacx.so`（arm64-v8a/armeabi-v7a/x86_64）
- [ ] 后台/锁屏/断电恢复测试
- [ ] Play 政策文案：“仅恢复自有档案”、不内置字典

**退出标准**

- 真机（arm64）完成一次 ZIP/7z 恢复；
- 切后台/锁屏不丢进度；
- 无整包拷贝，内存可控；
- 安装包可侧载/内测。

---

## D3 HarmonyOS（Deferred）

**目标**：ArkUI + NAPI，HAP 可签名安装。

- [ ] `acx-napi`：NAPI 导出、线程/回调、错误映射
- [ ] ArkUI：文件 Picker、模式、进度、暂停/停止、结果
- [ ] `libacx.so`（arm64-v8a）打包与加载
- [ ] 前台任务/断点；Picker 授权即时使用
- [ ] DevEco 签名、HAP 构建
- [ ] 真机验证（HarmonyOS 6+）
- [ ] RAR 能力按许可结论决定（可能首发不支持）

**退出标准**

- 真机完成 ZIP/7z 恢复；
- HAP 可安装/升级；
- 退后台可续算；
- 构建步骤文档化。

---

## P7 硬化与发布（持续）

- [ ] 差分测试：7-Zip/unrar oracle；随机语料
- [ ] 模糊测试：归档解析器（ZIP/7z/RAR 头）
- [ ] 性能：p/s、CPU、内存、ETA；回归门禁
- [ ] 安全：路径穿越、恶意归档、DLL 劫持、供应链
- [ ] 许可审计：cargo-deny、第三方 notices、RAR 策略
- [ ] 签名/公证/商店材料
- [ ] 文档/视频/FAQ
- [ ] 发布节奏：Windows beta → Windows 1.0；其他平台另行排期

---

## 关键路径与依赖

```text
W0 ──► W1 ──► W2 ──► W3 ──► W4 ──► W5 ──► Windows 1.0
                          │
                          └──► 共享 C ABI/测试向量 ──► D1–D3（后续）
```

- **W1 是最大风险**：ZIP/7z 加密、会话复用、断点、性能基线必须先打通。
- **RAR**：解压用途符合 UnRAR 许可；Full 版随包未修改 `UnRAR.exe`（仅进程），不链接、不复制源码；WinRAR 不随包。hashcat 随包但只作为外部进程，见 ADR-0004。
- **GPU**：hashcat 不是 Rust/Cargo 依赖；GPU 驱动/CUDA/HIP 由系统提供；无 GPU 时 CPU 多线程是完整基线。
- **其他平台**依赖 C ABI 稳定（W3 末冻结）；D1–D3 在 Windows 发布后再启动。
- **UI 工作量**：当前只做 Windows 一套（Avalonia）；移动端后续再评估。

## Agent 并行建议

| 轨道 | 角色 | 可并行 |
|---|---|---|
| 核心引擎 | core-engineer ×2 | ZIP/7z、RAR/分卷 |
| 候选/调度 | core-engineer | 与引擎解耦 |
| 测试/语料 | qa-engineer | 全程 |
| Windows UI | frontend-engineer | W3 起 |
| Android | frontend-engineer | Deferred |
| HarmonyOS | frontend-engineer | Deferred |
| 评审/许可 | reviewer/release | 每 PR/每阶段 |

## 里程碑验收（摘要）

| 里程碑 | 验收 |
|---|---|
| W0 | `cargo test` 本机通过；脚本可复现；CI 三平台绿 |
| W1 | Windows CLI 恢复 ZIP/7z；1M 字典 p/s 基线 |
| W2 | RAR 外部/分卷/快筛/爆破；Windows CLI 可用 |
| W3 | Windows GUI 可用；C ABI v1 |
| W4 | 安装/卸载/签名/自动解压全流程 |
| W5 | Windows beta；许可/安全/性能达标 |
| v1.0 | Windows 1.0；其他平台另行排期 |
