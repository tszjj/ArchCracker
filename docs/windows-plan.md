# Windows 全栈开发计划（当前唯一排期）

> 目标：在 Windows 10/11 x64 上交付“安装 → 拖放 → 恢复 → 解压 → 卸载”的完整体验。
> 其他平台（Linux/macOS/Android/HarmonyOS）**Deferred**，接口保留，不引入 SDK。
>
> **发布形态**：只做一个 **Full 版本**，不分 Lite/Full。Full 安装包按 ADR-0004 随包未修改的 `UnRAR.exe` 与 hashcat 二进制；hashcat 只走外部进程，不是 Rust/Cargo 依赖；无 hashcat/GPU 时 CPU 多线程功能完整。

## 1. “全栈”包含什么

| 层 | 交付 | 验收 |
|---|---|---|
| 内核 | Rust `acx-core`：ZIP/7z/RAR（外部）+ 候选 + 调度 + 断点 | 1M 字典、1GB 归档、缺卷/损坏分类 |
| C ABI | `acx.dll` + `acx.h` | C/C# 可加载；错误码/回调稳定 |
| CLI | `acx.exe` | 脚本可跑；退出码明确 |
| GUI | Avalonia 12 桌面 | 拖放/模式/进度/暂停/结果/自动解压 |
| 安装 | Inno Setup（首选）或 MSIX | 安装/升级/卸载；普通用户权限 |
| 信任 | 代码签名、哈希、无捆绑 | SmartScreen/Defender 可接受 |
| 文档 | README/FAQ/已知问题/许可 | 用户能自助 |

## 2. Windows 形态

```text
acx.exe                  CLI（Rust，直接依赖 acx-core）
ArchCracker.exe          Avalonia GUI（.NET 10）
acx.dll                  C ABI（Rust cdylib）
third_party/unrar/       UnRAR.exe（未修改）+ license.txt
third_party/hashcat/     hashcat（固定版本）+ MIT/第三方声明
```

- GUI 默认**进程内**加载 `acx.dll`；保留 `--sidecar` 开关，把内核放到独立进程，崩溃不影响 UI。
- 所有长任务在后台线程；UI 只接收限流后的进度（~10 Hz）。
- 默认零网络；不做自动更新；不收集遥测。
- hashcat/UnRAR 都只通过外部进程调用；GPU 驱动/CUDA/HIP 由用户系统提供。

## 3. W1：核心 CLI（优先级最高）

按以下顺序实现，每步可独立验收：

1. **归档预检**：格式/加密/条目/最小加密条目/分卷/SFX；错误分类。
2. **ZIP**：ZipCrypto + WinZip AES（W1-002 已实现 AE-1/AE-2、AES-128/192/256 读取/验证；7-Zip 差分待补）。
3. **7z**：W1-004 已实现 `sevenz-rust2` 读取、AES-256、`-mhe=on` 头加密、首块 64 KiB 探测 + 完整 CRC；与 7-Zip 26.04 CLI 差分。
4. **RAR（外部）**：W1-003 已实现检测 `UnRAR.exe`、整包 `t` 验证；密码走 stdin，不写 argv；W1-003b 在 factory 创建时预检一次并缓存，worker 不再重复预检；W1-003c 已在 WinRAR 6.24 下验证 RAR4 `-ma4` 与 RAR5。
5. **字典**：流式、UTF-8/UTF-16/GBK、去重、空行/长行。
6. **调度**：物理核数、有界队列、每 worker 独占会话、命中仲裁、暂停/停止。
7. **断点**：归档指纹 + 字典偏移；强杀恢复。
8. **CLI**：`-f -m dict -d -t --strict/--fast --resume --auto-extract`；退出码。

**W1 退出**：1M 字典在 ZIP/7z 样本上完成；RAR 样本通过外部 UnRAR 完成；p/s 记录；缺卷/损坏/未加密分类正确。

## 4. W2：引擎与攻击

- 快筛：ZIP verifier、7z 头/首块、RAR 头/密钥（clean-room；只做否决）。
- GPU 字典批量：hashcat 外部后端，ZIP AES 13600 + RAR5 13000 提 hash；`--gpu auto`；无 GPU/hashcat 回落 CPU。
- 掩码/暴力：字符集、长度、UInt128 键空间、分区、进度。
- 分卷/SFX：`.001` 拼接、PE overlay、缺卷提示。
- 批量：多包队列、包间密码复用。
- 编码变体：UTF-8/GBK 双试（按格式开关）。
- 成本预估：“预计 X 分钟/天”，超阈值确认。

**W2 退出**：掩码/暴力可暂停/恢复；快筛 vs 严格模式差异可解释；0 误报（按格式抽样）；hashcat GPU spike 有同机基准与 CPU 回退证据。

## 5. RAR 的 Windows 实现

**原则**：解压 RAR 本身符合 UnRAR 许可；Full 版随包未修改的 `UnRAR.exe`，只通过外部进程调用，不链接/不复制源码；WinRAR 不随包。

### 5.1 检测顺序

1. 安装目录 `third_party/unrar/UnRAR.exe`（Full 版默认）；
2. `ACX_UNRAR` 显式覆盖；
3. `%ProgramFiles%\WinRAR\UnRAR.exe` / `%ProgramFiles(x86)%` / 注册表同目录；
4. `PATH` 中的 `unrar.exe` / `UnRAR.exe`；
5. 用户手动指定路径（保存到本地配置）。

随包引擎缺失/损坏时：GUI 明确提示“RAR 引擎损坏”，提供“修复安装”/“选择 UnRAR.exe”；不自动下载。

### 5.2 调用

```text
UnRAR.exe t -p "<archive>"         # -p 触发提示；密码通过 stdin 提供，避免出现在 argv
UnRAR.exe x -p "<archive>" "<out>" # 命中后确认/解压
```

- 密码不写命令行；用 stdin/管道，日志脱敏。`-p-` 在部分版本表示“禁用密码”，不要使用；`-p` 的 stdin 行为已在 W1-003 用 UnRAR 7.22 验证；其他版本需回归。
- 超时/取消：杀进程树；错误输出映射为 `ACX_ERR_*`。
- `t` 用于**确认**；W2 起优先用 clean-room RAR 头/密钥 hash 交 hashcat GPU，疑似命中再交 `UnRAR.exe` 完整测试。
- 路径含空格/中文：参数用 `CommandLineToArgvW` 兼容的引用；不要拼接 shell 字符串。

### 5.3 性能策略

- Full 版随包 hashcat；RAR5/ZIP AES 优先走 hashcat（Rust 提 hash），7z 在 W2 spike 之后；RAR 外部 `t` 只做最终复核。
- hashcat 不是 Cargo 依赖；无 GPU/驱动不满足/hashcat 缺失时，CPU 多线程 + 外部 UnRAR 保持完整功能。
- RAR4/5 的 KDF 无法绕过；快筛只省“解压/进程”，不省 KDF。
- 桌面 RAR 的 p/s 目标按基准实测写，不引用未复现数字。
- hashcat 启动自检/内核编译有秒级到数十秒开销；小字典/无独显默认 CPU。

## 6. W3：Avalonia GUI

三屏：

1. **主界面**：拖放/选择、归档信息、模式 Tab、字典/字符集/长度、线程、fast/strict、自动解压。
2. **运行**：进度/速度/ETA、暂停/继续/停止、日志折叠、当前候选（可选脱敏）。
3. **结果**：密码大字展示/复制、报告、打开目录、失败原因（缺卷/损坏/未加密/不支持/未确认）。

交互：一屏完成 90%；高级参数折叠；运行中不弹模态；键盘 Ctrl+O/F5/Esc；高 DPI/深色/zh-en。

## 7. W4：安装与交付

- **Inno Setup 首选**（Win10/11、便携/安装两种）；MSIX 作为后续选项。
- 代码签名：OV/EV；无证书时明确标注“未签名测试版”。
- 安装包内容：`acx.exe`、`ArchCracker.exe`、`acx.dll`、`LICENSE`、`NOTICE`、`THIRD_PARTY_NOTICES.md`、`third_party/unrar/UnRAR.exe` + license、`third_party/hashcat/` + MIT/第三方声明；**不含 WinRAR/CUDA/HIP/GPU 驱动**。
- 卸载清理配置/日志需询问；不删用户解压目录。
- 崩溃转储：WER LocalDumps 或自带 mini-dump；日志默认不含完整密码。
- Defender/SmartScreen 提交；提供 SHA-256。

## 8. W5：Windows Beta 验收

| 项 | 标准 |
|---|---|
| 正确性 | 已知密码 100%；错误候选抽样 0 误报 |
| 错误分类 | 缺卷/损坏/未加密/不支持/头加密 100% |
| 性能 | `docs/benchmarks/` 记录 p/s（格式/线程/硬件） |
| 恢复 | 强杀后误差 ≤ 1 批（4096） |
| UI | 取消 < 200 ms；大文件不卡 |
| 安装 | 安装/升级/卸载；普通用户 |
| 合规 | UnRAR/hashcat 版本/许可/哈希齐全；无 RAR 源码；无 WinRAR/CUDA/HIP 随包 |
| AV | Defender/SmartScreen/VirusTotal 检查通过或有处理说明 |
| 兼容 | Win10 22H2、Win11 24H2 x64（ARM64 另评） |

## 9. Agent 分工（Windows 迭代）

| 任务 | 角色 | 备注 |
|---|---|---|
| 预检/错误分类 | core-engineer | 先写测试向量 |
| ZIP/7z 引擎 | core-engineer | 与 7-Zip 差分 |
| RAR 外部引擎 | core-engineer | 随包路径/进程调用/超时/密码 stdin |
| hashcat GPU 后端 | core-engineer | 外部进程、提 hash、CPU 回退 |
| 候选/调度/断点 | core-engineer | 与引擎解耦 |
| CLI | core-engineer | 退出码/脚本 |
| Avalonia | frontend-engineer | 3 屏，先 Windows |
| 语料/基准 | qa-engineer | 1M/1GB/分卷 |
| 安装/签名 | release-engineer | Inno/证书/Defender |
| 评审 | reviewer | 每 PR；许可/性能重点 |
