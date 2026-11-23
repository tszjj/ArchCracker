# ArchCracker 跨平台总体架构

> 状态：Accepted（M0 基线） · 更新：2026-11-24
> 相关：[ADR-0001 Rust 内核](adr/0001-rust-core.md) · [ADR-0002 前端拆分](adr/0002-frontend-split.md) · [ADR-0003 RAR 许可](adr/0003-rar-licensing.md)

## 1. 目标与约束

| 约束 | 说明 |
|---|---|
| 五平台 | Windows、Linux、macOS、Android、HarmonyOS |
| 两段式 | `core`（Rust 内核 + CLI + C ABI）与 `frontends`（桌面/Android/HarmonyOS）分离 |
| 格式 | 7z、ZIP、RAR4/RAR5；分卷、SFX、头加密 |
| 性能 | 会话复用、首块判错、多核并行、断点续跑 |
| 许可 | GPL-3.0-only；RAR/unRAR 单独处理，不污染内核 |
| 体验 | 简洁、离线、无遥测；Windows 首发 |
| 可维护 | 90% 复杂度在核心；前端各 3–5 屏；跨平台差异只在胶水层 |

## 2. 分层

```text
┌──────────────────────────────────────────────────────────────────────┐
│ 前端                                                                  │
│  Avalonia 12（Windows/Linux/macOS）  Compose（Android）  ArkUI（OHOS）│
│  CLI（桌面全平台，脚本/CI）                                            │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  C ABI / JNI / NAPI
┌──────────────────────────────▼───────────────────────────────────────┐
│ acx-ffi：不透明句柄、错误码、回调、JSON 配置、panic 隔离               │
└──────────────────────────────┬───────────────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────────────┐
│ acx-core（Rust，纯逻辑，无 UI/平台 GUI 依赖）                          │
│  jobs / planner / scheduler / resume / stats                          │
│  candidates：dictionary · mask · brute · rules · hybrid · dedup       │
│  engines：7z · ZIP · RAR(external/optional) · volume · SFX            │
│  probes：结构判据 + 可选签名快筛；命中交 confirmer                     │
│  platform：文件、进程、线程、locale（cfg 隔离）                        │
└──────────────────────────────┬───────────────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────────────┐
│ 依赖                                                                  │
│  sevenz-rust2（Apache-2.0） · zip（MIT） · unrar-rs/外部 unrar（许可待定）│
│  rayon · aes · sha2 · crc32fast · serde · thiserror                    │
└──────────────────────────────────────────────────────────────────────┘
```

**边界规则**

- `acx-core` 不依赖 `clap`/UI/平台 GUI；CLI 只做参数解析与输出。
- `acx-ffi` 只做 marshalling、生命周期、错误码；不含业务逻辑。
- 前端不复制算法/错误码；以 `core/crates/acx-ffi/include/acx.h` 为契约。
- 外部 `unrar` 的调用只能在 `engines::external` 中，便于替换/禁用。

## 3. 为什么是 Rust

结论来自 2026-11 的技术调研（见 ADR-0001）：

- 7z：`sevenz-rust2` 支持 AES-256、加密头（0.6+）、COPY/LZMA/LZMA2/PPMd/BZip2/Deflate/Brotli/LZ4/ZSTD 与 BCJ2 等过滤器，Apache-2.0。
- ZIP：`zip` crate 支持 ZipCrypto 与 WinZip AES（AE-1/AE-2）；多卷需自建容器层。
- RAR：`unrar-rs` 是纯 Rust 的 UnRAR 移植，覆盖 RAR4/5、`-p`/`-hp`、多卷、SFX；但受 unRAR 许可约束，不能默认静态链接进 GPL 内核。
- 平台：Rust Android 为 Tier 2；`aarch64-unknown-linux-ohos` 为 Tier 2 with host tools，可用 OHOS clang 作为 linker。
- 内存安全与 AI 可维护性显著优于 C++；性能上限高于 Go。

**C++（7-Zip 源码）**保留为差分测试 oracle 与性能对照，不作为主内核：7-Zip 是应用型代码库，Android/OHOS 需自行移植，且 RAR 部分许可同样受限。

## 4. 引擎与验证层

### 4.1 格式矩阵

| 格式 | 加密 | 读取/解密 | 分卷 | 备注 |
|---|---|---|---|---|
| 7z | AES-256、可选头加密 | `sevenz-rust2` | 自建拼接 Reader（`.7z.001`） | SFX 扫描 PE overlay |
| ZIP | ZipCrypto、WinZip AES-128/256 | `zip` + 自写容器层 | `.zip.001` 拼接；PKZIP `.z01` P2 | WinZip AES 支持需 P1 实测确认；multi-disk 由我们补 |
| RAR4 | AES-128、头加密 | 外部 `unrar` / 可选 `unrar-rs` | 外部引擎处理 | 仅桌面；用户自装，不随包 |
| RAR5 | AES-256、PBKDF2、头加密 | 外部 `unrar` / 可选 `unrar-rs` | 外部引擎处理 | 仅桌面；用户自装，不随包 |
| SFX | 继承底层 | 定位 overlay 后交引擎 | 同底层 | |

### 4.2 快筛与确认

```text
候选密码 (bytes)
   │
   ├─ 结构判据：verifier / 头 CRC / 压缩流头 / 首块解码失败 → 可靠否决
   ├─ 内容判据（可选快速模式）：文件签名表 → 可能漏，标注“未确认”
   ▼
疑似命中 → 官方参考引擎完整解压最小条目 → CRC/文件尾校验 → 发布
```

- 默认快速模式：store 条目用签名表（性能前提）；压缩条目用结构判据。
- 严格模式：store 条目完整解压/CRC；慢但不会漏。
- 任何命中必须由 7-Zip/unrar 参考实现确认，保证零误报。
- 快筛误否决只在“快速模式”出现；UI 必须显示“未确认”，并提供严格模式复核。

### 4.3 RAR 许可策略（重要）

unRAR 许可的“不得用于开发 RAR 兼容压缩器”与 GPL-3.0 §10 的额外限制冲突。因此：

1. **内核不静态链接 unRAR/7-Zip RAR 代码，也不随包分发/自动下载**；
2. 默认通过**用户自行安装的外部 `unrar`/`UnRAR.exe` 进程**完成 RAR 确认与解压；
3. `unrar-rs` 仅作为**可选 feature**，构建时显式开启，发布物需单独评估/法务确认；
4. 自研 RAR 头/密钥派生验密（clean-room，仅用于快筛）可与外部引擎配合；
5. Android/HarmonyOS 首发不内置 RAR；Android 可引导用户用已安装的 RAR 应用打开，后续再评估独立许可 add-on。

> 该策略在 `docs/adr/0003-rar-licensing.md` 中记录，许可结论出来前不得放宽。

## 5. C ABI 设计

### 5.1 原则

- 稳定、可版本化；结构体带 `size`/`version` 字段；未知字段忽略。
- 字符串一律 UTF-8 + 长度；不依赖 C 字符串结尾（兼容含 NUL 的路径？路径不允许 NUL）。
- 句柄不透明；创建/销毁成对；回调在 `stop` 返回后不再触发。
- Rust panic 不跨 FFI：`catch_unwind` → `ACX_ERR_PANIC`。
- 线程安全：一个 handle 同时只允许一个 `start`；`pause/resume/stop` 可从任意线程调用。

### 5.2 草案

```c
typedef struct AcxHandle AcxHandle;

typedef enum {
  ACX_OK = 0,
  ACX_ERR_INVALID_ARG = 1,
  ACX_ERR_IO = 2,
  ACX_ERR_UNSUPPORTED = 3,
  ACX_ERR_ARCHIVE = 4,
  ACX_ERR_MISSING_VOLUME = 5,
  ACX_ERR_CANCELLED = 6,
  ACX_ERR_INTERNAL = 7,
  ACX_ERR_PANIC = 8
} AcxStatus;

typedef struct {
  uint32_t struct_size;
  uint32_t version;
  const char* archive_path;     /* UTF-8, first volume */
  const char* dictionary_path;  /* nullable */
  const char* mask;             /* nullable */
  const char* charset;          /* nullable */
  uint32_t min_len, max_len;
  uint32_t threads;             /* 0 = auto (physical cores) */
  uint8_t  mode;                /* 0 dict, 1 mask, 2 brute, 3 hybrid */
  uint8_t  fast_mode;           /* 1 fast, 0 strict */
  uint8_t  auto_extract;
  const char* output_dir;       /* nullable */
} AcxAttackSpec;

typedef struct {
  void (*on_progress)(void* user, uint64_t tried, uint64_t total, double rate, uint64_t eta_sec);
  void (*on_hit)(void* user, const uint8_t* password, size_t len);
  void (*on_log)(void* user, int level, const char* message);
  void* user;
} AcxCallbacks;

AcxStatus acx_create(const char* config_json, AcxHandle** out);
void      acx_destroy(AcxHandle* h);
AcxStatus acx_start(AcxHandle* h, const AcxAttackSpec* spec, const AcxCallbacks* cb);
AcxStatus acx_pause(AcxHandle* h);
AcxStatus acx_resume(AcxHandle* h);
AcxStatus acx_stop(AcxHandle* h);
AcxStatus acx_status(AcxHandle* h, AcxStatusInfo* out);
const char* acx_version(void);
const char* acx_last_error(AcxHandle* h); /* thread-local copy */
```

### 5.3 语言绑定

| 前端 | 方式 |
|---|---|
| Avalonia (C#) | `[LibraryImport]` P/Invoke；结构体 `[StructLayout(LayoutKind.Sequential)]`；回调用 `UnmanagedCallersOnly` 或 `Marshal.GetFunctionPointerForDelegate`（注意生命周期） |
| Android (Kotlin) | JNI 薄层 `acx-jni`：`external fun start(...)`；Native 持有 handle；SAF fd → `/proc/self/fd/N` 或 `dup` 后传路径 |
| HarmonyOS (ArkTS) | NAPI 薄层 `acx-napi`：`napi_create_function` 导出 start/stop/status；ArkTS 侧 `import acx from 'libacx.so'` |
| CLI | 直接依赖 `acx-core`，不经 FFI（减少一层） |

## 6. 核心模块

### 6.1 任务与调度

- `JobManager`：单包/批量队列；已找到密码的包间复用。
- `AttackPlanner`：模式选择、成本估算、预检、线程数建议。
- `Scheduler`：producer → bounded channel → N workers；每 worker 独占会话；原子命中仲裁。
- `ResumeManager`：字典偏移/键空间索引 + 归档指纹 + 参数哈希；原子写盘。
- `Stats`：EWMA 速率、ETA、每 worker 计数。

### 6.2 候选源

- 字典：流式、BOM/UTF-8/GBK 自动识别、去重、长行限制；字节输出。
- 掩码：`?d ?l ?u ?s ?a ?b ?1..?4` + 固定字符 + 位置集合。
- 暴力：字符集 + 长度区间 + UInt128 键空间分区；短密码优先。
- 混合：字典 × 前后缀掩码。
- 规则（P2）：hashcat 风格最小集。
- 去重：bloom + 精确 U128 哈希；跨源可选。

### 6.3 编码

密码是字节，不是字符串：

- 7z/RAR5：UTF-8；
- RAR4：本地代码页/UTF-8 变体；
- ZIP：UTF-8 标志位；无标志位按 CP437/GBK 变体；
- 字典：BOM → 严格 UTF-8 → GB18030 回退；UI 可覆盖。

### 6.4 断点

```json
{
  "version": 1,
  "archive": {"path": "...", "size": 0, "head_hash": "...", "tail_hash": "..."},
  "attack": {"mode": "dict", "dict_hash": "...", "byte_offset": 0, "line": 0},
  "options": {"threads": 14, "fast_mode": true},
  "stats": {"tried": 0, "elapsed_sec": 0.0}
}
```

每 5 秒/5 万候选原子写；恢复前校验归档/字典/参数；不匹配让用户选择重跑。

## 7. 前端设计

### 7.1 桌面：Avalonia 12 / .NET 10

- 一套代码 Windows/Linux/macOS；MVVM；XAML。
- 主窗口一屏：拖放 → 模式/字典/线程 → 开始；进度/速度/ETA；暂停/停止；结果/自动解压。
- P/Invoke 调 `acx.dll`；先进程内，保留 sidecar 崩溃隔离开关。
- 进度回调限流 ~10 Hz；UI 线程不做解密。
- 打包：Windows MSIX/Inno + EV 签名；macOS universal + hardened runtime + 公证（官网分发，不上 Mac App Store）；Linux AppImage/Flatpak。

### 7.2 Android：Kotlin + Compose

- 文件：SAF `ACTION_OPEN_DOCUMENT` + 持久化权限；`ParcelFileDescriptor` → `dup` → native 路径；不整包拷贝。
- 输出：`CREATE_DOCUMENT`/SAF 目录；自动解压写到用户选择目录。
- 后台：前台服务 + 常亮；Android 15 `dataSync` 6h/24h 配额；默认“前台运行 + 可续算”，不承诺后台跑完。
- 包：每 ABI 的 `libacx.so`；JNI 薄层；Play 审查需明确“仅恢复自有档案”。

### 7.3 HarmonyOS：ArkTS/ArkUI + NAPI

- 文件 Picker 授权随进程失效，需即时使用；长任务前台 + 断点。
- `libacx.so`（arm64-v8a）经 NAPI 导出；DevEco 签名生成 HAP。
- 首发功能与桌面一致，但 RAR 视许可/外部引擎方案而定。

### 7.4 共享

- `frontends/shared/`：C ABI 头副本、错误码、攻击模式 schema、设计 token、i18n 词条、测试向量。
- 三端 UI 均为 3–5 屏；不做平台特有功能（除文件选择/分享）。

## 8. 构建与 CI

### 8.1 本地（Windows 首发）

```powershell
# 用户级工具链（免管理员）
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1
cargo build --workspace
cargo test --workspace
```

### 8.2 CI 矩阵

| Job | Runner | 内容 |
|---|---|---|
| core-windows | windows-latest | fmt/clippy/test/build |
| core-linux | ubuntu-latest | test/build |
| core-macos | macos-latest | test/build（arm64） |
| desktop | windows/ubuntu/macos | Avalonia build（M1 后） |
| android | ubuntu + NDK | `cargo ndk` + Gradle（P3） |
| harmony | 手动/自托管 | DevEco/NAPI 构建（P4，需华为工具链） |

Android/HarmonyOS 的 CI 需要 SDK/签名密钥；M0 只建 desktop 三平台矩阵，移动端用 `workflow_dispatch` 手动任务。

### 8.3 产物

- `acx` CLI（win/linux/mac）
- `acx.dll` / `libacx.so` / `libacx.dylib`
- 桌面安装包（MSIX/Inno/AppImage/dmg）
- Android AAB/APK（按 ABI）
- HarmonyOS HAP

## 9. 安全与隐私

- 默认零网络；无遥测/崩溃上报/在线查询。
- 不执行归档内文件；只解压到用户指定目录；路径规范化防 Zip Slip。
- 日志默认不记完整密码；调试模式需显式开启。
- 原生库从程序目录加载并校验哈希；发布物代码签名。
- 测试语料由仓库脚本生成；不提交真实用户档案。

## 10. 许可

- 本项目 GPL-3.0-only。
- `sevenz-rust2` Apache-2.0、`zip` MIT、`rayon` MIT/Apache-2.0、`aes`/`sha2` MIT/Apache-2.0：与 GPL-3.0 兼容。
- unRAR/7-Zip RAR：不兼容/受限；见 ADR-0003 与 `docs/licensing.md`。
- 前端：Avalonia MIT、Compose Apache-2.0、ArkUI 随 HarmonyOS SDK（需遵守华为条款）。

## 11. 风险

| 风险 | 影响 | 对策 |
|---|---|---|
| RAR 许可 | 无法默认支持 RAR | 外部 unrar/可选插件；法务确认；RAR 快筛自研 |
| sevenz-rust2 边界 | 加密头/PPMd/异常包差异 | 差分测试（7-Zip oracle）；语料矩阵 |
| HarmonyOS Rust 工具链 | 构建/加载不稳定 | 先 C ABI + 最小 NAPI spike；保留纯 ArkTS 降级 |
| 移动端后台限制 | 长任务被挂起 | 前台服务/常亮/断点续算；不承诺后台 |
| 应用商店政策 | 下架 | 仅自有档案声明；官网分发；不内置字典 |
| 性能目标 | 不达预期 | M1 基准；按 ROI 优化；不承诺未测数字 |
| 多前端成本 | 进度拖慢 | 桌面一套 + 移动各一套；共享契约/测试向量 |
| 供应链 | 依赖漏洞 | 锁定版本、cargo-deny、依赖审计 |
