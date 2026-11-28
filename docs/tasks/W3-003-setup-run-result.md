# W3-003：Setup → Run → Result 垂直切片 — 设计目标

- 状态：设计目标定稿（2026-11-28），尚未实现
- 分支：`windows-gui`（W3-001 C ABI v1、W3-002 Avalonia 骨架已完成并复审）
- 前置基线：`windows-gui @ a77cfd0`；PR #40 CI 7/7 通过（run `46111999727`）
- 角色：frontend-engineer 主责，core-engineer 支持 ABI/归档预检，qa-engineer 负责 GUI↔CLI 差分，architect/release 评审
- 依据：`docs/W3-PLAN.md` §3、`docs/tasks/W3-windows-gui-outline.md`、`docs/AUDIT-backend-W3-2026-11-28.md`

> 本文定义 W3-003 的设计目标与审计 P2 影响分析，不是准出标准。W3 准出仍只按 `docs/W3-PLAN.md` §4 与 `docs/W3-SIGNOFF.md`。

## 1. 目标

在 W3-002 骨架上打通第一条真实用户链路：

```text
选择/拖放 ZIP → 归档预检 → 字典攻击 → 进度/暂停/继续/停止 → 命中/未命中/失败 → 复制密码
```

本切片只开放 **ZIP + 字典模式**。目标是端到端证明 GUI 能正确使用 C ABI、不会阻塞 UI、能准确表达终态，并与 CLI 得到一致结论。

## 2. 范围与非目标

### 2.1 范围

- Setup：文件选择/拖放、显式路径校验、调用归档预检、字典文件选择、线程数设置；
- Run：进度、速度、ETA、暂停/继续/停止、脱敏日志；
- Result：密码字节展示与复制、终态说明、打开归档所在目录；
- NativeBridge：使用 W3-002 的 SafeHandle、UCO 回调、UI dispatcher；按 C ABI 参数调用 `create/start/status/pause/resume/stop/destroy`；
- 测试：ZIP 已知密码命中、错误密码未命中、未加密/损坏/缺文件分类、停止语义、GUI↔CLI 差分。

### 2.2 非目标

- 掩码、暴力、混合、规则、编码变体、strict、`rar_no_fast_reject`；
- 断点续跑 UI、批量任务、7z/RAR 攻击；
- 统计字段展示、报告导出、ETA/24h 容量预算展示（归 W3-004/005）；
- sidecar 真实进程、自动解压、安装包、GPU/hashcat。

## 3. 关键设计决策

### 3.1 需要新增非破坏性 ABI：归档预检

当前 C ABI v1 没有归档元数据接口，Setup 无法从内核得到格式、加密方式、条目数与错误分类。W3-003 必须先新增**附加函数**，不改变已冻结结构体布局：

```c
typedef struct {
  uint32_t struct_size;
  uint32_t version;
  uint32_t format;          /* 1 zip, 2 7z, 3 rar4, 4 rar5 */
  uint32_t encryption;      /* 0 none, 1 zipcrypto, 2 aes, 3 rar */
  uint64_t entry_count;
  uint64_t selected_index;
  uint8_t  whole_archive;
  uint8_t  header_encrypted;
  uint8_t  has_verification_target;
  uint8_t  reserved8;
  uint64_t reserved[4];
} AcxInspectionInfo;

AcxStatus acx_inspect(const char* path, AcxInspectionInfo* info);
```

约定：

- 只返回元数据，不返回密码、明文条目或日志；
- 缺卷/损坏/未加密/不支持分别返回已有 `ACX_ERR_MISSING_VOLUME`/`ACX_ERR_ARCHIVE`/`ACX_ERR_UNSUPPORTED`；
- 新增函数不改变 `ACX_ABI_VERSION`，不动 v1 结构体字段；这是 ABI 兼容扩展；
- 实施前必须由 architect 与 release 复审接口；release 需确认无许可影响。

### 3.2 Checkpoint 处理

W3-003 不提供续跑 UI，但 C ABI 在 `checkpoint_path=NULL` 时会生成默认 checkpoint。为避免把默认路径拼装问题带入用户流程：

- GUI 为每个 job 生成显式临时 checkpoint 路径；
- `resume=0`；
- UI 不展示、不承诺可续跑；
- job 停止后删除该临时文件（若存在）。

这使 `AUDIT-FFI-16` 不影响 W3-003，但 `AUDIT-CORE-03` 仍必须在切片内修复。

### 3.3 终态判定

`ACX_OK` 不能直接解释为“命中”。GUI 必须组合判断：

| 状态 | 判定 |
|---|---|
| `state=FINISHED` 且收到 `on_hit` | 命中 |
| `state=FINISHED` 且未收到 `on_hit` | 未找到 |
| `state=STOPPED` | 用户停止 |
| `state=FAILED` 或 `last_status != OK` | 失败 |
| `on_finished(status)` | 仅作终态通知，不单独作为业务结论 |

这直接关闭 `AUDIT-FFI-04` 对 UI 的语义风险。

### 3.4 Run 屏统计口径

W3-003 只显示 `tried/total/rate/ETA`。`fast_rejected/full_attempted/external_attempts/by_filter` 因 `AUDIT-FFI-03` 尚无 ABI 通道，明确移至 W3-005。

## 4. 模块与交互设计

### 4.1 Setup

- 文件选择/拖放只取第一个路径；多文件提示“仅处理首卷/首个文件”；
- 调用 `acx_inspect`，显示格式、加密、条目数、是否头加密；
- 未加密、缺卷、损坏、不支持格式直接阻断开始；
- 字典文件必须存在且非空；线程数限制为 1…`available_parallelism()`，不使用 `0` 以避开 `AUDIT-CLI-13` 的口径歧义；
- 开始按钮在预检成功前禁用。

### 4.2 Run

- 启动后创建一次 `AcxJobHandle`，一个 handle 只允许一个 job；
- `on_progress` 由 `NativeCallbackRouter` 限流到约 10 Hz，终态补充最后一次进度快照；
- 暂停/继续/停止通过 `IKernelService.Pause/Resume/Stop`；按钮状态按 handle 状态切换；
- 停止后不再期望 progress/hit/log，但允许一次 `on_finished`；
- 日志只写阶段与错误分类，不显示当前候选、不写完整密码。

### 4.3 Result

- 命中密码来自 `on_hit` 的 `byte[]`，按 UTF-8 尝试显示；不可解码时显示十六进制摘要并保留“复制原始字节”语义；
- 展示命中复核方式：ZIP 内置解压/CRC/HMAC；
- 失败页面只展示归档级分类与 `acx_last_error` 的即时复制文本；不宣称逐候选“密码错/损坏”二分；
- 提供“复制密码”“打开归档所在目录”“重新开始”，不提供自动解压。

## 5. 测试设计

| 类别 | 用例 | 验证点 |
|---|---|---|
| 命中 | ZIP ZipCrypto + 已知密码 | `on_hit` 字节、FINISHED、复制按钮 |
| 未命中 | 同归档 + 错密码字典 | FINISHED、无 hit、未找到文案 |
| 预检 | 未加密 ZIP | `ACX_ERR_UNSUPPORTED`，开始按钮禁用 |
| 预检 | 损坏 ZIP / 缺卷 | 按 structured error 分类提示，不解析错误文本 |
| 控制 | 暂停→继续→停止 | UI 状态机、STOPPED、on_finished、无 UI 冻结 |
| 生命周期 | 重复 start / destroy 后调用 | 不崩溃、错误状态明确 |
| 差分 | GUI 与 CLI 同归档/字典 | FOUND/MISS/error 分类一致 |
| ABI | `acx_inspect` 布局与错误码 | struct_size/version、C/C# smoke |

测试不得依赖工具版本，不得静默跳过；skip 必须显式报告（`AUDIT-CLI-07`）。断言使用结构化 ABI 字段，不用 stdout 子串（`AUDIT-CLI-08`）。

## 6. 审计 P2 影响分析

结论分类：**阻断**（必须在 W3-003 前/内修复）、**约束**（影响设计但不阻塞）、**延后**（不影响 W3-003）、**已修复**。

### 6.1 FFI / C ABI

| ID | 问题 | 对 W3-003 影响 | 处理 |
|---|---|---|---|
| FFI-01 | 回调内 `acx_last_error` 死锁 | 已修复 | 关闭；W3-003 回调仍禁止重入 ABI |
| FFI-03 | ABI 无统计通道 | 约束 | W3-003 不显示判据统计；W3-005 前新增 `acx_stats` |
| FFI-04 | Cancelled/stop 终态语义 | 约束 | 按 §3.3 组合 state + hit + finished 判定 |
| FFI-06 | C# smoke 覆盖弱 | 已修复 | 关闭；新增 W3-003 GUI E2E |
| FFI-07 | 裸指针无边界校验 | 约束 | W3-003 仅传 path/dict，masks/rules 为 null；C# 校验字符串非空与 NUL 终止 |
| FFI-08 | `measured_rate` 硬编码 | 不影响 | W3-003 不展示 estimate；W3-004 处理 |
| FFI-09 | `encoding_variants as u8` 截断 | 不影响 | encoding 属 W3-004 |
| FFI-10 | 文档陈旧 | 约束 | 设计以 `acx.h` 为准；旧 outline 已同步修正 |
| FFI-14 | null handle 语义不一致 | 不影响 | W3-003 始终使用 SafeHandle；禁止 null 路径 |
| FFI-16 | 默认 checkpoint 路径拼接 | 约束 | §3.2 显式临时 checkpoint，规避该路径 |
| FFI-17 | Rust 测试缺口 | 约束 | W3-003 补 GUI 层 stop/重复 start/生命周期用例；核心缺口按优先级排期 |
| FFI-11/12/13/15/18/19/20/21 | 已降 P3 或修复 | 不影响 | 不进入 W3-003 门禁 |

### 6.2 acx-core

| ID | 问题 | 对 W3-003 影响 | 处理 |
|---|---|---|---|
| CORE-01 | 7z full verify 吞 I/O 错误 | 不影响（W3-003 仅 ZIP） | W3-004 7z 前修复 |
| CORE-02 | ZIP full verify 把截断当 Miss | **阻断** | W3-003 前修复：明确 CRC/密码失败为 Miss，`UnexpectedEof` 为归档错误 |
| CORE-03 | STOPPED 时 checkpoint 保存失败升级错误 | **阻断** | W3-003 内修复：保存失败写 warning，仍返回 Stopped |
| CORE-04 | checkpoint 非原子替换 | 约束 | W3-003 临时 checkpoint 不用于续跑；W3-004 前修复原子写 |
| CORE-07 | 外部引擎 PATH/cwd 劫持 | 不影响（RAR 不在范围） | W3-004 RAR 前修复 |
| CORE-08 | RAR5 高 KDF DoS | 不影响 | W3-004/外部引擎场景处理 |
| CORE-11 | 编码统计瞬时不一致 | 不影响（encoding 不在范围） | W3-004 前修复 |
| CORE-12 | batch 隐式续跑 | 不影响 | batch/W3-004 处理 |
| CORE-15 | FFI 错误码粒度粗 | **阻断（通过预检解决）** | 新增 `acx_inspect` 提供结构化归档分类，不解析错误文本 |
| CORE-05/06/09/10/13/14/16 | 已降 P3/非缺陷 | 不影响 | 不进入 W3-003 门禁 |

### 6.3 CLI 与测试

| ID | 问题 | 对 W3-003 影响 | 处理 |
|---|---|---|---|
| CLI-04 | single `--estimate` 拒绝 dict | 不影响 | W3-003 不展示 estimate；W3-004 处理 |
| CLI-05 | batch 无全局 report stats | 不影响 | W3-005/W4 处理 |
| CLI-07 | 工具条件测试静默跳过 | 约束 | GUI 测试显式 skip 与版本记录 |
| CLI-08 | 脆弱断言 | 约束 | GUI 测试使用 ABI 结构化字段，不用文本 `contains` |
| CLI-09 | CLI 进程级控制状态 | 不影响 | GUI 只用 per-handle ABI 控制 |
| CLI-10/12 | helper 重复 | 不影响 | 抽公共 helper，非门禁 |
| CLI-13 | `--threads 0` 口径不一致 | 约束 | GUI 固定 1…可用并发数，禁止 0 |
| CLI-14/15 | 警告顺序/时间敏感 example | 不影响 | 不进入 GUI 路径 |
| CLI-01/02/03/06 | 原 P1，本次用户仅要求分析 P2 | 不直接阻断 GUI | GUI 不依赖 CLI；但 W3-003 差分测试不得照搬 CLI 语义 |

### 6.4 工程 / CI / 依赖

| ID | 问题 | 对 W3-003 影响 | 处理 |
|---|---|---|---|
| ENG-01 | GNU/MSVC 产物口径不一致 | 不阻断开发；W4 阻断 | W3-003 继续用当前 CI 产物，W4 前统一 |
| ENG-05 | 多版本 crypto/syn warn | 不影响 | 保持 warn 并记录 |
| ENG-06 | release strip | 不影响 | W4 打包处理 |
| ENG-07 | MSRV job 覆盖偏窄 | 约束 | W3-003 PR 继续跑完整本地门禁，远端 job 补强另排 |
| ENG-08 | ffi-smoke 依赖 runner 工具 | 不影响（当前 run 7/7） | 后续显式安装工具 |
| ENG-11 | core README 过时 | 不影响 | 文档清理 |
| ENG-02 | CI 绿灯 | 已关闭 | PR #40 run `46111999727` 7/7 |
| ENG-03/04/09/10/12 | 已降 P3 | 不影响 | 不进入 W3-003 门禁 |

### 6.5 总体判断

- **必须在 W3-003 前/内关闭**：CORE-02、CORE-03、CORE-15（通过 `acx_inspect`）。
- **作为设计约束保留**：FFI-03/04/07/10/14/16/17、CORE-04、CLI-07/08/13、ENG-07。
- **可安全延后**：7z/RAR、统计导出、encoding、batch、sidecar 真进程、发布 strip、工具链统一。
- **不影响 W3-003 开发启动的结论**：其余 P2 不阻塞；但上述三项关闭前不得宣称 W3-003 验收通过。

## 7. 验收条件（切片级）

1. ZIP ZipCrypto 字典命中、错密码未命中；
2. 未加密/损坏/缺文件由 `acx_inspect` 分类，GUI 不解析错误文本；
3. 暂停/继续/停止有效，STOPPED 与 FAILED 语义清晰；
4. UI 线程不阻塞，进度刷新约 10 Hz，终态补发最终进度；
5. GUI 与 CLI 差分结果一致；
6. 无自动解压、无完整密码日志、无 RAR/GPU 暴露；
7. 所有测试显式执行或显式 skip；CI 全绿；
8. `acx_inspect` 经 architect/release 复审，不破坏 v1 布局。

## 8. 回滚方案

- 未推送：`git reset --hard <W3-002 commit>`；
- 已推送：`git revert <W3-003 commit>`；
- ABI 回滚：保留 v1 结构体，仅移除新增 `acx_inspect`/`AcxInspectionInfo` 与 GUI 调用；
- 数据影响：临时 checkpoint 与本地日志删除；无 schema/落盘格式变化。

## 9. 交接格式

```text
STATUS: planned（设计目标定稿，未实现）
BRANCH: windows-gui
ROLE: frontend-engineer + core-engineer + qa-engineer
NEXT: M0 ABI 预检复审 → M1 Setup → M2 Run/控制 → M3 Result/复制 → M4 GUI↔CLI 差分
RISKS: CORE-02/03/15 未关闭前不得验收；统计与 encoding 延后到 W3-004/005
```
