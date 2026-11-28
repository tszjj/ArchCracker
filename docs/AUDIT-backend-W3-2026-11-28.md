# W3 前端设计前后端代码复核审计（逐项核实版）

- 审计日期：2026-11-28
- 审计基线：`windows-gui @ f890924`
- 审计范围：`core/crates/acx-core`、`core/crates/acx-ffi`、`core/crates/acx-cli` 的业务代码与测试代码，以及 `Cargo.toml`/`Cargo.lock`/`deny.toml`/CI/环境脚本/相关文档
- 审计方式：对既有评审报告中的每个问题逐项回查当前代码、测试与文档；不重新运行全量门禁。问题条目中的行号引用为审计基线 `f890924` 的修复前快照；修复状态以本轮代码与回填说明为准。
- 变更声明：初次审计未修改项目代码；随后按用户要求修复四项问题，并在本文逐项回填修复状态。
- 分级口径：
  - **P0**：契约内正常使用即可导致崩溃、死锁、数据损坏或错误安全边界，必须立即修复
  - **P1**：导致状态语义、错误分类或跨端契约不一致，联调/签核前应修复
  - **P2**：真实但影响有限，或只在特定条件/未来阶段显示
  - **P3**：清理、文档、可维护性项
  - **不适用/非缺陷**：原报告问题描述存在，但对当前 GUI 路径不构成问题，或属于正确设计

## 0. 总体结论

1. **未发现契约内可触发的 P0**。原 FFI “`acx_stop` 死锁” 和 CLI 两项 P0 经核实均需降级或限定适用范围。
2. **真正应优先处理的 P1**：
   - FFI `AcxStatusInfo.last_status` 不反映同步 API 失败；
   - `acx_last_error` 指针生命周期文档与实现不一致；
   - CLI exit code / 错误分类缺少单一事实源；
   - CLI/FFI ETA 速率表重复硬编码；
   - CLI single 未调用 `job::validate_job`；
   - CLI `Stopped`/`Cancelled` 退出与输出语义不完整。
3. **核心正确性 P2**：ZIP/7z full verify 把 I/O 截断误判为 Miss、STOPPED 时 checkpoint 保存失败升级为整体错误、checkpoint 非原子替换、编码统计瞬时不一致。
4. **条件性阻塞**：审计基线 `f890924` 当时 `windows-gui` 尚无远端 CI 绿灯；后续 PR #40 run `46111999727` 已 7/7 通过。GNU/MSVC DLL 产物口径未统一，仍阻塞 W4 打包，不阻塞 W3-003 编码。
5. 架构边界总体正确：GUI 应只通过 `acx-ffi` 的 C ABI 访问内核，不得直接调用 `acx-core`，也不得解析 CLI stdout。
6. 许可边界总体安全：hashcat、UnRAR/CUDA/HIP/OpenCL 均非 Cargo 依赖；RAR 仍仅走外部进程；未发现新增不兼容许可。

---

## 1. FFI / C ABI 逐项核实

### AUDIT-FFI-01 原 P0：`acx_stop` 与回调内 `acx_last_error` 潜在死锁

- **问题描述**：`stop_impl` 持有 `inner` 锁后调用 `gate.close()`；回调执行期间 `active > 0`，若回调内调用 `acx_last_error(handle)`，后者也取 `inner` 锁，可形成互等死锁。
- **核实结论**：机制真实存在。证据：`core/crates/acx-ffi/src/lib.rs:1021-1022`、`414-421`、`1204-1216`。但 `acx.h:127-130` 明确禁止回调内重入 `acx_*`，`acx_last_error` 属于该禁令。当前仅 `acx_last_error` 与 `acx_estimate` 缺少 `in_callback()` 防御，属于防御不一致。
- **严重程度评估**：原 P0 **降为 P2**。契约内正常使用不触发；违反明确文档契约才可能触发。
- **修复影响分析**：影响 `CallbackGate`、`finish_handle`、worker 错误写入与所有回调分发；改动很小，不改变 ABI 布局。
- **是否需要修复及理由**：**需要**。低成本消除 GUI 误用时冻结风险。
- **修复建议**：在 `acx_last_error` 入口加 `in_callback()` 早退（返回线程级错误或空串），并补并发回归测试。
- **修复状态（本轮）**：**已修复**。回调内调用返回静态提示；C ABI E2E 增加回调内重入断言。

### AUDIT-FFI-02 原 P1：`AcxStatusInfo.last_status` 不反映同步 API 失败

- **问题描述**：`finish_handle` 失败时只写错误字符串，不更新 `inner.last_status`；`acx_status` 读取的仍是上一次 worker 终态或 `ACX_OK`。
- **核实结论**：成立。`lib.rs:112-130`、`1075`；`tests/cabi.rs` 失败用例未断言该字段。
- **严重程度评估**：**维持 P1**。字段注释为“last operation”，与实际语义冲突，会误导前端错误分类。
- **修复影响分析**：影响 `acx_start/pause/resume/stop/status` 的所有同步失败路径；不改 ABI 结构。
- **是否需要修复及理由**：**需要**。W3 Result/日志需要可靠状态码。
- **修复建议**：`finish_handle` 仅错误分支同步写入 `inner.last_status = status_for_error(&error)`，成功的 `acx_status` 不得冲刷既有失败。
- **修复状态（本轮）**：**已修复**。同步失败写入 `last_status`；复审发现并修复成功查询冲刷失败态的回归；C ABI E2E 连续两次查询均断言 `ACX_ERR_IO`。

### AUDIT-FFI-03 原 P1：ABI 无统计字段输出通道

- **问题描述**：core 有 `JobStats`，但 `AcxStatusInfo`/`AcxEstimateInfo` 无 `fast_rejected`、`full_attempted`、`external_attempts`、`by_filter`。
- **核实结论**：成立。`core/crates/acx-core/src/job.rs:187-210`；FFI 只复制 tried/total/rate/eta。
- **严重程度评估**：原 P1 **降为 P2**。v1 ABI 从未承诺结构化统计字段，属后续功能缺口。
- **修复影响分析**：若加字段或新函数，需 architect/release 复审 ABI 冻结边界；影响 W3-005 报告导出，不影响 W3-002 骨架。
- **是否需要修复及理由**：**延后修复**。W3-005 前必须提供通道，但不阻塞当前骨架。
- **修复建议**：新增独立 `acx_stats(handle, AcxStatsInfo*)`，不要改 v1 已冻结结构布局。

### AUDIT-FFI-04 原 P1：Cancelled 语义不可达 / stop 终态为 `ACX_OK`

- **问题描述**：`Cancelled → ACX_ERR_CANCELLED` 文档承诺不可达；`Stopped/Cancelled` 在 FFI 均映射为 `ACX_OK`。
- **核实结论**：成立。`lib.rs:865-878`；scheduler 内部吞掉 `Cancelled` 后走 `RunOutcome::Stopped`。
- **严重程度评估**：原 P1 **降为 P2**。stop 返回 `ACX_OK + state=STOPPED` 是已有测试确认的设计语义。
- **修复影响分析**：主要影响文档与 `status_for_error` 死分支；不影响命中路径。
- **是否需要修复及理由**：**澄清优先，代码可不改**。避免前端误以为 `ACX_OK` 必然代表命中/穷举完成。
- **修复建议**：文档明确“`ACX_OK` 需结合 state 与 on_hit 判定终态”；删除不可达的 Cancelled 承诺或统一 force_stop 行为。

### AUDIT-FFI-05 原 P1：`acx_last_error` 指针生命周期文档宽于实现

- **问题描述**：头文件称返回字符串在同一 handle 下次调用前有效；实现复制到调用线程 thread-local，任意失败调用或再次调用都会覆盖。
- **核实结论**：成立。`acx.h:5-8` vs `lib.rs:1197-1216`。
- **严重程度评估**：**维持 P1**。缓存 `IntPtr` 或跨 handle 复用会造成错误文本串扰或悬垂感。
- **修复影响分析**：仅头文件与文档语义；NativeBridge 必须立即复制字符串。
- **是否需要修复及理由**：**需要**。低风险、低成本且直接影响错误诊断正确性。
- **修复建议**：头文件改为“同一线程下一次 `acx_last_error` 或失败调用前有效”；C# 立即 `Marshal.PtrToStringUTF8`。
- **修复状态（本轮）**：**已修复**。头文件、Rust doc 与 C# smoke 均已按“立即复制、不得缓存指针”统一。

### AUDIT-FFI-06 原 P1：C# smoke 只走 plain.zip 失败路径

- **问题描述**：C# smoke 创建未加密 ZIP，只挂 `on_finished`，未验证 hit/progress/log/error。
- **核实结论**：成立。`frontends/desktop/tests/AcxFfiSmoke/Program.cs:179-182`、`241-246`、`274-295`。
- **严重程度评估**：原 P1 **降为 P2**。它是测试覆盖缺口，不是产品代码缺陷。
- **修复影响分析**：仅 smoke 工程；但会影响 W3-002 NativeBridge 准入门禁可信度。
- **是否需要修复及理由**：**需要**。否则 W3 可能照搬失败路径模式而假绿。
- **修复建议**：加入 ZipCrypto 已知密码样本；断言 `on_hit` 密码、`on_progress >= 1`、`on_finished` 终态、`acx_last_error` 内容。
- **修复状态（本轮）**：**已修复**。C# smoke 自行生成 ZipCrypto 夹具，覆盖两种回调模型的命中、进度、日志、终态与缺失归档错误路径。

### AUDIT-FFI-07 原 P1：裸指针输入无边界校验

- **问题描述**：`read_cstr`/`string_array` 无法验证 NUL 结尾与数组实际长度。
- **核实结论**：部分成立。这是 C ABI 固有限制，当前只校验 null；头文件已声明指针借用契约。
- **严重程度评估**：原 P1 **降为 P2**。
- **修复影响分析**：影响 `build_job_spec`、`AcxAttackSpec` 文档与 NativeBridge 封送实现。
- **是否需要修复及理由**：**部分需要**。不可能完全校验，但应防 OOM 和误用。
- **修复建议**：限制 `mask_count/rule_count` 上限；文档明确数组长度必须等于 count、字符串必须 NUL 结尾。

### AUDIT-FFI-08 原 P2：`measured_rate` 硬编码

- **核实结论**：成立，头文件已注明 baseline。
- **严重程度**：**维持 P2**。
- **修复影响**：仅估算字段命名/文档。
- **是否修复**：低优先级；建议改名为 `baseline_rate` 或明确注释。
- **建议**：与 CLI 速率表统一下沉 core 时一起处理。

### AUDIT-FFI-09 原 P2：`encoding_variants as u8` 截断

- **核实结论**：成立，`job.rs` 为 `usize`，FFI 直接 `as u8`。
- **严重程度**：**维持 P2**。
- **修复影响**：仅 `acx_estimate` 输出。
- **是否修复**：需要，防静默错误。
- **建议**：`try_into().unwrap_or(u8::MAX)` 或饱和转换。

### AUDIT-FFI-10 原 P2：文档陈旧

- **核实结论**：成立。`docs/tasks/W3-windows-gui-outline.md` 仍称 ABI v0；`architecture.md` 仍有 JSON 配置等旧措辞。
- **严重程度**：**维持 P2**。
- **修复影响**：仅文档一致性。
- **是否修复**：需要。
- **建议**：以 `acx.h` 为唯一事实源，更新 C ABI v1、函数表、on_finished 语义、统计缺口。

### AUDIT-FFI-11 原 P2：C# `fixed long Custom[4]` 的 x64 假设

- **核实结论**：成立，但当前首发平台仅 x64，且尺寸断言通过。
- **严重程度**：原 P2 **降为 P3**。
- **修复影响**：仅 smoke/P/Invoke 结构。
- **是否修复**：可选。
- **建议**：改为指针宽度类型或注释“仅 x64 布局”。

### AUDIT-FFI-12 原 P2：C# smoke 死代码

- **核实结论**：成立，少量 helper 未使用。
- **严重程度**：**降为 P3**。
- **是否修复**：可选。
- **建议**：随 smoke 增强一并清理。

### AUDIT-FFI-13 原 P2：`CallbackSet.user: usize` 与 unsafe Send/Sync

- **核实结论**：成立，但有明确生命周期契约注释。
- **严重程度**：**降为 P3**。
- **是否修复**：不需要。
- **建议**：保持，前提是在 C 头文件持续明确 user 指针生命周期。

### AUDIT-FFI-14 原 P2：null handle 语义不一致

- **核实结论**：成立。`destroy(null)` no-op；`pause/resume/stop/status(null)` 返回 `ACX_ERR_INVALID_ARG`。
- **严重程度**：**维持 P2**。
- **修复影响**：头文件与 API 文档。
- **是否修复**：建议统一。
- **建议**：统一为“null 一律 INVALID_ARG”或在头文件逐函数标注。

### AUDIT-FFI-15 原 P2：`acx_estimate` 无 `in_callback()` 检查

- **核实结论**：成立，但估算无 handle 状态访问。
- **严重程度**：**降为 P3**。
- **是否修复**：不需要。
- **建议**：保持，或为一致性统一加检查。

### AUDIT-FFI-16 原 P2：默认 checkpoint 用 display 拼路径

- **核实结论**：成立，可能丢失非 UTF-8 路径信息。
- **严重程度**：**维持 P2**。
- **修复影响**：默认 checkpoint 生成逻辑与 resume 路径。
- **是否修复**：建议修。
- **建议**：用 `PathBuf::set_extension` / `OsString` 拼接。

### AUDIT-FFI-17 原 P2：Rust 测试缺口

- **核实结论**：部分成立。已有 struct_size、FD 拒绝、on_log 等测试；仍缺 version 错误、非法 flags、并发 pause/stop/status、mask/hybrid E2E、destroy 时 worker 活跃、last_error 生命周期等。
- **严重程度**：**维持 P2**。
- **是否修复**：选择性修复。
- **建议**：优先补 version/flag/并发/last_error 生命周期；mask/hybrid E2E 可复用 CLI 向量。

### AUDIT-FFI-18 原 P2：panic hook 写 stderr

- **核实结论**：成立，但仅控制台噪音。
- **严重程度**：**降为 P3**。
- **是否修复**：可选。
- **建议**：GUI 宿主可安装静默 hook，核心库不改。

### AUDIT-FFI-19 原 P2：`claim()` 中 `closed=false` 冗余

- **核实结论**：成立，纯冗余。
- **严重程度**：**降为 P3**。
- **是否修复**：可选清理。
- **建议**：删除冗余赋值。

### AUDIT-FFI-20 原 P2：reserved 未要求清零

- **核实结论**：成立。
- **严重程度**：**降为 P3**。
- **是否修复**：可选。
- **建议**：文档声明忽略 reserved，或未来 ABI v2 校验。

### AUDIT-FFI-21：`AcxAttackSpec` 字面量重复四次

- **核实结论**：成立，测试构造重复。
- **严重程度**：**P3**。
- **修复影响**：仅测试代码。
- **是否修复**：可选。
- **建议**：抽取 builder，已有 `job_spec` 可复用。

---

## 2. acx-core 业务代码逐项核实

### AUDIT-CORE-01 原 P1：7z full verify 将 I/O 错误吞成 Miss

- **问题描述**：`is_candidate_rejection` 将 `UnexpectedEof/Other` 视作候选错误，full verify 使用同一判定。
- **核实结论**：成立。`archive/sevenz.rs:595-608`；调用点 `193-196`、`226-229`。
- **严重程度评估**：原 P1 **降为 P2**。中央目录截断已被 preflight 分类；数据区截断/损坏可能假 NOT FOUND，不会误报 Hit。
- **修复影响分析**：影响 `archive/sevenz`、统计归类、CLI/FFI 错误状态；不改断点结构。
- **是否需要修复及理由**：**需要**。full verify 应区分错误密码与归档损坏。
- **修复建议**：full verify 只接受明确密码/CRC/校验失败为 Miss；`UnexpectedEof` 返回 `Truncated`，`Other` 升级为错误或明确枚举。

### AUDIT-CORE-02 原 P1：ZIP full verify 将 `UnexpectedEof` 吞成 Miss

- **核实结论**：成立。`archive/zip.rs:299-305`；调用点 `233`、`281`。
- **严重程度**：原 P1 **降为 P2**。
- **修复影响**：影响 ZIP full verify、统计和错误呈现；不改断点。
- **是否修复**：需要。
- **建议**：`InvalidData/InvalidInput` 可作 Miss，`UnexpectedEof` 返回 Truncated/IO。
- **修复状态（本轮）**：**已修复**。`is_candidate_rejection` 仅保留 `InvalidData/InvalidInput`；ZipCrypto 与 AES 两条 full-verify 路径的短读/`UnexpectedEof` 均返回 `AcxError::Truncated`；补分类单测与真实 AES 截断 E2E。

### AUDIT-CORE-03 原 P1：STOPPED 分支 checkpoint 保存失败升级整体错误

- **核实结论**：成立。`job.rs:1012-1022` 使用 `?`；Failed 分支 `1037-1050` 只加 warning。
- **严重程度**：原 P1 **降为 P2**。
- **修复影响**：影响 CLI/FFI 停止状态、warnings 和续跑可用性。
- **是否修复**：需要。
- **建议**：保存失败写 warning，始终返回 `JobStatus::Stopped`。
- **修复状态（本轮）**：**已修复**。抽出 `save_checkpoint_or_warn`，STOPPED 与 FAILED 分支统一降级为 warning，并补失败目录回归测试。

### AUDIT-CORE-04 原 P1：checkpoint save 先删后改非原子

- **核实结论**：成立。`checkpoint.rs:209-226`。
- **严重程度**：原 P1 **降为 P2**。
- **修复影响**：影响 Windows 断点写入与强杀恢复；不改 schema。
- **是否修复**：需要，尤其 Windows GUI。
- **建议**：Windows 用 `ReplaceFileW`/`MoveFileExW(REPLACE_EXISTING)`；Unix 保持 rename 覆盖；失败清理 temp。

### AUDIT-CORE-05 原 P1：`attack.rs` 冗余公共模块

- **核实结论**：成立。`attack.rs:1-28` 定义 `AttackMode/AttackSpec`，workspace 内未使用；真实路径为 `job::AttackConfig`。
- **严重程度**：原 P1 **降为 P3**。
- **修复影响**：影响公共 API；可能破坏外部消费者。
- **是否修复**：不急。
- **建议**：标记 deprecated，确认无外部用户后再删除。

### AUDIT-CORE-06 原 P2：Exhausted 报告 `completed_through=total`

- **核实结论**：行为存在，但不是缺陷。`job.rs:994-1004`；Exhausted 会删除 checkpoint。
- **严重程度**：**不属于问题/P3**。
- **是否修复**：不需要。
- **建议**：在字段注释说明 Exhausted 时归一化为 total。

### AUDIT-CORE-07 原 P2：外部引擎 PATH/cwd 劫持面

- **核实结论**：成立。`engines/external.rs:225-283` 信任 `ACX_UNRAR`/PATH/WinRAR 默认目录；`Command::new` 未显式设置 `current_dir`。
- **严重程度**：**维持 P2**，取决于威胁模型。
- **修复影响**：影响 RAR 引擎发现、GUI 引擎路径展示、错误分类。
- **是否修复**：条件需要；不可信环境或 GUI 允许相对路径时需要。
- **建议**：优先绝对路径；记录实际 engine path；显式子进程 `current_dir`。

### AUDIT-CORE-08 原 P2：RAR5 高 KDF DoS

- **核实结论**：成立。`rar5_verify.rs:28`、`139-150`。4-byte checksum 先行过滤，非法 check 不进入高 KDF。
- **严重程度**：**维持 P2**。
- **修复影响**：影响 RAR5 快筛、`fast_rejected/full_attempted`、strict/no-fast-reject。
- **是否修复**：条件需要；接受不可信归档时建议修。
- **建议**：增加 CPU/时间预算或降低 KDF 上限，超限回退外部 UnRAR。

### AUDIT-CORE-09 原 P2：timeout 溢出失去超时保护

- **核实结论**：成立。`engines/external.rs:165-190`。
- **严重程度**：原 P2 **降为 P3**。默认 60s，异常 timeout 才触发。
- **修复影响**：外部进程调用。
- **是否修复**：建议修，成本低。
- **建议**：`checked_add` 失败返回 unsupported 或钳制默认值。

### AUDIT-CORE-10 原 P2：checkpoint 指纹脆弱点

- **核实结论**：部分成立。mtime 指纹存在；未知格式默认 Zip 的 `format()` 当前未使用；`parse_u64 as usize` 在 32 位有截断。
- **严重程度**：原 P2 **降为 P3**。
- **修复影响**：断点续跑验证。
- **是否修复**：部分需要。
- **建议**：threads 用 `try_from`；未知格式显式报错；mtime 策略按产品决定。

### AUDIT-CORE-11 原 P2：编码统计瞬时不一致

- **核实结论**：成立。`encoding.rs:394-414` 先加后减；快照 SeqCst、增量 Relaxed。
- **严重程度**：**维持 P2**。
- **修复影响**：统计口径、CLI `--report-stats`、W3 实时统计；不影响密码正确性。
- **是否修复**：需要。
- **建议**：测试后根据 skip 结果一次性递增；或由 fast/full 派生 attempts。

### AUDIT-CORE-12 原 P2：batch 隐式自动续跑

- **核实结论**：成立。`batch.rs:543-545` 强制 `spec.resume = checkpoint.exists()`。
- **严重程度**：**维持 P2**。
- **修复影响**：batch 行为、manifest 契约、CLI 文档。
- **是否修复**：条件需要。
- **建议**：显式化 resume 配置；陈旧 checkpoint 仍需指纹校验。

### AUDIT-CORE-13 原 P2：重复逻辑

- **核实结论**：成立。两份 SHA256 hex、两份 `same_archive`、两份 `read_vint`、三个相似的 `job_estimate_from_*`。
- **严重程度**：原 P2 **降为 P3**。
- **是否修复**：可选。
- **建议**：抽内部 util；`job_estimate_from_*` 因语义差异可保留。

### AUDIT-CORE-14 原 P2：性能热点

- **核实结论**：部分成立。每秒 checkpoint sync_all、100ms 进度快照锁、256 worker 上限均存在；“每 worker 重解析元数据”主要对 ZIP 成立。
- **严重程度**：原 P2 **降为 P3**（普通负载）；高线程/大文件场景可升 P2。
- **是否修复**：条件需要。
- **建议**：watermark 未变化跳过写盘；共享 ZIP 元数据；进度快照按需拉取。

### AUDIT-CORE-15 原 P2：FFI 错误码粒度粗

- **核实结论**：成立。core 无稳定数值 code；FFI 多种归档错误合并为 `ACX_ERR_ARCHIVE`。
- **严重程度**：**维持 P2**。
- **修复影响**：core error、FFI ABI、GUI 错误映射。
- **是否修复**：W3 Result 需精确分类时修复。
- **建议**：core 增加 `error_kind/code`，ABI v2 暴露，v1 常量保持兼容。
- **修复状态（本轮）**：**已通过附加 v1 接口部分修复**。新增 `acx_inspect`/`AcxInspectionInfo` 提供格式、加密、条目、目标可通过预检与结构化错误；不提升 ABI 版本、不改冻结结构布局。运行期细粒度 `error_kind` 仍留待 ABI v2。

### AUDIT-CORE-16 原 P2：魔数与参数数量

- **核实结论**：部分成立。`headers > 100_000` 是防护上限；“8 参数构造函数”不成立，实际 7 参数。
- **严重程度**：**降为 P3**。
- **是否修复**：可选。
- **建议**：具名常量并写理由；删除过时 clippy allow 或改参数对象。

---

## 3. CLI 与测试代码逐项核实

### AUDIT-CLI-01 原 P0：退出码/错误分类无单一事实源

- **核实结论**：成立。CLI 常量在 `main.rs:24-31`；single 与 batch 映射不同；ABI 另有 `ACX_ERR_*`。
- **严重程度评估**：原 P0 **降为 P1**。对 CLI 自动化是真实问题；GUI 走 C ABI，不直接受影响。
- **修复影响分析**：影响 CLI exit code contract、CLI 测试；若统一 core 分类还会影响 FFI/GUI 映射。
- **是否需要修复及理由**：**需要**。CLI 承诺稳定退出码，single/batch 不应分裂。
- **修复建议**：core 或 CLI 内部建立单一 `ErrorClass`/映射函数；ABI 继续用自己的 `ACX_ERR_*`，不要混用 CLI 退出码。

### AUDIT-CLI-02 原 P0：ETA/24h/速率表硬编码

- **核实结论**：成立。CLI `main.rs:490-496`、`524-542`、`618-625`；FFI `lib.rs:153-161` 也重复同一速率。ABI 已有 `acx_estimate` 字段。
- **严重程度**：原 P0 **降为 P1**。是一致性/维护风险，不是 GUI 阻塞。
- **修复影响**：CLI 输出、FFI `acx_estimate`、相关测试。
- **是否修复**：需要，低优先级。
- **建议**：速率表与 ETA 计算下沉 core；`measured_rate` 改 `baseline_rate`；24h 常量集中定义。

### AUDIT-CLI-03 原 P1：参数校验重复，single 未调用 `validate_job`

- **核实结论**：成立。single `main.rs:188-260` 手写校验；core `job.rs:257-349` 有 `validate_job`；batch 调用。
- **严重程度**：**维持 P1**。
- **修复影响**：CLI single/batch、参数错误文案、部分边界测试。
- **是否修复**：需要。
- **建议**：构造 `JobSpec` 后统一调用 `job::validate_job`；CLI 只保留参数语法校验。

### AUDIT-CLI-04 原 P1：single `--estimate` 拒绝 dict

- **核实结论**：成立。`main.rs:257-260` 拒绝；core/batch 支持 dict estimate。
- **严重程度**：原 P1 **降为 P2**。
- **是否修复**：建议修。
- **建议**：放开 dict estimate，并补 CLI 测试。

### AUDIT-CLI-05 原 P1：batch 无全局 `--report-stats`

- **核实结论**：成立，manifest 仅逐 job 支持。
- **严重程度**：原 P1 **降为 P2**。
- **是否修复**：低优先级。
- **建议**：新增 batch 级参数覆盖 manifest job 的 `report_stats`。

### AUDIT-CLI-06 原 P1：Cancelled/Stopped 展示与退出语义不完整

- **核实结论**：成立。single Cancelled 无输出；batch summary 统计 cancelled 但退出优先级不完整。
- **严重程度**：**维持 P1**。
- **修复影响**：CLI 输出与退出码、自动化测试。
- **是否修复**：需要。
- **建议**：统一 `STOPPED/CANCELLED` 文案、summary 计数与退出优先级。

### AUDIT-CLI-07 原 P1：工具条件测试静默跳过

- **核实结论**：部分成立。测试通过 `eprintln` 后 return；Cargo 默认捕获 stderr，CI 显示全绿。
- **严重程度**：原 P1 **降为 P2**。
- **是否修复**：建议修。
- **建议**：统一 skip helper，输出显式 skip reason；CI 记录实际执行工具版本与 skip 数。

### AUDIT-CLI-08 原 P1：脆弱断言

- **核实结论**：成立。`contains("error")`、RAR 子串、`encoding attempts=2` 固定值。
- **严重程度**：原 P1 **降为 P2**。
- **是否修复**：建议修。
- **建议**：精确退出码 + 结构化字段解析；统计断言不变量，不写死脆弱数值。

### AUDIT-CLI-09 原 P1：Windows 控制层全局状态不适合 GUI 复用

- **核实结论**：成立；CLI 使用 `OnceLock`/进程级 handler；ABI 控制是 per-handle。
- **严重程度**：CLI 内 **P2**，对 GUI 不适用。
- **是否修复**：GUI 不需要。
- **建议**：GUI 坚持使用 ABI per-handle `acx_stop`。

### AUDIT-CLI-10 原 P2：测试 helper 重复

- **核实结论**：成立，多个测试重复 `scratch_dir/TempDir/write_dictionary`。
- **严重程度**：**P2**。
- **是否修复**：可选。
- **建议**：抽 `tests/common/test_env.rs`。

### AUDIT-CLI-11 原 P2：临时目录回退忽略错误

- **核实结论**：成立。
- **严重程度**：原 P2 **降为 P3**。
- **是否修复**：可选。
- **建议**：回退创建失败直接 panic，统一 RAII 清理。

### AUDIT-CLI-12 原 P2：统计字符串解析重复

- **核实结论**：成立，三处近似 helper。
- **严重程度**：**P2**。
- **是否修复**：建议修。
- **建议**：抽 `parse_stat` 与统计不变量断言 helper。

### AUDIT-CLI-13 原 P2：`--threads 0` single/batch 不一致

- **核实结论**：成立。single 帮助称 clamp，batch 拒绝 0。
- **严重程度**：**P2**。
- **是否修复**：需要。
- **建议**：统一为拒绝 0 并调用 `validate_job`。

### AUDIT-CLI-14 原 P2：batch warning 早于 max_parallel 校验

- **核实结论**：成立。
- **严重程度**：**P2**，影响很小。
- **是否修复**：建议修。
- **建议**：先校验参数再计算 warning。

### AUDIT-CLI-15 原 P2：工具版本与时间敏感 example

- **核实结论**：成立。
- **严重程度**：**P2/P3**。
- **是否修复**：可选。
- **建议**：记录工具版本；example 只输出观测值，不做硬断言。

---

## 4. 工程 / CI / 依赖 / 文档逐项核实

### AUDIT-ENG-01 原 P1：Windows GNU/MSVC 产物口径不一致

- **核实结论**：成立。README/bootstrap 指向 GNU；CI Windows/MSVC job 上传 DLL，ffi-smoke 用默认 DLL；GNU job 只测试。
- **严重程度**：原 P1 **降为 P2**；W4 打包前升级为阻塞。
- **修复影响**：core README、bootstrap、CI artifact、未来打包脚本。
- **是否修复**：**需要，W4 前**。
- **建议**：确定发布 target（建议 MSVC），GNU 仅交叉验证；产物按 toolchain 命名。

### AUDIT-ENG-02 原 P1：`windows-gui` 无远端 CI 绿灯

- **核实结论**：成立，文档已如实标注。
- **严重程度**：**条件性 P1**。日常开发不阻塞，W3 签核/合并 main 前阻塞。
- **修复影响**：PR、签核文档、状态同步。
- **是否修复**：需要。
- **建议**：push `windows-gui` 开 PR，取得 7/7 绿灯后回填 run id。
- **修复状态（后续）**：**已修复**。PR #40 run `46111999727` 7/7 通过。

### AUDIT-ENG-03 原 P1：`AGENTS.md` 阶段状态滞后

- **核实结论**：成立。`AGENTS.md:43/48` 仍写 W2 进行中、GUI 未开始。
- **严重程度**：原 P1 **降为 P3**。
- **修复影响**：仅入口文档。
- **是否修复**：需要，低成本。
- **建议**：同步为 W1/W2 已签核、W3 开发中、C ABI v1 已实现。

### AUDIT-ENG-04 原 P2：CI paths-ignore 使许可文档跳过 deny

- **核实结论**：成立，但 cargo-deny 校验依赖图，Markdown 变化风险很低。
- **严重程度**：**降为 P3**。
- **是否修复**：可选。
- **建议**：发布前拆分 license workflow 或不忽略许可文档。

### AUDIT-ENG-05 原 P2：多版本 crypto/syn 只 warn

- **核实结论**：成立。`deny.toml:26` warn；lock 中存在多版本。
- **严重程度**：**P2**。
- **是否修复**：不必须。
- **建议**：保留 warn 并注明来源；MSRV 提升后评估统一。

### AUDIT-ENG-06 原 P2：release 保留符号待打包 strip

- **核实结论**：成立，仓库内尚无 strip 步骤。
- **严重程度**：**P2**，W4 发布债务。
- **是否修复**：W4 前需要。
- **建议**：打包脚本 strip 并记录体积；保留 panic 捕获语义。

### AUDIT-ENG-07 原 P2：MSRV job 覆盖偏窄

- **核实结论**：成立，只跑 test。
- **严重程度**：**P2**。
- **是否修复**：建议修。
- **建议**：补 `cargo check --all-targets --locked` 与 release build。

### AUDIT-ENG-08 原 P2：ffi-smoke 依赖 runner 预装 gcc/c++

- **核实结论**：成立。
- **严重程度**：**P2**。
- **是否修复**：建议修。
- **建议**：显式安装 MinGW 或改用发布同 target 编译器。

### AUDIT-ENG-09 原 P2：C# fixed long 指针宽度假设

- **核实结论**：成立但 x64 首发不受影响。
- **严重程度**：**P3**。
- **是否修复**：可选。
- **建议**：改指针宽度类型或注明 x64-only。

### AUDIT-ENG-10 原 P2：`GITHUB.md` 仍写 6 job

- **核实结论**：文字属实，但对 main 历史绿灯准确；windows-gui 新增 ffi-smoke 后未同步。
- **严重程度**：**P3**。
- **是否修复**：W3 合并 main 后修改。
- **建议**：写为“main 6 job / windows-gui 7 job”。

### AUDIT-ENG-11 原 P2：`core/README.md` 仍 M0 skeleton

- **核实结论**：成立。
- **严重程度**：**P2/P3**。
- **是否修复**：需要。
- **建议**：改为当前 W2 + W3 C ABI v1 基线描述。

### AUDIT-ENG-12 原 P2：许可登记未区分生产/dev

- **核实结论**：部分成立，已有 writer-only 备注但表格无列。
- **严重程度**：**P3**。
- **是否修复**：建议修。
- **建议**：增加“生产/开发”列。

### 版本风险复核

| 项目 | 核实结论 | 严重程度 | 是否修复 |
|---|---|---|---|
| `zip 9.8.2` caret | lock 固定 9.8.2，允许 9.x 升级 | 低 | 不立即修；升级时重跑 MSRV |
| `sevenz-rust2 0.20.2` | caret `<0.21`，不会跳 0.25；0.25 需 Rust 1.93 | 无问题 | 不修 |
| `clap 4.5` | lock 固定 4.6.9 | 低 | 不修 |
| `Cargo.lock` | 存在，version 4 | 无问题 | 保持 |
| hashcat/UnRAR/CUDA/HIP/OpenCL | 均非 Cargo 依赖 | 无问题 | 保持 |

---

## 5. 修复优先级与 W3 决策

### 5.1 建议立即修复（W3-002 NativeBridge 实质接入前）

1. AUDIT-FFI-01：给 `acx_last_error` 增加回调重入防御（**本轮已完成**）；
2. AUDIT-FFI-02：`last_status` 反映同步 API 失败（**本轮已完成**）；
3. AUDIT-FFI-05：统一 `acx_last_error` 生命周期文档与 NativeBridge 复制规则（**本轮已完成**）；
4. AUDIT-FFI-06：C# smoke 升级为命中/进度/错误路径覆盖（**本轮已完成**）。

### 5.2 建议 W3-003/005 前修复

1. AUDIT-CLI-01：CLI 错误分类单一事实源；
2. AUDIT-CLI-02 / FFI-08：速率表与 baseline ETA 下沉 core；
3. AUDIT-CLI-03：single 调用 `validate_job`；
4. AUDIT-CLI-06：Stopped/Cancelled 语义；
5. AUDIT-FFI-03：结构化统计 ABI 通道；
6. AUDIT-CORE-01/02/03/04/11：归档错误分类、停止状态、checkpoint 原子性、统计守恒。

### 5.3 正式签核/发布前条件阻塞

1. AUDIT-ENG-02：`windows-gui` PR CI 7/7；
2. AUDIT-ENG-01：GNU/MSVC 发布产物口径统一；
3. AUDIT-ENG-06：打包 strip；
4. AUDIT-FFI-03：若 W3-005 报告导出进入验收，必须提供统计 ABI 通道。

### 5.4 前端设计可直接采用的稳定结论

- GUI 只通过 `acx-ffi` 访问内核，不调用 `acx-core`，不解析 CLI stdout。
- `on_finished(ACX_OK)` 不能单独判定命中；必须结合 `acx_status.state` 与是否收到 `on_hit`。
- 续跑依据是 `completed_through`，不是 `tried`。
- `attempts` 是变体级，`candidates` 是候选级，skipped 不计 attempts。
- 密码是字节序列，不保证 UTF-8；只展示于结果页，不写日志。
- `acx_estimate` 是基线估算；实际速率来自运行状态。
- Windows 桌面只用 `ACX_INPUT_PATH`；fd/uri 当前返回 unsupported。
- 项目不做自动解压；sidecar 仅预留开关。
- 错误码以 `acx.h` 为唯一事实源，GUI 不得依赖英文错误文本。

## 6. 最终审计判定

- **当前后端可以开始 Avalonia 骨架工程与 MVVM 分层设计**。
- **NativeBridge 实质联调前，应先关闭第 5.1 节四项。**
- **W3 正式签核前，必须关闭第 5.3 节条件阻塞。**
- 原评审报告整体方向正确，但严重程度普遍偏高；本次逐项核实后，未确认任何契约内可触发 P0。
- 后续修复状态：第 5.1 节四项已关闭；W3-003 三项前置（CORE-02、CORE-03、CORE-15）也已关闭。
