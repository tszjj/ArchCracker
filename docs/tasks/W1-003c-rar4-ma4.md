# W1-003c：RAR4 `-ma4` 端到端验证

- 分支：`fix/w1-003c-rar4-ma4`
- 角色：core-engineer（主对话实现）、reviewer（独立评审）
- 状态：实现完成，待 PR/评审
- 前置：[W1-003](W1-003-rar-external.md)（RAR 外部引擎）

## 背景

W1-003 只完成了 RAR5 端到端验证。当时 WinRAR 7.22 无法生成 `-ma4` 样本，RAR4 仅覆盖
magic/预检代码路径。WinRAR 已调整为 **6.24 x64**，可以生成真正的 RAR4 归档，本切片补上
端到端验证，并修正 RAR4 的预检/候选退出码差异。

## 环境与样本

- Windows 11 x64；WinRAR/UnRAR 6.24 x64（`Rar.exe` / `UnRAR.exe` 文件版本 6.24.0）。
- 样本由本机 `Rar.exe` 生成，不提交仓库：

```powershell
rar a -ma4 -ep1 -p encrypted-rar4.rar hello.txt
```

- 归档头 magic：`52 61 72 21 1a 07 00`（RAR4），不是 RAR5 的 `... 01 00`。
- 同时生成未加密 RAR4 与 `-hp` 头加密 RAR4 用于手工对照。

## 发现

1. **RAR4 缺少密码时 `t -p-` 返回 3，不是 11**。UnRAR 输出
   `Checksum error in the encrypted file ... Corrupt file or wrong password.`；
   RAR5 才返回 11。
2. RAR4 文件加密时 `l -p-` 返回 0，清单中加密条目以行首 `*` 标记；头加密时 `l -p-`
   返回 3，且主头 flags（偏移 10..12）含 `0x0080`（`MHD_PASSWORD`）。
3. **RAR4 错误密码的候选测试也返回 3**，不是 11；原实现会把每个错误候选当成外部错误中止。
4. `l -idq` 会完全抑制清单输出，拿不到 `*` 标记；去掉后输出仍受 64 KiB 截断保护。
5. **未加密但损坏的 RAR4** 也可能让 `l -p-` 返回 3，但主头 flags 不含 `0x0080`；
   预检必须用该标志区分“头加密”和“损坏”。

## 范围

- `core/crates/acx-core/src/archive/rar.rs`
  - 预检新增 RAR4 exit 3 分支：`l -p-` 成功且带 `*` 标记 → 文件加密；`l -p-` 返回 3 且
    RAR4 主头 flags 含 `0x0080` → 头加密；其余一律按损坏报错，不进入字典。
  - `listing_args()` 去掉 `-idq`，保留清单输出用于 `*` 标记；输出仍受 64 KiB 截断保护。
  - `classify_test_exit()`：RAR4 exit 3 → Miss；RAR5 exit 3 仍为 External。
  - 新增 4 个单元测试：RAR4/RAR5 退出码分类、RAR4 主头 flags、`*` 标记识别。
- `core/crates/acx-cli/tests/w1_rar_external.rs`
  - `create_rar` 支持附加开关；新增 `local_rar4_external_cli`：
    生成 `-ma4` 加密/未加密样本，断言 RAR4 magic，验证命中、错误字典、未加密退出码；
    破坏未加密 RAR4 主头 CRC，断言损坏归档 exit 3、不显示 `Encryption: rar`、不跑字典。
- 文档：本任务、W1-003 状态、PROJECT-GUIDE、README、AGENTS、roadmap、windows-plan。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

- [x] `-ma4` 样本 magic 为 RAR4，CLI 显示 `Format: rar4`。
- [x] 正确密码 exit 0 / `FOUND`；错误字典 exit 1；未加密 RAR4 exit 3。
- [x] `-hp` RAR4 正确密码 exit 0、错误字典 exit 1（手工）。
- [x] 现有 RAR5/ZIP/FFI/CLI 测试保持通过。
- [x] 不改变 RAR 仍只通过外部 UnRAR 进程的许可边界；无新依赖。

## 验证结果

- `cargo fmt --all -- --check`：通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo test --workspace --locked`：
  - `acx-core` 单元 46（原 42，新增 4）；
  - CLI 单元 4；
  - 集成 9（ZIP 6 + RAR 3：RAR5、RAR4、Unicode；RAR4 内含损坏回归）；
  - FFI 2。
- 本机 RAR 集成实际执行 3 个测试，均通过（未跳过）。
- 手工验证（WinRAR 6.24）：
  - RAR4 文件加密：hit exit 0、miss exit 1；
  - RAR4 `-hp` 头加密：hit exit 0、miss exit 1；
  - RAR4 未加密：exit 3；
  - 损坏的未加密 RAR4：exit 3，提示 listing 失败，不显示 `Encryption: rar`、不进入字典；
  - 归档 magic 与 `Format: rar4` 均正确。

## 未验证 / 风险

- **RAR4 exit 3 语义不唯一**：预检已用主头 `0x0080` 标志把“头加密”和“可见但损坏”分开；
  但候选阶段若密码正确而数据损坏，UnRAR 仍返回 3，当前按 Miss，最终可能显示 `NOT FOUND`
  而不是明确“归档损坏”。RAR5 的 3 仍按 External 处理。完整错误分类留 W2。
- 预检依赖 `l -p-` 输出中的 `*` 标记；这是 RAR 控制台标记，不是本地化文本，但仍需在更多
  WinRAR/UnRAR 版本上回归。清单输出受 64 KiB 截断保护，极端情况下（加密条目位于大量未加密
  条目之后）可能漏掉标记，后续可改为直接读 RAR4 文件头 flags。
- RAR4 分卷/SFX、不同代码页密码、超大归档未覆盖。
- 非 Windows 平台仍无 RAR 运行时验证；CI 无引擎时集成测试跳过。
