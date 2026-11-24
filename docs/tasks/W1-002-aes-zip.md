# W1-002：WinZip AES ZIP 恢复

- 分支：`feat/w1-aes-zip`
- 角色：planner（主对话）、core-engineer（主对话直接实现）、reviewer（独立评审）
- 状态：进行中

## 目标

在 W1-001 的 ZIP 引擎上补齐 WinZip AES（AE-1/AE-2，AES-128/192/256）候选验证，使同一 CLI 可直接恢复 AES 加密 ZIP：

```powershell
acx -f aes.zip -m dict -d dict.txt -t 4
```

## 范围

- `zip` crate 开启 `aes-crypto` feature。
- `ZipSession::test_password`：
  - ZipCrypto 保持现有路径：头校验 + 完整解压 + CRC32 终判。
  - AES 走 `by_index_decrypt`：PBKDF2-HMAC-SHA1 派生 + 2 字节 verifier；通过后完整读取条目，由 crate 校验 HMAC-SHA1-80；HMAC 失败映射 Miss。
  - AES 不依赖 CRC 字段（AE-2 的 CRC 为 0）；不得用 CRC=0 造成假命中。
- 预检：
  - 使用 crate 的中央目录 `aes_settings()` 判定 AES（与解密路径同源）；不依赖仅存在于本地头的字段。
  - 非空加密条目优先；若只有零长度 AES 条目，可选择并验证（HMAC 可判定）；若只有零长度 ZipCrypto 条目，仍按原策略拒绝。
- CLI 移除“AES 不支持”的拦截；输出 `Encryption: aes`。
- 测试：AES-128/192/256、stored/deflated、正确/错误/空密码、零长度 AES、篡改认证码、CLI 端到端。
- 文档：本任务、`docs/licensing.md`、`README.md` 状态、`docs/architecture.md` 平台矩阵措辞。

## 非目标

- 7z/RAR、分卷/SFX、断点、GUI。
- 真实第三方工具（7-Zip/WinRAR）差分测试；本切片只做 crate 生成语料与篡改语料。
- 性能基准（AES PBKDF2 吞吐另列）。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- 所有现有 ZipCrypto 测试保持通过；
- 新增 AES 测试通过；
- 手工：AES ZIP 正确密码 exit 0，错误密码 exit 1，未加密 exit 3；
- `cargo-deny` 许可检查通过（新增依赖均为宽松许可）。

## 结果

- `zip` 开启 `aes-crypto`；AES 预检改用 crate 的中央目录 `aes_settings()`（与 `by_index_decrypt` 同源），不再只扫本地 extra 字段，避免“标记 AES、实际按 ZipCrypto 解”的错位。
- 验证链路：PBKDF2-HMAC-SHA1 → 2 字节 verifier → 完整读取条目 → HMAC-SHA1-80 认证码。verifier 通过但 HMAC 失败映射 `Miss`；AES 不使用 CRC（AE-2 CRC=0）。
- 支持 AES-128/192/256、AE-1/AE-2 读取路径、stored/deflated；零长度 AES 条目可凭 HMAC 验证，零长度 ZipCrypto 仍拒绝。
- 测试：core 28（新增 5 个 AES 用例）+ CLI 4 + 集成 5 + FFI 2；含 stored/deflated 篡改认证码用例。
- 验证命令：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --locked`、`cargo +1.89 test --workspace --locked`、`cargo deny check licenses bans sources` 全部通过。
- 未验证：第三方 7-Zip/WinRAR 生成的真实 AES ZIP 差分、>64 MiB 条目、AE-1 外部样本、AES PBKDF2 吞吐基准；不提交未实测的性能数字。
