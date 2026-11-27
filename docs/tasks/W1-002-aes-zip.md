# W1-002：WinZip AES ZIP 恢复

- 分支：`feat/w1-aes-zip`
- 角色：planner、core-engineer、reviewer
- 状态：完成（PR #2，独立评审通过，CI 6/6）

## 设计目标

解决「ZIP 加密不止一种」的问题。面向用户手里的 AES 加密 ZIP 场景，在 W1-001 的传统加密基础上补齐 WinZip AES（128/192/256 位、AE-1/AE-2），让同一条 CLI 命令直接恢复 AES ZIP，无需用户先判断加密类型。

## 实现要点

- `zip` crate 开启 `aes-crypto`。
- 预检用中央目录的 `aes_settings()` 判定 AES，与解密路径同源，避免「标记 AES、按传统加密解」的错位。
- 验证链路：PBKDF2-HMAC-SHA1 派生密钥 → 2 字节校验字 → 完整读取条目 → HMAC-SHA1-80 认证。校验字过但 HMAC 失败算未命中。AES 不看 CRC（AE-2 的 CRC 为 0）。
- 非空加密条目优先；只有零长度 AES 条目时可用 HMAC 验证；只有零长度传统加密条目仍拒绝。
- CLI 移除「AES 不支持」拦截，输出 `Encryption: aes`。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

覆盖 AES-128/192/256、stored/deflated、正确/错误/空密码、零长度 AES、篡改认证码、CLI 端到端。原有传统加密测试保持通过。

## 结果

core 29（新增 6 个 AES 用例）+ CLI 4 + 集成 6 + FFI 2 通过。fmt、clippy、工作区测试、MSRV 1.89、cargo-deny 全绿。手工：AES ZIP 正确密码 exit 0、错误 exit 1、未加密 exit 3。

## 许可与引用

新增依赖均为宽松许可，`cargo-deny` 通过，已登记许可文档。测试语料由 `zip` crate 生成，不引入第三方二进制。

## 评审与对照意见

独立评审通过。未做第三方 7-Zip/WinRAR 生成的真实 AES ZIP 差分、1GB 条目、AE-1 外部样本、PBKDF2 吞吐基准；未实测的性能数字不记录。
