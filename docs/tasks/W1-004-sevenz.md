# W1-004：7z AES / 头加密 / 首块探测

- 状态：完成（本地分支 `feat/w1-004-7z`，按里程碑统一推送）
- 角色：core-engineer、reviewer
- 依赖：`sevenz-rust2` 0.20.2（Apache-2.0；0.25 要求 Rust 1.93，超出本项目 MSRV 1.89）
- 范围：7z 读取、AES-256 解密、头加密、首块快筛、CLI 分发；不含分卷/SFX、掩码/暴力、界面

## 设计目标

解决「第三种主流格式缺失」的问题。面向持有 7z 加密包的用户，用内置库补齐普通 7z、AES-256 内容加密、头加密（`-mhe=on`）三类场景，让同一条 CLI 命令可用。命中必须经过完整解压与 CRC 校验，快筛只用于否决，保证正确性优先。

## 实现要点

- **预检与头加密**：用空密码尝试打开；成功则读文件表判断 AES；报「需要密码」则记为头加密，条目表暂不可见，调度器不把它当未加密。
- **目标选择**：选加密块的第一个文件（有数据流、非目录、非空、有 CRC）；多块取最小。选块首文件避免 solid 归档为到达目标解压前置文件；要求 CRC 保证可验证。
- **两级验证**：先解所选块前 64 KiB（错误密钥下 LZMA 通常立即报错即否决），再重新打开完整读取并校验 CRC32 与长度。COPY（不压缩）条目无压缩流结构，跳过快筛直接完整校验，避免同一候选做两次密钥派生。完整校验原限 64 MiB，W1-006 已改为固定缓冲区流式读取。
- **密码编码**：7z 用 UTF-16LE；UTF-8 候选转为字符串再转 UTF-16LE；非 UTF-8 候选算未命中。
- **错误映射**：校验失败、校验和不匹配、无效数据等算未命中；不支持的压缩方法、内存限制、签名错误等算归档/环境错误，不吞掉。
- **工厂缓存**：缓存元数据与解析结果；头加密因格式限制按候选重新解头。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked
cargo deny check licenses bans sources
```

覆盖明文、AES 文件/头加密、stored、五种压缩方法、solid、空归档、损坏头、工厂会话、连续错误候选不中止。CLI 覆盖命中/错误字典/未加密。可选：`$env:ACX_7Z` 指向官方 7-Zip 后运行 `cargo test -p acx-cli --test w1_sevenz -- --ignored`。

## 结果

core 59（新增 13）+ CLI 19（含 1 个忽略的官方差分）+ FFI 2 通过；本机 fmt/clippy/测试/MSRV/release/cargo-deny 全绿。官方 7-Zip 26.04 差分已实际运行通过（文件/头/stored/solid/Unicode/明文），反向验证本地样本可被官方工具测试。

## 许可与引用

`sevenz-rust2` 及其 bzip2/ppmd 传递依赖已加入许可白名单。官方 7-Zip `7zr.exe` 只作本地/CI 对照工具，不提交、不随包。

## 评审与对照意见

评审通过。已知边界：7z AES 无独立认证器，损坏载荷与错误密码不可完全区分，完整 CRC 失败按未命中；条目无 CRC 报不支持；Brotli/LZ4/ZSTD/Deflate 未启用；畸形流可能按归档错误中止；头加密归档损坏时可能进入字典流程最终显示未找到。
