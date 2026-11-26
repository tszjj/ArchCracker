# W1-009：RAR5 快速密码校验

- **状态**：**完成（reviewer APPROVE + 2026-11-26 法务复核附条件通过；更广泛第三方 `-hp` 语料为后续质量项）**
- **分支**：`feat/w1-009-rar5-fast-check`
- **依赖**：W1-003/003b/003c、W1-008
- **角色**：core-engineer + reviewer + release-engineer（许可复核）
- **范围**：RAR5 进程内 check 快筛、外部 `UnRAR.exe t` 命中确认、许可文档；不含 RAR4 快筛、RAR 解压/压缩、GPU

## 1. 背景与目标

W1-008 实测 RAR5 1M × 1.3 GB = 4515 s（75 min），瓶颈是每候选启动一次 `UnRAR.exe t`。RAR5 加密头/文件加密记录含 KDF 参数和 12-byte check；进程内计算 check 可以安全否决明显错误候选，把外部进程只留给可能的命中。

目标：

- 错误候选快速 `Miss`，不启动 `UnRAR.exe`；
- 可能的命中仍由外部 `UnRAR.exe t` 复核，不能由快筛直接输出 `FOUND`；
- 不实现 RAR 解压/压缩，不复制/链接 UnRAR 源码；
- RAR4、非 ASCII、无 check、解析失败全部回退外部，保证正确性优先；
- 1M RAR5 实测吞吐提升一个数量级以上。

## 2. 设计

- 新模块 `archive/rar5_verify.rs`：
  - 解析 RAR5 头加密（type 4）或文件加密 extra record（type 1）；
  - 保存 `kdf_count`、16-byte salt、12-byte check；
  - check 前 8 字节 + 后 4 字节 SHA-256 校验；
  - `PBKDF2-HMAC-SHA256(password, salt, 1<<kdf_count + 32)`，XOR 折叠为 8 字节；
  - 只对 ASCII 候选启用；
  - 任何不确定情况返回 `None`，回退外部。
- `RarSession::test_password`：
  - `Some(false)` → `Miss`；
  - `Some(true)`/`None` → 外部 `UnRAR.exe t`；
  - 外部退出码/命中语义不变。
- `RarFactory` 创建时解析一次 check，worker 复用；不新增每候选文件 I/O。
- 依赖：`sha2` 直接依赖（已有传递依赖），不新增 RAR 库。

## 3. 验收

- [x] KDF 已知向量（salt/check/正确密码）通过；
- [x] 本机 `Rar.exe` 生成的 RAR5 `-p` fixture：正确/错误密码；
- [x] RAR5 `-hp` 头加密 fixture：正确/错误密码 + CLI FOUND；
- [x] 完整 CLI RAR5/RAR4/Unicode/分卷/SFX 测试通过；
- [x] 1M RAR5 实测：578.958 s / 1727.2/s（对比 4515.104 s / 221.5/s，7.80×；4096 in-flight 窗口）；
- [x] 命中仍由外部 `UnRAR.exe t` 复核；
- [x] 非 ASCII、无 check、check 校验失败、KDF count 超限回退；
- [x] 许可文档/ADR-0005 更新；
- [x] fmt/clippy/MSRV/release/cargo-deny。

## 4. 风险与边界

- 非 ASCII 候选仍走外部；中文/Unicode 字典的 RAR5 性能提升有限。
- RAR5 check 是 64-bit 判据；匹配仍外部确认，零误报目标不变。
- RAR4 无等价 check；RAR4 1M 仍不在 W1 性能承诺内。
- 快筛只做 KDF/check，不做解密/解压；任何扩展到数据解密都需重新 ADR/许可评审。
- check 解析必须对损坏/恶意 KDF count 有界；当前上限 24，失败回退。
- 头加密 `-hp` 已用本机 Rar.exe fixture 验证；仍需更多第三方样本。
- 许可分析是工程判断，不是正式法律意见；ADR-0005 已按项目负责人确认于 2026-11-26 完成法务复核（附条件），发布前 release-engineer 按条件检查。

## 5. 交接

```text
STATUS: done（W1-009 slice；reviewer APPROVE + 法务复核附条件通过）
CHANGED: core/crates/acx-core/src/archive/rar5_verify.rs,
         core/crates/acx-core/src/archive/rar.rs,
         core/crates/acx-core/src/archive/mod.rs,
         core/crates/acx-core/Cargo.toml, core/Cargo.lock,
         core/crates/acx-cli/tests/w1_rar_external.rs,
         docs/adr/0005-rar5-password-verifier.md, docs/licensing.md,
         docs/adr/0003-rar-licensing.md, docs/architecture.md,
         docs/benchmarks/W1-009.md
VERIFIED: 98 core + 39 CLI（1 ignored）+ 2 FFI;
          1M RAR5 578.958s / 1727.2/s; KDF vector; RAR5 -p/-hp fixture; CLI regression
NOT VERIFIED: non-ASCII fast path (intentionally deferred); broader third-party -hp corpus
NEXT: 保持 ASCII-only/外部复核边界；补更广泛第三方 `-hp` 语料；W1 准出评估
RISKS: licensing boundary; non-ASCII fallback; header-encryption corpus
```
