# RAR4 `-hp` 首头校验可行性评估（W2-007 F4）

- 日期：2026-11-27
- 结论：**no-go**。普通 RAR4 与 RAR4 `-hp` 均继续走外部未修改 `UnRAR.exe t`，不新增快筛。
- 决策依据：`docs/tasks/W2-007-cpu-fast-filters.md` §6「RAR4 范围 / RAR 许可边界」、`docs/adr/0003-rar-licensing.md`、`docs/adr/0004-bundled-engines.md`、`docs/adr/0005-rar5-password-verifier.md`。

## 评估范围

只评估「能否在不越过许可边界的前提下，在进程内用候选密码校验 RAR4 `-hp` 头加密归档的首头，从而在调用 UnRAR 前否决错误候选」。不评估 RAR4 数据解压、压缩或自研解码器。

## 现状证据（代码）

- `core/crates/acx-core/src/archive/rar.rs`：
  - `test_password()`（`:117-182`）对所有 RAR4/RAR5 候选统一调用外部 `external::run_cancellable` 执行 `UnRAR t`；
  - RAR5 的 `Rar5Verifier` 只在 RAR5 分支生效（`:129-142`），RAR4 没有等价判据；
  - `rar4_header_encrypted()` / `rar4_header_is_encrypted()`（`:511-531`）仅读取主头 12 字节的 `0x0080` 标志，识别「头已加密」，不解密任何内容；
  - `classify_test_exit()`（`:433-445`）把 RAR4 退出码 3 按 Miss 处理。
- 依赖清单（`core/crates/acx-core/Cargo.toml`）没有 AES/HMAC 相关 crate；`sha2` 只用于 SHA-256 指纹与 RAR5 校验。

## 为什么 no-go

1. **必须实现 RAR4 头解密**：RAR4 `-hp` 的头部使用 RAR4 自有 KDF + AES-CBC。要验证首头必须先按 RAR4 规范派生密钥并解密头块，这属于「自研 RAR 解码」，直接越过 W2-007 §6 的「不解压 RAR、不做自研 RAR 解码」边界。
2. **需要新依赖**：AES-CBC 需要引入新的加密 crate（如 `aes`/`cbc`），W2-007 明确「无新增依赖预期」，新增依赖须登记 `docs/licensing.md` 并经 architect/release 单独评审，超出本切片范围。
3. **缺少可靠的认证器**：即使解密出首头，RAR4 头没有可直接当作密码 verifier 的认证字段；要判断「密码正确」仍需解析头结构与 CRC，风险接近重新实现 RAR 解析，误杀风险不可接受。
4. **收益无法在本切片证明**：`external_attempts` 已能计数每次 UnRAR 调用；本切片不要求 RAR4 性能收益，且 RAR5 check 快筛已覆盖高价值路径。

## 影响与后续

- 行为不变：RAR4（含 `-hp`）每候选仍调用外部 `UnRAR t`；`--strict` / `--rar-no-fast-reject` 对其无额外影响。
- 统计：`fast_rejected` 中 RAR4 恒为 0，`rar5_check_value` 只统计 RAR5；`external_attempts` 正确反映实际调用次数。
- 若未来重新评估：需在 ADR 中明确 RAR4 头校验的法律边界，登记新依赖，并给出「只否决、不解压」的可证明实现与差分证据；在此之前不得实施。

## 验收对照

对应 W2-007 §8 第 4 条：产出本 go/no-go 文档即满足；no-go 分支下「普通 RAR4 与 `-hp` 均继续外部进程」由现有 E2E（`w1_rar_external.rs`）与计数断言覆盖。
