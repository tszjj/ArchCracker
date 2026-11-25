# ADR-0005：RAR5 密码校验器边界

- 状态：**Proposed（W1-009 实现；release-engineer/法务许可复核前不标 Accepted）**
- 日期：2026-11-26
- 相关：`docs/licensing.md`、ADR-0003、ADR-0004、`docs/tasks/W1-009-rar5-fast-check.md`
- 影响：`core/crates/acx-core/src/archive/rar5_verify.rs`、`archive/rar.rs`、`docs/benchmarks/W1-009.md`

## 背景

W1-008 实测 RAR5 1M × 1.3 GB 需要 4515 s（约 75 min），瓶颈是每个候选启动一次外部 `UnRAR.exe t`。RAR5 文件加密/头加密记录包含 KDF 参数和 12 字节 password check；可以在进程内计算 check 值，把明显错误的候选直接否决，命中再由外部 `UnRAR.exe t` 复核。

## 决策

1. 新增独立 RAR5 密码校验器：
   - 只解析 RAR5 头/文件加密记录中的 `kdf_count`、16-byte salt、12-byte check；
   - 用 PBKDF2-HMAC-SHA256 计算 check；不实现 RAR 压缩/解压；
   - 只用于**否决**：`check` 不匹配直接 `Miss`；匹配仍调用外部 `UnRAR.exe t`，不直接输出命中。
   - **来源说明**：结构来自公开 RAR5 technote；check 的完整派生（`iterations+32`、XOR 折叠、4-byte SHA-256 校验）未在 technote 公开，参考了公开第三方格式实现文档（`nzbdav-rar 0.4.0` MIT、`omnizip-rar 0.21.117` MIT OR Apache-2.0）并用本地 `Rar.exe` 做黑盒差分。未复制或链接 UnRAR 源码，也未复制上述实现代码；这不构成正式 clean-room/法律结论，发布前必须由 release-engineer/法务复核。
2. RAR4 不做进程内校验；继续外部 `UnRAR.exe t`。RAR4 1M 不在 W1 性能承诺内。
3. 目前只对 **ASCII 候选**启用快速否决；非 ASCII 候选回退外部引擎，直到 OEM/UTF-8 编码差分覆盖。编码不一致造成假阴性的风险高于性能收益。
4. 头加密/文件加密记录解析失败、缺少 check、check 自身 SHA-256 校验失败、KDF count 超过 24、非 RAR5：一律回退外部引擎，不把解析失败当密码错误。
5. `UnRAR.exe` 仍只通过 `engines::external` 进程调用；继续随包未修改二进制（ADR-0004）。不链接、不调用 `unrar.dll`、不复制 unRAR 源码。
6. 不新增 `unrar`/`unrar-rs`/RAR 解压库依赖；只新增 `sha2`（MIT/Apache-2.0）直接依赖，用于 check 自身校验和 PBKDF2-HMAC-SHA256。

## 许可边界

- 这是**独立 Rust 实现**，不是 UnRAR 源码，也不声称正式 clean-room 法律结论；结构依据公开 RAR5 technote，check 细节来自公开第三方格式资料与本地黑盒差分。官方 technote 明确把 check 细节指向 UnRAR 源码，因此**不能声称仅凭官方公开规范完成**。
- 校验器不压缩、不解压、不实现 RAR coder，只做 KDF + check 比较；不用于创建 RAR 归档。
- UnRAR License 第 2 条针对 UnRAR 源码/压缩算法重建的限制不直接适用于该独立实现；但这只是工程合规判断，不是法律意见，发布前仍需 release-engineer/法务复核。
- 外部 `UnRAR.exe t` 只做密码/完整性测试，不是 `x/e` 解压交付；`t` 内部可能临时解密/校验块，但不写用户文件。
- RAR/WinRAR 是权利人商标；UI 只说明兼容性，不暗示 RARLAB 背书。

## 备选

| 方案 | 结论 | 原因 |
|---|---|---|
| 继续每候选项外部 `t` | 保留为 oracle | 正确性最强，但 1M 约 75 min |
| 进程内 RAR5 check + 外部确认 | **采用** | 10× 量级提升，保留 `t` 作为命中 oracle |
| 进程内 RAR5 完整解密/解压 | 拒绝 | 越过“不解压 RAR”边界，许可/实现风险大 |
| RAR4 进程内校验 | 暂缓 | 缺等价 check；RAR4 `-hp` 需解密首头，另行评审 |
| 自研完整 RAR 解码器 | 拒绝 | 与项目边界和许可策略冲突 |

## 后果

**正面**

- 1M RAR5 错误候选从 4515 s 降到 424.8 s（W1-009 实测，14 线程）；
- 命中仍由外部 UnRAR `t` 复核，保留零误报目标；
- 不引入 RAR 解压器/压缩器，不链接 unRAR。

**负面/风险**

- 非 ASCII 候选仍走外部，中文/Unicode 字典性能提升有限；
- 头加密（`-hp`）已用本机 `Rar.exe` fixture 验证；更广泛的第三方 `-hp` 样本仍待补；
- check 值 64-bit 仍可能极小概率误接受，但外部确认会拒绝；
- KDF count 上限/恶意归档需要有界；factory 缓存的是创建时的 header/check 快照，运行期间不得修改归档，否则快速否决可能基于旧 check；
- 许可判断需 release-engineer/法务复核。

## 验证

- KDF 已知向量（salt/check/正确密码）；
- 本机 Rar.exe 生成的 RAR5 `-p` fixture：正确/错误候选；
- 1M × 1.3 GB RAR5：424.838 s，2353/s，RSS 3.1 MB；
- RAR5 非 ASCII 候选回退外部测试；
- RAR4 回归测试保持外部路径；
- `cargo fmt`、`clippy -D warnings`、MSRV 1.89、release、cargo-deny。

## 参考

- [RAR 5.0 archive format（RARLAB）](https://www.rarlab.com/technote.htm)
- [UnRAR License（SPDX）](https://spdx.org/licenses/UnRAR.html)
- [WinRAR EULA](https://www.rarlab.com/license.htm)
- ADR-0003、ADR-0004、`docs/licensing.md`
