# ADR-0001：内核采用 Rust

- 状态：Accepted
- 日期：2026-11-24
- 决策者：ArchCracker 架构组（AI Agent + 人类维护者）
- 相关：`docs/architecture.md`、`docs/adr/0003-rar-licensing.md`

## 背景

需要在 Windows、Linux、macOS、Android、HarmonyOS 上运行同一套压缩包密码恢复内核，覆盖 7z（AES-256/头加密）、ZIP（ZipCrypto/WinZip AES）、RAR4/RAR5（头加密/多卷）、分卷与 SFX，并要求高吞吐、可维护、AI Agent 可协作。

候选：Rust、C++（7-Zip/p7zip/unrar 源码）、Go。

## 决策

**内核采用 Rust**：Cargo workspace，纯逻辑核心 + CLI + C ABI（`cdylib`/`staticlib`）。C++/7-Zip 保留为差分测试 oracle 与性能对照，不作为主内核。

结构：

```text
core/
  crates/acx-core/   # 领域/候选/调度/引擎/探针
  crates/acx-cli/
  crates/acx-ffi/    # C ABI + include/acx.h
  crates/acx-jni/
  crates/acx-napi/
```

## 理由

1. **格式覆盖**
   - `sevenz-rust2`：AES-256、加密头（0.6+）、COPY/LZMA/LZMA2/PPMd/BZip2/Deflate/Brotli/LZ4/ZSTD、BCJ2 等，Apache-2.0。
   - `zip`：ZipCrypto、WinZip AES（AE-1/AE-2），MIT；多卷由我们自建容器层。
   - `unrar-rs`：纯 Rust 的 UnRAR 移植，覆盖 RAR4/5、`-p`/`-hp`、多卷、SFX；但受 unRAR 许可约束（ADR-0003）。
2. **跨平台**
   - Android 为 Tier 2（NDK）。
   - `aarch64-unknown-linux-ohos` 为 Tier 2 with host tools；可用 OHOS clang 包一层 linker。
   - 桌面三平台一等；C ABI 可被 Avalonia/Compose/ArkUI 复用。
3. **可维护性**
   - 内存安全、无 GC、错误处理显式；AI Agent 生成/评审比 C++ 更可控。
   - 单 workspace 统一 fmt/clippy/test，CI 简单。
4. **性能**
   - 与 C++ 同量级；SIMD/AES-NI 可通过 `std::arch`/`aes` crate 使用；线程用 `rayon` 或显式 worker。
5. **许可**
   - 自有代码 Apache-2.0；Apache-2.0/MIT 依赖兼容。
   - RAR 部分单独处理，不污染内核。

## 备选与不选原因

| 方案 | 不选原因 |
|---|---|
| C++ + 7-Zip 源码 | 7-Zip 是应用型代码库，非稳定库 API；Android/OHOS 需自行移植；解析型 CVE 多，AI 维护风险高；RAR 许可同样受限 |
| Go | 7z 生态意外地完整（bodgit/sevenzip），但 HarmonyOS 无官方 target、gomobile 仅实验；ZIP AES 需自写；性能与 SIMD 弱 |
| C#/.NET | HarmonyOS 无可靠运行时；NativeAOT 不覆盖 OHOS |
| Kotlin/JVM | 桌面/Android 可，HarmonyOS 不可 |

## 后果

**正面**

- 一套核心覆盖五平台；C ABI 稳定后前端可独立演进。
- 纯 Rust 减少 unRAR/7-Zip 代码的许可暴露（RAR 仍需外部/可选）。
- 测试/CI/依赖审计可自动化。

**负面/风险**

- `sevenz-rust2`/`zip` 的边界行为需以 7-Zip 为 oracle 做差分测试。
- RAR 仍受许可限制：默认外部 `unrar`，移动端可能首发不支持。
- HarmonyOS Rust 工具链为 Tier 2，需自建 linker/打包验证；保留“C ABI + 最小胶水”的降级路径。
- Rust 生态的 RAR 实现较年轻，需大量差分/模糊测试。

## 验证方式

- P0：空壳 workspace 在三桌面 CI 通过。
- P1：ZIP/7z 语料与 7-Zip 输出对比；性能基线。
- P2：RAR 与 `unrar` 差分；许可评审。
- P5/P6：Android/HarmonyOS 真机跑通最小 C ABI 调用。

## 参考

- sevenz-rust2: https://docs.rs/sevenz-rust2/latest/sevenz_rust2/
- zip crate: https://docs.rs/zip/9.1.3/zip/index.html
- unrar-rs: https://docs.rs/unrar-rs/0.11.0/unrar_rs/
- Rust OpenHarmony target: https://doc.rust-lang.org/nightly/rustc/platform-support/openharmony.html
- Rust Android target: https://doc.rust-lang.org/nightly/rustc/platform-support/android.html
- 7-Zip license: https://www.7-zip.org/license.txt
