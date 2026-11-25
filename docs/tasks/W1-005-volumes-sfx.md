# W1-005：分卷 / SFX 与预检完整化

- **状态**：完成（本地分支 `feat/w1-005-volumes-sfx`；按用户要求**未推送 GitHub**，待里程碑统一推送）
- **角色**：core-engineer + reviewer
- **范围**：ZIP/7z 字节分卷、RAR 外部引擎分卷、7z/ZIP/RAR SFX 数据区定位、缺卷/截断/损坏分类；不含 PKZIP spanned `.z01`（明确报不支持）
- **依赖**：无新增 Cargo 依赖

## 1. 目标

让用户只传第一分卷或 SFX `.exe` 就能预检，并在跑字典之前明确区分：

- 完整分卷 → 正常恢复；
- 缺卷 → `missing archive volume: ...`，不跑字典；
- 截断/损坏 → `archive is truncated/damaged: ...`；
- ZIP 旧式 spanned `.z01` → 明确 `Unsupported`，不误报损坏。

## 2. 实现

### 2.1 `ArchiveSource`

新增 [source.rs](../../core/crates/acx-core/src/archive/source.rs)：

- 检测 magic；若首字节为 `MZ`，扫描 PE/SFX stub 后的归档签名（上限 32 MiB），得到格式与 payload 偏移；
- 解析分卷命名：
  - ZIP/7z `name.zip.001`、`name.7z.001`、`.0001`；
  - RAR `name.part1.rar`、`name.part01.rar`、`name.part001.rar`；
  - 旧式 RAR `name.rar` + `name.r00`、`.r01`；
  - 传入 `.002` / `.part2.rar` / `.r01` 时回退到第一分卷；
- 缺中间卷立即返回 `MissingVolume`，不进入引擎；
- 最后卷缺失时：
  - ZIP/7z 数值分卷用“最后两卷等大”启发式；
  - RAR 单分卷 `.part1.rar` 读主头 archive flags（RAR4 `MHD_VOLUME`、RAR5 archive flags bit 0）；
  - RAR 多分卷由 UnRAR 的 `Cannot find volume` 诊断转成 `MissingVolume`，不依赖等大启发式。
- `.z01/.z02`（PKZIP spanned）在 ZIP 下明确返回 `Unsupported`。

`VolumeReader` 把多个 part 拼成一个 `Read + Seek` 流：

- 逻辑偏移 0 = 第一分卷 `start_offset`；
- 读跨卷时自动切换文件句柄；
- 每个 worker 打开独立句柄，避免 seek 竞争；
- 支持 SFX 偏移，ZIP/7z 引擎无需感知卷或 stub。

### 2.2 引擎接入

- **ZIP**：`ZipArchive<VolumeReader>`；SFX ZIP 从 payload 偏移开始，保留原 ZIP 偏移语义。缺失 EOCD/中央目录分类为截断，再按 `ArchiveSource` 判断是否缺卷。
- **7z**：`SevenZSession` 持有 `ArchiveSource`；预检、首块探测、完整 CRC 都通过 `VolumeReader` 读取。头加密仍按候选重新解头。
- **RAR**：`ArchiveSource` 只做卷集合校验，外部 UnRAR 始终接收第一分卷或 SFX `.exe`；缺最后卷时用 RAR volume flag 在预检前拦截。

### 2.3 错误分类

`AcxError` 新增：

```text
MissingVolume(String)
Truncated(String)
Corrupt(String)
```

CLI 仍统一 exit 3，但消息明确：

```text
acx: missing archive volume: ...\movie.7z.002
acx: archive is truncated: ...
acx: archive is damaged: ...
acx: unsupported archive: PKZIP spanned ...
```

7z 预检把 `BadSignature` / 头 CRC / 结构性 `Other` 归为损坏，`UnsupportedCompressionMethod` 仍为不支持；ZIP 预检把 `EOCD`/中央目录缺失归为截断。

## 3. 测试与验证

### 3.1 自动测试

- `acx-core`：**77** 个单测（新增 18 个：16 个 source + 2 个 RAR volume flag）：
  - 多分卷拼接读取；
  - `.001` 缺中间卷；
  - `.0001` 四位分卷；
  - 传入 `.002` 回退第一分卷；
  - RAR `.partN` 缺卷；
  - RAR 旧式 `.rar + .r00` 顺序；
  - 最后卷缺失提示；
  - 7z SFX / RAR SFX 偏移；
  - 无 payload 的 PE；
  - `.z01` 明确不支持；
  - RAR4/RAR5 volume flag 解析；
  - `VolumeReader` 跨卷 seek/read；
  - 完整归档使用 `.2024` / `.r01` 等“像分卷”的扩展名不被误判。
- `acx-cli`：**34** 个集成测试（33 默认 + 1 个 `#[ignore]` 官方 7-Zip 差分）：
  - ZIP ZipCrypto/AES 分卷命中；
  - ZIP 缺卷 exit 3；
  - 7z 分卷命中；
  - 7z 缺卷 exit 3；
  - 7z SFX 命中；
  - ZIP SFX 命中；
  - `.z01` 明确不支持；
  - RAR `.partN` 分卷命中与缺卷 exit 3；
  - 单卷但命名为 `.zip.001` / `.7z.001` 不误判缺卷；
  - 直接传 `.zip.002` / `.7z.002` 回退第一分卷；
  - 完整归档 `.2024` 扩展名不误判缺卷；
  - 单卷 RAR 命名为 `.part1.rar` 不误判缺卷（RAR5 main header archive flags）。
- `acx-ffi`：2 个测试不变。

### 3.2 命令

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked
cargo build --workspace --release --locked
cargo deny check licenses bans sources
```

本机结果全部通过；host 为 `x86_64-pc-windows-gnu`，MSVC 待 CI。

### 3.3 手工 / 外部验证

- 用 7-Zip 26.04 `7zr` 生成的 7z 分两卷：CLI `FOUND`；删除 `.002` 报 `missing archive volume`。
- 7z 文件 + `MZ` stub：CLI `FOUND`。
- WinRAR 6.24 `Rar.exe a -m0 -v1k` 生成 7 卷：CLI 从 `part1` `FOUND`；删除中间卷报缺卷；删除最后 `part7` 也报 `missing archive volume`（UnRAR `Cannot find volume` 诊断）。
- ZIP AES 分卷、ZIP SFX 由测试内 `zip` writer 生成并验证。

## 4. 限制与未验证

- **PKZIP spanned `.z01/.z02`** 未实现，明确报不支持；当前只支持 7-Zip 风格字节分卷 `.zip.001`。
- ZIP SFX 用“在完整 ZIP 前加 `MZ` stub”的样本验证；某些会重写 central-directory 偏移的第三方 SFX 打包器未验证。
- SFX 扫描上限 32 MiB；payload 在 stub 更后面的 PE 不支持。
- 最后卷缺失检测依赖：
  - ZIP/7z 数值分卷的“最后两卷等大”启发式；
  - RAR 单分卷 archive flags；多分卷的 UnRAR `Cannot find volume` 诊断。
  单卷 `.001` 被截断时可能被报告为缺 `.002`，这是命名启发式的歧义。
- RAR4 SFX + 头加密（`-hp`）未单独验证；RAR 外部引擎由用户安装，CI 无引擎时跳过。
- 未做 1M/1GB 分卷性能基准；未做 fuzz。
- 分卷/SFX 的 `ArchiveInfo` 暂不暴露卷数/偏移给 CLI/前端；只保证打开与错误分类。

## 5. 交接

```text
STATUS: done
CHANGED: core/crates/acx-core/src/archive/{source,mod,zip,sevenz,rar}.rs,
         core/crates/acx-core/src/error.rs,
         core/crates/acx-cli/tests/w1_volumes_sfx.rs,
         core/crates/acx-cli/tests/w1_rar_external.rs, docs/...
VERIFIED: cargo fmt/clippy/test (77 core + 34 CLI incl. 1 ignored + 2 FFI),
          cargo +1.89 test, release build, cargo-deny,
          split ZIP/7z/RAR, ZIP/7z SFX, missing-volume classification
NOT VERIFIED: PKZIP spanned .z01, unusual SFX offsets, >32 MiB stub,
              RAR4 SFX -hp, volume/SFX performance, non-Windows runtime
NEXT: W1-006 断点续跑
RISKS: ZIP/7z final-volume detection is heuristic; RAR diagnostics are
       localized/engine-dependent. PKZIP spanned and unusual SFX layouts
       are explicitly unsupported.
```
