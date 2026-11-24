# W2-001：hashcat GPU 字典后端 spike

- 分支：`feat/w2-hashcat-spike`
- 角色：planner、core-engineer、qa、reviewer
- 状态：待开始（W2）

## 目标

在不把 hashcat 变成 Rust/Cargo 依赖的前提下，为 ZIP AES 与 RAR5 添加可选 GPU 字典后端；无 hashcat/GPU 时 CPU 多线程路径保持完整。

```powershell
acx -f aes.zip -m dict -d dict.txt --gpu auto
```

## 范围

- Rust 侧提取 hashspec：
  - ZIP AES：`13600` 所需盐、verifier、auth、首块密文、CRC；
  - RAR5：`13000` 所需盐/KDF/check/头加密记录（clean-room，不复制 unRAR 源码）。
- `engines::external` 增加 hashcat 进程封装：检测、`--status-json`、`--potfile-path`、`--session/--restore`、取消/超时、临时文件清理。
- CLI：`--gpu auto|cpu|hashcat`；默认 auto。
- 命中后必须由 `ArchiveSession`（ZIP/外部 UnRAR）完整复核；GPU 结果不能直接发布。
- CPU 回退：hashcat 缺失、无 GPU、驱动不满足、模式不支持时自动走现有 scheduler。

## 约束

- **hashcat 不是 Cargo 依赖**；不得加入 CUDA/HIP/OpenCL 绑定，不复制 hashcat 内核。
- Full 版随包 hashcat 二进制由 manifest 固定版本；不随包 GPU 运行时/驱动。
- 临时 hash/potfile 放受限目录、用后删除；日志不落密码。
- 不引入 WinRAR/GPL 提取器。

## 验收

- 同机同语料 1 亿候选，ZIP AES/RAR5 相对 CPU ≥5×（或给出不达标结论）。
- 命中密码 100% 经 ZIP/UnRAR 复核。
- 取消 ≤2 秒，无残留 hashcat 进程/临时文件。
- 删除 `third_party/hashcat`（或设置不可用）后，全部 CPU 测试通过。
- `cargo tree`/`Cargo.lock` 无 hashcat/GPU 依赖。
- 许可清单、`THIRD_PARTY_NOTICES`、manifest 更新。

## 非目标

- ZipCrypto/7z/多卷（后续）；
- GUI 开关；
- 自研 GPU 内核；
- 随包 CUDA/HIP/驱动。

## 结果

（实现后补充）
