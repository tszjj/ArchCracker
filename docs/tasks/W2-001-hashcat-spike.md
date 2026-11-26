# W2-001：hashcat GPU 字典后端 spike（Deferred）

- 分支：`feat/w2-hashcat-spike`（暂不创建）
- 角色：planner、core-engineer、qa、reviewer
- 状态：**Deferred（W2 不启动）**
- 决定：GPU 加速不是 W1 准出或 W2 准入条件；W2 先完成 CPU 快筛/攻击/批量，W2 退出后重新评审本任务

## 延后决定

本切片保留设计草案，但**不在 W2 启动**。原因：

1. CPU 多线程路径仍是产品基线，必须先完成快筛、掩码/暴力、批量和稳定性；
2. GPU 依赖用户驱动/OpenCL/CUDA 矩阵，无法在 CI 稳定验证；
3. hashcat 随包属于 W4 Full 交付，提前实现会增加许可/AV/安装包风险；
4. W1 还没有 1M/1GB CPU 基准；没有基线就无法判断 GPU 的 ≥5× 是否真实。

因此 W2-001 不阻塞 W2 准入，也不作为 W2 退出条件。

## 解除条件

满足以下条件后，另开评审再决定是否启动：

- W1 准出、W2 CPU 范围完成，且有稳定 p/s 基线；
- 明确目标格式/模式（ZIP AES 13600、RAR5 13000）和可复现语料；
- hashcat 二进制来源/版本/SHA-256/许可清单可固定，且确认 W4 随包策略不变；
- 有可用的 Windows GPU 测试机与驱动矩阵，或明确只做“检测/回退/实验”而不承诺性能；
- 更新本任务的状态、验收与 ADR-0004 影响说明。

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

**Deferred（未实现）**。不创建分支、不新增依赖、不随包 hashcat；CPU 路径保持唯一已交付实现。W2 退出后按“解除条件”重新评审。
