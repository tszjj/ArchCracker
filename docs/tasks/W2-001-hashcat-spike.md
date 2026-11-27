# W2-001：hashcat GPU 字典后端试验（已推迟）

- 分支：`feat/w2-hashcat-spike`（暂不创建）
- 角色：planner、core-engineer、qa、reviewer
- 状态：**已推迟，W2 不启动**
- 决定：GPU 加速不是 W1 准出或 W2 准入条件；W2 先完成 CPU 快筛、攻击与批量，W2 退出后重新评审

## 设计目标

解决「CPU 路径吞吐不够时能否用 GPU 加速」的问题。面向 ZIP AES 与 RAR5 的大字典场景，设想在不引入 GPU 依赖的前提下，把哈希提取交给外部 hashcat，命中仍由归档引擎复核。当前先保留设计草案，不在 W2 实现：CPU 多线程仍是产品基线，GPU 依赖用户驱动且无法在 CI 稳定验证，随包 hashcat 属 W4 交付，且尚无 CPU 基线判断加速是否真实。

## 解除条件

满足以下条件后另开评审决定是否启动：

- W1 准出、W2 CPU 范围完成，且有稳定的吞吐基线；
- 明确目标格式与模式（ZIP AES 13600、RAR5 13000）和可复现语料；
- hashcat 二进制来源、版本、SHA-256、许可清单可固定，且 W4 随包策略不变；
- 有可用的 Windows GPU 测试机与驱动矩阵，或明确只做「检测/回退/实验」而不承诺性能；
- 更新本任务的状态、验收与 ADR-0004 影响说明。

## 设计草案

目标命令：`acx -f aes.zip -m dict -d dict.txt --gpu auto`

- Rust 侧提取 hashspec：ZIP AES 提取盐、校验字、认证码、首块密文与 CRC；RAR5 提取盐、派生参数与校验值（clean-room，不复制 unRAR 源码）。
- `engines::external` 增加 hashcat 进程封装：检测、状态 JSON、独立 potfile、会话恢复、取消/超时、临时文件清理。
- CLI 增加 `--gpu auto|cpu|hashcat`，默认 auto；命中后必须由归档引擎完整复核，GPU 结果不直接发布。
- CPU 回退：hashcat 缺失、无 GPU、驱动不满足、模式不支持时自动走现有调度器。

## 验收（解除启动后适用）

- 同机同语料 1 亿候选，ZIP AES/RAR5 相对 CPU ≥5 倍（或给出不达标结论）；
- 命中密码 100% 经归档引擎复核；
- 取消 ≤2 秒，无残留进程或临时文件；
- 移除 hashcat 后全部 CPU 测试通过；依赖清单无 hashcat/GPU 条目。

## 许可与引用

hashcat 不作为 Rust/Cargo 依赖，不加入 CUDA/HIP/OpenCL 绑定，不复制 hashcat 内核。Full 版随包二进制由 manifest 固定版本，不随包 GPU 运行时与驱动；临时哈希文件放受限目录、用后删除，日志不落密码。不引入 WinRAR/GPL 提取器。相关决策见 ADR-0004。

## 结果

已推迟，未实现。不创建分支、不新增依赖、不随包 hashcat；CPU 路径保持唯一已交付实现。W2 退出后按「解除条件」重新评审。
