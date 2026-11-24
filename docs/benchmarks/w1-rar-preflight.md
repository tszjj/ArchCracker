# W1 RAR 预检缓存（非正式基准）

- 日期：2026-11-24
- 环境：Windows 11 专业版 10.0.26300；Intel i5-14600K（14 核 / 20 线程）
- 构建：debug（`cargo build -p acx-cli`，Rust GNU / MinGW）
- 对比：
  - 基线 `ff7d3e0`（W1-003）：`RarFactory::new()` + 每 worker `open()` 重新预检；
  - W1-003b：factory 缓存 `ArchiveInfo`，CLI 复用 `archive::preflight`。
- 归档：RAR5，单文件 `hello.txt`，172 B；密码 `P@ssw0rd123`
- 字典：1 条错误密码（只测启动/预检开销，不测候选吞吐）
- 命令：

```powershell
acx -f encrypted.rar -m dict -d wrong.txt -t <4|16|32>
```

## 结果

每次配置预热 2 次，随后 5 次取中位数；退出码均为 1（NOT FOUND）。

| 线程 | 基线中位数 | W1-003b 中位数 | 变化 |
|---:|---:|---:|---:|
| 4 | 206 ms | 136 ms | -34% |
| 16 | 243 ms | 135 ms | -44% |
| 32 | 376 ms | 135 ms | -64% |

W1-003b 的耗时基本不随线程数变化；基线随线程数增加，因为每个 worker 多出
`unrar t -p-`（加密归档再加 `unrar l -p-`）两次进程启动。

## 解释与限制

- 这里测的是**进程启动/预检开销**，不是候选密码吞吐；候选验证仍是每候选一次
  整包 `unrar t`，W2 才做 clean-room 头/KDF + hashcat。
- 归档很小且字典只有 1 条，因此基线耗时几乎全是重复预检；真实大归档中预检本身
  占比会上升，但重复次数仍为 `2N`。
- debug 构建、单机、单次会话；未测 release、冷文件缓存、杀毒软件干扰。
- 未记录电源模式/CPU governor；计时只用于同机相对比较，不作为正式 p/s 基准。
- 预期进程数（加密 RAR）：基线 `2 + 2N`，W1-003b 固定 `2`（`t -p-` + `l -p-`）。
