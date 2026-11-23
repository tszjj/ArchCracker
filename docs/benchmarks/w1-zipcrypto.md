# W1 ZIP/ZipCrypto 基线（非正式基准）

- 日期：2026-11-24
- 环境：Windows 11 专业版 10.0.26300；Intel i5-14600K（14 核 / 20 线程）
- 构建：`cargo build --release -p acx-cli`（Rust 1.100 GNU / MinGW 16.2）
- 归档：deflated ZipCrypto ZIP，单条目 `hello.txt`（未压缩 960 B，文件 163 B）
- 字典：1,000,000 条唯一错误 ASCII 密码，13,888,890 B
- 命令：

```powershell
acx -f deflated_encrypted.zip -d bench-1m-unique.txt -t 4
```

## 结果

| 构建 | 线程 | 耗时（含启动/字典加载） | 近似吞吐 |
|---|---:|---:|---:|
| release | 4 | 1.575 s | ~635k 候选/秒 |
| debug | 4 | 4.474 s | ~224k 候选/秒 |

结果均为 `NOT FOUND`（exit 1），无错误退出。

## 重要限制

- 这是**极小条目**：绝大多数错误密码在 ZipCrypto 1 字节头检查就被否决，没有进入解压/CRC。
- 不能把该数字外推到 7z/RAR5 KDF、大文件、solid 归档或 CPU 受限场景。
- 冷启动、字典加载、4 线程调度都计入耗时；未做多轮取中位数。
- 正式基准需要 1 GB 级归档、store/deflate 混合、1/2/4/8 线程、CPU 利用率与内存峰值；待 W1 后半段补。

## 复现

测试归档由 `core/crates/acx-core/src/archive/zip.rs` 的测试 helper 生成（`ZipWriter` + `with_deprecated_encryption`），或由 reviewer 的临时脚本生成；不提交二进制语料。
