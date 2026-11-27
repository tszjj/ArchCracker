# tests & corpus

测试语料与跨语言测试向量。**仓库不提交归档/字典二进制**，只提交生成脚本、清单、哈希与小型文本向量。

## 目录（P1 建立）

```text
tests/
├─ corpus/                 # 生成脚本 + manifest（不提交大文件）
├─ vectors/                # 小型测试向量：密码、期望结果、错误分类
├─ differential/           # 与 7-Zip/unrar oracle 的对照脚本
└─ fuzz/                   # 归档头/分卷/SFX 模糊测试
```

## 语料矩阵

| 维度 | 取值 |
|---|---|
| 格式 | 7z、ZIP、RAR4、RAR5、SFX |
| 加密 | ZipCrypto、WinZip AES-128/256、7z AES、RAR4/5、头加密（7z `-mhe=on`、RAR `-hp`） |
| 分卷 | 无、2 卷、10 卷；`.001`、`.0001`、`.part1.rar`、`.r00` |
| 条目 | store、deflate、LZMA/LZMA2、BZip2、PPMd |
| 大小 | 1 KB、10 MB、1 GB（稀疏/生成） |
| 密码 | ASCII、中文、emoji、64 位、含空格 |
| 字典编码 | UTF-8（有/无 BOM）、UTF-16LE、GBK |
| 负例 | 缺卷、截断、CRC 损坏、未加密、空包、不支持、错误密码 |

## 规则

- 生成脚本必须记录命令行、工具版本、文件大小、SHA-256。
- 差分测试以 7-Zip / unrar 为 oracle；本项目结果与 oracle 不一致即失败。
- 不执行来源不明的归档；fuzz 语料由脚本变异生成。
- 性能测试固定机器/电源模式/杀软状态，结果写入 `docs/benchmarks/`。

## 当前状态

M0：仅目录说明。P1 加入 ZIP/7z 语料生成器与首个差分用例。
W1-004 起，7z 单测/CLI 集成测试在测试进程内用 `sevenz-rust2` writer 生成夹具；官方 7-Zip 26.04 `7zr` 仅作为本机差分 oracle（见 `docs/tasks/W1-004-sevenz.md`），二进制不提交。
W1-005 起，ZIP/7z 分卷与 SFX 夹具在测试进程内生成；RAR 分卷用本机 `Rar.exe -m0 -v1k` 生成，CI 无引擎时跳过（见 `docs/tasks/W1-005-volumes-sfx.md`）。

W2-008（2026-11-28 预期目标已定稿、**尚未实现**）将在本目录补齐 `corpus/` 生成脚本与 manifest、`differential/` oracle 脚本与向量；只提交脚本、哈希与报告，不提交归档/字典二进制。详见 `docs/tasks/W2-008-corpus-differential-benchmark.md`。
