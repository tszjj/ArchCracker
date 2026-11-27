# tests/corpus — W2-008 本地语料

本目录只提交**脚本与说明**；生成的归档、字典、manifest 输出都在 `tests/corpus/out/`（已被 `.gitignore` 排除），不入库。

## 生成步骤（Windows x64）

```powershell
# 1) 归档夹具：ZIP ZipCrypto/AES、7z AES、头加密 7z、RAR4/RAR5、截断/损坏负例
cd core
cargo run -p acx-cli --example w2_008_fixtures -- ..\tests\corpus\out\fixtures

# 2) 字典与 manifest（含每条文件的 SHA-256、大小、生成命令口径）
cd ..
python tests/corpus/generate.py --out tests/corpus/out --count 1000000
```

可选环境变量：`ACX_7Z`（7z.exe）、`ACX_UNRAR`（UnRAR.exe，同目录需有 `Rar.exe`）。工具不在时对应夹具会被跳过并在生成日志中说明，绝不用假夹具替代。

## 内容

| 文件 | 用途 |
|---|---|
| `out/fixtures/zipcrypto.zip` | ZipCrypto 负例/命中，默认与 `--strict` 对照 |
| `out/fixtures/aes.zip` | WinZip AES-256，`zip_verifier` 计数 |
| `out/fixtures/aes.7z` | 7z AES，`sevenz_first_block` 与 `full_attempted` 对照 |
| `out/fixtures/header_aes.7z` | 7z 头加密（外部 7-Zip 生成），头加密路径计数 |
| `out/fixtures/rar5.rar` / `rar4.rar` | RAR 外部 oracle 与 `rar5_check_value` / `external_attempts` |
| `out/fixtures/{truncated,corrupted}.zip` | 归档级错误分类负例 |
| `out/dictionaries/dict_1m.txt` | 1M 字典（末尾为已知密码） |
| `out/dictionaries/dict_small.txt`、`dict_unicode.txt`、`dict_hybrid.txt` | 差分/编码/混合小语料 |
| `out/manifest.json` | 所有输入的 size + SHA-256，供报告引用 |

## 规则

- 不提交任何 `*.zip` / `*.7z` / `*.rar` / `*.dict`，只提交脚本、README 与报告。
- 差分以外部 7-Zip / UnRAR 为 oracle；工具缺失时跳过对应用例并在报告中标注。
- 生成脚本固定随机性（字典按索引命名），manifest 记录时间与平台，便于复现。
