# W1-005：分卷 / SFX 与预检完整化

- 状态：完成（本地分支 `feat/w1-005-volumes-sfx`，按里程碑统一推送）
- 角色：core-engineer、reviewer
- 范围：ZIP/7z 字节分卷、RAR 外部引擎分卷、7z/ZIP/RAR SFX 数据区定位、缺卷/截断/损坏分类；不含 PKZIP 旧式 `.z01`（明确报不支持）
- 依赖：无新增依赖

## 设计目标

解决「用户只拿到第一分卷或 SFX 自解压包时能否直接恢复」的问题。面向分卷与自解压归档场景，让用户只传第一分卷或 `.exe` 就能预检，并在跑字典前明确区分完整、缺卷、截断/损坏、不支持四类情况，不把缺卷误报成密码错误。

## 实现要点

- **归档源**（`archive/source.rs`）：检测文件标识；`MZ` 开头时扫描 PE 自解压头后的归档签名（上限 32 MiB）得到数据偏移；解析分卷命名（ZIP/7z `.001`/`.0001`、RAR `.partN`、旧式 `.rar + .r00`），传后续卷时回退第一卷；缺中间卷立即报错，最后卷缺失按格式判定（ZIP/7z 用「最后两卷等大」启发式，RAR 读主头标记或用 UnRAR 诊断）。
- **卷读取器**：把多个分卷拼成可读写流；逻辑偏移从第一分卷的数据起点算；每个线程独立句柄；ZIP/7z 引擎无需感知卷或自解压头。
- **引擎接入**：ZIP/7z 通过卷读取器预检与验证；RAR 只做卷集合校验，仍把第一卷或 SFX 交给外部引擎。
- **错误分类**：新增缺卷/截断/损坏三类错误，CLI 统一 exit 3 但消息明确；`.z01/.z02` 明确报不支持。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 test --workspace --locked
cargo deny check licenses bans sources
```

覆盖多分卷拼接、缺中间/最后卷、四位分卷、后续卷回退、SFX 偏移、`.z01` 不支持、单卷误判防护、跨卷 seek/read。

## 结果

core 77（新增 18）+ CLI 34（含 1 忽略）+ FFI 2 通过；本机全绿。手工：7-Zip 26.04 生成的两卷 7z 命中、删卷报缺卷；WinRAR 6.24 生成的 7 卷 RAR 命中、删中间或末卷均报缺卷。

## 许可与引用

无新增依赖；官方 7-Zip/WinRAR 生成的样本只作本地对照，不提交仓库。

## 评审与对照意见

评审通过。已知边界：PKZIP `.z01/.z02` 明确不支持；最后卷检测在 ZIP/7z 用启发式，单卷 `.001` 截断可能误报缺 `.002`；SFX 扫描上限 32 MiB；RAR4 SFX 头加密未单独验证；未做分卷性能基准或模糊测试。
