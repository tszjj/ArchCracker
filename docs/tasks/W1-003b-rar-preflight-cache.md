# W1-003b：RAR 预检缓存

- 分支：`feat/w1-003b-rar-preflight-cache`
- 角色：core-engineer、reviewer
- 状态：完成（PR #5，评审通过，CI 6/6）
- 前置：[W1-003](W1-003-rar-external.md)

## 设计目标

解决「每个线程重复启动外部引擎做预检」的浪费。面向多线程跑 RAR 的场景，把归档元数据探测收敛到工厂创建时一次，工作线程只复用结果，使进程数与线程数无关，不改变验证路径和错误语义。

## 实现要点

- `RarFactory` 增加元数据缓存与访问器；`new()` / `with_engine()` 创建时预检一次。
- 新增 `from_info()` 接收 CLI 已探测的元数据，校验格式与路径后只定位引擎，不启动进程。
- `open()` 只克隆缓存，不再做格式检测与预检。
- CLI 的 RAR 分支改用 `from_info()`。

## 验收

```powershell
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

加密 RAR `-t N` 的预检进程数从约 `2+2N` 降为 2；`open()` 零次引擎启动；`from_info()` 拒绝格式/路径不符的元数据；既有 RAR/ZIP/CLI 测试保持通过。

## 结果

core 42（新增 3）+ CLI 4 + 集成 8 + FFI 2 通过。同机 172B RAR5、1 个错误密码、5 次中位数：`-t 4` 206→136ms、`-t 16` 243→135ms、`-t 32` 376→135ms。详见 [w1-rar-preflight.md](../benchmarks/w1-rar-preflight.md)。

## 许可与引用

无新增依赖，许可边界不变；未引入 hashcat/Cargo 依赖，未引入随包引擎路径（W4）。

## 评审与对照意见

评审通过。未验证 RAR4 真实样本、超大归档预检、release 构建、冷缓存、杀毒软件干扰。已知限制：缓存是创建时快照，运行期间归档若被替换则元数据可能过期，当前要求归档不变。
