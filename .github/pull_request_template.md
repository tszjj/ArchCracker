## 变更说明

<!-- 一句话说明这个 PR 做了什么 -->

## 类型

- [ ] feat（新功能）
- [ ] fix（修复）
- [ ] docs（文档）
- [ ] chore（构建/CI/依赖）
- [ ] refactor（不改变行为）

## 验证

<!-- 实际运行的命令与结果；不要写"应该没问题" -->

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 影响

- 平台：<!-- Windows / Linux / macOS / Android / HarmonyOS，哪些已验证/未验证 -->
- 许可：<!-- 是否新增依赖；是否触及 unRAR/RAR 代码 -->
- 性能：<!-- 有基准就贴 before/after；没有写"无" -->
- 兼容性：<!-- C ABI/错误码/断点格式是否变化 -->

## 检查清单

- [ ] 遵循 `AGENTS.md` 与对应角色文件
- [ ] 新增文件带 `SPDX-License-Identifier: GPL-3.0-only`
- [ ] 新依赖已登记 `docs/licensing.md`
- [ ] 未提交样本/密钥/生成物
- [ ] 未把"未验证"写成"已完成"
