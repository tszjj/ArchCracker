# Agent 协作规范

本目录把“一个 AI 写全部代码”拆成**可委派、可评审、可交接**的角色。它不依赖特定运行时：DSH 的 `subagent`/`workflow`、Codex、Claude Code 等都可以用同一套角色提示词。

> **先读 [`POOL.md`](POOL.md)**：同类工作优先复用已有 agent，不要为每个 PR 新建 reviewer / 实现者。

## 1. 角色

| 文件 | 角色 | 主要产出 |
|---|---|---|
| `roles/architect.md` | 架构师 | ADR、接口、任务拆分、跨平台约束 |
| `roles/researcher.md` | 技术调研 | 方案对比、来源/版本/许可证据、未验证项 |
| `roles/core-engineer.md` | 内核工程师 | Rust 核心、引擎、调度、FFI、单元测试 |
| `roles/frontend-engineer.md` | 前端工程师 | Avalonia/Compose/ArkUI、打包、平台胶水 |
| `roles/qa-engineer.md` | 测试工程师 | 语料、差分测试、模糊测试、基准 |
| `roles/reviewer.md` | 评审者 | 正确性/许可/性能/跨平台评审意见 |
| `roles/release-engineer.md` | 发布工程师 | CI、签名、安装包、发布说明 |

## 2. 派发任务

### 2.1 先复用，后新建（默认）

完整规则见 [`POOL.md`](POOL.md)。派发前先 `list_agents`：

1. 同角色 + 同领域 + 相关上下文且 `inactive`：用 `send_message` 续用；
2. 该领域 reviewer 已存在：不要为每个 PR 新建，直接复用；
3. 现有 agent 正忙：先判断能否等待/拆分，不要重复开同类 agent；
4. 只有无合适槽位、需要独立评审（现有 reviewer 参与了实现）、或需要隔离上下文时，才新建。

复用消息只给变更点，不重贴整份仓库：

```text
延续 <role>:<domain> 的任务。
本次目标：...
变更/新增文件：...
必须重读：...
验收：...
禁止：...
不要重复已完成的检查；结束时按 AGENTS.md §6.5 交接。
```

新建时 `description` 使用 `角色:领域` 前缀（如 `reviewer:rar`），方便后续找回。

### 2.2 用 subagent（1–2 个独立任务）

Prompt 必须自包含，建议模板：

```text
你是 ArchCracker 的 <role>。先读：
- 仓库根 AGENTS.md
- docs/agents/roles/<role>.md
- docs/architecture.md（相关章节）
- 任务涉及的文件

任务：
<一句话目标>

范围：
<允许修改的文件/目录>

输入：
<issue/文档/失败用例>

验收：
- [ ] ...
- [ ] 运行 <命令> 通过

禁止：
- 修改范围外的文件
- 引入新依赖（除非任务明确要求）
- 提交样本/密钥/生成物
- 声称未运行的测试已通过

结束时按 AGENTS.md §6.5 输出交接。
```

### 2.3 用 workflow（3+ 独立方向）

`workflows/` 下是可复用的 JS 编排脚本。把脚本内容传给 `workflow` 工具，`meta` 里写 name/description/phases，`args` 传任务参数。

- `research-fanout.js`：多方向调研 → 汇总
- `feature-cycle.js`：计划 → 实现 → 评审 → 验证

> 注意：workflow 每次都会新建子 Agent，不共享父对话，也不能复用已有 agent；适合同域**一次性** fan-out，不适合小步后续迭代。每个 prompt 必须带仓库路径、角色文件、验收标准。

## 3. 协作规则

1. **单一所有者**：同一文件同一时间只有一个实现者；评审者只读/评论。
2. **分支隔离**：`feat/`、`fix/`、`docs/`、`chore/`；不直接在 `main` 提交。
3. **接口先行**：核心/前端并行时，先冻结 `acx.h`/错误码/JSON schema；接口变更走 ADR。
4. **评审门禁**：每个 PR 至少 1 个 reviewer；核心/许可/安全改动加 architect 或 release。
5. **测试证据**：PR 写清运行命令与结果；未验证项显式列出。
6. **不越界**：core-engineer 不改前端；frontend-engineer 不改算法/许可；qa 不提“顺手修”的 PR。
7. **失败要暴露**：构建/测试失败原样报告，不带“应该没问题”。

## 4. 任务包模板

```markdown
## Task <id>: <一句话>
Role: core-engineer
Branch: feat/<id>-<slug>
Scope: core/crates/acx-core/src/engines/zip/
Inputs:
- docs/architecture.md §4
- tests/corpus/zip-aes.json
Acceptance:
- [ ] ZipCrypto/AES 读取通过
- [ ] `cargo test -p acx-core zip` 通过
- [ ] 不新增依赖
Out of scope: UI、RAR、移动端
```

## 5. 交接格式

```text
STATUS: done | blocked | partial
CHANGED: <files>
VERIFIED: <commands + results>
NOT VERIFIED: <items>
NEXT: <one concrete step>
RISKS: <licensing/perf/cross-platform>
```

## 6. DSH preset（可选）

DSH 支持在 profile 的 `cordis.patch.yml` 里声明 `@deepseek-ai/dsh-agent-preset`，用 `@deepseek-ai/dsh-persona` 给人设、用工具行给工具。**本项目不自动改用户的 profile**；`docs/agents/dsh-presets.example.yaml` 只是模板，启用前需：

1. 复制 `standard` preset 的完整 `plugins` 列表（否则新 preset 没有工具）；
2. 把 `dsh-persona` 的 `prefix` 换成 `roles/<role>.md` 的摘要；
3. 备份 `cordis.patch.yml`，重启 DSH 验证；
4. 只影响新会话，现有会话保留旧组合。

在没有验证前，优先用 `subagent` + 角色文件，效果等价且不碰全局配置。

## 7. 反模式

- 一个 Agent 同时改核心 + 三端 UI + CI。
- 没有任务包就开工；没有验收标准就“完成”。
- 用“先跑起来”引入许可受限代码。
- 评审者顺手重构；实现者自己批准自己。
- 把父对话的隐含上下文当成子 Agent 已知。
