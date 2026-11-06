# T02-A 候选供给审计（wrapgate8 @ 20261106T155418，3 run 合并）

## 待办原文假设 vs 实测

待办 T02-A 原文："检查最新批次 wrapgate8 的 125 次 trial 中 120 次 null reject 的具体来源：实际空输出、传输失败、解析失败、包装转换失败分别统计。"

**实测结论：不存在 null 输出问题，该前提不成立。**

| 供给环节 | 计数 | 判定 |
|---|---|---|
| candidate 事件总数 | 125 | = trial 总数（125 次准入决策） |
| 零长度候选（实际空输出） | **0** | 供给无空输出 |
| plateau LLM 调用状态 | 130/130 = ok | 无传输/调用失败 |
| p_fail（解析/包装失败） | **0** | 全部 parseable |
| r_fail（不可重放） | **0** | 全部可执行（trial 均执行） |

## 120 个 reject 的真实构成（按谓词组合）

| 来源类别 | 计数 | 含义 |
|---|---:|---|
| u_fail，无即时证据（¬gcode∧¬gstate） | 81 | 语义错误响应且无新边/新状态——strict-U 的"纯错误响应"拒绝 |
| u_fail ∧ Gcode | 20 | **strict-U 否决带即时代码证据的候选**（已知 U/代码冲突，含 hnb=2） |
| u_fail ∧ Gstate | 13 | 语义错误响应携带新状态证据 |
| p∧u∧r 但无任何新颖性 | 6 | 正常接受但无证据 |
| durable / provisional | 4 / 1 | 保留 |

**判定**：候选供给健康（全部可执行、可解析、有真实 Mock 响应）；gate 的 120 次拒绝全部发生在**可执行候选**上。T03 的进入条件"可执行候选上的拒绝分支"满足（120 个）。注意 20 个 U∧Gcode 拒绝正是 Q1 资源选择命题的核心张力——被拒者中有带代码证据者。

## T02-A 其余条目现状（缺口如实挂账）

- [x] gate 前候选池保存：candidate-events 在准入决策**之前**逐候选记录（source/action/prompt_hash/raw_reply_hash/candidate_hash/tokens）——含被拒者，不只收集转正者。
- [x] 可执行/不可执行分列：125/0。
- [ ] 配对实验 checkpoint 快照（fuzzer 队列/计数器/目标协议状态恢复）：**未实现**——现有 queue-checkpoints.jsonl 只记 queue 概要，不含完整 checkpoint 恢复；T04 配对 runner 需先建（见 T03-T05 入口设计）。
- [ ] 独立 seed/block 表与 RNG 流分离：runner 未按臂固定 RNG seed（155418 campaign_id 碰撞事故同源）；T06 需实现 P0-A 的独立 UUID/seed 注入。
- [x] 合成样本与贡献评估候选分离：当前无合成样本机制（机制测试仅合同自测层，未混入 campaign 候选流）。
