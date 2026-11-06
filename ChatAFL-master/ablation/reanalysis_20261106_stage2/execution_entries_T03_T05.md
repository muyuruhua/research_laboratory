# T03–T05 执行入口设计（设计文档，非已实现声明）

状态：**TODO**。本文件给出策略↔实现↔臂名映射与前置依赖；任何条目在 T06 合同验收通过前不得视为存在。

## T03｜Q1 三策略（A/B/C）

| 策略 | 实现要点 | 计划臂名 | 前置依赖 |
|---|---|---|---|
| A 直接服务 | 复用 wrapdirect 的强制留存路径 + 候选服务额度规则（每可执行候选 64 charged，与 B/C 同额） | `q1a_direct` | T02-C 挂账 1（campaign 级预算硬顶 P） |
| B gate 后不回流 | = wrapgate8 语义 + 同额度规则；被拒候选的 64 额度**留空不转移**（新增 env：`CHATAFL_Q1_NO_REFLOW=1`，在调度层把节省额度记入 idle 账） | `q1b_gate_idle` | 同上 + `q1_budget_flow` 账本 |
| C gate 后回流 | = wrapgate8 语义 + 被拒候选额度转移到普通变异（新增 env：`CHATAFL_Q1_REFLOW=1`；每笔回流记录来源候选/额度/接收队列/实际消费） | `q1c_gate_reflow` | 同上 |

- 共同点：同候选供给（threshold=1 Mock 自然供给已验健康，T02-A）、gate 外规则与 wrapgate8 对齐；A/B/C 仅差"拒绝后额度的去向"。
- 账本新表 `q1_budget_flow`：{candidate_id, saved_amount, destination(idle|ordinary_queue), consumed, remaining}；验收=C 的 consumed/registered ≥ 0.8。
- **不要求 B 与 A/C 等实际调用数**（A/B 是机制拆分）；A vs C 才是同预算收益比较。

## T04｜Q2 三路配对 runner

| 路径 | 实现要点 | 前置依赖 |
|---|---|---|
| PV 路 | 复用现行 provisional 服务（S1 前缀保护 + 64 charged） | — |
| 同根 ordinary 路 | 同一 root 的会话以 ordinary 队列身份入队（prov_ordinary_match 已有机制），**同算子、同 M2 窗口、同额度** | 算子差异表（先审计：PV vs ordinary 的 favored/energy/调度差异逐项列出） |
| 常规 corpus 路 | 额度交还常规 queue（不优先服务该 root） | checkpoint 快照（T02-A 挂账） |

- 形态：**离线配对 runner**（从 checkpoint 派生三路子战役，各 64 charged，固定 seed 表），不是在线臂——在线臂无法同起点。
- 主读数：beyond-trial 新增 source branches（依赖分类器复核=T02-C 挂账 3）+ 首次收益调用位置；P64 为次要代理。
- `ordedf8`：保持 INCONCLUSIVE（全 ordinary 队列下与 ordmatch 退化同规则，已证）；若验 EDF 需人为构造 ≥2 可执行根竞争的场景（固定候选混合 + 仅切 EDF）。

## T05｜Q3 配置白名单审计

- 先跑配置白名单导出器：对 wrapgate8 / cal_run_rate8 / calibrated8 / cal_ewma8 / cal_shrink 五臂导出 run-config 全字段 diff，白名单 = {STATE_SELECT, CAL_SHRINK_PSEUDO, cal_* 参数}；出现白名单外差异 → FAIL。
- 主比较（合同 §3）：cal_shrink vs wrapgate8；cal_shrink vs cal_run_rate8。在线、独立 campaign、固定 P 预算（依赖 T03 的硬顶机制共用）。
- 预测诊断沿用同流 prequential（生产公式），只作机制证据。

## 实现顺序建议（下一会话）

1. T06 前置：人工复核 0d46afb1 的 535 行 diff（分类器正确性）→ 通过则提交为正式基线 commit；
2. 实现 campaign 级预算硬顶 P + `q1_budget_flow` 账本（T03 三臂共用地基）；
3. 实现 T03 三臂（runner 条目 + 合同测试：正常/拒绝/回流/耗尽案例）；
4. 实现 T04 离线配对 runner（checkpoint 派生）；
5. T06 全量合同验收 → T07 并行 smoke（12+3 臂）。
