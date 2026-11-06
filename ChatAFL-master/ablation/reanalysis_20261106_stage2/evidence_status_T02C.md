# T02-C 代码收益证据：身份与见证现状（stage-2 冻结时点）

## 已满足项（有 42 运行证据）

- [x] **源码分支身份固定**：source/gcno/scope 由 155418 批逐容器核验（gcov-artifact-source-audit，69 文件一致）；分支身份 = source-branch ID（1362 分支 scope），bitmap slot 不冒充分支。
- [x] **基线扣除口径**：每 run 的初始种子重放并集已可计算（155418 审计用其得到 B 终点）；分叉前覆盖基线 = 该并集。
- [x] **重放 oracle**：terminal.json 的 covered_branch_ids 即 retained-corpus replay union（reset-aware 重放，collection 命令留痕）。
- [x] **预算/首次增益账本**：42/42 通过 ledger_check_T02B（L1–L5，含每根 ≤64 charged）。

## 计费分类实测（42 运行合计）

mutation 428,675 / calibration 210,723 / shadow 4,016 / candidate(trial) 1,325 / prov-annotate 260；unpaired starts = 0。
**口径声明**：calibration 计费已入账本（互斥、无双记）；prov-annotate 按合同不计候选预算；shadow 是观测成本单列。T02-B 恒等式所需"共同前置 + 候选服务 + 常规探索 + 其他 + 未用 = 上限"中，"未用额度"当前**不可直接从账本导出**（campaign 级预算上限 P 未实现为硬顶）——挂账 1。

## 未满足项（挂账，正式收益试验前必须解决）

1. **campaign 级固定调用预算 P 未实现**：现有 campaign 是固定时长（2700 s），调用数自然增长。T03/T04 的同预算比较需要把 P 实现为调度层硬顶（达到 P 后停止变异、仅保留收尾），否则"A/C 同预算"只能按实际调用数事后配对（弱化设计）。→ T03 实现项。
2. **ever-seen 见证缺失**：provisional 过期删除根与未转正后代的 queue/replay 文件，无只读审计副本。"64 次执行发现的代码"无法完整重演（只保留 retained）。→ 需 P0-D 式只读副本目录（expunge 时移入 `witness-tomb/` 而非删除）。实现后指标命名才可从 retained-corpus replay union 升级为 executed-input union。
3. **calibration 路径 novelty 捕获缺口**（基线 0d46afb1 声称修复，未经我审计）：工作区含 prov_trial_slots 重写（MAP_SIZE 位集、绑定 candidate/invocation），三项合同自测 PASS；但其正确性证据目前只有自测——**T06 前需人工复核该 535 行 diff + 用带辨别力的 immediate/beyond/unknown 场景复测**，之后 Q2 主终点方可依赖分类器。
4. **AUC/时间点快照**：cov_over_time 有采样点（SKIPCOUNT），但分叉级（T04 三路配对）需要调用点快照——T04 runner 实现项。
5. **重放稳定性规则**：未预置"首次发现输入 × 独立重放 × 复现频率"管线；terminal 并集含单次命中。→ 正式试验前固定规则（候选：≥2/3 重放复现方计入稳定集，其余单列）。

## 与实验合同的衔接

T01 主终点依赖本文件挂账 1（P）与 2（witness）；Q2 主终点另依赖挂账 3（分类器复核）。三项均列入 T03–T06 的前置验收。
