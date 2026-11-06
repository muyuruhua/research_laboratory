# Stage-2 实验合同（T01）

冻结于任何新实验启动之前；与 `baseline_manifest.json`、`legacy_run_index.json` 同目录。参数表中标 **TBD** 的项在正式收益试验（T08）启动前必须定值，定值依据先导方差，不得看正式结果后调整。

## 0. 统一规范

- **分析单位** = 独立 campaign（run）。候选/episode/root 嵌套于 campaign，不作独立样本。
- **第一轮核心终点** = 固定实际 target-invocation 预算 P 下的新增 source branches（retained-corpus replay union 减分叉前基线并集；口径见 T02-C）。固定 wall-clock 比较另设预算，不与 fixed-call 混同声明。
- **成本四账分离**：target invocations（含互斥分类）、wall-clock 秒、采样 CPU 秒、LLM attempts/tokens/latency（Mock 值仅描述 Mock 条件）。
- **删失规则**：预算未完成=删失（单列原因：TTL/容量/park/战役结束/技术失败）；技术失败 run 整 run 剔除但保留计数；缺测不作零收益、不静默排除。P64 类比率一律附 N/C/F/U 与逻辑界。
- **区间与多重比较**：主比较每 Q 至多 1 个（下表），全部预注册；非主比较标 exploratory。区间用 campaign 级配对差值的 bootstrap/置换（报告分辨率与假设）；不因"不显著"判等价。
- **机制剂量前置**：任一主比较先验剂量（见各 Q"剂量线"），剂量不足 → INCONCLUSIVE，不作收益判读。

## 1. Q1 主比较（gate 的资源回流）

- **问题**：拒绝候选后是否避免无效后续工作，且省下额度回流普通探索后，同预算下代码收益改善？
- **策略**（T03 实现后映射为臂）：A 直接服务 / B gate 后不回流 / C gate 后回流，同候选供给、同预算上限、gate 外规则固定。
- **主比较**：A vs C 在相同实际总调用预算下的新增 source branches（B 作机制拆分中间量）。
- **剂量线**：可执行候选上的拒绝分支 ≥ 10 个/臂；C 的回流额度实际消费 ≥ 80%（账本核验，防只登记不执行）。
- **最小有意义增益**：**TBD-α**（候选：新增分支 ≥ +5% 或同覆盖成本 −15%；定值前不作通过判定）。
- **不可替代为收益的证据**：拒绝率、lineage 调用减少、CPU 下降（只构成资源测量）。
- 输出后 gate 结论限定请求后成本；请求前节省另设实验，不并入本贡献。

## 2. Q2 主比较（PV 的有限调用价值）

- **问题**：同一 eligible root 的 64-call PV 产出是否高于匹配的 ordinary 变异与常规 corpus 探索（机会成本）？
- **三路配对**（T04 runner）：PV / 同根 ordinary（同算子同额度）/ 常规 corpus（同父 checkpoint 交还额度），统一 64-call 计费合同。
- **主比较**：PV 路 vs ordinary 路的 beyond-trial 新增 source branches（排除候选 trial 即时覆盖；分类器用冻结基线的 slot-set 证据，calibration 路径捕获缺口修复后方可作主终点——见 T02-C 挂账）。
- **剂量线**：配对根数 ≥ 20/条件（含未服务/删失根，全部保留在清单）。
- **最小有意义增益**：**TBD-β**。
- **不可替代**：不同候选群体 P64 差、转正率、"优先服务带来的更早收益"（后者只能称预算/服务分配价值）。
- 附在线机会审计：等待/TTL/未服务原因（生产队列公平性单列，不由配对实验替代）。

## 3. Q3 主比较（scorer 在线收益）

- **问题**：相同底座与预算下，校准 scorer 是否优于不校准基线与简单在线调度？
- **臂**：wrapgate8（不校准基线，底座一致性经配置白名单核验）/ cal_run_rate8 / calibrated8 / cal_ewma8 / cal_shrink。白名单只允许 scorer 及其声明参数（kappa=8、α=0.05）。
- **主比较**：cal_shrink vs wrapgate8（固定调用预算下新增 source branches）；cal_shrink vs cal_run_rate8 为第二主比较。依据：三批方向一致（+4.7/+4.0/+10.3）+ 同流 prequential shrink 最低，选 shrink 为先行验证对象；**此选择基于历史数据，正式确认需独立批次**。
- **剂量线**：weighted 选择 ≥ 100/臂且 changed ≥ 10；posterior 连续性合同 PASS。
- **最小有意义增益**：**TBD-γ**。
- **不可替代**：changed-selection 计数、Brier/log-loss 改善（中间环节证据）；离线反事实收益。

## 4. TBD 参数表（T08 前定值）

| 参数 | 含义 | 候选值 | 定值依据 |
|---|---|---|---|
| TBD-α | Q1 最小增益 | +5% 分支 或 −15% 成本 | 先导配对差值方差 |
| TBD-β | Q2 最小增益 | beyond-trial 分支差 | 20+ 配对根先导 |
| TBD-γ | Q3 最小增益 | +5% 分支 | 三批历史 SD |
| P | 固定调用预算 | campaign 级（如 15k/run）与 root 级 64 并存 | 容量核算 |
| 正式 threshold/warmup/energy | 论文条件 | ≠ smoke 的 threshold=1/warmup=8 | T08 冻结 |

## 5. 适用范围声明

首轮全部为 BFTPD+指定 Mock（seed 20261102）；结论限定于该供给条件与该 Mock 的候选质量分布。真实网关与跨协议外推在 T08 独立批次处理，不由 Mock 结果替代。
