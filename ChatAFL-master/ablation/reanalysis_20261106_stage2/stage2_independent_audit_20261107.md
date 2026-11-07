# Stage-2 独立只读复核（2026-11-07）

复核对象：`T07_233140_matrix/evidence/index.json` 的 45 个归档、每个归档内的 `run-config.jsonl`、`execution-events.jsonl`、`fuzzer_stats`、Q1 flow、以及 `cov_over_time.csv.v4/{baseline,terminal,scope,replay-plan}.json`。未修改归档，未启动容器。

## 可以由原始归档直接确认的事实

- evidence index 有 45 条记录，container ID、campaign ID、`rng_seed`、`afl_rng_seed` 均各自 45 个唯一值。45 个归档的 `seeds_sha256` 相同（这是固定输入种子快照，不是重复独立性的证明）；因此“重复有不同 RNG/campaign”可确认，但没有独立 seed/block 表。
- 每个归档的 started invocation 与 ended invocation 数相等，`invocation_id`、`attempt_id` 在 starts 和 ends 内均无重复；starts 与 ends 完全配对，事件中的 `execution_kind` 均属于 calibration/mutation/candidate/shadow/prov-annotate。所有 invocation start 没有 `root` 字段（不是 null root，而是字段缺失）。
- 以 mutation invocation 的首尾事件计算，45 个 mutation 窗口为 1334–2041 秒；35/45 小于 1800 秒。因此报告将 T07 时长线判 FAIL 是正确的。全臂不能被称为已满足“每次超过 30 分钟”的冒烟门槛。
- Q1 三臂原始数值闭合：
  - q1a8 terminal branch = 488/504/486，charged=12000/次；
  - q1b8 terminal branch = 481/490/488，charged=10336/9120/10144，saved=idle=1664/2880/1856，reflow=0；
  - q1c8 terminal branch = 495/496/485，charged=12000/次，saved=1472/2368/2176，reflow=1472/2368/2176。
  报告中的均值 492.7、486.3、492.0 以及 q1b 的平均 idle 2133、q1c 的平均 reflow 2005 均可由这些原始值算出；这不是“零流量”。
- 45 个 terminal coverage JSON 都标记 `acceptance=complete`、`coverage_complete=true`、`fixed_execution_coordinates_valid=true`、`n_unreplayable_ledger_entries=0`。其测量定义明确是 retained corpus replay 的 cumulative branch union，不是同一运行时的 bitmap coverage；该限定必须保留。
- Q1 `q1a8` 每次 direct-service provisional admit 数为 47/42/38；q1b/q1c 的 flow 事件数量分别为 26/45/29 与 23/37/34，flow amount 与 `fuzzer_stats` 相符。

## 报告或验收表述需要收窄的地方

### 1. “L1–L7 45/45 PASS”不是当前 checker 输出的逐运行结果

`T07_ledger_check.json` 只有 15 个键（按 arm 键），而 index 有 45 个 run。`ledger_check_T02B.py` 的 `out[r.get('stage2_id', r['arm'])]` 会把同一臂的三次结果覆盖，故该 JSON 不能支持“45/45”这一 checker 计数。原始 45 归档的上述事件一致性可以逐归档复算，但应该生成使用 `arm + run/campaign_id/container_id` 的 45 个唯一键后再写“45/45”。

此外，checker 的若干规则是报告性而非强制性：

- L2 只记录 `unpaired_starts`，不把它加入 fails；end 端额外/重复 ID 也未检查。
- L3 只有 `Counter`，没有预注册 kind 集合或 starts 总和校验。
- L5 只检查事件中的 `root` dict；本批所有 starts 都没有 `root` 字段，因此“root ≤64”在本批是 vacuous check，不能声称验证了 root cap。
- L7 只比较 `len(starts) > budget`，没有验证 charged 的逐类计费恒等式，也没有核对 Q1 saved/idle/reflow 与 effective cap；Q1 flow 和 fuzzer_stats 另行提供了这些数据，但不应归入该 checker 已验证的 L7。

### 2. “45/45 exit 0、无 OOM、POSTRUN 干净”可以由执行记录支持，但不等于时长通过

每个 archive 的结果目录 manifest/归档确实保留了容器 ID，原始 `run_summary.csv` 及 run-config 可核对退出终因；然而 T07 仍有 35 个 mutation 窗口不足 1800 秒。报告把机制计量 PASS 与时长线 FAIL 分开是合理的，不能合并成整体 T07 PASS。

### 3. Q1 结果仍然只是机制/描述性结果

coverage 端点和三臂 B 值可以算，但三次重复、且按报告预注册规则，不能建立收益方向。q1a8 与 q1c8 的 terminal branch 均约 492，数值区间重叠；q1b 少执行调用且分支略少，说明留空语义的机会成本，但不能据此证明回流有净收益。Q1 A/C 的 direct-service 与 gate+reflow 仅回答预注册比较；没有同候选 checkpoint 的配对反事实。

## 原始 checker 应修的最小缺口（下一次运行前完成）

1. 输出 key 改成 `campaign_id`（并同时保存 arm、run、container_id）；若 archive index 没有 run 字段，从归档 run-config 读取。
2. L2 对 start/end 两侧做唯一性、集合相等和每个 start/end 的 attempt/candidate 绑定检查；未配对必须 FAIL（除非明确记录合法 tail cutoff）。
3. L3 预注册允许的 execution kinds，并检查 `sum(kinds)==starts`；未知 kind 必须 FAIL。
4. L5 显式处理 root 字段缺失：若该 run 声称有 provisional root，则缺失必须 FAIL；否则报告 `not-applicable`，不能输出 PASS。
5. L7 使用 charged 计数（按账本字段）而不是全部 starts；校验 `charged <= cap`、termination reason、refused-at-cap，以及 Q1 的 `saved = idle + reflow_consumed + pool_left` 和 `charged + idle <= cap`（分别按策略）。
6. 为正式收益实验补完整 checkpoint/seed/block 身份，避免只凭共同 `seeds_sha256` 宣称独立。

## 结论

Stage-2 报告对“P=12000 导致时长线失败”和“尚不能作 Q1–Q3 收益结论”的方向判断是可靠的；对 45/45 L1–L7 已被 checker 验证、root≤64 已被验证等表述需要收窄。下一步应先按 T07 失败项重跑满足时长，并在重跑前修正 checker 的 45-run 键覆盖、root 缺失语义和 L7/Q1 恒等式；随后再进入 T04 配对 checkpoint 与正式收益实验，不能把当前 smoke 当作贡献证明。
