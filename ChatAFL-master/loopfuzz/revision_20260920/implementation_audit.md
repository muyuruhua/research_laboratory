# LoopFuzz 实现与 first_paper.md 设计契约核查

核查日期：2026-09-20。核查方式：只读源代码检查；未修改 fuzzer、未运行 fuzzing 实验，也未读取凭证。本文件辅助本轮论文修订，不构成对实验二进制的复现认证。

## 范围与版本限制

需求来源为 `C_two_papers/first_paper.md`；本轮已保存的需求快照为同目录 `first_paper.snapshot.md`。核查对象为仓库当前工作目录中的 `LoopFuzz/afl-fuzz.c`、`LoopFuzz/aflnet.c`、`LoopFuzz/evidence-cal.h`、`LoopFuzz/evidence-cal.c` 和 `LoopFuzz/config.h`。以下行号均指核查时文件；之后的源码编辑可能使行号漂移。

核查时 `git rev-parse HEAD` 为 `4ec7e65670e0c2d91d15cf3cf89f21071beb9f38`。这只是当前 checkout 的版本标识。没有据此证明 `Key_Experiment` 中每次归档实验使用相同 commit、相同容器镜像、相同编译产物或相同运行开关。当前源码发现的问题不得无证据地归因到每一个归档 run；反过来，归档日志中出现与设计一致的字段，也不能证明当前源代码已实现完整设计。

文中需区分三个层次：用户指定的新设计契约、当前源码实际行为、归档实验实际支持的观察。尤其不能以代码注释中的 “paper-aligned” 或日志字段名替代执行路径核查。

## A. 影响核心贡献成立的差异

### A1. Native coverage save 绕过完整 durable admission gate

严格设计要求：只有 `P ∧ U ∧ R ∧ G_code` 的 LLM 候选才能进入 durable mutation queue。

实际路径如下：

1. `afl-fuzz.c:12761–12764` 在 P 通过时先调用 `common_fuzz_stuff`。
2. `afl-fuzz.c:12552–12553` 在该函数内调用 `save_if_interesting` 并记录 native save 结果。
3. `afl-fuzz.c:10184` 检测 `has_new_bits(virgin_bits)`，`10207` 已执行 `add_to_queue`。
4. `afl-fuzz.c:12772–12774` 才计算完整 P/U/R/G；`12776–12784` 只处理尚未 native-save 的候选，没有因 U/R 失败而撤销已发生的 native promotion。

因此，U 或 R 失败但产生 native bitmap novelty 的候选仍可进入 durable queue。`afl-fuzz.c:3251` 还明确把 native-promoted 的实际 disposition 覆盖为 `EC_DURABLE`，而 `3267` 对该 disposition 固定写出原因 `P^U^R^G_code`，即 reason 字符串本身不能证明每个 predicate 都通过。

论文处理：保留严格判定式作为设计契约，明确现有 native-save 路径未完全受该 gate 控制。不得声称现实现已经保证“所有 durable LLM candidates 均满足完整 gate”。日志审计须直接检查 P/U/R 字段与实际 disposition，而不能只检查 disposition_reason。

### A2. 常规 D/E 路径的 state-only provisional 分支缺少可达证据

严格设计要求：`P ∧ U ∧ R ∧ ¬G_code ∧ G_state` 产生 provisional entry，即无需已产生 code novelty 就能识别独立的 state novelty。

当前 `G_state` 来自 trial 前后 IPSM 图节点/状态边数量差（`afl-fuzz.c:2991–2992,3009–3010`）。图新增只发生在 `update_state_aware_variables` 中：函数位于 `4441`，图节点创建位于 `4488,4533`，状态边创建位于 `4579`，新增状态边计数位于 `4580`。

该函数在 `afl-fuzz.c` 中的调用点为：

| 调用点 | 触发条件 |
|---|---|
| 9736 | initial dry run |
| 10217 | native coverage save 已创建 queue entry |
| 12592 | direct-arm force admission 后 |
| 12667 | provisional entry 已创建后 |

在被检查的常规 D/E candidate trial 中，没有 native save 的候选在 gate 计算前不更新 IPSM 图，因此 `G_state` 差值为零；有 native save 时，`G_code` 已为真。provisional 创建后才更新图不能使之前的判定条件成立。该路径没有提供独立的 state-only novelty 检测。

论文处理：state-only admission 是待实现/验证的设计要求。不能把现有 provisional 数为零解释成候选质量高、state-only exploration 不必要或两级队列已成功避免污染。应在 gate 前对 trial 的 observed state sequence 与既有 IPSM 做独立 novelty 比较，并以相应版本的实验验证设计。

### A3. 64 descendants / 30 s 不是严格执行上限

默认值位于 `afl-fuzz.c:777–779`：budget 为64、TTL为30000 ms、最大 live entries 为64。创建时在 `12675–12679` 设置 provisional 状态、预算和 deadline。

但计费与过期发生在整个 `fuzz_one` 返回之后：`19286` 执行 `fuzz_one`，`19291–19294` 才进行 provisional accounting 和 expiry sweep。`12694–12696` 事后累加整轮 execution 数、扣减剩余预算。`12698–12705` 先处理 code gain 并立即转 durable，`12708–12714` 才检查 budget 和 TTL。

后果：单轮可以超过64次 execution或30 s；在预算/deadline之后产生的 code gain 仍可能使 entry 转 durable。当前 TTL 也由 whole-cycle sweep 检查，不是实时中断的时限。

论文处理：当前实现只能描述为 cycle-boundary budget/TTL accounting，不得写为“at most 64 descendants or 30 seconds, whichever comes first”的已实现保证。严格设计需在每次验证 execution 前检查预算/时限，并在产生收益时检查是否仍在允许 horizon 内。

### A4. Episode 不具有固定的 mutation exposure

`afl-fuzz.c:19243` 结束前一 episode，`19245–19246` 选择状态并开始新 episode，`19258–19259` 选择/记录 seed，`19286` 调用一次 `fuzz_one`。下一次选择之前才 finalize；如果启用 synchronization，`19296–19300` 的同步也处于此区间内。

`fuzz_one` 不是各状态相同的 execution 数：`14510` 调用 `calculate_score(queue_cur)`，`15592,15609` 按 `perf_score` 等参数设 mutation stage 数量。选择不到可用 seed 时，`19213–19215` 的内层循环仍会进行新的 state selection；上一尝试可被 finalize 为零 execution 的 episode。

论文处理：当前 source 记录的是一次调度尝试/`fuzz_one` 区间，不能把它等同所有状态固定 mutation budget。新设计应冻结固定 exposure、排除无有效 seed 的空 episode，并隔离与目标 seed 无关的执行。若分析现有日志，应报告 execution 数分布与空 episode 处理规则，避免把不等 exposure 混作同质 Bernoulli trials。

## B. Predicate 与 reward 的精确定义

### B1. P 是调用方接受的 schema 标志，非完整 wire-format 正确性证明

`afl-fuzz.c:2984` 直接采用调用方传入的 `p_pass`。动作候选在 `14320–14328` 传入 `1` 和 `actions-schema-valid`；suggested request 在 `14430–14438` 传入 `1` 和 `suggested-request-schema-valid`。这不等于协议字段、长度、终止符、语义约束均已独立验证。

MQTT text-to-binary 转换失败后，`afl-fuzz.c:14421–14425` 仍回退原始文本，而稍后的同一调用点继续传 `p_pass=1`。`common_fuzz_stuff` 的请求分区解析发生在 `12321–12324`，region_count为零会报错，而不是由一个完整的 P predicate 有序拒绝。

论文处理：将现有 P 描述为“候选/action schema 被接收”更准确；完整结构与 wire-format validity 为严格设计要求，不能依据 `p_pass=1` 直接认定。

### B2. U 的适用协议与故障观察有限

`afl-fuzz.c:2999–3000` 的 U 要求 P、已执行、`FAULT_NONE`、至少一个 parsed state、没有 error hint。响应序列的 hint 来自 `2904–2910` 调用 `classify_state_error_hint`。

分类器 `aflnet.c:2370–2411` 对 FTP、SMTP、RTSP、HTTP、SIP、IPP 的 4xx/5xx 给出 likely-error 标记（`2377–2385`）；其他协议返回 unknown/0。它不是完整的二进制协议错误判定，也没有在 admission evaluator 中提供独立 reset/drop 验证。

论文处理：现有 U 为特定解析器及 fault observer 下的 operational acceptability，不能声称覆盖所有拒绝码、reset/drop、业务错误或真实语义状态。

### B3. R 宽于指定目标/frontier reachability

`afl-fuzz.c:3001–3003` 接受以下任一条件：state_count > 1、target_hit、IPSM state-edge增量或node增量。target_hit 按序列中是否出现 target_sid 计算（`2908–2909`）。

因此，观察到多个响应状态即可通过 R，并不要求确实到达指定 target 或事先定义的 frontier。论文应区分 generic transition evidence 与 requested target hit，严格 R 的证据另行实现/验证。

### B4. G_code 与主 reward 实际包含 hit-count novelty

`has_new_bits` 的契约写在 `afl-fuzz.c:6436–6439`：返回1表示旧 tuple 出现新 hit-count bucket，返回2表示此前未见 tuple。实际赋值可见 `6486–6492`。`10184` 接受所有非零返回，`10213` 为每次此类 native save 增加一次 `code_gain_events`。

`G_code`（`3005–3007`）接受 native promotion、bitmap byte增量或favored count增量。episode reward（`4295`）是 `code_gain_events` 是否增加；`4298` 把该计数差命名为 `new_code_edges`。因此 reward 独立于 IPSM novelty，但不是严格“此前未见 source-level code branch/edge”的指标。

此外，`admission_take_snapshot` 在 `2779` 用 `count_non_255_bytes(virgin_bits)` 记录 bitmap slots，日志却在 `3344–3345` 将其命名为 `pre_code_branches` / `post_code_branches`。该单位不能直接当作 source-level branch coverage。

论文处理：现有日志中应分别称 AFL bitmap occupancy 和 native coverage-save events。严格设计的 primary reward 应固定为独立、统一的 previously unseen code coverage 单位；favored 与 hit-count-only novelty 可另列敏感性分析。不得把 source branch覆盖、hashed tuple覆盖、hit-count bucket和save event数量混为一谈。

## C. Calibration 已实现部分与作用边界

### C1. Discounted update 的数学部分一致

`evidence-cal.c:13–17` 初始化 Beta(1,1)，`20–24` 实现

`alpha <- 1 + gamma * (alpha - 1) + r`

`beta <- 1 + gamma * (beta - 1) + (1-r)`。

`evidence-cal.h:43–44` 默认 gamma=0.995、epsilon=0.1。`afl-fuzz.c:4307–4314` 在 episode finalize 时更新 posterior，`19243` 保证下一轮 state selection 前更新。`3190–3193` 记录更新前 alpha、beta、posterior mean，具有按 prior prediction 对照随后 reward 的数据顺序。

但默认常量存在不等于“已在 pilot 后冻结”，需要实验配置/时间记录支持。discount 只在该状态被更新时施加（`4307–4310`），不是按全局时间给所有未选状态统一衰减。

### C2. 实现为 Thompson-sampled weighted selection

`afl-fuzz.c:4171–4173` 对每个状态采 Beta 样本，乘以 frontier factor 后截为 u32；`4189–4195` 建累计权重，`4200–4202` 进行加权随机选择。这不是经典 argmax Thompson selection。

FAVOR 模式先进行5个 round-robin state cycles（`4227–4237`），随机选择/round-robin路径不重新计算 Thompson scores。低样本 floor 是相对乘子，整数截断和状态可用性也会影响最终调度，所以不应把 epsilon 写成无条件永久无饥饿保证。

固定 arm 的 error/productivity penalty 位于 `4116–4124`；calibration 开启后替换该固定 penalty。MQTT额外 topology/differential/forwarding启发式仍保留在 `4128–4156`。论文应给出相邻 arm 共同的 base/frontier 部分，不能把全部实际调度简化为仅含 posterior 的选择器。

### C3. Posterior 不直接控制 admission decision

`admission_evaluate`（`afl-fuzz.c:2978–3016`）和 `ec_decide_disposition`（`evidence-cal.c:134–141`）不读取 alpha/beta/theta。posterior只在 `afl-fuzz.c:4170–4173` 进入 scheduling。

论文处理：D/E应共享同一 admission contract，E通过改变调度和后续探索 exposure 间接影响 candidate/provisional的机会。不能声称当前 posterior直接改变 durable阈值或直接校准P/U/R。严格因果比较仍需核实其他开关、代码和资源政策一致。

## D. Arm、repair 和资源政策

### D1. C/D/E 名称与有效开关

`afl-fuzz.c:2947–2950` 根据 flags命名：有 no_admission为C，否则 calibration为E，其余为D。`18797–18800` 按 `getenv("CHATAFL_NO_ADMISSION")` 是否存在启用direct，因此设为字符串 `"0"` 也会启用；`18827–18831` 的calibration开关则要求非空且不为 `"0"`。

direct arm仍先执行trial，`12776–12783` 只在未native-save、无fault等条件下强行入队；`12573–12579` 还拒绝timeout/crash/error。它不是未经目标执行就把每个文本proposal写入队列的实现。

论文处理：给出实际 launch配置，而不是仅用口头arm名称推断行为。C应描述为在共同trial执行/故障策略后放宽gain准入的counterfactual；严格同prompt/output的比较限于相同snapshot的candidate replay，不能声称分叉的自适应完整campaign始终具有相同输出。

### D2. Repair 必须显式关闭，默认值不能支持已关闭主实验

`afl-fuzz.c:727` 中 `ablation_no_refinement=0`；`13768–13769` 在未关闭时调用periodic refinement。`18678–18680` 通过 `CHATAFL_NO_REFINEMENT` 是否存在关闭。`18681–18691` 明确指出未开启hypothesis mode时该ablation是no-op。

论文处理：主C/D/E设计明确repair off，但不能把此设计直接写成所有历史run事实。需检查launcher、resolved flags及日志；repair保留为可选诊断feature，完整repair_event与独立repair对照缺失时不列核心贡献。

### D3. 当前 resource-cap 字段不证明总调用/总token上限已实施

`afl-fuzz.c:3052` 把 `CHATTING_THRESHOLD` 写成call_cap；其值在 `config.h:78` 为64。实际条件在 `afl-fuzz.c:13748` 约束plateau handler的chat_times，不代表grammar setup、enrichment、repair、retry等所有模型调用的总上限。

`CHATAFL_TOKEN_CAP` 在被核查源码中仅见 `afl-fuzz.c:3053–3055` 读取并写日志，未见对应的总token预算强制执行逻辑。

论文处理：equal-policy/equal-cap是要求，不是凭字段存在即可确认的现有保证；需明确total call/token accounting边界、重试/失败计费和stop条件。实际usage必须单独报告，不能从同trigger推导同calls/tokens。

## E. 日志可信度和字段缺口

### E1. Start run_config 写在环境flags解析之前

`afl-fuzz.c:18588` 调用 `run_config_log("start", NULL)`，然后执行grammar/enrichment（`18591–18592`）。实际hypothesis开关到 `18660–18665` 才读；NO_REFINEMENT到 `18678`；NO_ADMISSION到 `18797`；CALIBRATION/gamma/epsilon/provisional overrides/event-log开关到 `18827–18863`。

因此start行可能记录默认D arm、默认repair/其他flags和默认calibration参数，即使launcher请求C/E或参数覆盖。该位置注释“after the ablation/env block”与实际代码顺序不符。`19433` 的end记录处于flags解析之后，但进程非正常结束时不保证存在该行。

论文处理：不能仅用start行判定arm或有效设置。需结合launcher环境、命令、容器/二进制版本、end记录；若未核实，归为unresolved configuration。要保证startup failure完整计入ledger，应在任何LLM调用之前解析所有effective flags并记录它们，同时保留失败phase。

### E2. Candidate、admission、provisional 与 bug schema 尚不完整

| 日志及源码位置 | 当前限制 | 分析含义 |
|---|---|---|
| run_config，3020–3078 | 缺target commit、container image digest、CPU/memory quota；模型/endpoint等字段也需和真实请求配置核对 | 不能单独复原完整运行环境 |
| candidate，3081–3117 | 无每行run_id、完整raw candidate或稳定artifact path；只有hash、摘要等 | 拒绝候选的shadow replay与完整audit可能受限 |
| admission，3271–3357 | 无response hash、独立reset/drop；coverage字段单位见B4；native disposition_reason可能不反映P/U/R实际值 | 不可用reason字符串替代predicate核验 |
| provisional，3121–3146 | provisional_id每条event递增（3127），不是稳定实体ID；first_productive_descendant使用当前last_native_save_index（3138–3139） | 该descendant可能是整轮最后一次save；实体连接应至少用run + candidate/queue标识核对 |
| episode，3174–3207 | mutations是total_execs差，new_code_edges是save-event差；warmup/random路径的score需核对 | reliability等结果只适用于定义明确且有效的episodes |
| bug，3149–3170 | 最小crash/hang/oracle-save记录；未形成完整reached/triggered及vulnerable/patched证据链 | 不能从bug-events条数得出CVE/root-cause数量或rediscovery recall |
| repair | 本轮未找到first_paper要求的完整repair_event字段链 | 不支持repair核心贡献或严格before/after解释 |

常规state/candidate/provisional记录缺乏显式run_id时，必须保留其所属run目录作为命名空间；不能跨run直接按候选序号join。JSONL以append方式写入（`2934–2943`）不代表schema已满足完整审计要求。

## 对正文修订的建议表述边界

方法节可以完整提出严格的execute-before-promote、两级队列、固定episode与discounted Beta设计，并用统一符号区分response acceptability U和productivity posterior theta。实现/证据边界应明确：当前prototype含判定数学、posterior和事件记录，但当前执行路径仍存在native admission bypass、state-only novelty不可达、预算事后计费、exposure不统一及配置/成本审计不足。

现有结果只按经过验证的真实单位、运行版本和对照条件报告。未完成的严格C/D/E因果比较、provisional conversion、独立fixed-horizon downstream productivity、可靠校准指标与historical-CVE ground truth应留空；不能用旧配置结果填补新设计证据。无需为论文修订擅自修改fuzzer或重新启动实验。
