# bftpd 三臂审计：20261027T150457

分析对象仅限本批 `wrapdirect8 / wrapgate8 / salvage8`，每臂 3 次独立运行、每次 95 分钟。结论依据九份完整归档中的运行配置、执行与候选血缘账本、provisional 生命周期、shadow 记录，以及逐输入覆盖回放记录。

**本批不能确认三个臂谁的实际漏洞发现或代码覆盖效果最好。Q1 有资源分配机制改变的有限证据；Q2 的验证条目全部零服务；Q3 没有开启。覆盖采集又系统性漏掉登录成功的会话，现有覆盖终值不能支撑效果排名。** 这不是“三个机制都已被证伪”，而是需要区分机制观察、未执行的实验和失效的测量。

## 1. 三个关键问题的判定

| 问题 | 本批可以回答的部分 | 对论文贡献的判定 |
|---|---|---|
| Q1：Gating 是否避免无效资源分配？ | direct 的跟踪候选后代消耗 694 次调用，未记录到后代新边保存事件；gate/salvage 不再给予这些类别的后代执行，另外支付 shadow 成本。资源分配确实发生改变。 | **有限机制证据；净收益未证实。** 不同臂候选不相同，provisional 零服务，覆盖测量不完整，无法证明同等发现能力下省资源。 |
| Q2：Provisional Validation 是否发现普通变异难发现的代码价值？ | 9 个 provisional 全部在验证前以 `no-executable-M2` 结束，预算 64 次全部保留、后代执行 0、转换 0。 | **未成功开展检验。** 不能把 0 转换解释为经过验证后“无价值”，也没有等预算普通变异对照。 |
| Q3：Calibration 是否优于简单在线调度？ | 九份配置全部 `calibration=false`；332 次选择全部 `warmup-eligible`，没有进入基于权重的状态选择。 | **未检验。** 本批没有开启 Calibration 的处理组，也没有 EWMA/run-rate 等在线调度对照。 |

对 `first_paper_revised3.md` 的当前意义：可报告“准入策略改变了候选后代的执行预算，并暴露了验证服务和覆盖测量问题”；暂不能报告“Gating 提升资源效率”“Provisional 发现了普通变异难发现的价值”或“Calibration 优于简单调度”。

## 2. 范围、完整性与公平性

- 只读取三个 `results-bftpd_ablation_*_20261027T150457` 目录中的九份准确命名 `out-bftpd-loopfuzz_[123].tar.gz`。排除所有 `.incomplete.*` 副本，不混入较早批次或其他目标。
- 九个 status 都是 `completed / exit_code=0`。三个独立审计的归档 SHA256 相互一致；完整哈希、字节数、status 和配置保存在 `data/manifest.json`。
- 九份配置的 fuzzer、target、image、输入 seeds 哈希一致；fuzzer commit 记录为 `c73afe54a`，fuzzer SHA256 为 `b58ab7e66fce31b17fbb5bb575c260cb9604e8c40b0218b3c49bf00297af60eb`。但**每次实际初始 queue 都是 184 个输入，九份初始输入的内容哈希多重集合全部不同，差异不只是 queue 顺序**。初始语料经过 LLM enrichment 后已不相同，是效果比较的额外变动因素，不能把配置中的 seeds 哈希相同当成实际启动语料相同。列表与有序/忽略顺序指纹保存在 coverage 审计和 manifest 中。
- 所有配置都使用 plaintext wrap、固定阈值 8、`no_adaptive=true`。direct 关闭准入限制；gate 开启 gate、provisional、shadow；salvage 在 gate 基础上增加 salvage。因此 gate 对 direct 不是纯粹只改变一个布尔开关的单因素比较；salvage 对 gate 才主要对应 salvage 的增量。
- RNG 未固定，编号同为 run1 不代表配对。统计实验单位是一次 campaign，不能把几百个候选或几万次调用当作独立重复。每臂 n=3，只报告观察值与限制，不作显著优越、等效或非劣效声明。
- 解析与 join 审计没有坏 JSON、重复 candidate/trial 键、重复 invocation ID 或未配对 start/end，也没有孤立的跟踪候选祖先。候选键使用归档与 campaign_id，避免不同运行 candidate_id 重号。
- 配置时钟记录每次约 5,700,000 ms，即 95 分钟，包含初始 LLM/语法与 enrichment。首次目标调用前耗时 7.57–9.51 分钟；`fuzzer_stats` 后阶段时钟只有约 85.42–87.37 分钟，不能把初始化成本排除后再比较。

## 3. 每次运行的核心观察值

`后代执行` 指跟踪候选血缘的 mutation + AFL seed calibration，不含候选原始试执行、shadow。下表的“分支”是**不完整 gcov 回放观察值**，仅供核账，不能用作效果排名。

| 臂 | run | AFL 计数执行 | 候选 | 实际 durable / provisional / reject | 后代执行 | shadow 调用 | 原生新边保存事件 | 不完整分支 | 缺 gcda / 回放输入 |
|---|---:|---:|---:|---|---:|---:|---:|---:|---|
| wrapdirect8 | 1 | 20,896 | 52 | 52 / 0 / 0 | 307 | 0 | 51 | 198 | 623 / 659 |
| wrapdirect8 | 2 | 19,921 | 42 | 42 / 0 / 0 | 8 | 0 | 52 | 198 | 594 / 619 |
| wrapdirect8 | 3 | 19,859 | 47 | 47 / 0 / 0 | 379 | 0 | 46 | 197 | 556 / 583 |
| wrapgate8 | 1 | 22,733 | 50 | 0 / 2 / 48 | 0 | 112 | 48 | 198 | 561 / 603 |
| wrapgate8 | 2 | 20,385 | 53 | 0 / 1 / 52 | 0 | 176 | 45 | 198 | 521 / 544 |
| wrapgate8 | 3 | 19,898 | 48 | 0 / 1 / 47 | 0 | 80 | 47 | 198 | 546 / 576 |
| salvage8 | 1 | 20,568 | 43 | 0 / 3 / 40 | 0 | 64 | 55 | 198 | 549 / 573 |
| salvage8 | 2 | 22,404 | 54 | 0 / 1 / 53 | 0 | 96 | 50 | 198 | 542 / 568 |
| salvage8 | 3 | 22,579 | 55 | 0 / 1 / 54 | 0 | 176 | 50 | 198 | 543 / 575 |

三臂平均 AFL 执行数为 20,225.3、21,005.3、21,850.3；gate 和 salvage 相对 direct 的观察增幅分别为 3.86%、8.03%。**这些是吞吐量趋势，不是发现能力或资源效率提升的证明。** 原生新边保存事件合计为 149、140、155；它们是 AFL `hnb==2` 的保存事件数，不是去重源代码分支数，不能与 gcov 分支直接等同。salvage 的吞吐较高与 wrapgate 的新边事件较少，也不足以决定哪条臂“最好”。

执行账本共有 189,251 对 start/end，AFL 计数执行为 189,243。差额 8 次是停机末尾 `execution_id_before == execution_id_after` 的 wrapper 调用，未推进 AFL 执行计数，不是少统计了八次已完成执行。

## 4. Q1：门控已经改变预算分配，但收益证据还不足

以下均为每臂三次运行合计：

| 工作量 | wrapdirect8 | wrapgate8 | salvage8 |
|---|---:|---:|---:|
| 候选原始试执行 | 141 | 151 | 152 |
| 持久候选 | 141 | 0 | 0 |
| 跟踪候选后代 mutation | 630 | 0 | 0 |
| 跟踪候选后代 seed calibration | 64 | 0 | 0 |
| 后代新边保存事件 | 0 | 0 | 0 |
| 后代调用耗时，秒 | 206.592 | 0 | 0 |
| shadow 调用 | 0 | 368 | 336 |
| shadow 调用耗时，秒 | 0 | 78.906 | 67.028 |
| 候选原始试执行耗时，秒 | 28.159 | 31.339 | 30.155 |
| 跟踪候选相关调用总耗时，秒 | 234.751 | 110.245 | 97.183 |
| 无跟踪候选祖先的 mutation 调用 | 44,531 | 47,701 | 49,482 |

这是超出“只统计拒绝多少输入”的证据：策略影响了候选入队后的执行，而不只是输入数量。direct 的 630 次后代 mutation 实际集中在两个候选根：run1 candidate24 的 291 次、run3 candidate22 的 339 次，两者都没有记录到后代新边保存。包含 calibration 后，694 次后代调用消耗 206.592 秒。

但这部分支出只占 direct 已接纳调用约 **1.144%**，对应三次 95 分钟总墙钟约 **1.208%**；不能据此宣传巨大节省。表中的时间是 invocation wrapper 的墙钟经过时间，不是 CPU 时间，不含 LLM 等待、外部 reset 和其他调度成本。跨臂总耗时差值也不是同一批候选的因果反事实。

gate/salvage 的后代执行为零还有一个重要原因：其 provisional 条目完全没有获得验证。把这部分“没服务”全部记成聪明地节省资源，会掩盖验证未运行的问题。无跟踪候选祖先的 mutation 增加，也不能直接解释成全部由门控省出的预算；这类血缘还可能包含最初由 LLM enrichment 生成的 seeds，不是纯粹无 LLM 的普通变异基线。

还存在误拒风险：direct run2 candidate5 的原始试执行 invocation6589 是本批唯一跟踪 LLM 血缘的新边保存事件，`G_code=true`、`U=false`，其 gate 意向仍为 reject。它揭示代码阳性候选可能被 U 条件挡住；不代表 gate 臂确实生成并丢掉了同一个输入，因为跨臂候选流不同。

**Q1 的准确表述：本批观察到门控改变了后续预算分配，减少了对本次未产出新边的候选后代的继续执行；尚不能证明总成本下降且发现能力得到维持。** 固定时长下不能使用 `1 - execs_gate / execs_direct` 作为节省率，更少执行也可能意味着变慢。

## 5. Q2：验证机会为零，不能评价 provisional 的代码价值

九个条目的生命周期完全一致：`admit → expire(reason=no-executable-M2)`，`descendant_execs=0`、`descendant_code_gain=0`、`budget_left=64`，没有 convert/censor，也不是 64 次验证耗尽或 TTL 到期。

| 臂 | run | candidate_id | queue_entry | 入队原因 |
|---|---:|---|---|---|
| wrapgate8 | 1 | 13、42 | 390、560 | state novelty |
| wrapgate8 | 2 | 17 | 395 | state novelty |
| wrapgate8 | 3 | 24 | 473 | state novelty |
| salvage8 | 1 | 9、10、41 | 356、368、560 | salvage |
| salvage8 | 2 | 3 | 295 | salvage |
| salvage8 | 3 | 53 | 570 | state novelty |

salvage 共尝试 151 次，4 次成功入队，但四次都未验证。`salvage_succeeded` 只证明入队成功，不证明代码收益。salvage 提取的是候选窗口中可用的无错消息子序列，不能仅凭计数把它描述成已发现有价值前缀。

本地源码的 `entry_can_fuzz_full_session()` 要求存在 region 且每个 region 都有状态序列；`provisional_select_service()` 在此条件失败时以 `no-executable-M2` 退出。这能解释记录含义，但归档没有给出具体哪个 region 缺失，当前本地源码也不自动等于历史二进制的构建源码，因此不在此认定具体实现根因。

shadow 提供了应继续调查的正面线索：gate 选中的 23 个拒绝候选中有 2 个 shadow 阳性；salvage 的 21 个中有 2 个阳性。具体是 gate run1 candidate7、run2 candidate1，以及 salvage run2 candidate1、run3 candidate3。其中 gate run2 和 salvage run3 的候选原始 `G_code=false`、`G_state=true`，说明初始无代码证据的候选也可能在小步变异中出现代码证据。

这仍不构成 Q2 的成功结果：shadow 是有选择的诊断样本，没有持久保留收益，也没有与普通变异匹配预算。日志 `shadow_new_edges` 合计 11、16，在本地实现中实际是 `hnb==2` 阳性调用次数；shadow 不更新 virgin bitmap，同一未见边可重复计入，不能写成独立发现 11/16 条新边，更不能代替 provisional conversion。

**Q2 的准确表述：本批没有执行到可评价 Provisional Validation 的阶段；shadow 暗示存在被拒候选的后续代码潜力，但尚未证明可转化收益，更未证明普通变异难以发现。** direct 的唯一阳性是候选原始试执行，不能记作延迟验证收益。

## 6. Q3：控制器关闭，而且实际选择都在 warmup

九份 `run-config.jsonl` 均为 `calibration=false`。332 次 scheduler selection 全部 `reason=warmup-eligible`，episode 中 `sampled_theta=-1`。323 次 `posterior_updated=true` 是被动后验更新，不能证明后验影响了动作。本地源码也区分了“记录/更新 posterior”和“开启 Calibration 后用 posterior 计算选择分数”；FAVOR 的加权选择还需要完成五轮状态遍历。

执行类别名称中的 `calibration` 指 AFL seed calibration，与论文中的在线 Calibration 调度机制是两件事。

因此本批既不能证明 Calibration 有效，也不能证明无效。即使增加同样配置的重复次数，也不会补出一个未开启的处理组。后续对比必须同时验证控制器开启、确实越过 warmup、有实际加权选择，并设置简单在线调度对照。

## 7. 阻断效果结论的覆盖采集缺陷

对九份归档的全部 `checkpoints.jsonl` 及对应 replay log 逐输入核查，**5,035 / 5,300 = 95.0%** 的输入没有 session gcda。缺失与成功登录完全一致地相关：

| 回放日志 | 有导入 gcda | 缺 gcda |
|---|---:|---:|
| 出现 `230 User logged in.` | 0 | 5,008 |
| 未出现上述成功登录响应 | 265 | 27 |

这不是只有少量崩溃会话无法 flush：另有 **2,225 个正常 exit 0 的回放也没有 gcda**。每次运行的前 184 个 initial-queue 输入全部缺失，累计分支为零；因此不能把零值解释为初始种子没有执行代码。各臂缺失比例分别为 1,773/1,861（95.27%）、1,628/1,723（94.49%）、1,634/1,716（95.22%）；相近的缺失率仍不能消除“成功登录后的路径整体不可见”的系统性偏差。

可直接复核 wrapdirect8/run1 的两个归档成员：

- `out-bftpd-loopfuzz/cov_over_time.csv.v4/replay-000001.log`：成功登录，正常执行文件/目录相关命令，最后 `221 See you later...`；checkpoint 却是 `imported_gcda=[]`、分支 0。
- `.../replay-000185.log`：USER 被变异为未知命令，后续多为 `503 USER expected.`；反而导入了 12 个 gcda 文件，首次增加 146 个分支。

二者日志和对应 checkpoint 元数据保存在 `data/coverage/coverage.json` 的 `evidence_logs`，可回到原归档验证。`terminal.json` 的 `replay_anomalies=0` 没有涵盖这一问题；回放中的 SIGPIPE 被分类为 finding，不能据其数量宣称发现独立漏洞。

九次覆盖 scope 相同，采集到的分支集合并集为 198、交集为 197，唯一差异是 direct3 未采集到 `commands.c:209:branch0`。这只说明**不完整观测集合**接近，不能证明真实代码覆盖饱和，也不能证明各臂非劣效。

本地代码显示 collector 创建 jail 内 gcov 目录，而 bftpd 登录后降权；目录对降权用户不可写是待复现的疑点。`gcov.patch` 已在 chroot 后 unset `GCOV_PREFIX`，不能直接断言是简单双重前缀。审计确认的是“登录成功后 gcda 系统性缺失”，具体权限或 flush 原因需要单独复现。

已保留 dense checkpoint 曲线与公共时间/公共执行预算 AUC，但全部标为 diagnostic，不用于方法收益比较。覆盖量度本来也是“已保存 corpus 的累计回放覆盖”，而非精确的在线首次分支发现时间；修好采集后也需保留这个口径限制。

## 8. LLM 请求情况与成本口径

| 三次运行合计 | wrapdirect8 | wrapgate8 | salvage8 |
|---|---:|---:|---:|
| 调用记录 | 673 | 676 | 677 |
| 成功 | 649 | 655 | 656 |
| transport-error | 24 | 21 | 19 |
| api-error | 0 | 0 | 2 |
| 已报告 prompt + completion tokens | 723,136 | 710,842 | 732,207 |

合计 2,026 条请求记录，1,960 次成功。此次不是全程无效 KEY 导致没有 LLM 输入的批次。两个 API 错误缺少 HTTP 状态字段，按 seq 命名的原始响应又被后续成功响应覆盖，无法从本批恢复其 HTTP 状态；不据此声称 401 仍存在。

调用 seq/cum_calls 不是跨 fork 的唯一请求键，累计 tokens 也不单调；应逐行统计请求与 usage。上述 tokens 是已报告 usage，不保证覆盖无 usage 错误的实际计费。LLM 初始化请求有并发，不能把每个请求 latency 简单相加后从 95 分钟中相减；脚本同时保留时间区间并集。目标调用耗时也不能替代总 CPU/墙钟成本。

## 9. 最有利于论文、同时可证伪的后续顺序

1. **先修测量，再重算现有 corpus。** 用成功登录及执行 STOR/LIST/HELP/QUIT 的固定回放作为采集验收：正常结束且确实导出登录后 gcda；保留用户/权限、输出路径及 flush 证据。现有 queue 可以重新离线回放，先恢复有效结果；不需要立即重跑整场 campaign。重新回放只能恢复已保存输入的覆盖，无法恢复从未保留的临时输入。
2. **先使 provisional 获得真实服务，再评价价值。** 对可执行候选验证实际调用推进、预算扣减、TTL/censor/convert 归因；对不可执行条目记录具体 region 与状态注释失败原因，确保处理策略不把 0 服务混作验证无收益。尤其复核本批 shadow 阳性的四个候选，但其 shadow positivity 不保证修复后重放一定成功。
3. **Q1 用固定候选流隔离准入策略。** 比较 direct、gate-only、gate+provisional，保持候选流和源种子一致，分开统计候选试执行、后代验证、shadow、普通 mutation、LLM/CPU/总墙钟成本与可保留代码收益；保留 live campaign 作为外部有效性验证。达到相同有效收益时用更少预算，或同预算下获得更高收益，才能支持资源效率贡献。
4. **Q2 用等预算反事实。** 对状态阳性而初始代码阴性的同一候选，把 provisional 后代搜索与普通 mutation 对照匹配调用预算；比较可重放的独有代码分支、首次收益成本与持久保留后的后续收益，不能只比较入队率或转换率。
5. **Q3 单独建立实际启用的处理组。** 对齐 gate/provisional 与其他条件，比较 Calibration、EWMA、run-rate 和固定策略；记录 warmup 后实际生效的选择数。不能只延长本批关闭 Calibration 的三臂来回答 Q3。

本批最值得继续追踪的线索是“部分被拒的 state-positive/code-negative 候选，在 shadow 中出现后续代码证据”。它与 Q2 的核心动机相符，但目前的 provisional 零服务使这条贡献链条尚未闭合。Q1 已有可量化机制观察，幅度有限且必须扣除诊断成本；Q3 需要新的有效实验设计。

## 10. 产物与复现

- `data/manifest.json`：九份原归档 SHA256、status、配置与排除的 incomplete 文件；也记录本地解释用源码的哈希，不将其当成历史构建证明。
- `data/per_run.csv`、`data/summary.json`：合并核对后的逐次运行指标与各臂汇总。
- `data/workload/`：请求、调用与耗时账本审计。
- `data/provisional/`：候选准入、血缘、shadow、九个 provisional 生命周期。
- `data/coverage/`：覆盖完整性、dense 诊断曲线、认证日志证据与分支集合。
- `figures/mechanism_audit.png`、`.svg`：逐次运行的后代/诊断工作量、耗时和覆盖缺失情况。

在仓库根目录运行：

```bash
bash ablation/analysis-bftpd_20261027T150457/scripts/run_analysis.sh
```

或显式指定仓库和新的输出目录：

```bash
bash /path/to/analysis-bftpd_20261027T150457/scripts/run_analysis.sh /path/to/ChatAFL-master /path/to/new-analysis-output
```

依赖 Python 3、numpy、matplotlib；原始 tar/status 全程只读。脚本重建 JSON/CSV/图形，并检查三个独立审计的哈希、候选数、配置与执行总数一致性。报告为人工解读，复现脚本不自动改写正文。
