以下是领域专家针对【/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz/main.tex】内容给出的最严谨专业的修改建议，必须严谨结合修改建议进行修改，要求修改后main.tex编译成main.pdf后不超过25页。

问题1：缺乏 LoopFuzz-no-admission 对照，核心贡献无法被因果隔离

需要修改和更新的位置： Section 4.2，5.3， 8，Abstract，Conclusion

问题： 论文的核心主张是runtime admission control 能提升 LLM-guided stateful fuzzing，但当前消融实验只包含关闭 local repair，frontier scheduling，hypothesis validation、adaptive triggering，没有包含最关键的 LoopFuzz-no-admission。论文第一版本中现在也承认该条件不存在，因此现有实验只能支持“integrated control policy”的整体效果，不能证明 P/U/R/G admission boundary 本身的独立贡献。

建议： 你考虑下能不能这样，最优方案是补充 LoopFuzz-no-admission：保持相同 LLM endpoint，prompt，query budget，plateau trigger，scheduling policy 和 schema check，仅绕过 P/U/R/G admission，将 request-producing outputs 直接入队。若无法补实验，则要在标题，Abstract，Contributions，RQ 和 Conclusion 中降低表述强度，将主张改为“integrated closed-loop control strategy improves state exploration”，不要写成 admission formula 已被独立验证。

 

问题2：缺少 candidate-level P/U/R/G 日志，机制证据链不闭合

位置： Section 4.2，Table 2，Section 5.4， 6， 8

问题： 表2 定义了 P/U/R/G admission predicates，但 Section 5.4 明确说明当前 archive 不包含 normalized admission-event logs，因此无法恢复 U/R/G pass rates，rejection reasons，per-candidate repair latency 或 admission-rate summary。这样一来，论文无法量化“哪些 LLM candidates 被过滤，为什么被过滤，过滤后是否避免 queue pollution”。

建议： 增加机制表，至少报告每个 target 的 LLM proposals，P fail，U fail、R fail、G fail、admitted count、admission ratio、median bounded-trial latency、median coverage/IPSM gain。若历史 archive 无法恢复，应在 Threats 中明确承认，并在主张中避免声称已量化 semantic drift 或 admission effectiveness。

 

问题3：bounded trial execution 的运行时开销未量化，影响公平性判断

位置： Section 4.2， 5.4，Section 8

问题： LoopFuzz 对通过 P 的候选执行 bounded trial，再根据 U/R/G 决定是否入队。每次 trial 都是真实网络交互和覆盖测量，会占用 24 小时 wall-clock fuzzing budget。但论文中没有报告 trial 次数，平均 trial 延迟，trial 总耗时，因此减少了多少普通 mutation executions。现有 Table 4 只给 run-level LLM/token/validation counters，不足以判断 LoopFuzz 的收益是否伴随额外执行预算消耗。

建议： 在 Table 4 或新增 Overhead Accounting 表中报告：bounded trial count、trial latency、LLM-call latency、total time in LLM path、normal executions/sec、coverage per million executions。若无法准确恢复，至少给出上界估计，并在 Threats 中明确写明 trial overhead is not normalized across systems。

 

问题4：RQ1 预设“open-loop generation 会导致 coverage regression”，但数据并未充分支持该前提

位置： Section 5 RQ1、Section 6.1

问题： RQ1 问 LoopFuzz 是否避免 direct open-loop generation 造成的 coverage regressions。但 Section 6.1 的结果显示 ChatAFL 相对 AFLNet 仅在少数目标上低于 AFLNet，例如 Exim，在多个目标上 ChatAFL 持平或更好。RQ1 的措辞将“coverage regression”作为前提，会让审稿人质疑实验问题设计带有预设结论。

建议： 将 RQ1 改为中性问题，例如：“Does LoopFuzz improve branch coverage relative to AFLNet and ChatAFL under the closest implementation lineage?” 在 Section 6.1 中明确说明 ChatAFL 并非普遍 regression，LoopFuzz 的价值主要是进一步提升或稳定，而不是普遍“避免回退”。

 

问题5：安全发现完全缺失，和 Computers & Security 期刊定位存在张力

位置： Abstract、Section 5.2、Section 7、Section 8、Conclusion

问题： 论文面向 protocol fuzzing 和安全期刊，但没有报告 unique crashes、bugs、vulnerabilities、CVE 或可复现 crash triage。Section 5.2 明确说 crash discovery 不属于 endpoint analysis，因为 crash triage 和 root-cause validation 未规范化。 这会使审稿人质疑论文的安全价值是否足够。

修改建议： 最好补充一个 Bug/Crash Triage 小节：报告每个 fuzzer-target 的 unique crashes、dedup 方法、复现情况、root-cause 状态和是否为已知 bug。若无法完整 triage，至少给初步统计并明确本文是 campaign-control/coverage/state-exploration study，不声称漏洞发现优势。

 

 

问题6：Hyp. pass 大量为 0%，但论文没有解释这对 Grammar Hypothesis Loop 和 repair 贡献的影响

位置： Table 4、Section 5.4、Section 6、Section 7

问题： Table 4 中多个 target 的 Hyp. pass 为 0.0±0.0%，包括 LightFTP、Exim、Live555、Kamailio、Forked-daapd、Lighttpd1；bftpd 和 Pure-FTPd 也很低。与此同时，论文将 Hypothesis-Driven Modeling 和 Counterexample-Guided Local Repair 作为贡献。若 hypothesis validation 几乎不通过，读者会怀疑主要收益是否来自 scheduling 或 plateau control，而不是 grammar hypothesis / repair。

建议考虑： 增加 “Interpreting low hypothesis-pass rates” 小节，明确 Hyp. pass 是否是 sampled hypothesis validation pass，而不是 request admission pass。进一步报告 repair 被触发次数、repair 后是否提升 admission 或 gain。如果 repair 很少生效，应降低其贡献表述，把它描述为可审计机制或潜在机制，而非主要实验证实贡献。

 

问题7：Forked-daapd 是核心负例，说明 IPSM edge 与 branch coverage 可脱钩

位置： Abstract、Section 6.1、Section 6.5、Conclusion

问题： Forked-daapd 上 LoopFuzz 的 final b_abs 低于 AFLNet 和 ChatAFL，且方差明显更大；但 LoopFuzz 的 response-derived IPSM edges 均值略高。这说明更多 response-derived state structure 不一定转化为更深 branch exploration。手稿已有失败分析，但仍缺少定量机制证据解释哪些 state-progressive candidates 是 branch-unproductive。

建议： 将 Forked-daapd 明确写成设计边界，而不只是例外。补充 productive-edge 指标：只有伴随 new coverage、favored queue entry 或后续 branch gain 的 IPSM edge 才计为 productive。并报告 Forked-daapd 的 plateau calls、candidate admissions、state-progressive but branch-unproductive 比例；若无法恢复，应承认 state-signal mismatch 目前只是合理解释而非已证实机制。

 

问题8：外部 NSFuzz/MBFuzzer artifacts 不可直接比较，容易被误读为 SOTA 排名

位置： Section 5.2、Table 7、Table 8、Table 9、Section 6.3、Conclusion

问题描述： NSFuzz branch artifacts 与 AFLNet-lineage b_abs 来自不同 artifact surface；NSFuzz edge count 也不等同于 AFLNet-lineage response-derived IPSM edges。LightFTP 上 NSFuzz branch count 为 414.3±9.8，而 AFLNet-lineage rows 约为 71；同时 NSFuzz edge count 只有 11.0±0.0，与 AFLNet-lineage edges 完全不同。Mosquitto 的 MBFuzzer 也只有 worker-level replay branches，没有 AFLNet-lineage edges。

修改建议： Table 7/8/9 caption 中明确写 “not same-pipeline ranking”。主文不要用这些表支持 SOTA dominance，只作为 external diagnostics。若要主张外部竞争力，需在同一 build、instrumentation、replay、budget 下重跑 NSFuzz/MBFuzzer 或将 LoopFuzz 转换到同一 metric surface。

 

问题9：Mosquitto/LoopFuzz 运行时间严重不足，但仍出现在 benchmark 叙述中

位置： Section 5.1、Table 9、Section 8

问题： Table 9 显示 AFLNet Mosquitto 是约 1479 分钟，而 LoopFuzz Mosquitto 只有 137.4±134.7 分钟，明显不是同预算比较。虽然手稿说其不用于 performance conclusions，但 Mosquitto 仍作为 10-target benchmark 的一部分出现，容易造成误导。

建议： 将 MQTT/Mosquitto 从 primary benchmark 叙述中移出，放入 artifact-integrity appendix。明确说明提前终止原因：crash、harness failure、timeout、API failure 还是 archive 缺失。若无法解释，应在 Threats 中承认这是数据完整性问题。

 

问题10：模型端点披露不完整，复现性仍不足

位置： Section 5.1、Section 8

问题： 手稿写 ChatAFL 和 LoopFuzz 使用同一个 pinned OpenAI-compatible gpt-5.4-mini endpoint，并报告 temperature、attempts 和 max_tokens，但没有给出完整 endpoint provenance、模型快照日期、API provider、是否为 public model、是否可由审稿人访问、默认 top_p / penalties / seed 行为。当前公开资料中存在 GPT-5.4 mini 相关模型页面，但如果实验用的是“OpenAI-compatible”私有或代理端点，仍需明确说明可复现性边界。

建议： 在 Section 5.1 中补全：provider、exact model ID、snapshot/version date、endpoint URL 类型、是否公开可访问、默认参数值、是否支持 seed。若是私有 endpoint，应明确写出“not bit-for-bit reproducible through public OpenAI API”，并提供 logged prompts/replies 作为 replay artifact。

 

问题11：ChatAFL baseline 的 LLM 替换策略没有解释清楚

位置： Section 5.1、Section 5.2、Threats

问题描述： 手稿说 ChatAFL 和 LoopFuzz 使用同一 pinned endpoint，以控制 LLM 差异；但未充分说明这是否偏离 ChatAFL 原始实现的模型、temperature 或 prompt setting。若 ChatAFL 原始系统用不同模型，而本实验替换为新 endpoint，则结果是“same-endpoint reimplementation comparison”，不是原始 ChatAFL paper 的直接复现。

修改建议： 明确写成：本实验比较的是 AFLNet/ChatAFL-lineage under a controlled shared model endpoint，而非原始 ChatAFL artifact 的完全复现。补充原始 ChatAFL 配置与本文配置的差异表，并在 Threats 中说明该替换可能改变 ChatAFL baseline 性能。

 

问题12：RQ1、RQ2、RQ3 使用高度重叠的数据，研究问题区分度不足

位置： Section 5、Section 6.1–6.3

问题描述： RQ1 问 whole-campaign effect，RQ3 问 end-of-campaign outcome，两者主要都由 Table 5 endpoint b_abs / edges 回答。RQ2 虽然强调 IPSM escape dynamics，但结果也主要使用 final edges 和 Fig. 4 trajectory。三个 RQ 之间的证据高度重叠，容易显得实验设计重复。

修改建议： 重组 RQ：RQ1 评估效率，例如 time-to-X coverage 或 area under coverage curve；RQ2 评估 state exploration endpoint 和 trajectory；RQ3 评估稳健性，例如 run-to-run variance、coefficient of variation、negative-target behavior。这样每个 RQ 对应不同指标，不只是重复 endpoint 表。


13：LightFTP 的 branch coverage 早期饱和，作为 b_abs 改进证据的信息量很低

位置： Table 5，Figure 3、Section 6.4

问题： LightFTP 在 AFLNet/ChatAFL/LoopFuzz 的 same-build lineage 中 branch coverage 约 71，并在早期饱和；手稿也写到 AFLNet 和 ChatAFL 约 60 分钟到 71，LoopFuzz 约 120 分钟到 71.7，之后到 1440 分钟基本不变。 这说明 LightFTP 对 b_abs endpoint 的区分度很低。

建议： 在 b_abs 结果统计中将 LightFTP 标注为 saturated target。不要用它支撑 coverage breadth 的叙述。对 LightFTP 的主要价值应转向 cross-artifact metric divergence 和 IPSM edge behavior，而不是 branch-coverage improvement。

 

14：P/U/R/G 中 R 和 G 的边界仍有语义重叠

位置： Section 4.2，Table 2、Section 4.2.3

问题： R 的 pass rule 包含 “creates a new response-derived relation”，G 的 pass rule 包含 “new IPSM node/path/edge”。这两者在实现层面可能重叠，读者不容易理解什么时候 R pass 但 G fail。手稿说 R 是 reachability、G 是 campaign novelty，但 Table 2 的定义仍不够清晰。

建议： 修改 Table 2：R 只判断是否到达非拒绝/目标/可用状态序列；G 单独判断该 trial 相对当前 global campaign 是否产生新 coverage、new IPSM edge、favored entry。增加一个具体例子：candidate 到达目标状态所以 R pass，但该 edge 已由其他 execution 先注册且无 coverage delta，所以 G fail。

 

15：productivity(s) 定义缺失，调度公式不可复现

位置： Section 4.4

问题： β(s) 公式中使用 p_s = productivity(s)，且阈值 p_s < 0.005 影响状态惩罚；但正文没有精确定义 productivity(s) 是 coverage-producing execution 比例，IPSM-edge discovery rate，queue-favored rate，还是其他指标。

建议： 在公式后补充严格定义，例如：p_s 是最近 W 次选择 state s 的 executions 中产生 new coverage bit 或 new IPSM edge 的比例。明确 W，更新窗口，分母为 0 时的默认值，以及 0.005 阈值来源。

 

16：h(s) 在线更新规则缺失，状态 promotion/demotion 不可复现

位置： Section 4.4

问题： 手稿定义 h(s)∈{0,1,2}，并说它由 response-code classification 初始化且 online updated，使状态可 promoted/demoted。但没有说明从 0 到 2、从 2 到 1、从 1 恢复到 0/2 的具体阈值、窗口或衰减规则。

建议： 增加伪代码或表格：例如连续 k 次 productive execution 后设为 2；连续 m 次 rejection 或 timeout 后设为 1；若后续产生 coverage/IPSM gain 则恢复。若实现已有固定常数，正文必须披露，以兑现“constants reported for auditability”的承诺。

 

17：adaptive plateau threshold 的更新与 unproductive streak 之间存在潜在触发歧义

位置： Section 4.4

问题： τ 根据 edge growth rate 每 60 秒调整：Ė>5 时 700，1<Ė≤5 时 600，Ė≤1 时 512。plateau path 在 unproductive streak reached τ 时打开。若 τ 随 Ė 降低而下降，而 streak 不重置，则可能出现 streak “追上”下降阈值而触发 plateau 的情况。正文没有说明 τ 更新是否只在 streak reset 后生效，或是否会立即作用。

建议： 明确 τ 更新规则：τ 是否按窗口生效，streak 是否在阈值改变时重置，是否使用 hysteresis 或 minimum dwell time。若实现中不存在问题，应给一句实现限定；若无法证明，应在 appendix 中补充触发日志分布。

 

18：plateau activation 差异很大，但未做分层分析

位置： Table 4，Section 5.4，Section 6

问题： Table 4 中部分目标 plateau calls 接近 64-call budget，例如 LightFTP、bftpd、Pure-FTPd；但 ProFTPD、Exim、Kamailio、Forked-daapd 明显更低。该差异直接关系到“LLM intervention 到底是否发挥作用”，但结果部分没有按 high-activation / low-activation target 分析收益来源。

建议： 增加 Plateau Activation Analysis：按 plateau calls 将目标分组，比较每组的 branch/edge gain、LLM calls、Hyp. checks、Hyp. pass、token volume。特别解释 ProFTPD/Exim/Kamailio 的 gains 是来自低频 intervention、initial enrichment、state scheduling，还是普通 mutation path。

 

19：Prompt/token counters 方差很大，但没有异常值或分布分析

位置： Table 4，Section 5.4

问题： Table 4 中多个 token / hypothesis-check counters 方差很大，例如 LightFTP prompt tokens、Pure-FTPd prompt tokens、Kamailio hypothesis checks、Lighttpd1 hypothesis checks 等。这说明运行间机制行为差异明显，但论文只报告 mean±SD，没有展示分布、异常运行或与 endpoint 的关系。

建议： 增加 per-run scatter 或 appendix table：x 轴为 LLM calls / plateau calls / token count / Hyp. checks，y 轴为 final b_abs / edges。说明异常 token 使用是否来自长 prompt、重复 retries、target-specific logs，还是正常 stochastic variation。

 

20：ablation 结果缺少统计检验，不能支撑机制必要性叙述

位置： Section 5.3、Table 10、Section 6.6

问题： Table 10 来自独立 ablation archive，且 full-controller rows 与 primary archive 不同。手稿说明两者不应完全一致，这是合理的；但如果只报告 delta 而没有 p/q/effect size 或 confidence interval，就不能判断每个 ablation 的变化是否超出随机波动。

建议： 为每个 ablation vs full-controller 增加 Mann-Whitney p/q，Cliff’s δ，bootstrap 95% CI。小幅 delta 不要解释为机制趋势。Table 10 caption 中强调该表衡量 exposed sub-policies sensitivity，而不是完整 admission-boundary necessity。

 

21：主实验只有 selected cache，没有完整 launch ledger，存在 survivorship bias 风险

位置： Section 5.1、Table 3、Section 8

问题： 现在论文中说明 primary selected cache 中每个非 MQTT target-fuzzer cell 都有 10 selected eligible runs，但同时承认当前 package 不保留完整 raw pre-filter launch ledger。selected cache 的 10/10 不能证明所有 planned launches 都成功，也不能排除 artifact recovery failure 或 pre-filter failure。

建议： 补充 launch manifest：planned，launched，completed，excluded <1400min，missing metrics，artifact failure，selected。每条 excluded run 给 reason。没有这份表时，Table 3 应避免写得像完整计划矩阵无缺失，只能说 selected cache 完整。

 

22：wall-clock fairness 仍不够充分，缺少 CPU/resource trace

位置： Section 5.1、Section 8

问题： 手稿说明每个 container 有 one-CPU quota，但 runs 不 pin 到 physical cores，且 aggregate artifact 不保存 global batch schedule，因此无法重建 co-scheduling。对于 fuzzing，CPU contention，I/O，daemon reset 和 network timing 都可能影响 endpoint。

建议： 增加 cgroup CPU usage，execs/sec，daemon resets，coverage per execution，batch schedule，resource trace。至少把 trajectory claims 限定为 same container quota 下的 descriptive wall-clock traces，不要隐含 CPU-time-normalized superiority。

 

23：LLM stochasticity 和可复现性处理仍不足

位置： Section 5.1，Section 8

问题： Plateau assistance temperature 为 1.2，且模型端未设置 random seed，top_p，presence/frequency penalty 等参数，默认值依赖 provider。prompt reuse filter 也不是 deterministic memoization cache。

建议： 固定并报告所有 sampling parameters；若 endpoint 不支持 seed，明确说明。发布 raw prompts，raw replies，parsed actions，schema results，latency、token counts。增加 replay mode：用已记录 LLM actions 重放 fuzzing path，以区分模型随机性和控制策略效果。

 

24，标题和摘要暗示通用 protocol fuzzing，但证据主要限于文本/半文本 request-response protocols

位置： Title，Abstract、Introduction、Section 8、Conclusion

问题： 论文题目和摘要使用 broad “stateful protocol fuzzing”，但 primary targets 是文本或半文本 request/response protocols；P 的 parseability、U 的 response-code classification 和 IPSM response-derived signal 对二进制，加密，强格式协议未验证。Section 8 才讨论范围限制，出现较晚。

建议： 在 Abstract 或 Introduction 末尾提前限定适用范围：LoopFuzz is designed and evaluated for textual or semi-textual request/response protocols where response-derived progress is visible. 对 TLS，QUIC，SSH，IPsec，DTLS 等二进制/加密协议，明确需要专门 adapter，避免被审稿人攻击，不声称已验证通用性。

 

25，Lighttpd1 与 Forked-daapd 共同暴露 IPSM edges 指标的适用性边界

位置： Table 6、Section 6.2、Section 6.3、Discussion

问题： Lighttpd1 上 branch coverage 显著提升，但 edges vs ChatAFL 不显著；Forked-daapd 则是 edges 均值略高但 branch coverage 显著下降。这两个目标共同说明 IPSM edges 不是普适 coverage proxy，尤其对 HTTP 低状态协议和 DAAP/DACP noisy response signal 都可能失真。

修改： 在 Discussion 增加 “When IPSM edges are informative” 小节。区分 state-rich protocols，low-state protocols，noisy-response protocols。报告 productive edges 或 edge-to-branch productivity，以减少单纯 edge count 的误导。

 

26：样本量 n=10 对部分中等效应功效不足，未量化统计结论限制

位置： Section 5.2，Table 6，Section 8

问题： 每个 cell 10 runs，使用 Mann-Whitney U + BH correction + Cliff’s δ。方法合理，但对中等效应的统计功效有限。Table 6 中多个 positive-by-mean but not significant 的结果可能是 underpowered，而非无效。

建议： 增加 bootstrap CI 和 power discussion。说明 n=10 在 BH correction 下能稳定检出的最小效应量大约需要较大的 Cliff’s δ。对 q>0.05 但 δ 中等的结果，表述为 “inconclusive under current power”，不要写成 no effect。

 

27：P/U/R/G predicate 中 target adapter rescue rule 太模糊

位置： Table 2，Section 4.2.2

问题： U 的 pass rule 中写 “adapter or productivity evidence may rescue an apparent error state”，但没有说明哪些 protocol adapter 可以 rescue，rescue 需要多少 productivity evidence，是否对所有 target 一致。该规则会直接影响 admission，若不清楚，审稿人会怀疑是否 target-specific tuning。

建议： 增加 protocol adapter rule summary：每个 target/protocol 的 rejection code/text，timeout policy、unparsable response policy、rescue threshold、state normalization、G novelty rule。把这些规则作为 reproducibility appendix。

 

28：Counterexample-guided local repair 的“一次只修一个字段/production”不是硬约束

位置： Contributions，Section 4.3

问题： 贡献列表说 repair patch one field constraint or production at a time，但 Section 4.3 又承认该约束由 repair prompt 和 audit log enforced，不是 hard AST differencing，也没有 counterexample minimization。 这会让贡献表述显得过强。

建议： 若能实现 hard AST diff，应拒绝超过一个 field/production 的 patch。若不能，则贡献改为 “prompt-constrained and audit-logged local repair”，避免暗示形式化保证。

 

29：Figure 2 与 Algorithm 1 对 repair 触发时机的表达不够一致

位置： Figure 2，Algorithm 1，Section 4.3–4.4

问题：认真检查一遍， Figure 2 中 Tier-1 sampling 通过 counterexample 箭头直接指向 Tier-2 repair，容易暗示 sampling failure 直接触发 repair。但 Algorithm 1 中 repair gate 位于 adaptive plateau gate 内，sampled validation 和 repair 并不是同一个即时触发逻辑。

建议： 修改 Figure 2 箭头标签为 “counterexample evidence accumulates”，并在 caption 说明 repair only occurs when plateau and repair gates both open。或者在 Algorithm 1 中把 counterexample accumulation 与 repair trigger 分成两个明确状态变量。

 

30：Contributions 列表将实验发现作为贡献，层级混淆

位置： Section 1 Contributions

问题： 前四项是设计或机制贡献，第五项 “Finding on Closed-Loop Control” 是实验观察。将 finding 与 method contribution 并列，会让贡献列表显得不规范。

建议： 将第五项移出 contributions，改为 Introduction 末尾的 evaluation summary。Contributions 只保留方法、机制、artifact 或 evaluation methodology 本身。

 

31：LightFTP 的 NSFuzz artifact 差距巨大，需要更强警示

位置： Section 6.4，Table 7，Table 8

问题： LightFTP 是 cross-artifact metric divergence 的最强例子：same-build AFLNet-lineage b_abs 约 71，而 NSFuzz artifact branch count 为 414.3；同时 NSFuzz artifact edge count 只有 11，AFLNet-lineage edges 超过 180。 这很容易被读者误读成 pipeline error 或不公平比较。

建议： 在 Section 6.4 开头明确写：LightFTP demonstrates why auxiliary NSFuzz rows cannot be read as same-metric rankings。必要时将 NSFuzz 表移到 appendix，主文只保留概述。

 

32：Mealy-style abstraction 符号引入后使用不足

位置： Section 2.2、Section 4

问题： Section 2.2 引入 M=(Q,I,O,Δ̂,Λ̂,q0)，但后续主要使用 Q、edges 和 transition evidence；I、O、Λ̂ 几乎没有承担后续推导作用。 这会增加形式化负担，却不增强论证。

建议： 简化该段，只保留 Q，observed transition relation 和 q0。或者在 Section 4 中系统性回调这些符号，例如明确 deg⁺(s) 来自 Δ̂，response classification 来自 Λ̂。

 

33：Conclusion 与 Abstract 重复度过高，且没有提供新的 take-away

位置： Abstract、Section 9 Conclusion

问题： Conclusion 重复 Abstract 中的主要数字：edges vs AFLNet/ChatAFL、b_abs vs AFLNet/ChatAFL、Forked-daapd negative case、NSFuzz mixed picture。 结论虽准确，但缺少更高层次的设计洞察。

建议： Conclusion 改成三点：一是 closed-loop control 的适用边界；二是 response-derived IPSM 何时有用、何时会误导；三是未来需要 no-admission ablation，candidate logs，same-pipeline SOTA rerun。避免重复摘要数字。

 

34：缺少真实 archived trace case study 支撑 semantic drift 叙事

位置： Section 2.4、Figure 1、Section 6、Discussion

问题： FTP RETR before PASV/PORT 是合理 motivating example，但当前没有说明它是否来自真实 archived execution。由于 candidate-level logs 缺失，读者无法看到实际 semantic drift 被 admission 拒绝的案例。

建议： 增加 2–3 个真实 trace case study：state summary，LLM candidate，P/U/R/G decision，server response，queue outcome，repair/scheduling consequence。如果没有真实日志，应把 Figure 1 明确标注为 illustrative example，而非 empirical evidence。

