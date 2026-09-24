
故事线调整：

不要再把这篇论文讲成：LLM 帮助协议 fuzzing 找到更多漏洞了

把论文从“LLM + 若干规则”升级成：一个能够在线判断协议状态信号是否可信的证据校准控制器。

相应标题：When Protocol States Mislead: Calibrating Response-Derived Feedback for LLM-Assisted Stateful Fuzzing

这个故事也有学术价值。

我们的目标期刊是这个：Journal of Network and Computer Applications
我今年投过一篇到这个期刊，但是还在审稿中，到时候写好我可以很快帮你投稿~

最聪明的主线不是：

LLM 找到更多漏洞。

而是：

LLM 会产生候选，response-derived state 会提供代理反馈，但二者都不能被直接信任；系统必须通过真实执行、分层准入和在线代码生产率校准，决定什么值得进入长期队列、什么值得继续探索。

最重要的执行顺序是：

冻结原项目；
补 candidate/state-selection 日志；
拆分 (G_{\text{code}}) 和 (G_{\text{state}})；
实现 provisional/durable 两级队列；
实现最简单的 discounted Beta-Thompson calibration；
四 target pilot；
pilot 不支持就立即降级 calibration；
先做 6 个、再扩展到 12 个历史 CVE；
运行五个清楚的 causal arms；
十周内完成并投稿。
这样既保留了现有 LoopFuzz 的大部分资产，也能把当前最严重的三个缺陷——缺乏 admission 对照、状态新颖性与代码进度错位、漏洞证据不统一——转换成论文的新核心。

LoopFuzz 重构与快速投稿执行方案

一、最终研究定位

1. 不再讲的故事

停止强调：LLM 能生成更多协议消息，因此发现更多漏洞或覆盖更多状态。

这个故事的问题是：

没有新 0-day 时影响力明显下降；
LLM 调用量不公平会直接破坏比较；
IPSM edge 增长不等于代码探索更深入；
当前四个模块没有被独立、因果地验证；
“LLM + 多个启发式规则”容易被审稿人认为是系统堆叠。
2. 新的关键问题

论文应该回答：当协议 fuzzer 使用响应码或响应序列作为“协议状态”时，这个状态信号什么时候是真正有用的程序进度，什么时候只是没有代码收益的表面新颖性？对于 LLM 生成的候选，系统能否利用运行时证据在线校准这种信号，再决定是否进入长期队列及是否继续调度？

这比“LLM 找到更多漏洞”更稳，因为它研究的是一个普遍的方法学问题：

Response-derived state novelty is an imperfect proxy for program progress.

3. 推荐标题

When Protocol States Mislead: Evidence-Gated Admission and Online Feedback Calibration for LLM-Assisted Stateful Fuzzing

因为“States Mislead”本身并非全新发现。StateAFL 已经明确指出，响应码可能不能正确反映服务器内部状态，甚至产生冗余状态和浪费的测试。

我们不要声称：We are the first to show that response-derived states can be misleading.

应该声称：Prior work identified limitations of response-derived state abstraction. We study a different problem: how a response-visible fuzzer can retain its deployability while learning, online, whether each observed state signal is productive enough to guide LLM proposal admission and subsequent fuzzing.

二、最终只保留三个主要贡献

Contribution 1：Evidence-gated queue admission

推荐表述：We introduce an execute-before-promote admission controller that prevents LLM-generated protocol requests from entering the durable mutation queue until they receive structural, behavioral, reachability, and program-progress evidence from the live target.

不要只说“检查生成内容是否合法”。重点是：

LLM 只是 hypothesis generator；
生成不等于接受；
每个候选必须先在 bounded trial 中执行；
durable queue 是一种需要证据支持的长期资源；
admission 的目标是减少 queue pollution，而不是提高文本质量。
Contribution 2：Online calibration of response-derived state utility

推荐表述：We learn the downstream code productivity of response-derived states online, distinguishing state-space expansion from useful program progress and reducing the scheduling weight of edge-rich but branch-poor states.

这里不要把 Beta-Bernoulli、UCB 或 Thompson sampling 本身写成算法创新。

已经存在：

把协议状态选择建模为多臂老虎机的工作，而且其初步结果甚至弱于 AFLNet；The Bandit’s States
使用 Beta-Bernoulli 和 Thompson sampling 做 fuzzing seed scheduling 的 T-Scheduler；T-Scheduler
2025 年已经出现 state-significance-guided protocol fuzzing。SSGFuzz
因此，你们的新意必须是以下组合：

被校准的是 response-derived proxy 的可靠性；
校准目标是独立的 code productivity；
校准同时作用于 LLM 候选准入和状态调度；
有 candidate-level、state-selection-level 的可审计证据；
在 edge/branch 明显不一致的真实 target 上验证适用边界。
Contribution 3：Controlled empirical evidence

推荐表述：We conduct a controlled evaluation that isolates admission and state calibration under matched model configurations, intervention policies, resource limits, launch accounting, and coverage instrumentation, complemented by information-controlled rediscovery of historical vulnerabilities.

注意不要过度承诺“完全等 token、完全等调用次数”，因为自适应 campaign 的运行轨迹不同，plateau 出现次数也可能不同。

更严谨的说法是：

equal model configuration；
equal maximum call/token budget；
identical intervention-trigger definition；
identical prompt information policy；
actual calls/tokens 全部报告；
另做 cost-matched comparison。

三、必须对现有实验设计做的关键调整

1. 不要把状态效用继续写成 U(s)

当前 P/U/R/G 中，U 已经表示 response acceptability。再定义：

[
U(s)=P(\text{productive gain}\mid s)
]

会造成符号冲突。

建议改成：

[
\theta_s=P(r=1\mid \text{scheduler selects state }s)
]

或者：

[
C(s)=P(\text{code progress}\mid s)
]

全文统一称为：

state productivity；
calibrated utility；
productivity posterior；
calibrated confidence。
不要再用 U(s)。

2. 必须区分两种 edge

全文任何地方都不要单独写“edge”。

统一使用：

IPSM/state edge：响应状态机中的边；
code edge 或 code branch：程序覆盖反馈。
否则“edge 增长但 branch 下降”的核心故事会被术语混淆。

3. 当前 G predicate 需要拆开

现在 G 把以下信号混在一起：

new code coverage；
new IPSM node/path/edge；
favored queue entry。
但新故事的核心恰恰是：

IPSM novelty 不能自动等同于 code progress。

因此建议把 G 拆成：

[
G_{\text{code}}=\text{new code branch/edge or favored code-coverage entry}
]

[
G_{\text{state}}=\text{new IPSM node/path/edge}
]

这一步非常重要。否则系统一边声称“状态新颖性可能误导”，一边又允许任何新 IPSM edge 作为 durable promotion 的充分证据，逻辑会自相矛盾。

四、最聪明的算法设计：两级队列，而不是一个硬门

单纯把所有 candidate 分成“进入”和“不进入”还不够。最合理的是增加：

provisional queue；
durable queue。

1. 三种结果

情况 A：直接进入 durable queue

候选满足：

[
P\land U\land R\land G_{\text{code}}
]

即：

结构正确；
服务器响应可接受；
到达目标或 frontier；
已经产生独立的代码或 favored 证据。
这种候选可以立即进入 durable queue。

情况 B：进入 provisional queue

候选满足：

[
P\land U\land R\land \neg G_{\text{code}}\land G_{\text{state}}
]

即：

请求有效；
状态也发生了变化；
但暂时没有代码收益。
这正是 Forked-daapd 所暴露的风险类别。

该候选只能进入 provisional queue，并获得固定、小规模的验证预算，例如：

一个 AFL energy cycle；或
最多 64 次 descendant mutations；或
最多 30 秒本地验证。
出现代码收益后再晋升 durable queue；否则过期删除。

情况 C：直接拒绝

包括：

P fail：格式、字段、长度、终止符或 schema 错误；
U fail：4xx/5xx、timeout、reset、drop 或不可解析响应；
R fail：没有到达目标/frontier，停留在 sink；
没有任何 code/state gain。
2. 为什么两级队列比简单 P/U/R/G 更强

它直接解决了论文的新问题：

一个新响应状态值得保留，但证据强度还不足以支持长期进入主队列。

这产生了非常清楚的新指标：

state-only provisional rate；
provisional-to-durable conversion rate；
provisional expiration rate；
promotion latency；
avoided durable-queue entries；
downstream productivity after promotion。
这比模糊的“queue quality 提高了”更可证伪、更容易写成论文贡献。

五、在线 State-Utility Calibration 的具体设计

1. 把“state selection”定义为一次 episode

不要对每一次普通 execution 更新一次 posterior，否则：

reward 极度稀疏；
同一次调度会被重复计算；
各状态获得的 mutation energy 不同。
定义一次 state-selection episode：

scheduler 选择状态 (s)；
选择一个能够到达 (s) 的 seed；
对该 seed 执行一个固定 energy cycle；
episode 结束后计算是否产生 code progress。
主 reward 定义为：

[
r_t(s)=
\begin{cases}
1,&\text{episode discovers a previously unseen code branch/edge}
0,&\text{otherwise}
\end{cases}
]

建议：

branch/code-edge gain 作为主 reward；
favored descendant 作为次要或敏感性 reward；
不允许把 IPSM novelty 纳入主 reward，否则形成循环定义。
2. Beta-Bernoulli posterior

对每个 response-derived state (s) 维护：

[
\theta_s\sim\text{Beta}(\alpha_s,\beta_s)
]

初始化：

[
\alpha_s=1,\quad\beta_s=1
]

episode 成功：

[
\alpha_s\leftarrow\alpha_s+1
]

episode 失败：

[
\beta_s\leftarrow\beta_s+1
]

posterior mean：

[
E[\theta_s]=\frac{\alpha_s}{\alpha_s+\beta_s}
]

3. 必须考虑非平稳性

随着覆盖逐渐饱和，同一状态的成功概率会下降。单纯永久累加的 Beta posterior 隐含近似平稳假设。

建议采用 discounted update：

[
\alpha_s\leftarrow 1+\gamma(\alpha_s-1)+r_t
]

[
\beta_s\leftarrow 1+\gamma(\beta_s-1)+(1-r_t)
]

建议主实验先用：

[
\gamma=0.995
]

但必须在 pilot 后冻结，不能看完整实验结果再调。

敏感性分析只需要：

[
\gamma\in{0.99,0.995,1.0}
]

不要扩展更多超参数。

4. 调度分数

保留现有 frontier bonus，把固定的 (p_s<0.005) penalty 替换为 calibrated confidence：

[
\tilde{\theta}_s\sim\text{Beta}(\alpha_s,\beta_s)
]

[
Score(s)=Frontier(s)\cdot
\left[\epsilon+(1-\epsilon)\tilde{\theta}_s\right]
]

其中：

(Frontier(s))：现有的 frontier/topology 项；
(\tilde{\theta}_s)：Thompson sample；
(\epsilon)：最低探索权重，防止低样本状态永久饿死。
建议：

[
\epsilon=0.1
]

同样在 pilot 后冻结。

5. 不能声称什么

不要声称：

The controller learns the true protocol state.

它没有学习服务器真实语义状态，只是在学习：

某个 response-derived state signal 对后续代码探索是否有预测价值。

准确表述：

The controller calibrates the instrumental utility of an observed state proxy; it does not recover or verify the server’s semantic state.

六、Forked-daapd、Lighttpd1、LightFTP 如何变成论文核心证据

这三个不是零散的“失败案例”，而是三种 proxy misalignment 类型。


Target

现象

解释

论文中的角色

Forked-daapd

IPSM edge 增加、branch 降低

state proxy 过度扩张

false progress / overestimation

Lighttpd1

branch 大幅增加、IPSM edge 小幅增加

code progress 未被 state proxy 充分反映

underestimation

LightFTP

branch 已饱和、IPSM edge 继续增长

proxy 在饱和区继续产生表面新颖性

saturation mismatch

建议增加一个专门的 RQ：

RQ1: When does response-derived state exploration align with program progress?

报告：

每个 target 的 state-edge gain 与 code-branch gain；
state selection episode 的 productivity；
IPSM edge 数量与 downstream branch gain 的相关性；
calibrated posterior 随时间变化；
edge-rich/branch-poor state 的权重变化；
三个典型 target 的状态级案例图。
这三个 target 共同证明的不是“LoopFuzz 总是更好”，而是：

固定信任响应状态在不同程序上会产生方向相反的误差，因此需要在线校准。

七、最终实验矩阵

原来的五个 arm 思路基本正确，但需要重新定义，使每个相邻比较只改变一个因素。


Arm

LLM

Admission

Scheduler

核心作用

A. AFLNet

无

原始

AFLNet

基础非 LLM baseline

B. Controlled ChatAFL

有

open-loop/direct

ChatAFL lineage

测量开放式 LLM proposal

C. LoopFuzz-direct

有

parseable candidate 直接 durable

固定 LoopFuzz scheduler

admission 的反事实对照

D. LoopFuzz-gated-fixed

有

evidence gate + provisional queue

原固定策略

隔离 admission 收益

E. LoopFuzz-gated-calibrated

有

与 D 完全相同

posterior calibration

隔离 calibration 收益

最关键的因果比较

B vs A

回答：

加入开放式 LLM proposal 总体上带来了什么？

这不是 admission 的因果比较。

D vs C

两者必须保持：

相同 prompt；
相同 LLM output；
相同 trigger；
相同 scheduler；
相同 repair 配置；
唯一区别是 admission。
回答：

execute-before-promote 是否减少 queue pollution，并提高单位成本的代码进度？

E vs D

唯一区别是：

D：固定 (p_s) 或固定 state penalty；
E：calibrated posterior。
回答：

在线校准是否解决 edge/branch misalignment？

Controlled ChatAFL 不应强行使用相同 scheduler

如果把 Controlled ChatAFL 的 scheduler 完全改成 LoopFuzz scheduler，它就不再是可信的 ChatAFL-lineage baseline。

正确做法不是让五个系统所有条件都一样，而是：

每个因果比较中的相邻两个 arm 只改变一个核心因素。

八、Counterexample repair 的处理

1. 主实验中先关闭 repair

建议 C、D、E 三个核心 LoopFuzz arm 的主实验全部关闭 repair。

原因：

当前缺少 repair-trigger 和 before/after 事件日志；
repair 会同时影响 candidate、admission 和 scheduler；
会污染 D vs C、E vs D 的因果解释；
当前 sampled hypothesis pass rate 很低，无法支撑 repair 是主要驱动因素。
2. 只有满足条件才升级为第四贡献

增加一个次要 arm：

E-no-repair；
E-with-repair。
Repair 至少要记录：

repair_id；
repair_parent；
failure type；
counterexample；
hypothesis_before_hash；
hypothesis_after_hash；
changed_field；
validation_before；
validation_after；
post-repair P/U/R/G；
post-repair downstream gain；
repair token/latency。
只有满足以下条件才作为贡献：

有足够 repair 事件，不是每个 target 只有个位数；
repaired candidate 的重新通过率明显高于未修复候选；
post-repair downstream code gain 稳定；
no-repair vs repair 有独立的统计支持；
至少在多个 target 上方向一致。
否则统一降级为：

an optional implementation feature evaluated diagnostically.

不要因为“贡献数量多”而保留一个无法证明的贡献。三个清楚、因果成立的贡献比四个互相混淆的贡献更适合 TOSEM。

九、LLM 公平性：需要纠正原计划中的一个矛盾

1. “相同 plateau trigger”不等于“相同调用次数”

不同 fuzzer 的覆盖轨迹不同，因此 plateau 出现时间和次数也不同。

所以不能同时声称：

trigger 自适应；
实际调用次数完全相同；
实际 token 完全相同。
最合理的设计是双口径。

2. 主实验：equal-policy/equal-cap

所有 LLM arm 使用：

同一模型和版本；
同一 endpoint；
同一 temperature；
同一 top-p、penalties；
同一 max output tokens；
同一 prompt information policy；
同一 plateau definition；
同一最大调用次数；
同一最大总 token；
同一超时和重试规则。
但是实际 calls/tokens 如实报告。

论文写：

All LLM arms use identical model configurations, intervention policies, and resource ceilings. Actual calls and token usage are reported because adaptive campaign trajectories can trigger different numbers of interventions.

3. 次实验：cost-matched comparison

可以报告：

coverage gain per 1k total tokens；
coverage gain per LLM call；
CVE rediscovery per 100k tokens；
达到共同 token budget 时的 coverage；
达到共同 call count 时的 coverage。
如果需要严格相同调用次数，可以做一个固定 intervention schedule，例如每 N 次 execution 触发一次。但它只能作为 cost-controlled sensitivity，不应替代真实 plateau policy。

4. Recorded-action replay 的正确用途

Recorded-action replay 不能作为自适应系统的主要端到端比较。

原因是不同 arm 的队列和状态轨迹会发生分叉；在 A 中记录的动作，放到 B 的不同 campaign state 中未必仍然有意义。

它适合：

测试 parser；
重放 P/U/R/G；
比较不同 admission controller；
验证日志和结果确定性；
对同一个 target snapshot 测候选；
provider-free artifact evaluation。
不适合声称：

replay 后的完整 fuzzing campaign 等价于在线 campaign。

十、必须建立的日志系统

不要把所有内容硬塞进一个 candidate 表。建议至少拆成六类 append-only event。

1. run_config

每个 run 一行：

run_id；
arm；
target；
target commit；
container image digest；
fuzzer commit；
model/version/endpoint；
temperature/top-p；
token cap/call cap；
random seed；
CPU/memory quota；
start/end time；
termination reason；
schema_version。
2. candidate_event

run_id；
candidate_id；
prompt_id；
prompt_hash；
raw_reply_hash；
raw_candidate 或 artifact path；
action type；
input tokens；
output tokens；
source_state；
requested_target_state；
generation timestamp。
3. admission_trial

candidate_id；
trial_id；
P/U/R；
P/U/R reason code；
response_code；
response_hash；
timeout/reset/drop；
observed_state_sequence；
target/frontier reached；
pre/post IPSM nodes；
pre/post IPSM state edges；
pre/post code branches；
favored；
trial latency；
disposition：reject/provisional/durable。
4. provisional_event

candidate_id；
provisional_id；
validation budget；
descendant executions；
descendant code gain；
first productive descendant；
conversion time；
durable promotion；
expiration reason。
5. state_selection_episode

episode_id；
selected_state；
source seed；
alpha_before/beta_before；
posterior_mean_before；
sampled_theta；
frontier_score；
final selection score；
number of mutations；
new code branches；
new state edges；
reward；
alpha_after/beta_after；
episode latency。
校准指标必须使用 posterior_mean_before，不能用观察 reward 后更新的 posterior，否则会产生信息泄漏。

6. repair_event

只在保留 repair 时使用，字段如前述。

7. bug_event

oracle_id；
CVE_id，仅保存在独立 benchmark metadata，不进入 prompt；
reached；
triggered；
first trigger timestamp；
reproducing input；
vulnerable result；
patched result；
sanitizer stack；
root-cause signature。

十一、实验指标需要重新定义

1. 直接可计算指标

candidate generation count；
P/U/R failure distribution；
provisional admission rate；
direct durable admission rate；
provisional-to-durable conversion；
provisional expiration；
median trial latency；
token/call usage；
code gain per candidate；
code gain per 1k tokens；
state-selection productivity；
execution throughput。
2. 不要把 accepted-candidate precision 定义成即时 G pass

如果 admission 的 G 本身要求 coverage gain，那么：

[
\frac{\text{admitted candidates with gain}}
{\text{admitted candidates}}
]

会接近 100%，属于定义上的循环，不是有价值的结果。

应该定义：

Downstream productivity@H：一个 admitted/provisional candidate 是否在随后固定的 H 次 descendant mutations 内产生新 code branch。

例如：

[
Precision@64=
\frac{\text{within 64 descendants producing code gain}}
{\text{admitted candidates}}
]

3. Avoided queue pollution 需要对照，不能只靠日志推断

真正的 avoided queue pollution 应通过：

LoopFuzz-direct；
LoopFuzz-gated-fixed；
两者比较得出。

定义：

在 direct arm 中进入 durable queue、但在固定 downstream horizon 内从未产生代码收益的 candidate 数量。

不能仅统计 D arm 中被拒绝的 candidate，然后把它们全部叫作“avoided pollution”，因为其中可能存在被误拒绝但后续有价值的 candidate。

建议随机抽样少量 rejected candidate 做 shadow validation，以估计 admission false negative。

4. Calibration 指标

除了最终覆盖，还必须报告：

reliability diagram；
Brier score；
Expected Calibration Error；
AUPRC，适合成功事件稀疏的情况；
predicted productivity vs observed productivity；
state-level posterior evolution；
state-edge gain/code-gain ratio。

十二、历史漏洞基准的正确构建方式

你提出的方向是正确的，而且比继续追 0-day 更适合方法论文。已知真实漏洞是 fuzzing 评测中认可的 ground truth；近年的评测研究还特别警告，不应把“CVEs 数量”当成主要科研价值。Prudent Evaluation Practices

但需要做以下修正。

1. 不要简单使用“旧 release vs 新 release”

两个不同 release 之间可能包含：

安全补丁；
其他 bug fix；
重构；
编译配置变化；
依赖升级。
这样 patched-version 差异不一定来自 CVE patch。

最可靠的版本对是：

vulnerable base commit；
同一 base commit + upstream security patch。
即只 cherry-pick 最小官方修复补丁，其他代码和构建条件完全一致。

2. 使用 information-controlled rediscovery

严格说不应叫 fully blinded，因为构建 benchmark 的人必然知道 CVE。

准确术语：

information-controlled historical vulnerability rediscovery

控制措施：

prompt 不含 CVE 编号；
RFC corpus 不含安全公告；
seed 不含 PoC；
fuzzer 不读取 patch；
benchmark metadata 与运行环境隔离；
最好由另一位成员准备 vulnerability pair，学生只拿匿名 oracle ID。
论文可以写：

Security findings are evaluated through information-controlled rediscovery of historical vulnerabilities. Discovery of previously unknown vulnerabilities is not an optimization objective.

3. 每个漏洞必须区分 reached 与 triggered

参考 Magma 的做法：

reached：执行到漏洞相关代码；
triggered：漏洞条件真正成立。
Magma 使用真实漏洞及 source-level ground-truth instrumentation，避免用 crash 数量冒充漏洞数量。Magma

Oracle 优先级：

source-level trigger predicate；
ASan/UBSan/MSan；
deterministic crash + patch validation；
protocol semantic invariant；
differential vulnerable/patched behavior。
只有执行到 patch 行，不代表触发漏洞。

4. CVE 选择标准

每个候选必须满足：

真实历史漏洞；
patch commit 可定位；
能通过网络协议输入触发；
不依赖复杂人工配置；
可在容器内稳定构建；
能定义独立 oracle；
修复补丁规模可控；
vulnerable 与 patched 版本输入兼容；
不需要复用公开 exploit；
不属于只能通过本地文件或 CLI 触发的问题。
5. 不要第一天就做 20 个

最快方案：

第一阶段：6 个 CVE pilot

两周内先完成：

6 个漏洞；
至少 3 种协议；
vulnerable/patched replay；
oracle 稳定性测试。
退出标准：

oracle 可重复率 ≥95%；
patched 版本不触发对应 oracle；
所有基准可自动构建和清理；
seed/benchmark 中无 CVE 泄漏。
第二阶段：扩展到 12 个

6 个全部稳定后再扩展到 12 个。

只有在构建非常顺利时扩到 16–20 个。不要为了达到“20”拖延论文一个月。

6. 报告指标

CVE-level recall；
probability of rediscovery by deadline；
time-to-trigger；
Kaplan-Meier time-to-trigger curve；
reached-but-not-triggered；
patched-version oracle activation；
unique oracle/root-cause IDs；
code coverage before trigger；
executions before trigger；
tokens before trigger；
CVEs per CPU-hour；
CVEs per 100k tokens。
不以以下指标为主：

crash 文件数量；
stack-hash 数量；
sanitizer report 数量；
CVE 数量的简单加总。
7. 安全隔离

所有历史漏洞环境：

只绑定 localhost 或隔离容器网络；
禁止外网访问；
不使用 privileged container；
使用临时文件系统；
不公开未清理的 exploit corpus；
每次运行后重建 target 状态。

十三、Research Questions 与假设

RQ1：状态信号是否与代码进度一致？

How reliably does response-derived state novelty predict downstream program progress across targets and campaign phases?

指标：

state edge/code branch alignment；
calibration error；
三类 boundary target；
saturation 前后变化。
RQ2：Evidence-gated admission 是否有效？

Does execute-before-promote admission reduce durable queue pollution and improve downstream productivity under matched LLM and scheduling conditions?

主比较：

D vs C。
主指标：

downstream productivity@H；
branch AUC；
durable queue size；
provisional conversion；
cost per new branch。
RQ3：在线校准是否优于固定 state policy？

Does online productivity calibration improve state scheduling over a fixed response-state heuristic?

主比较：

E vs D。
主指标：

branch coverage AUC；
final branch coverage；
time to 95% common endpoint；
branch gain per state-selection episode；
target-level regressions。
RQ4：历史漏洞发现能力

Does calibrated evidence-gated fuzzing improve reproducible rediscovery of historical vulnerabilities?

指标：

CVE recall；
time-to-trigger；
patched-version false activation；
cost-normalized recall。
RQ5：成本与适用边界

What are the runtime, throughput, and LLM costs, and under which target characteristics does the method fail to help?

重点报告：

Forked-daapd；
saturated LightFTP；
-低 LLM activation targets；
high rejection targets；
token outliers。

十四、运行次数、资源和统计方案

1. 当前 n=10 的主要问题

现稿已经显示，在 80 个 ablation comparisons 进行 BH 修正后，没有模块比较显著。n=10 对中等效应和多重比较明显不足。

Fuzzing 评测指南通常要求：

真实程序；
多次独立运行；
长时间 campaign；
统计显著性和效应量；
完整 artifact；
不只报告 coverage；
避免挑选完成的 run。Prudent Evaluation Practices
2. 最节省资源的分层设计

所有五个 arm

每 target 先做 10 次；
每次 24 小时；
保留完整 launch ledger。
三个核心 causal arm：C、D、E

再补 10 次，使其达到：

每 target 20 次。
这比所有 baseline 全部跑 20 次节约很多资源，同时增强最关键的：

admission contrast；
calibration contrast。
如果 9 targets：

第一阶段：5 × 9 × 10 × 24 = 10,800 CPU-hours；
核心补充：3 × 9 × 10 × 24 = 6,480 CPU-hours；
合计：17,280 CPU-hours。
96 个有效 CPU core 理论上约 7.5 天，考虑失败和调度建议预留 10–12 天。

3. 不再筛选“selected completed rows”

必须保存：

planned run；
launched；
completed；
timeout；
crash；
infrastructure failure；
extraction failure；
excluded；
exclusion reason。
分析采用 intention-to-run ledger。

只有预先规定的基础设施失败可以 rerun；不能因为结果差而排除。

4. 随机化

target-arm-run launch order 随机化；
同一批机器形成 block；
每个 arm 在每个 host block 中均匀分布；
固定并保存 fuzzer random seed；
不让某个 arm 总在白天或低负载时运行；
记录容器 CPU throttling 和 exec/s。
5. 统计分析

每个 target 分别报告：

median/mean；
bootstrap 95% CI；
Mann-Whitney U；
Cliff’s delta；
BH correction。
跨 target 报告：

target-level macro average；
hierarchical bootstrap；
不把不同 target 的所有 run 混在一起当成独立样本。
时间到漏洞：

Kaplan-Meier；
right censoring；
deadline recall；
每个 CVE 单独报告。

十五、论文中图表规划

必须有的图

Motivating mismatch figure
Forked-daapd、Lighttpd1、LightFTP 的 state-edge/code-branch 对比。
Controller architecture
LLM proposal → P → bounded trial → U/R → (G_{\text{code}})/(G_{\text{state}}) → reject/provisional/durable。
Posterior calibration process
state-selection episode → pre-update prediction → observed branch reward → posterior update。
Branch coverage trajectories
五个 arm，同一 coverage pipeline。
Calibration reliability diagram
predicted productivity vs observed productivity。
Queue disposition figure
P/U/R fail、provisional、durable、expired、converted。
Historical CVE Kaplan-Meier curves。
Cost-performance frontier
coverage/CVE recall vs tokens、CPU-hours。
必须有的表

Prior work and novelty boundary；
arm configuration matrix；
target/protocol/build matrix；
complete LLM configuration；
admission predicate definitions；
candidate/provisional/state-event logging schema；
final branch and AUC results；
mechanism metrics；
historical CVE benchmark；
negative/boundary cases；
repair diagnostics；
threats to validity。

十六、论文逐节重写方案

Abstract

按照以下逻辑：

response-derived state 是常用但不可靠的 proxy；
LLM proposal 会放大错误 proxy 带来的队列污染；
提出 evidence-gated、two-tier admission；
提出 online state-productivity calibration；
在 matched conditions 下验证；
使用历史漏洞 rediscovery；
报告收益、成本和失败边界。
不要在 abstract 第一段讲 0-day 或漏洞数量。

Introduction

推荐顺序：

stateful protocol fuzzing 需要状态反馈；
response-visible abstraction 部署简单，但不保证与内部代码进度一致；
LLM 可以提出新请求，但也会把无效状态假设注入 durable queue；
三个 target 揭示三种 mismatch；
研究问题：何时应该信任状态信号？
解决方案：evidence gate + provisional queue + calibration；
三个贡献。
Motivation

重点使用真实结果：

Forked-daapd：false progress；
Lighttpd1：hidden progress；
LightFTP：saturation mismatch。
不要只使用虚构 FTP 示例。

Design

分成：

LLM proposal interface；
P/U/R；
(G_{\text{code}}) vs (G_{\text{state}})；
provisional/durable queue；
productivity posterior；
calibrated scheduling；
optional repair。
Evaluation

先写 preregistered RQ、arms、metrics，再写结果。

不要先看到结果再调整 RQ。

Security findings

改名：

Historical Vulnerability Rediscovery

明确：

不优化 0-day；
不用 crash 数量排名；
使用 vulnerable/patched pair；
oracle-based root cause；
reached/triggered 分离。
Discussion

必须正面讨论：

response-derived state 不是 semantic state；
calibration 不能修复 coarse state aliasing；
black-box deployability 与内部状态精度的权衡；
LLM 成本；
provider nondeterminism；
calibration cold start；
branch saturation；
target-specific negative effects；
repair 未独立验证时的限制。

十七、快速执行时间表

以 10 -14天为上限。到期投稿，不继续无限增加模块。

1：备份和冻结，

tag 当前论文和代码：loopfuzz-legacy-v1；
归档当前 PDF、数据和脚本；
创建新分支：loopfuzz-calibration；
写一页 frozen protocol；
确定主 RQ、arms、metrics；
禁止继续找 0-day。
交付物：

repository tag；
experiment protocol v1；
一页 novelty matrix。
2：日志与语义修复

完成：

拆分 (G_{\text{code}}) 和 (G_{\text{state}})；
定义 reject/provisional/durable；
实现六类事件日志；
加入 schema version；
加入 complete launch ledger；
单元测试 P/U/R reason code；
确保 candidate 到 descendant gain 可 join。
验收标准：

candidate event 完整率 ≥99.9%；
不存在没有 candidate_id 的 trial；
不存在没有 episode_id 的 posterior update；
运行后能重建全部 promotion decision。
没有通过，不允许开始大实验。

3：实现 provisional queue 和 calibration

完成：

provisional TTL/budget；
Beta posterior；
discounted update；
Thompson scheduling；
pre-update prediction logging；
fixed-policy fallback；
repair 默认关闭。
所有参数在周末冻结。

4：四 target pilot

选择：

Forked-daapd；
Lighttpd1；
LightFTP；
一个原本稳定正向的 target，如 ProFTPD 或 Pure-FTPd。
运行：

5 arms；
3 runs；
每次 4–6 小时。
只用于：

查 bug；
验证日志；
检查 posterior 是否更新；
检查 provisional conversion；
估算 LLM 和 CPU 成本；
冻结参数。
不把 pilot 结果混入最终统计。

第一个 kill test

只有满足以下条件才保留 calibration 为主要贡献：

posterior prediction 能实际产生非退化差异；
Forked-daapd 的 branch-poor states 被逐步降权；
Lighttpd1 不因 IPSM edge 少而被全部压制；
至少三个 pilot target 没有明显 throughput 灾难；
calibration 指标优于固定 state score；
E vs D 至少出现合理、方向可解释的差异。
如果失败：

calibration 降为 exploratory；
主故事改为 evidence-gated queue admission；
不再花三周重造复杂 RL 算法。
5：历史漏洞 pilot

完成 6 个 CVE pair：

构建 base+patch；
定义 reached/triggered oracle；
清除 prompt/seed 泄漏；
vulnerable/patched replay；
自动化容器构建；
运行短时 sanity test。
如果两周还不能稳定完成 6 个，不再追求 20 个，最终保持 8–12 个高质量漏洞。

6：正式实验

随机化 launch；
五个 arm 每 target 10 runs；
核心 C/D/E 补到 20 runs；
每次 24 小时；
自动健康检查；
只对预定义 infrastructure failures 重跑；
每天生成 launch completeness report；
不允许中途查看结果后改参数。
7：CVE 正式实验与数据冻结

12 个 CVE 为目标；
每个 arm 10 runs；
可使用 12 小时 deadline；
生成 frozen raw data checksum；
导出 analysis-ready tables；
从此禁止修改算法。
8：统计和图表

学生必须先交：

arm configuration table；
launch ledger；
candidate flow table；
target-level result table；
calibration table；
CVE table；
所有图的最终数据文件。
没有表，不允许先写结果故事。

9：全文重写

按新结构重写，不在旧稿上继续局部打补丁。

必须优先完成：

Introduction；
Motivation；
Design；
Experimental protocol；
Main results。
Related Work 和 Discussion 最后写。

10：内部审查并投稿

只允许：

修正事实错误；
修正图表；
缩减 claim；
补 artifact 文档；
做一次必要的 confirmatory rerun。
禁止：

增加新算法；
增加新协议；
更换模型；
追新 CVE；
新增第三套 state representation；
根据正式结果重新调超参数。

防止继续卡住的时间管理规则

1. 目标就是必须完成投稿

如果 calibration 没有效果：

降级；
保留为 failure analysis；
以 admission paper 投稿。
如果 CVE recall 没提升：

报告没有提升；
强调 reproducible benchmark、成本和边界；
不继续找容易触发的 CVE 美化结果。
如果 repair 没效果：

降为 feature；
不再跑更多 repair ablation。
2. 论文成败的最低条件

D vs C 清楚支持 admission；
E vs D 支持 calibration；
candidate-level 机制证据完整；
有至少 8–12 个历史漏洞；
当前直接先行工作比较充分；
≥9 个 targets；
核心 arms 至少 20 runs；
artifact 可重放。
3.如果 admission 和 calibration 都不稳定

不要再拖：

如实写成 integrated system + boundary analysis；
投 Computers & Security；
结束项目，让学生转 survey 或下一条研究线。

最终建议的贡献段落

可以直接作为 Introduction 的初稿：

This work makes three contributions. First, we introduce an evidence-gated, execute-before-promote admission controller for LLM-generated protocol requests. The controller separates provisional state novelty from evidence sufficient for durable queue promotion, preventing syntactically valid but behaviorally unproductive proposals from permanently shaping the mutation campaign. Second, we present an online calibration mechanism that estimates the downstream code productivity of response-derived states and combines productive confidence with frontier exploration. The mechanism does not claim to recover semantic protocol states; instead, it learns when a response-visible state proxy is useful for guiding fuzzing. Third, we provide a controlled, candidate-level evaluation that isolates admission and calibration under matched model configurations and resource ceilings, and evaluates security outcomes through information-controlled rediscovery of historical vulnerabilities on vulnerable/patch-paired targets.
