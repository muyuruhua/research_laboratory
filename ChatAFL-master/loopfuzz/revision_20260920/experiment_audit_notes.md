# Key_Experiment 数据审计（2026-09-20）

本审计仅使用用户指定的 `Key_Experiment`。未混入大小写不同的 `key_experiment`、旧稿表格、旧消融包或其它结果目录。源文件只读；没有解压整个归档到磁盘，没有输出请求正文、提示词、凭证或服务地址。

## 可复核产物

- `audit_experiments.py`：标准库分析脚本，读取全部18个 `run_summary.csv`、对应 `.result_manifest.tsv`/`.sample_status`，流式扫描90个 LoopFuzz归档中的指定日志成员；保留所有181个summary记录，包括提前终止和来源信息不完整的记录。
- `experiment_audit.json`：summary的SHA-256、逐目录清单、全部native endpoint均值/样本标准差、逐归档安全配置子集、事件数量、join缺口、运行累计计数。
- `observed_tables.tex`：可直接include的inventory、描述性endpoint、日志数量三张表。该文件没有填充任何缺失的confirmatory A--E比较。
- `observed_costs.tex`：9个target末次已保存calls/tokens计数的逐run范围，tokens单位为千。
- `plot_native_endpoints.py`及`native_endpoints.{pdf,svg,png}`：三目标×两指标的描述性均值±样本标准差图，PNG为300dpi；图中保留全部run，注明异长观测和各目标独立纵轴尺度。Matplotlib版本3.10.8，已读图检查重叠。

复算命令（在 `ChatAFL-master` 目录）：

```bash
python3 loopfuzz/revision_20260920/audit_experiments.py
```

## 数据范围和状态核算

现有归档仅有 `aflnet` 与 `loopfuzz` 两类文件标签，共181个归档。90个LoopFuzz `run-config.jsonl`的首个配置记录均声明 `arm=loopfuzz-gated-fixed`、`calibration=false`；未发现独立的Controlled ChatAFL、direct、calibrated arm归档族。后续实现审计指出初始配置写入发生在部分环境开关解析之前，因此这些声明必须经launcher、end记录和有效执行路径交叉验证，不能单凭初始记录证明每次实际arm配置。`Key_Experiment/ablation`未提供结果文件。

18个manifest每个有10条，合计180条，与180个status sidecar对应；不能将这种事后结果manifest当作包含“计划但未启动”项目的完整intention-to-run ledger。Pure-FTPd AFLNet另有第11个归档及summary记录，缺少manifest/status，时间属于后续批次。保留该行作完整性展示，但不声称其为预先计划的独立重复。Pure-FTPd AFLNet第2行 `exit_code=1` 仍标为 `completed`；第11行的`completed`也没有status sidecar支持。

LoopFuzz summary状态为60个`completed`、12个`sigabrt`、18个`oom_killed`标签。12个SIGABRT分别为Forked-daapd8、Kamailio3、Lighttpd1 1。18个137退出分别为bftpd7、ProFTPD7、Pure-FTPd4。退出码137本身不能证明真实OOM，尤其其中大部分发生在约25小时终止窗口附近；本审计不重新猜测根因。LoopFuzz有150行run-config，即90个start与60个end记录。

全部91个AFLNet summary观测runtime为1499分钟；LoopFuzz为410--1522分钟。`runtime_min`由`fuzzer_stats`的`floor((last_update-start_time)/60)`计算，非包括所有初始化/模型阶段的完整CPU时间。不能将native最后一行endpoint称为严格24小时共同终点，也不能用completed筛选后均值推断总体效果。

## 现有endpoint与动机边界

全部summary行均有数值endpoint；表内统计包含所有行、不删除提前结束结果、不选择最大值。`b_abs`来自`cov_over_time.csv`最后一行的绝对分支覆盖数；`edges`来自`plot_data`最后一行第13列，是IPSM state edges。`l_abs`为绝对源码行覆盖数。统计量是每组算术均值和样本标准差（ddof=1）。没有计算显著性、因果效应或matched-budget收益。

| Target | AFLNet code branches | LoopFuzz code branches | AFLNet IPSM state edges | LoopFuzz IPSM state edges |
|---|---:|---:|---:|---:|
| Forked-daapd | 2330.8 ± 60.0 | 2662.6 ± 151.4 | 21.6 ± 2.1 | 21.8 ± 2.3 |
| Lighttpd1 | 1940.7 ± 21.2 | 2126.0 ± 15.0 | 17.7 ± 2.5 | 29.7 ± 1.3 |
| LightFTP | 71.9 ± 2.8 | 71.1 ± 0.3 | 185.6 ± 12.4 | 212.1 ± 12.4 |

这些是异长native endpoint，不能证明first_paper要求的全部三类机制。尤其新批Forked-daapd不支持沿用旧稿的“分支下降而IPSM state edges增加”；Lighttpd1也不是状态增长很小的直接证据。LightFTP数值与近饱和/状态扩张的诊断方向一致，但单凭终点仍不能证明完整时间过程或具体状态的误导。三类动机应明确列为待检验情形，或将本批观察与未复核旧档分开。

## 日志审计及其解释限度

90包均有schema-v2 run-config及state-episodes；69包有candidate/admission文件。合计1610个candidate记录、1599个trial记录、1582个`reject`标签、17个`durable`标签、0个`provisional`标签、59583个episode记录。所有被读取JSONL均可解析。11个candidate无trial匹配（Forked-daapd8，Kamailio3），没有trial找不到candidate；1599/1610的记录join率约99.32%，不能声称达到99.9%验收标准。此比率也不是完整生成器事件捕获率，因为未生成或未记录候选的调用不可由这些表推断。

交叉检查发现12个run的最终`fuzzer_stats.cal_episodes`比JSONL行数少，8个run的`disposition_reject`累计计数比JSONL拒绝行数少，多出现在非零退出run。这与末次统计快照早于最后事件一致，但未验证具体写盘原因；机制计数优先使用逐事件JSONL，成本累计计数须标明是最后保存的快照，可能未包含最后窗口。

全部90包都没有`provisional-events.jsonl`或`repair-events.jsonl`。日志文件缺失或行数0可以报告为“observed record count 0”；provisional转化率、过期率、promotion latency、downstream productivity、repair成功率等结果必须留空，不能填0。ProFTPD10包均无candidate/admission文件，但有模型调用累计计数，不能把无候选日志写成无LLM使用。

记录的decision label不等价于验证后的queue membership。当前源码审计显示native保存可在统一admission判断之前发生，应由实现审计解释；不能用1582个reject标签直接宣称“避免1582次queue pollution”。没有direct arm和descendant horizon归因，因此无法估计避免污染或admission false negative。

需特别区分现有字段的实际含义：

- `admission-events.jsonl`中的`pre_code_branches`/`post_code_branches`在当前源码里填的是`bitmap_bytes`，不是gcov分支数；不能与`b_abs`混用。
- `state-episodes.jsonl`的`new_code_edges`填的是`code_gain_events`差，即native coverage-save事件数；`has_new_bits`也包含计数桶新颖性，不能写成“新增独立code edge数量”或严格branch reward。
- 固定策略仍更新posterior作日志。当前源码在`calibration=false`时把posterior mean写入`sampled_theta`，初始阶段部分记录为-1；字段名不证明实际进行Thompson采样或该posterior驱动调度。
- episode `mutations`实际为`total_execs`差，观测范围0--17080，不是统一固定64次descendant预算。预更新posterior可供探索性诊断，但不能直接填符合新实验协议的校准效能结果。
- bug-event kinds包含`oracle_abstained`、hang、teardown、crash；未提供完整historical CVE vulnerable/base+patch、reached/triggered、patch replay证据。不能把这些事件数量当CVE数量或漏洞发现率。

字段解释参考当前 `LoopFuzz/afl-fuzz.c` 的 `admission_log_candidate_event`、`cal_episode_finalize`、`save_if_interesting`、`choose_target_state`；归档统一记录 `fuzzer_commit=3e2d8b48b`。未独立验证每个归档二进制与当前工作树内容完全一致，因此源码解释应与归档数值事实区分。

## 模型配置与成本

90包共同记录model别名`codex-auto-review`、temperature grammar=0.5/plateau=1.2、top-p=1.0、max_output_tokens=4096、call_cap=64、token_cap=0、no_refinement=false、hypothesis=false、gamma=0.995、epsilon=0.1、provisional budget=64、TTL=30000ms、max_live=64。模型别名不是固定provider模型快照。配置缺少可验证target commit、image digest、CPU/memory quota等字段，不能宣称完整资源匹配。repair开关也未满足first_paper要求的核心C/D/E repair-off设计。

90包`fuzzer_stats`的累计计数共13,563次调用、10,237,947 prompt tokens、9,233,121 completion tokens，合19,471,068 tokens。这些是工具计数而非独立provider账单。每run调用37--248次，说明run_config的64不能解释为全API调用硬上限；token_cap=0也不能解释为所有LLM arms已有共同有限token预算。候选token字段通常对应产生候选的调用，不能逐候选简单累加为全campaign成本。

| Target | 观测calls/run范围 | 观测total tokens/run范围 |
|---|---:|---:|
| bftpd | 199--248 | 198015--301786 |
| Exim | 106--123 | 109406--150956 |
| Forked-daapd | 37--163 | 124107--540945 |
| Kamailio | 56--65 | 157039--183187 |
| LightFTP | 156--161 | 174939--224720 |
| Lighttpd1 | 131--181 | 168512--241356 |
| Live555 | 123--151 | 264081--329677 |
| ProFTPD | 188--192 | 170114--198818 |
| Pure-FTPd | 207--242 | 200201--264132 |

所有需要新的五arm对照、common deadline、严格code reward、完整候选/descendant attribution、历史CVE基准或资源公平性的结果格应保持空白。已有数据足以支持现状审计和探索性描述，不足以声称新控制器已完成验证。
