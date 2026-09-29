#!/usr/bin/env python3
"""Summarize raw-source audit and distinguish absent data from undefined metrics."""
from pathlib import Path
from collections import Counter, defaultdict
import csv, gzip, hashlib, json, re, statistics

BASE=Path(__file__).resolve().parent
OUT=BASE/'table_source_audit_20260928'
a=json.loads((OUT/'raw_archive_audit.json').read_text())
t=json.loads((OUT/'table_checks.json').read_text())
mapping=json.loads((OUT/'lighttpd1_source_mapping.json').read_text())
duplicate_checks=json.loads((OUT/'duplicate_archive_checks.json').read_text())
assert len(duplicate_checks)==20 and all(x['byte_identical_archive'] for x in duplicate_checks)
runs=json.loads((BASE/'filled_run_evidence.json').read_text())['runs']
raw={r['source_rel']:r for r in a['records']}
with gzip.open(BASE/'vector_figure_evidence_20260928.json.gz','rt') as f: cached=json.load(f)['runs']
hash_errors=[]
for r in cached:
 rec=raw[r['source_rel']]
 if rec['files']['cov_over_time.csv']['sha256']!=r['coverage_sha256']:hash_errors.append((r['source_rel'],'coverage'))
 if r['arm']=='E' and rec['files']['state-episodes.jsonl']['sha256']!=r['episode_sha256']:hash_errors.append((r['source_rel'],'episodes'))
assert not hash_errors, hash_errors
names=dict(zip(['lightftp','bftpd','proftpd','pure-ftpd','exim','live555','kamailio','forked-daapd','lighttpd1'], ['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']))
observed=(BASE/'observed_tables.tex').read_text()
# Independently compare the D log counts table against streamed original archives.
for target,name in names.items():
 rr=[r for r in raw.values() if r['in_ledger'] and (r['arm'],r['target'])==('D',target)]
 line=next(l for l in observed.split(r'\label{tab:observed_log_counts}',1)[1].splitlines() if l.startswith(name+' &'))
 cells=[x.strip() for x in line.removesuffix(r'\\').split(' & ')]
 expected=[sum(r['numeric'][k] for r in rr) for k in ['candidates','trials']]
 expected +=[sum(r['dispositions'].get(k,0) for r in rr) for k in ['reject','provisional','durable']]
 expected +=[sum(r['numeric']['episodes'] for r in rr)]
 assert [int(x) for x in cells[1:]]==expected,(target,cells,expected)
config={}
for arm in ['C','D','E']:
 rr=[r for r in raw.values() if r['in_ledger'] and r['arm']==arm]
 end=[e for r in rr for e in r['configs'] if e['phase']=='end']
 config[arm]={'runs':len(rr),'runs_with_end_config':sum(any(e['phase']=='end' for e in r['configs']) for r in rr),
              'end_calibration':dict(Counter(str(e.get('calibration')) for e in end)),
              'end_no_refinement':dict(Counter(str(e.get('no_refinement')) for e in end)),
              'recorded_fuzzer_commits':sorted({str(e.get('fuzzer_commit')) for r in rr for e in r['configs']})}
for r in a['records']:
 if not r['in_ledger']:print('Unlisted archive numeric evidence:',json.dumps({k:r[k] for k in ['source_rel','numeric','dispositions','coverage']},indent=2))
print('Config evidence:',json.dumps(config,indent=2))
print('Counts:',json.dumps(a['arms'],indent=2))
findings={
 'conclusion':'Results are derived from Key_Experiment, but the current filename-based join is incomplete and mismatches one Lighttpd1 run. Design/source-review/literature tables are not measured results.',
 'disk_archives':a['disk_archives'],'ledger_runs':a['ledger_runs'],'archive_parse_errors':len(a['archive_parse_errors']),
 'raw_to_ledger_mismatching_archives':len(a['ledger_disagreements']),
 'raw_to_summary_mismatching_archives':len(a['summary_disagreements']),
 'coverage_hashes_verified':len(cached),'E_episode_hashes_verified':sum(r['arm']=='E' for r in cached),
 'numeric_evidence_duplicate_groups':a['duplicate_numeric_evidence'],
 'configuration_diagnostics':config,'source_mapping':mapping,
 'byte_identical_duplicate_pairs':len(duplicate_checks),'distinct_numeric_archive_evidence':a['disk_archives']-len(duplicate_checks),
 'table_and_sample_checks':t,
 'limitations':['Raw numeric/log verification does not establish identical builds, independent launches, authentic arm treatment, complete provider costs, or causal effects.',
                'IPSM means in tables were checked against run_summary.csv; raw plot_data was additionally checked for the two mismapped Lighttpd1 archives.',
                'Absence of lifecycle logs does not justify zero conversion or false-negative rates.']}
(OUT/'findings.json').write_text(json.dumps(findings,indent=2)+'\n')

rowmatrix='\n'.join('| '+names[target]+' | '+' | '.join(str(t['run_count_matrix'][target][arm]) for arm in ['A','B','C','D','E','E-gamma099','E-gamma100'])+' |' for target in names)
rows=[]
for arm in ['A','B','C','D','E','E-gamma099','E-gamma100']:
 d=a['arms'][arm];p=d['log_presence']
 rows.append(f"| {arm} | {d['runs']} | {p['candidate-events.jsonl']} | {p['admission-events.jsonl']} | {p['state-episodes.jsonl']} | {p['provisional-events.jsonl']} | {p['repair-events.jsonl']} |")
logmatrix='\n'.join(rows)
report=f'''# 当前论文表格数据来源与缺口审计（2026-09-28）

对象：`main.revised.tex` 及其实际引用的三个表格输入、附录与校准统计表。按 research-writing-skill 和 scientific-toolkit-skill 核对。原始输入限定为用户指定的 `Key_Experiment/benchmark` 和 `Key_Experiment/ablation`；设计要求另参照 `C_two_papers/first_paper.md`。本次输出为审计报告，不把来源修复候选值写入论文。

## 结论

**不能笼统回答“所有表里的数据都来自 Key_Experiment，而且已经完整正确”。** 表 9–15 中的已填观测数值、统计量和附录表 A.1 的来源链确实指向该目录；但表 1–8、16–19 中还有方法定义、文献归纳、当前工作树源码审计、计划设置和未完成模板。更关键的是，bftpd B/D 两臂存在字节级重复归档，Lighttpd1–D 的文件名连接也存在已经核实的错配与漏纳，当前“来源目录正确”不等于“逐运行连接正确或已使用全部档案”。

本次独立流式读取 **{a['disk_archives']} 个压缩档案**，而论文台账包含 **{a['ledger_runs']} 条**；原目录 summary 共 {a['summary_rows']} 行。检查日志解析、覆盖积分、候选/trial/episode 数量、处置标签、P/U/R 首失败分布、trial 延迟和保存的调用/token 计数。原始读取解析错误 {len(a['archive_parse_errors'])} 个；对于台账已纳入的文件，原始数值与提取台账不一致的档案为 {len(a['ledger_disagreements'])} 个。后者仅证明提取一致，不能证明文件与 summary 连对，也不能证明归档互不重复。

## 逐表性质与来源

| 当前表号 | 内容 | 性质与来源 | 当前判断 |
|---|---|---|---|
| 1 | 三种 state/code mismatch 假设 | `first_paper.md` 的研究假设；当前解释参考档案端点 | 不应当作已验证机制结果 |
| 2 | 相关工作与创新边界 | 引用文献及作者比较 | 不是实验数据 |
| 3 | P/U/R、G_code/G_state | 方法定义与审计字段要求 | 不是实测结果 |
| 4 | 设计契约与实现边界 | `LoopFuzz/afl-fuzz.c` 等当前源码和 `implementation_audit.md`，部分限制参照日志 | 不能自动归因到每一个历史实验二进制 |
| 5 | 必需日志 schema | 设计要求 | 列出字段不代表历史归档已记录 |
| 6 | A–E 五臂矩阵 | 预期的消融设计 | 不证明所有归档具有受控且正确的实际开关 |
| 7 | target/protocol/build | 对象名称对应档案，协议为对象属性；commit/image/reset 等为空 | 27 个构建字段空单元格 |
| 8 | LLM 公平性配置 | 待冻结的正式实验配置 | 9 个值为空；历史配置不能代替共同冻结配置 |
| 9 | benchmark 数量、状态、时长 | `run_summary.csv` 与归档台账 | 源自该目录；Lighttpd1–D 数量/范围应在映射修复后重算 |
| 10 | A/D branches 与 IPSM | summary 的 `b_abs`、`edges`，算均值与样本 SD | 源自该目录；Lighttpd1–D 受影响 |
| 11 | D 候选、trial、处置、episode | tar 内 `candidate-events.jsonl`、`admission-events.jsonl`、`state-episodes.jsonl` | 本次按原日志复算吻合已纳入文件；仍漏纳一个 D 归档 |
| 12 | E 的 Brier/ECE/AUPRC、参考值、区间 | tar 内 E 的 `state-episodes.jsonl`，由绘图分析脚本计算 | 原始日志派生统计；不等于独立代码分支、固定预算 episode 的指标 |
| 13 | A–E branches 与 AUC | summary `b_abs`；tar 内 `cov_over_time.csv` 积分 | 44 个现有单元格、1 个缺失组；Lighttpd1–D 有跨运行错配 |
| 14 | C/D/E 机制 | candidate/admission JSONL 的计数、处置、P/U/R、latency；其余留空 | 已填内容为日志统计；不能把标签当作已核验真实队列行为 |
| 15 | D 调用和 token 范围 | tar 内 `fuzzer_stats` 的 `llm_total_calls`、`llm_prompt_tokens`、`llm_completion_tok` | 是最后保存的累计计数，不是独立账单或总 CPU 时间；D 来源集应修复后复算 |
| 16 | repair 开关对照 | 可选实验结果模板 | 12 个结果单元格为空 |
| 17 | 历史 CVE 基准 | 六个预留槽位 | 1–6 是行号，不是发现 6 个 CVE；36 个证据字段为空 |
| 18 | CVE rediscovery 结果 | A–E 结果模板 | 35 个结果单元格为空 |
| 19 | threats | 研究设计、源码/归档限制的归纳 | 不是一张新实验测量表 |
| A.1 | 全部已纳入分组 | summary、轨迹与 status 的 60 组聚合，含 gamma 敏感性组 | 受相同 Lighttpd1–D 来源问题影响；“complete”需限定为当前台账 |

## 已核实的重复计数（P0）

bftpd 的 ChatAFL(B) 有两批 10 个包，位于 benchmark 的 Sep-17 与 Sep-19 目录；LoopFuzz(D) 两批位于 Sep-17 与 Sep-18 目录。文件编号发生了循环位移，但**完整压缩包 SHA-256 一一相同**。共 20 对重复包，40 个文件只提供 20 份不同档案。这不是“可能不独立”的弱提示，而是已确认同一份字节内容被重复纳入。

| 受影响项 | 当前论文 | 按不同档案去重后（审计值，尚未回填） |
|---|---:|---:|
| bftpd B 的 n | 20 | 10 |
| bftpd D 的 n | 20 | 10 |
| bftpd B branches 均值 ± sample SD | 492.2 ± 13.7 | 492.2 ± 14.1 |
| bftpd D branches 均值 ± sample SD | 502.7 ± 7.3 | 502.7 ± 7.5 |
| bftpd D candidate / trial | 26 / 26 | 13 / 13 |
| bftpd D episode | 6,498 | 3,249 |

均值可能不变，SD、实际 n、事件总量和按 run 的不确定性却会改变。表9–11、13–14、A.1 及相关图形中的样本数/总体计数均须重新计算。表15的 min/max 不一定改变，但来源清单也应同步去重。

全部 518 个包在消除这 20 份重复后，有 **498 份不同数值档案证据**；计入 Lighttpd1 映射修复后，A/B/C/D/E 为 94/91/90/99/76，两个 gamma 组各 24。主五臂虽合计 450，仍有 E 缺组；各组多出的档案不能抵消其它组缺失。不同档案也不自动等于满足正式设计的独立运行。

完整对应关系与哈希见 `duplicate_archive_checks.json`。本轮不直接修改论文实验值，以上列为必须修正的来源审计发现。

## 已核实的 Lighttpd1–D 来源连接错误（P0）

目录：`Key_Experiment/benchmark/results-lighttpd1_Sep-17_02-35-46/`。

| 比较项 | 磁盘 `_11.tar.gz` | summary 的 `_10` 行 | 磁盘 `_12.tar.gz` | summary 的 `_11` 行 |
|---|---:|---:|---:|---:|
| start_time | 1789717877 | 1789717877 | 1789718087 | 1789718087 |
| last_update | 1789806821 | 1789806821 | 1789806823 | 1789806823 |
| l_abs | 4084 | 4084 | 4112 | 4112 |
| b_abs | 2115 | 2115 | 2139 | 2139 |
| IPSM nodes | 9 | 9 | 9 | 9 |
| IPSM edges | 30 | 30 | 29 | 29 |
| runtime_min | 1482 | 1482 | 1478 | 1478 |

summary 有 `_10`，但磁盘缺少同名文件；磁盘有 `_12`，但 summary 没有该文件名。7 个数值字段完整吻合上表所示的跨文件名对应关系，这是强证据表明结果清单与归档编号错位，不是仅凭相同覆盖值猜测。不能因此臆测文件何时、由谁重命名。

当前台账只保留同名可连接项：跳过 summary 的 `_10`，遗漏磁盘 `_12`，把 summary `_11` 的 2139/29/1478 与磁盘 `_11` 的 AUC、日志和调用成本拼在一条运行记录里。论文曾把 2115 vs 2139 记为未解决的来源差异，但没有识别完整错配原因。数值端点、AUC、事件、成本混合后，表 9–15 与 A.1 中受影响的 D 数量、端点、日志、成本及关联图表需重新核算；原始 E 校准表 12 不受这条 D 映射直接影响。

正确处理：保持原始文件不变，建立基于时间戳、内容哈希和实验身份的显式来源映射，重新生成运行台账、D 聚合及相关图表，并核验是否为独立运行。目前实际存在 11 个 Lighttpd1–D 压缩包，论文只统计 10 个；全部目录的 518 个文件不自动等于 518 次可用于因果推断的独立运行。

现有 `verify_filled_data.py` 的唯一性检查只检查文件路径不同，不能识别改名复制；它只确认“台账列到的同名文件存在、summary 字段一致、台账聚合与表格一致”，不会枚举所有多余归档，也不核对 summary 时间戳与 tar 内身份。因此先前 PASS 的含义需要收窄。这次新增全目录差集、原始成员核验和内容哈希去重，发现了这两类缺口。

## 当前样本数量缺口

下面是**论文当前台账**的实际 n，不是补跑后的样本量；bftpd B/D 数量待去重，D–Lighttpd1 数量待上述映射修复；表内数字是问题版台账的记录数，不是本轮认可的独立 n。

| Target | A | B | C | D | E | E γ=.99 | E γ=1 |
|---|---:|---:|---:|---:|---:|---:|---:|
{rowmatrix}
| 合计 | 94 | 101 | 90 | 108 | 76 | 24 | 24 |

- 对主实验名义 N=10：bftpd–E 完全没有归档，少 10 次；Forked-daapd–E 只有 6 次，少 4 次。合计是 **14 次数量缺口**。其它组多出的运行不能抵消这些缺口，也不自动证明独立性或共同预算。
- 两个 gamma 敏感性组各为 8 targets × 3 runs，Forked-daapd 两组均无数据。若要求每组也有 10 个实测 run，则各个已有组还少 7 次；不能把 n=3 的 SD 或置信区间按 n=10 处理。
- `first_paper.md` 还要求 C/D/E 每 target 20 次。按去重并修复来源映射后的档案数量机械计算，C/D/E 分别差 90/81/104，共 275 条。该数不是补跑工期承诺：旧运行若配置、版本、独立性或预算不可验证，不能直接计入正式证据包。
- 用户指定“不足 10 按 10”目前体现在名义目标 N=10；统计均值/样本 SD 用实际观测 n（SD 分母 n−1）。缺失没有补 0，也没有复制现有数据冒充独立重复。

## 目前还缺哪些实质证据

| 优先级 | 缺口及对应表 | 需要的数据 | 对结论的影响 |
|---|---|---|---|
| P0 | 来源身份，表9–15/A.1 | bftpd B/D 内容去重、Lighttpd1 显式映射、完整纳入/排除台账、启动身份及源哈希 | 当前有重复计数与跨运行连接，需先修正再报告总量 |
| P0 | 构建与运行环境，表7 | target/fuzzer commit、镜像 digest、编译/coverage 参数、seed、reset hook、CPU/memory quota、host block、throttling | 不足以确认 D−C / E−D 只变一个因素 |
| P0 | 实际 LLM 策略，表8 | 解析后的实际 arm/flags、模型不可变版本、各调用类参数、prompt 版本、失败/重试/超时、全调用及 token 硬上限与执行证据 | 历史 model alias、call_cap=64、token_cap=0 不能证明公平预算 |
| P1 | 完整候选后代链，表14 | 稳定 candidate/queue/descendant ID、真实 promotion 时间、每个后代执行/覆盖增量、验证窗口与删失 | 缺 Productivity@64、promotion latency、queue pollution 和每候选收益 |
| P1 | provisional 生命周期，表14 | admission→validation→durable/expired/pending 完整事件、实际预算/TTL | 没有日志不能填“转化率0”；C 某些指标为不适用 |
| P1 | 反事实与漏拒，表14 | 相同输出/快照、相同后代预算的 C–D paired replay；随机 rejected shadow-validation 及抽样概率 | rejection count 不等于避免污染，false-negative rate 未知 |
| P1 | 真正的校准证据，表14/RQ1 | 固定能量且完成的 episode，更新前概率、独立 source-branch reward、状态/IPSM/code 的时间对齐 | 表12的 logged coverage-save reward 不可替代；hit-count novelty 单位不同 |
| P1 | 正式性能/统计，表13及结果节 | 共同构建和 24h 支持、完整失败/删失台账；D−C/E−D 效应、95% CI、MWU、Cliff's δ、BH 校正 | 目前是不同时间跨度的描述性端点/AUC，不能直接作因果/显著性结论 |
| P1 | 历史漏洞ground truth，表17–18 | CVE身份、vulnerable commit、最小安全补丁、独立 reached/triggered oracle、重放输入、patch反证、触发时间及删失 | 没有完成任何可验证的 CVE rediscovery 比较；crash/abort数量不能代替 |
| P1 | 完整成本，表15/RQ5/18 | 进程/容器 CPU 使用积分、吞吐、模型等待、逐调用成功失败重试及 token、触发前成本 | runtime_min 不能换算成实测 CPU-hours；末次计数不是账单 |
| P2 | repair，表16 | off/on 独立对照、repair-parent、修改字段、前后验证、后代收益及 token/latency | 可选扩展；不保留 repair 核心贡献时不应为填表强加新实验 |

所有 blank 单元格不都意味着“目录里完全不存在相关字段”。例如 run-config 保存了历史温度、top-p、gamma、模型别名，fuzzer_stats 保存了部分成本，但它们还缺有效开关、共同冻结策略和可复现身份；表 8 空白代表正式配置未确认。表 14 的 Brier/ECE/AUPRC 空白则代表**目标定义对应的数据缺失**，而不是没有任何可算的概率日志。

本次全量扫描中，当前未去重台账中各类日志的文件存在数如下；D 的分母和汇总须去重及补纳后更新。文件缺失/无记录与测得零效应必须区分；有日志也不证明事件捕获完整。

| Arm | 已纳入归档 | candidate | admission | episode | provisional | repair |
|---|---:|---:|---:|---:|---:|---:|
{logmatrix}

ProFTPD 在 D/E 的 candidate/admission 日志均缺失，但存在非零模型调用。D/E 各有 1 个 candidate 没有匹配 trial；这不能通过自动补一条失败 trial 解决。C/D/E 的 trial latency 仅来自有 trial 的 67/84/55 个运行，当前表已明确该分母。

实际配置补充：当前已纳入 C/D/E 分别有 73/82/65 个包保存了 end run-config；其 calibration 值分别为 false/false/true，提供部分配置佐证。记录的 fuzzer commit 有多个版本；这些 end 记录的 no_refinement 全为 false，不能据此认证预设的 repair-off 主实验，也不能忽略 hypothesis 等开关而反推 repair 一定运行。D 计数尚含重复文件，详细按归档结果见 `findings.json`。

## 已有数据还能做什么

1. bftpd 应按内容哈希去重，Lighttpd1 应通过现有文件重新映射，不应直接要求为缺失编号补跑。
2. 表12已经利用 E 的 28,866 条 episode 中 23,113 条正执行记录（排除 5,753 条零执行记录），计算 Brier、ECE、AUPRC 和按 run bootstrap 的区间；bftpd E 缺组。2000 次 bootstrap、10 个 bin、随机种子等是分析设置，不是新测得的实验结果。
3. 已有 `cov_over_time.csv` 可继续做有观测支持的共同时间窗描述性分析、每时点有效 n 与敏感性分析。0–24h 完整 AUC 仍需明确起点/终点支持与删失，不能外推缺失轨迹。当前 A/B/C/D/E 保存的 runtime 范围分别为 1499–1539、1463–1509、1437–1524、1460–1524、1412–1520 分钟。
4. B/C/E 的最终调用/token 计数已有，可扩展描述性成本表。核心五臂中 B–E 的 375 份已纳入文件有成本计数，但包含上述 20 份重复；去重并补纳新发现的 D 档案后为 356 份不同成本档案。每增量覆盖的归因成本、CPU-hours、账单价格仍需要独立证据。
5. Gamma 组的 endpoint/AUC 已列附录；n=3 支持小样本探索，不能自动满足正式敏感性验证。
6. 源码审计所述 gate 顺序、独立 state-only novelty、预算执行和 episode 暴露量问题，需要核实实验二进制并通过最小验收。仅补更多现实现运行，未必能产生论文所需的机制证据。

## 验证范围与可复核文件

- 原始审计：`audit_table_sources_20260928.py`；只流式读取指定成员，不展开整个 tar、不输出原始提示词或请求正文。
- 机器证据：`table_source_audit_20260928/raw_archive_audit.json`、`findings.json`、`duplicate_archive_checks.json`、`lighttpd1_source_mapping.json`、`table_checks.json`。
- 表格回查：现有 `verify_filled_data.py` 和 `verify_layout_references_20260928.py` 均 PASS；应按上述范围理解，不视为来源完整性证书。
- 本次额外核对表11原始计数、表12全部8个已有 target 的指标及区间，并核验 **{len(cached)} 个覆盖文件哈希、{sum(r['arm']=='E' for r in cached)} 个 E episode 文件哈希**与绘图缓存完全一致。
- 全量 raw-summary 不一致档案数：{len(a['summary_disagreements'])}；详见机器证据，不能把不一致静默修正成想要的结论。
- 原始数值证据重复组数（coverage+fuzzer_stats双哈希）：{len(a['duplicate_numeric_evidence'])}；20 对均进一步通过完整压缩包 SHA-256 证实字节级重复。

建议顺序：先修复内容去重、来源映射和完整台账，再确认有效配置及最小日志验收，然后补主臂缺组与候选/episode机制，最后完成历史 CVE 配对和成本、统计报告。论文目前拥有相当数量的描述性档案结果，但尚未形成 `first_paper.md` 要求的完整受控机制与安全效果证据链。
'''
(BASE/'TABLE_DATA_PROVENANCE_AUDIT_20260928.md').write_text(report)
print('Detailed report written:',BASE/'TABLE_DATA_PROVENANCE_AUDIT_20260928.md')
