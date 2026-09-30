from pathlib import Path
import json,shutil,hashlib,re,subprocess
a=Path(__file__).resolve().parent;r=a.parent
for k in ['thompson1933','davis2006pr','efron1979']:
 p=a/'sources'/k;d=json.loads((p/'round5.json').read_text());shutil.copy2(p/'round5.pdf',p/'paper.pdf');shutil.copy2(p/'round5.txt',p/'paper.txt')
 old=json.loads((p/'retrieval.json').read_text());info=subprocess.check_output(['pdfinfo',str(p/'paper.pdf')],text=True)
 old.update(status='fulltext_downloaded',source=d['url'],sha256=d['sha256'],pages=int(re.search(r'Pages:\s*(\d+)',info)[1]),identity_check='Original title, authors, and paper body verified')
 if k=='efron1979':old.update(text_mode='scanned body; directly inspected rendered PDF pages 2--4, original pages 1--3; plain text contains cover only')
 (p/'retrieval.json').write_text(json.dumps(old,indent=2)+'\n')
web={
'mann1947':{'source':'https://webspace.ship.edu/pgmarr/Geo441/Readings/Mann%20and%20Whitney%201947%20-%20On%20a%20Test%20of%20Whether%20one%20of%20Two%20Random%20Variables%20is%20Stochastically%20Larger%20than%20the%20Other.pdf','pages':12,'evidence':'Browser retrieved the complete PDF (cover + 11 article pages), including Section 1 and the distribution-free U-statistic derivation. Local HTTP download timed out. No local PDF hash asserted.'},
'cliff1993':{'source':'https://www.scribd.com/document/502817913/Delta-de-Cliff','pages':16,'evidence':'Browser exposed the full transcribed original article, from original page 494 through references on page 509. Definition and independent-groups interpretation checked. This is a third-party mirror, not a publisher PDF. The separately fetched local page is only an access shell and is not used as full-text evidence.'}}
for k,x in web.items():
 p=a/'sources'/k;d=json.loads((p/'retrieval.json').read_text());d.update(status='fulltext_web_reviewed',sha256=None,**x);(p/'retrieval.json').write_text(json.dumps(d,indent=2)+'\n')
rows=[
('blueman2025',[3,4],'Design overview; simulated BLE boards','supported','真实 BLE 协议栈在物理层仿真环境中交互；保留 simulations 的限定，不将其写成物理硬件实测。'),
('distfuzz2025',[2,3,4],'Table I and architecture','supported','常规事件、故障事件和时间间隔；消息序列反馈与对称性剪枝。原句各机制均有全文支持。'),
('gramatron_effective_grammar_aware_2021',[2,3,4],'Sections 2--3, grammar automata','attribution_split','将 CFG 转为自动机进行生成和变异；已拆开与 CarpetFuzz 的合并引证，避免两篇都支持同一组机制的歧义。'),
('carpetfuzz_documentation_2023',[3,4],'Challenges and option constraints','attribution_split','从自然语言文档抽取选项冲突/依赖关系；已单独陈述，未将其误归为通用语法自动机。'),
('formatfuzzer',[2,4],'Binary templates and format-aware fuzzing','supported','输入为二进制格式模板，可构建生成器、解析器和变异器；不据此主张无须人工模板精化。'),
('fuzztruction2023',[3,4],'Sections 2--3, generator fault injection','supported','在输入生成程序中注入故障，利用隐含格式约束生成测试输入；原句为机制描述。'),
('miner2023',[2,3,4],'Overview; REST API sequence generation','supported','保留有效请求序列作为模板并偏向较长序列；学习关键请求参数。原句未将其等同长期队列代码收益验证。'),
('llmif_augmented_large_language_2024',[2,4],'Specification extraction and algorithm overview','attribution_split','抽取消息格式、字段值、头部结构及依赖来生成设备测试输入；已与 ChatAFL/Fuzz4All 分开逐项引证。'),
('fuzz4all_universal_fuzzing_large_2024',[2,3,4],'Autoprompting and fuzzing loop','attribution_split','跨多种程序输入语言，以自动提示、生成和变异开展测试；不声称已验证所有协议类型。'),
('fuzzgpt2024',[2,3,5],'Historical bug programs; in-context learning/fine-tuning','version_limited','可用 2023 作者稿题名不同但六位作者及 FuzzGPT 方法对应；支持当前 unusual programs 的窄表述。正式 ICSE 2024 版尚未逐页比对。'),
('whitefox2024',[3,4],'Motivating example; source-derived requirements','supported','利用优化器源代码总结触发条件并生成相应测试；原句获得支持，不推出 LoopFuzz 性能。'),
('prophetfuzz2024',[2,4],'Documentation constraints and few-shot option prediction','supported','依据文档及示例预测高风险选项组合；当前表述没有声称纯零样本或未经验证即可认定漏洞。'),
('hybridllm2026',[2,3,4],'Section III, LLM-assisted concolic execution','supported','HyLLfuzz 在灰盒覆盖平台期使用 LLM 辅助 concolic 执行；当前 hybrid fuzzing 概述得到支持，来源为作者稿。'),
('hgfuzzer2026',[2,4],'Path conditions, harness generation, target-specific mutators','version_limited','取得 2025 三作者预印本，正式 2026 条目为四作者。已删除更具体的 predicate-guided synthesis，保留 LLM-assisted directed greybox fuzzing；正式版机制仍待比对。'),
('bandits_states2023',[2,3,4],'Sections 3--4, state-selection bandit formulation','novelty_boundary_clarified','已有协议状态 bandit 建模，讨论非平稳奖励，初步结果弱于 AFLNet。本文不得将 bandit 或代码反馈本身称为创新；表格已改为组合边界。'),
('tscheduler2024',[1,4,5],'Section 3.2; Algorithm 1','required_prior_work_added','要求文件所指为 Luo 等 AsiaCCS 2024，非 Zhang 2026。Beta 参数更新、Thompson 抽样及覆盖特征稀有度修正在算法中明确；已补入正文及边界表，正式元数据由 Crossref 核对。'),
('fox2024',[3,4],'Section 2, online stochastic control formulation','supported','将覆盖引导变异模糊测试建模为在线优化/随机控制，目标为期望代码覆盖收益；原句准确。'),
('fishfuzz2023',[2,3],'Overview of multi-distance and dynamic prioritization','supported','多距离指标、动态目标排序和队列裁剪共同引导探索/利用；原句的距离优先化表述可保留。'),
('protocolguard2026',[2,3,4],'Specification rules and dynamic verification','supported','规范性要求形成规则，结合代码分析定位不一致，再进行动态验证；当前表述支持语义正确性与覆盖奖励的区分。'),
('bsfuzzer2026',[2,3,4],'Semantic extraction and state-machine violations','supported','从 BLE 规范提取语义约束、状态信息，并合成上下文感知测试检测逻辑缺陷；原句范围准确。'),
('mercuriuzz2026',[2,3,4],'Section IV; QUIC logical vulnerabilities','supported','目标为 QUIC 实现逻辑漏洞，区分响应违例、资源异常与通用内存崩溃；不能将覆盖增长视为漏洞证明。'),
('magma2020',[2,8,10],'Sections 4 and 4.3, ground-truth metrics','supported','原文区分 reached、triggered 与 detected；故障位置被覆盖不等于触发。补丁配对和提示信息控制属于本文协议，未归为 Magma 原有规则。'),
('profuzzbench_benchmark_stateful_protocol_2021',[2,3,4],'Benchmark workflow and reproducibility','supported','协议目标、构建/运行/分析流程及确定性挑战支持协议 fuzzer 评测平台的陈述。'),
('fuzzbench2021',[2,3,4],'Section 2, benchmark methodology','supported','提供可重复实验、重复 trial 和统计报告。正文未把默认配置当作所有实验的唯一规范。'),
('reliability_benchmarking_2022',[2,3,4],'Research questions and proxy reliability','supported','区别相关性与排名一致性；覆盖与漏洞数高度相关并不保证比较排序一致。当前谨慎解释覆盖的表述获得支持。'),
('sok_prudent_evaluation_practices_2024',[2,3,4],'Recommendations 4--5; evaluation review','supported','不以覆盖/栈哈希单独充当漏洞结果，强调统计评估、重复和实验可重复性；不能替代本文尚未完成实验。'),
('greenbenchmark2023',[4,7,9],'Benchmark construction; resource/accuracy trade-off','supported','以较短任务和随机化初始条件研究降低评测成本；正文只据此说明成本需要报告，没有把其流程当成本研究已执行。'),
('benchmarkproperties',[6,7,8,9],'Controlled covariates and holistic benchmarking','supported','初始种子覆盖和执行速度会影响相对表现与排名；正文不将其推广为任何不受控 endpoint 都能给因果解释。'),
('mutationassessment2023',[2,3,4],'Mutation analysis and fault detection','supported','评估检测注入故障的能力，补充覆盖度指标；本文未声称自己已完成 mutation-based 实验。'),
('thompson1933',[1,2,8],'Sections 1--3','adaptation_clarified','原文以证据形成概率并据此随机分配；不证明本文的折扣、frontier 加权或比例采样形式。已明确这些是本文的适配。'),
('davis2006pr',[1,2,4],'ROC/PR relation and interpolation','metric_distinction_fixed','原文强调 PR 分析及非线性插值；不证明任意 AUPRC 与非插值 AP 恒等。已统一报告实际实现的 AP，并写明与梯形积分不同。'),
('efron1979',[2,3,4],'Original pp. 1--3, Section 2 and Eqs. (2.1)--(2.5)','resampling_scope_clarified','原文从独立样本的经验分布有放回重抽样以近似抽样分布。95% 百分位区间、整 run 和分层设计为本文选择，不能宣称原文保证当前依赖数据的覆盖率。扫描正文通过页面图像审阅。'),
('benjamini1995',[2,6,12],'Theorem 1 and Appendix A','guarantee_qualified','原始 FDR 保证针对独立检验统计量。本文共享比较组/相关覆盖终点未证明该条件；改为 nominal q 并删除无条件控制承诺。'),
('kaplan1958',[2,3],'Original pp. 457--458; Section 1.1','assumption_added','观察时限须独立于生存/触发时间的标准设定已核对；正文补入非信息性右删失限定并保留故障中断警告。'),
('mann1947',[2,3],'Original pp. 50--51; Section 1','inference_scope_clarified','原文对两个独立连续分布的随机样本定义 U 统计量，非一般中位数差检验。协议现在明确 run 层独立性及并列值处理；全文通过浏览工具读取，未声称本地下载成功。'),
('cliff1993',[494,495,496],'Original article pp. 494--496, independent-group dominance','effect_definition_clarified','原文将组间优势定义为两方向概率之差，并讨论并列值及分布假设。正文明确 δ 的方向；所审为全文镜像转录，出版社 PDF 仍未取得。')]
p=a/'assessments.json';d=json.loads(p.read_text())
for k,pages,section,assessment,note in rows:d[k]={'pages':pages,'page_kind':'printed journal pages' if k=='cliff1993' else 'PDF page including cover','section':section,'assessment':assessment,'note':note}
for k in ['nsfuzz','ssgfuzz2026','wingmuzz2025','zhang2026thompson','brier1950']:
 d[k]={'pages':[],'section':None,'assessment':'fulltext_unresolved','note':'出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。'}
p.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
print('Review records:',len(d))
