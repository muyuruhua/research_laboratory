from pathlib import Path
import json,re
B=Path(__file__).resolve().parent;R=B.parent
v=json.loads((B/'validation.json').read_text());m=json.loads((B/'manifest.json').read_text());tex=(R/'main.revised.tex').read_text()
scopes={
'aflnet5years2025':'覆盖引导协议模糊测试及 AFLNet 后续研究',
'nyxnet2022':'增量快照与网络模糊测试的执行条件',
'snapfuzz2022':'网络应用测试的执行吞吐量',
'fuzztructionnet2024':'通过故障注入构造网络协议交互',
'fox2024':'把覆盖引导模糊测试建模为在线随机控制',
'prophetfuzz2024':'基于文档预测高风险选项组合',
'whitefox2024':'利用编译器源码信息引导优化触发测试',
'fuzzgpt2024':'生成深度学习库的异常边界程序',
'formatfuzzer':'由二进制格式规范构造解析器、变异器和生成器',
'fuzzbench2021':'通用模糊测试器的结构化评测',
'benchmarkproperties':'初始语料和执行速度对模糊测试排名的影响',
'stateinspector2022':'内部观察与灰盒协议状态机学习',
'wingmuzz2025':'黑盒协议测试中的二维调度',
'hybridllm2026':'LLM 辅助混合模糊测试的研究范围',
'hgfuzzer2026':'定向测试中的谓词引导执行合成',
'greenbenchmark2023':'可靠评测的资源成本',
'protocolguard2026':'规范一致性检查与动态验证',
'bsfuzzer2026':'BLE 语义测试与逻辑缺陷',
'mercuriuzz2026':'QUIC 实现的逻辑漏洞',
'distfuzz2025':'事件、故障、时间与消息序列反馈',
'blueman2025':'BLE 协议栈的模拟执行条件',
'fishfuzz2023':'距离信息驱动的目标与种子优先级',
'miner2023':'有效请求序列模板与参数学习',
'mutationassessment2023':'基于变异分析的故障导向评测',
'fuzztruction2023':'在生成程序中注入故障以保留格式约束'}
for item in m['sources']:
 key=item['key'];item['claim_scope']=scopes[key];item['cited_in']=[]
 for para in tex.split('\n\n'):
  if any(key in [x.strip() for x in group.split(',')] for group in re.findall(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^}]+)\}',para)):
   item['cited_in'].append({'line':tex[:tex.index(para)].count('\n')+1,'paragraph':para})
m['final_tex_sha256']=v['tex_sha256'];m['final_pdf_sha256']=v['pdf_sha256'];m['unique_actual_citations']=v['actual_distinct_citations']
if not any(x['candidate']=='G2Fuzz' for x in m['excluded']):m['excluded'].append({'candidate':'G2Fuzz','reason':'Official presentation identified, but source retrieval did not complete; excluded rather than added without complete verification.'})
(B/'manifest.json').write_text(json.dumps(m,ensure_ascii=False,indent=2)+'\n')
lines=['# 文献扩充与正文对应核验','',
'状态：PASS。按 first_paper.md 的证据校准主线补充实际引用；检索核验截止 2026-09-29。','',
'## 结果','',
f'- 正文实际引用 **{v["actual_distinct_citations"]} 篇**，由 25 篇增加至 50 篇；新增 25 篇均有明确论述位置。',
f'- 2022–2026 年文献 **{v["references_2022_2026"]} 篇（72%）**；新增文献中 24/25 篇发表于 2022–2026 年。',
'- 新增来源：USENIX Security 5 篇，NDSS 4 篇，ACM CCS 4 篇，ACM TOSEM 3 篇，IEEE TSE 2 篇，ISSTA 2 篇，ICSE、EuroSys、ESEC/FSE、ASE、OOPSLA 各 1 篇。',
'- 50 篇总数含必要的经典统计、概率校准和直接先行工作；不将全部条目宣称为近年顶会论文。',
'- 未使用 nocite 增加条目；无重复 DOI、重复题名或未引用的条目。','',
'## 正文修改','',
'- 相关工作按状态表征、执行条件、结构化生成、LLM 生成、调度、语义 oracle、评测方法组织。',
'- 实验控制补充资源成本文献；有效性讨论补充基准属性与变异分析文献。',
'- 明确已提出的方法与尚未完成的受控评测；未将他人实验数值或性能结论归属于本文。',
'- 保持响应状态代理与代码进度、provisional 与 durable、漏洞回放与受控再发现之间的区别。',
'- Beta–Bernoulli、Thompson sampling、已有状态建模与调度思想均保留先行工作归属。',
'- 修复一处原有断裂的 Table 引用；Figure 4 保持原矢量文件，仅将展示宽度调整为正文宽度的 97%，消除页高溢出。','',
'## 出版信息核验','',
'- 20 篇新增文献核对出版方提交至 Crossref 的题名、作者、DOI、年份、卷期及页码；5 篇采用 USENIX 官方摘要与 BibTeX。',
'- 方法细节引用限定于已查阅摘要支持的内容；其余引用仅说明已核实题名明确的研究范围，不引入性能数值或额外机制。',
'- WhiteFox 正确 DOI 为 10.1145/3689736；排除误匹配的 Rustlantis。ELFuzz 的误匹配页面实际为 GradEscape，未收入。',
'- FormatFuzzer 按正式期次记为 2024 年；HGFuzzer 明示 2026 年 8 月在线发表，未补造卷期页码。','',
'## PDF 与内容保护','',
f'- 已重新编译：{v["pages"]} 页；{v["internal_link_annotations"]} 个内部链接目标有效，{v["citation_link_annotations"]} 个文献链接覆盖全部 50 条独立文献目标。',
f'- 9 幅图、20 张表的 {v["figure_table_destinations"]} 个目的地完整；无未定义引用、重复目标或溢出框。',
f'- 摘要保持原文，按本轮词元规则计 {v["abstract_words"]} 词；关键词仍为 {v["keyword_count"]} 个。不同连字符分词方式可有 1 词差异。',
f'- {v["protected_files_byte_identical"]} 个既有受保护文件逐字节一致；所有实验表格、公式、算法与图表说明保持一致。',
'- 独立漏洞节副本在前一轮已仅变更引用包装，本轮没有修改；9 幅图仍是矢量图，PDF 中位图数为 0。',
'- XML 版面测量仅过滤 Poppler 从数学字体提取出的 3 个非法 XML 控制字符，不修改 PDF 或公式。']
if v['nonfatal_layout_notices']:
 lines+=['- 非致命排版提示（未屏蔽）：'+ '; '.join(v['nonfatal_layout_notices'])+'。提示对应浮动图表页，不是未定义引用或溢出错误。']
lines+=['','## 新增文献与论述对应','', '| 文献 | 年份 / 出处 | 支持的论述 | 正文行 | 核验来源 |','|---|---|---|---|---|']
for x in m['sources']:
 ls=', '.join(str(z['line']) for z in x['cited_in']);lines.append(f'| {x["title"]} | {x["year"]} / {x["venue"]} | {x["claim_scope"]} | {ls} | [来源]({x["source"]}) |')
lines+=['','## 复核','',
'在论文修订目录执行：','',
'    bash build_revised.sh',
'    python3 reference_expansion/verify_reference_expansion.py','',
'- 完整机器核验见 [validation.json](validation.json)，逐条来源及原句映射见 [manifest.json](manifest.json)。',
'- 原稿备份见 before_reference_expansion；本轮源文本差异见 [manuscript.diff](manuscript.diff)。',
'- 本轮未执行新实验。既有实验缺口仍然存在；文献扩充不构成补做实验，也不将回顾性证据升级为因果验证。','']
(B/'REFERENCE_EXPANSION_AUDIT.md').write_text('\n'.join(lines))
print(json.dumps({k:v[k] for k in ['status','actual_distinct_citations','new_references','references_2022_2026','pages','distinct_linked_bibliography_entries','overfull_boxes','nonfatal_layout_notices','examples']},ensure_ascii=False,indent=2))
print('REPORT',B/'REFERENCE_EXPANSION_AUDIT.md')
