from pathlib import Path
import ast,re,json,hashlib,subprocess,tempfile,collections,difflib,html,unicodedata
A=Path(__file__).resolve().parent;R=A.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
node=next(n for n in ast.parse((R/'reference_expansion/verify_reference_expansion.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='parse_bib')
exec(compile(ast.Module(body=[node],type_ignores=[]),'parser','exec'))
bib=parse_bib((R/'references.expanded.bib').read_text());before_bib=json.loads((A/'bibliography.json').read_text())
ass=json.loads((A/'assessments.json').read_text());sources={p.parent.name:json.loads(p.read_text()) for p in (A/'sources').glob('*/retrieval.json')}
assert set(bib)==set(ass)==set(sources), (set(bib)-set(ass),set(ass)-set(bib))
tex=(R/'main.revised.tex').read_text();before=(A/'before/main.revised.tex').read_text()
def occurrences(text,source='main.revised.tex'):
 out=[]
 for i,m in enumerate(re.finditer(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^{}]+)\}',text),1):
  # Each citation is associated with the complete sentence or table row containing it.
  para_start=text.rfind('\n\n',0,m.start())+2;para_end=text.find('\n\n',m.end());para_end=len(text) if para_end<0 else para_end
  para=text[para_start:para_end];rel=m.start()-para_start
  if '&' in para and '\\\\' in para:
   st=text.rfind('\n',para_start,m.start())+1;en=text.find('\n',m.end());en=para_end if en<0 else en
  else:
   starts=[x.end() for x in re.finditer(r'(?<!al)(?<=[.!?])\s+(?=[A-Z\\])',para[:rel])]
   st=para_start+(starts[-1] if starts else 0)
   rest=text[m.end():para_end];n=re.search(r'[.!?](?=\s|$)',rest);en=m.end()+n.end() if n else para_end
  context=text[st:en].strip();keys=[k.strip() for k in m[1].split(',')]
  out.append({'id':f'C{i:03}','source':source,'line':text.count('\n',0,m.start())+1,'keys':keys,'sentence':context,'paragraph':para.strip()})
 return out
before_occ=occurrences(before);after_occ=occurrences(tex)
assert len(before_occ)==49 and sum(len(o['keys']) for o in before_occ)==57
(A/'sentence_occurrences.before.json').write_text(json.dumps(before_occ,indent=2,ensure_ascii=False)+'\n')
(A/'sentence_occurrences.after.json').write_text(json.dumps(after_occ,indent=2,ensure_ascii=False)+'\n')
old_by_key=collections.defaultdict(list)
for o in before_occ:
 for k in o['keys']:old_by_key[k].append(o)
seen=collections.Counter();matrix=[]
for o in after_occ:
 for k in o['keys']:
  j=seen[k];seen[k]+=1;old=old_by_key[k][j] if j<len(old_by_key[k]) else None
  e=ass[k];s=sources[k]
  matrix.append({'id':f"{o['id']}:{k}",'key':k,'original_reference':k in before_bib,'before_line':old['line'] if old else None,'after_line':o['line'],'before_sentence':old['sentence'] if old else None,'after_sentence':o['sentence'],'assessment':e['assessment'],'evidence_pages':e['pages'],'page_kind':e.get('page_kind','PDF page including cover'),'evidence_section':e['section'],'interpretation':e['note'],'fulltext_status':s['status'],'source':s.get('source'),'source_version_note':s.get('version_note'),'source_sha256':s.get('sha256')})
(A/'sentence_evidence_matrix.json').write_text(json.dumps(matrix,indent=2,ensure_ascii=False)+'\n')
(A/'retrieval_manifest.json').write_text(json.dumps(list(sources.values()),indent=2,ensure_ascii=False)+'\n')
# Assert the empirical results have only the declared terminology change.
marker=r'\section{Available Evidence and Results}'
old_tail=before.split(marker,1)[1];new_tail=tex.split(marker,1)[1]
old_tail=old_tail.replace('reports the BS, ten-bin ECE, and AUPRC as AP;','reports the BS, ten-bin ECE, and non-interpolated AP;').replace('BS / ECE / AUPRC &','BS / ECE / AP &')
assert old_tail==new_tail,'Unexpected empirical-results change'
snapshot=json.loads((A/'snapshot.json').read_text());protected=[]
for path,info in snapshot.items():
 p=Path(path)
 if p.name in ['main.revised.tex','main.revised.pdf','references.expanded.bib']:continue
 assert sha(p)==info['sha256'],str(p);protected.append(str(p))
expected=set(bib);cites=[k for o in after_occ for k in o['keys']]
assert set(cites)==expected and len(expected)==51
aux=(R/'main.revised.aux').read_text();bbl=(R/'main.revised.bbl').read_text()
assert set(re.findall(r'\\bibcite\{([^{}]+)\}',aux))==expected
assert set(re.findall(r'\\bibitem(?:\[[^]]*\])?\{([^{}]+)\}',bbl))==expected
abstract=re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}',tex,re.S)[1];words=re.findall(r"\b[A-Za-z0-9]+(?:[’'-][A-Za-z0-9]+)*\b",abstract)
keywords=re.search(r'\\begin\{keyword\}(.*?)\\end\{keyword\}',tex,re.S)[1].split(r'\sep')
assert 150<=len(words)<=200 and len(keywords)<=5
run=lambda args:subprocess.check_output(args,cwd=R,text=True,stderr=subprocess.PIPE)
info=run(['pdfinfo','main.revised.pdf']);pages=int(re.search(r'^Pages:\s*(\d+)',info,re.M)[1])
desttext=run(['pdfinfo','-dests','main.revised.pdf']);(A/'pdf_destinations.txt').write_text(desttext)
dests={}
for line in desttext.splitlines():
 m=re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"',line)
 if m:dests[m[4]]={'page':int(m[1]),'x':int(m[2]),'y':int(m[3])}
tree=ast.parse((R/'verify_reference_links_20260930.py').read_text())
ps=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ps' for t in n.targets))
with tempfile.TemporaryDirectory(prefix='claim_audit_') as tmp:
 p=Path(tmp)/'inspect.ps';p.write_text(ps);annotations=run(['gs','-q','-dNODISPLAY','-dBATCH','-dNOSAFER','-f',str(p)])
(A/'pdf_annotations.txt').write_text(annotations);counts=collections.Counter();internal=0
for line in annotations.splitlines():
 if line.startswith('EXTERNAL\t'):continue
 typ,page,dest,rect=line.split('\t',3);assert typ=='INTERNAL' and dest in dests
 xy=list(map(float,re.findall(r'-?\d+(?:\.\d+)?',rect)));assert len(xy)==4 and xy[2]>xy[0] and xy[3]>xy[1];assert 1<=dests[dest]['page']<=pages
 counts[dest]+=1;internal+=1
for k,n in collections.Counter(cites).items():assert counts['cite.'+k]>=n,(k,n,counts['cite.'+k])
assert len({tuple(dests['cite.'+k].values()) for k in bib})==51
log=(R/'main.revised.log').read_text();blg=(R/'main.revised.blg').read_text();critical=[l for l in log.splitlines() if any(t in l for t in ['Overfull','undefined','destination with the same identifier','! LaTeX Error','! Package'])]
assert not critical,critical
statuses=collections.Counter(sources[k]['status'] for k in before_bib)
validation={'build_and_document_integrity':'PASS','all_50_final_publication_fulltexts_verified':False,'scope':'Full-text-based verification of cited sentences, with explicit inaccessible-source and version limitations; not validation of empirical data or every statement in the source papers.','original_references':50,'current_references':51,'original_citation_groups':49,'original_citation_uses':57,'current_citation_groups':len(after_occ),'current_citation_uses':len(cites),'original_source_status_counts':dict(statuses),'supplemental_reference':'tscheduler2024','unresolved_fulltexts':[k for k in before_bib if sources[k]['status']=='unavailable'],'version_limited':[k for k in before_bib if sources[k]['status']=='fulltext_preprint_version_limited'],'web_fulltexts_without_local_pdf':[k for k in before_bib if sources[k]['status']=='fulltext_web_reviewed'],'abstract_words':len(words),'keywords':len(keywords),'pages':pages,'internal_links':internal,'citation_links':sum(n for k,n in counts.items() if k.startswith('cite.')),'linked_citation_targets':51,'dangling_links':0,'critical_latex_messages':critical,'bibtex_warnings':[l for l in blg.splitlines() if l.startswith('Warning--')],'underfull_notices':log.count('Underfull'),'experimental_results_unchanged_except_AP_label':True,'protected_inputs_unchanged':protected,'file_hashes':{p.name:sha(p) for p in [R/'main.revised.tex',R/'main.revised.pdf',R/'references.expanded.bib']}}
(A/'validation.json').write_text(json.dumps(validation,indent=2,ensure_ascii=False)+'\n')
for name in ['main.revised.tex','references.expanded.bib']:
 diff=''.join(difflib.unified_diff((A/'before'/name).read_text().splitlines(True),(R/name).read_text().splitlines(True),fromfile='before/'+name,tofile='after/'+name))
 (A/(name+'.diff')).write_text(diff)
# Human-readable audit; explicitly separate source availability from support verdicts.
lines=['# 全文—正文论断逐句审查（2026-09-30）','','## 结论与未完成边界','','**未达到“原 50 篇正式发表版本全部完成全文核验”。不得将本报告或编译检查的 PASS 改写为所有引用都已完全核实。**','','- 原稿 50 篇、49 处引文组、57 次文献使用已逐一列入证据矩阵；没有抽样省略条目。','- 43 篇完成基于可访问全文的对应引用句核查：41 篇有本地原始 PDF，另 2 篇通过浏览器阅读全文。','- FuzzGPT、HGFuzzer 另取得早期预印本：窄范围陈述可对照，但正式版版本差异仍未完成核验。','- 5 篇未取得完整原文：NSFuzz、SSGFuzz、WingMuzz、Zhang 等（2026）及 Brier（1950）。出版记录或摘要验证不能代替全文验证。','- 为满足 first_paper.md 明确要求，另补入并审查真正的 T-Scheduler（Luo 等，AsiaCCS 2024），没有把它与 Zhang 等（2026）混同。当前正文引用 51 篇、59 次。','','## 本轮实质修正','','1. 分开 Gramatron/CarpetFuzz，以及 ChatAFL/LLMIF/Fuzz4All 的机制归属，消除一组引文笼统支撑多项机制的歧义。','2. 增补 T-Scheduler；删除未以 Zhang 全文证实的 Beta 机制归属，并收窄与 SSGFuzz 的排他性比较。','3. HGFuzzer 只保留作者稿和正式题名共同支持的高层定位，删除更具体且尚未完成最终版核验的 predicate-guided synthesis。','4. 明确 Guo 的 ECE 在本文中是对二元 episode reward 概率的适配，不直接等同原文的预测类别置信度校准。','5. 统一为现有实现实际计算的非插值 AP；去除 AP 与任意 AUPRC 面积等同的表述。数值没有重算。','6. Efron 引文限定为 bootstrap 原理；整 run 抽样、百分位区间和层级设计明确为本文的分析选择。','7. Mann–Whitney 限定独立 run 对比并处理并列值，不把秩检验直接解释为中位数差；Cliff δ 明确优势概率之差及方向。','8. BH 改为 nominal q，指出原始保证所需独立性并未由共享比较组/相关终点自动满足；KM 补充非信息性删失条件。','9. Thompson 原始论文与本文折扣、frontier 权重和比例采样适配明确区分；不宣称后者由经典文献保证。','10. 根据 Efron 原始扫描论文补齐页码 1–26。','','## 审查方法','','检查每个引文所在完整句子或表格行，并查看相邻机制/统计解释是否将本文设计或实测结论归属于外部文献。取得完整论文后，定位与引文对应的原始方法、定义、结果和限制；报告页码/章节及支持范围。本报告不声称逐字转录所有原文，也不重新验证这些论文的实验结果。','','页码默认包含 PDF 封面；Cliff 条目使用期刊印刷页码。arXiv/作者稿并不被称为出版社最终排版版本。除已知题名/作者差异单列的两篇外，其余作者稿的结论仅限当前实际引用的论断。','','## 来源与版本限制','','- Mann–Whitney：浏览器成功读取完整 12 页 PDF（封面 + 11 页论文）；本地下载超时，未伪造本地 SHA-256。','- Cliff：浏览器读取原论文 494–509 页的全文镜像转录。镜像可能存在 OCR 差异；它不是出版社 PDF，本地请求只返回访问外壳，不作为全文副本。','- Efron：27 页扫描 PDF，只有封面可自动提取文字。正文原 pp. 1–3 经渲染图像直接审阅，不能将封面文字量冒充 OCR 全文。','- FuzzGPT：预印本题名为 Large Language Models are Edge-Case Fuzzers: Testing Deep Learning Libraries via FuzzGPT，正式题名已变化；六位作者相符。','- HGFuzzer：2025 预印本为三作者；2026 正式条目为四作者。相关机制不可假定逐字未变。','','## first_paper.md 对应检查','','| 要求 | 当前处理 |','|---|---|','| response-derived state 不等于独立代码进度 | 保留双反馈分离；StateAFL 的既有发现被明确承认。 |','| LLM 只提出候选，execute-before-promote，provisional/durable | 方法与创新边界保持一致；未以他人生成方法代替本文准入证据。 |','| 不将 Beta/Thompson 本身当创新 | 补入 T-Scheduler，保留 The Bandit’s States 和 SSGFuzz；强调组合与独立证据。 |','| Magma / 漏洞证据分层 | reached / triggered / detected 区分不变；回放不等于受控再发现。 |','| 公平性与五 arm 因果对照 | 保持 matched policy/cap 与实际使用量的区别；未将未完成实验写成完成。 |','| 缺失数据与证据限制 | 实验数值及输入文件不变；本轮仅修正引证与统计措辞，不填造实验。 |','| 摘要和关键词限制 | 摘要 '+str(len(words))+' 词，关键词 '+str(len(keywords))+' 个。 |','','这只能确认本轮改动与上述主线约束相容；不能因为引证修订就宣称整篇已满足所有实验完成要求。SSGFuzz 等未取得全文的创新比较仍有待解决的证据缺口。','','## 逐篇覆盖清单','','| # | key / 题名 | 正文行号 | 来源状态 | 页码 / 章节 | 结论 |','|---:|---|---|---|---|---|']
labels={'fulltext_downloaded':'本地全文','fulltext_web_reviewed':'浏览器全文（无本地 PDF）','fulltext_preprint_version_limited':'早期版本；待最终版','unavailable':'全文未取得'}
for i,(k,b) in enumerate(bib.items(),1):
 e=ass[k];s=sources[k];loc=', '.join(str(o['line']) for o in after_occ if k in o['keys']);title=b['title'].replace('{','').replace('}','').replace('|','/')
 pg=', '.join(map(str,e['pages'])) or '—';sec=e['section'] or '—'
 lines.append(f"| {i} | {k}: {title} | {loc} | {labels[s['status']]} | {pg}; {sec} | {e['assessment']} |")
lines+=['','## 逐句证据矩阵','','以下每项对应一次实际文献使用，保留修改前后原句；多文献同句分别给出证据，避免用其中一篇替代整组。完整可机读记录见 sentence_evidence_matrix.json。']
for row in matrix:
 k=row['key'];lines+=['',f"### {row['id']} — main.revised.tex:{row['after_line']}",'',f"- 状态：{row['assessment']}；{labels[row['fulltext_status']]}",'- 原句：'+(row['before_sentence'] or '（本轮新增必需文献）'),'- 当前句：'+row['after_sentence'],f"- 原文位置：{row['evidence_pages']} / {row['evidence_section']}（{row['page_kind']}）",'- 核查说明：'+row['interpretation'],f"- 来源记录：[retrieval.json](sources/{k}/retrieval.json)"]
lines+=['','## 编译与文件完整性','','- 编译通过，'+str(pages)+' 页；51 个引文目标、'+str(validation['citation_links'])+' 个文献链接；无悬空链接。','- 无未定义引用、Overfull 越界和致命 LaTeX 错误。仍有 '+str(validation['underfull_notices'])+' 条非致命 Underfull 提示，不能据此声称完成了新的全篇视觉排版检查。','- 4 条 BibTeX 缺页码提示保留：DistFuzz、ProtocolGuard、BSFuzzer、MerCuriuzz。未将 PDF 文件页数擅自当会议出版页码。','- 结果章节仅调整 AP 名称；实验表输入和 first_paper.md 的 SHA-256 与开始时完全相同。','- 逐项验证见 [validation.json](validation.json)；文稿差异见 [main.revised.tex.diff](main.revised.tex.diff)。','','## 后续关闭条件','','须取得并核查五篇缺失全文，并比对 FuzzGPT、HGFuzzer 的正式版。对来源镜像的严格出版版本复核，还需补存 Mann–Whitney 和 Cliff 的可信最终版 PDF。完成这些条件前，不能声称“50 篇正式版全文逐句审查全部通过”。']
(A/'FULLTEXT_CLAIM_AUDIT_20260930.md').write_text('\n'.join(lines)+'\n')
status=R/'CITATION_STATUS.md'
if not (A/'before/CITATION_STATUS.md').exists():(A/'before/CITATION_STATUS.md').write_bytes(status.read_bytes())
status.write_text('# 引用状态（2026-09-30）\n\n当前主稿实际引用 51 篇：原有 50 篇，另按 first_paper.md 补入 T-Scheduler。\n\n原 50 篇中，43 篇完成基于可访问全文的对应引用句核查（41 篇本地 PDF，2 篇浏览器全文）；2 篇仅取得有版本差异的早期预印本；5 篇全文仍未取得。不得写作全部正式版全文核验通过。\n\n本轮已修正多文献机制归属、创新边界及 AP/ECE/bootstrap/检验假设表述，并重编译 PDF。详见 [逐句全文审查](fulltext_claim_audit_20260930/FULLTEXT_CLAIM_AUDIT_20260930.md) 与 [验证结果](fulltext_claim_audit_20260930/validation.json)。\n\n上一轮书目存在性核验见 [历史报告](reference_reality_audit_20260930/REFERENCE_REALITY_AUDIT_20260930.md)。该报告是历史快照，其中 T-Scheduler 和 Efron 页码待核问题已在本轮解决，不应以旧版脚本覆盖当前稿件或引用状态。\n')
print(json.dumps(validation,ensure_ascii=False,indent=2))
