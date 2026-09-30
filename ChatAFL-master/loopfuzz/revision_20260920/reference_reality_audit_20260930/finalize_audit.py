from pathlib import Path
import ast, re, html, json, hashlib, subprocess, tempfile, collections, unicodedata
from urllib.parse import quote
ROOT=Path(__file__).resolve().parent.parent
OUT=Path(__file__).resolve().parent
node=next(n for n in ast.parse((ROOT/'reference_expansion/verify_reference_expansion.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='parse_bib')
exec(compile(ast.Module(body=[node],type_ignores=[]),'parser','exec'))
bib=parse_bib((ROOT/'references.expanded.bib').read_text())
def norm(s):
 s=unicodedata.normalize('NFKD', html.unescape(s))
 return re.sub('[^a-z0-9]','',s.lower())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):return subprocess.check_output(args,cwd=ROOT,text=True,stderr=subprocess.PIPE)
official=[]
for key,f in bib.items():
 if f.get('doi'):continue
 path=OUT/'official'/f'{key}.html'
 source=html.unescape(re.sub('<[^>]+>','',path.read_text()))
 matches=[x for x in parse_bib(source).values() if norm(x.get('title',''))==norm(f['title'])]
 assert len(matches)==1,(key,len(matches))
 other=matches[0]
 checks={k:norm(f.get(k,''))==norm(other.get(k,'')) for k in ['title','author','year','pages']}
 venue=lambda s:norm(re.sub(r'Security\s+20(\d\d)',r'Security \1',s))
 checks['venue']=venue(f['booktitle'])==venue(other['booktitle'])
 assert all(checks.values()),(key,checks)
 official.append({'key':key,'checks':checks,'source_fields':other,'evidence_file':str(path.relative_to(ROOT)),'sha256':sha(path)})
(OUT/'official_metadata_comparison.json').write_text(json.dumps(official,ensure_ascii=False,indent=2)+'\n')
tex=(ROOT/'main.revised.tex').read_text()
body=tex.split(r'\begin{document}',1)[1]
for name in re.findall(r'\\input\{([^{}]+)\}',tex):
 p=ROOT.parent/name
 if not p.suffix:p=p.with_suffix('.tex')
 body+='\n'+p.read_text()
cites=[k.strip() for g in re.findall(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^{}]+)\}',body) for k in g.split(',')]
aux=(ROOT/'main.revised.aux').read_text(); bbl=(ROOT/'main.revised.bbl').read_text()
compiled=set(re.findall(r'\\bibcite\{([^{}]+)\}',aux))
items=set(re.findall(r'\\bibitem(?:\[[^]]*\])?\{([^{}]+)\}',bbl))
assert set(cites)==compiled==items==set(bib)
assert len(bib)==50
assert len({f['doi'].lower() for f in bib.values() if f.get('doi')})==42
assert len({norm(f['title']) for f in bib.values()})==50
pages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo','main.revised.pdf']),re.M)[1])
desttext=run(['pdfinfo','-dests','main.revised.pdf'])
(OUT/'pdf_destinations.txt').write_text(desttext)
dests={}
for line in desttext.splitlines():
 m=re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"',line)
 if m:dests[m[4]]={'page':int(m[1]),'x':int(m[2]),'y':int(m[3])}
tree=ast.parse((ROOT/'verify_reference_links_20260930.py').read_text())
ps=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ps' for t in n.targets))
with tempfile.TemporaryDirectory(prefix='citation_current_') as d:
 p=Path(d)/'inspect.ps';p.write_text(ps)
 annotations=run(['gs','-q','-dNODISPLAY','-dBATCH','-dNOSAFER','-f',str(p)])
(OUT/'pdf_annotations.txt').write_text(annotations)
links=[]
for line in annotations.splitlines():
 if line.startswith('EXTERNAL\t'):continue
 assert line.startswith('INTERNAL\t'),line
 _,page,dest,rect=line.split('\t',3)
 assert dest in dests,(page,dest)
 xy=list(map(float,re.findall(r'-?\d+(?:\.\d+)?',rect)))
 assert len(xy)==4 and xy[2]>xy[0] and xy[3]>xy[1]
 assert 1<=dests[dest]['page']<=pages
 links.append({'page':int(page),'destination':dest,'rect':xy})
counts=collections.Counter(x['destination'] for x in links)
for key,n in collections.Counter(cites).items():assert counts['cite.'+key]>=n,(key,n)
assert len({tuple(dests['cite.'+k].values()) for k in bib})==50
log=(ROOT/'main.revised.log').read_text();blg=(ROOT/'main.revised.blg').read_text()
critical=[l for l in log.splitlines() if any(t in l for t in ['Overfull','undefined','destination with the same identifier','! LaTeX Error','! Package'])]
assert not critical,critical
before=(OUT/'references.before_protocolguard_fix.bib').read_text()
current=(ROOT/'references.expanded.bib').read_text()
assert before.replace('and Zhao, Qingchuan and Guo, Shanqing and Liu, Xiaofeng},','and Zhao, Qingchuan and Guo, Shanqing},')==current
assert (OUT/'main.before.tex').read_bytes()==(ROOT/'main.revised.tex').read_bytes()
validation={'status':'PASS','scope':'Bibliography existence, official-page metadata and current PDF citations; not full-text claim validation','bibliography_entries':50,'doi_entries':42,'official_without_doi':8,'pages':pages,'internal_links':len(links),'citation_links':sum(n for k,n in counts.items() if k.startswith('cite.')),'linked_citation_targets':50,'dangling_destinations':0,'duplicate_dois':0,'duplicate_titles':0,'main_tex_unchanged_this_audit':True,'bibliography_only_change':'Remove duplicate Xiaofeng Liu from ProtocolGuard, following the NDSS author list','bibtex_warnings':[l for l in blg.splitlines() if l.startswith('Warning--')],'latex_underfull_notices':log.count('Underfull'),'missing_page_fields':[k for k,f in bib.items() if not f.get('pages')],'hashes':{p.name:sha(p) for p in [ROOT/'main.revised.tex',ROOT/'references.expanded.bib',ROOT/'main.revised.pdf']},'official_comparison':official}
(OUT/'current_validation.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2)+'\n')
live=json.loads((OUT/'live_crossref_comparison.json').read_text())
assert len(live)==42 and all(x.get('status')==200 and x.get('doi_match') and x.get('year_match') for x in live)
cached=json.loads((OUT/'cached_metadata_comparison.json').read_text())
assert len(cached)==42 and all(x['title_ok'] for x in cached)
lines=['# 参考文献真实性逐条核验（2026-09-30）','','## 结论','','当前 main.revised.tex 实际加载 references.expanded.bib，共 50 条，全部在正文引用并进入 PDF。50 条均找到相应外部出版记录，未发现凭空杜撰或 DOI 指向完全无关论文的条目。文献存在性与全部书目字段准确性、正文引用准确性分别判断。','','- 42 条 DOI：本轮实时 Crossref DOI 查询均返回对应记录，题名、作者完整姓名、出版信息结合原始缓存逐项复核。','- 8 条无 DOI：7 条 USENIX、1 条 PMLR，实时官方页面中的 BibTeX 题名、作者、年份、页码和会议逐项核对通过；不以 HTTP 200 单独认定真实性。','- 无重复 DOI、重复规范化题名或未引用条目。','','## 确切修正','','ProtocolGuard 的 Crossref 作者记录将 Xiaofeng Liu 重复列在第 7 位和第 10 位；当前 BibTeX 原样继承了这一错误。NDSS 官方作者页仅列 9 人且 Xiaofeng Liu 只出现一次。本轮已删除末尾重复作者，重新编译 PDF；正文和实验数据未改变。','', '[NDSS 官方作者页](https://www.ndss-symposium.org/ndss-paper/protocolguard-detecting-protocol-non-compliance-bugs-via-llm-guided-static-analysis-and-dynamic-verification/)；抓取证据见 official/protocolguard2026.html。','','## 需要保留的说明','','- Magma、Nyx-net、The Closer You Look, The More You Learn：Crossref 将主标题与副标题分字段存储；合并后与 BibTeX 完整题名一致。','- FormatFuzzer：Crossref 题名含 scp 展示标签；去除标签后对应。以上四项是初始匹配脚本的表示差异，不是虚假文献。','- SSGFuzz：首次上线为 2025-07-09，正式出版年为 2026。当前按出版社推荐引用使用 2026，不应据此声称该工作到 2026 年才首次出现。','- HGFuzzer：记录显示 2026-08-22 在线发表，尚未获得卷期页码；当前保留在线发表状态。','- Fuzz4All：完整姓名 Jia Le Tian 可对应，Crossref 的 given=Jia、family=Le Tian 与当前 BibTeX 姓名解析不同。本轮未擅自更改姓氏拆分；姓名格式仍需依据作者/出版社推荐引用确认。','- pages 字段为空的条目共七条：StateAFL 已使用文章号 191，HGFuzzer 保留在线发表状态；其余五条为 Efron (1979)、DistFuzz、ProtocolGuard、BSFuzzer、QUIC 逻辑漏洞论文。已取得的元数据未给出可用页码，不能据此断言论文原文没有页码。Project Euclid 本轮返回短页面，未将其用作补页码证据。','- first_paper.md 点名的 T-Scheduler 身份仍未确认；当前 Zhang 等的 Thompson-sampling 种子调度论文确实存在，但没有足够证据证明二者是同一个工作。该要求仍不能宣称已完全满足。','','## 逐条清单','','所有 DOI 条目均有实时查询记录；其中四个题名表示差异已用 subtitle 字段或标签规范化解释。编号按下表顺序，不冒充 PDF 中的引用编号。','','| 序号 | 引用 key | 完整题名 | 年份 | 一手来源 |','|---:|---|---|---:|---|']
for i,(key,f) in enumerate(bib.items(),1):
 title=f['title'].replace('{','').replace('}','').replace('|','/'); doi=f.get('doi')
 source=f'[{doi}](https://doi.org/{quote(doi,safe="/")})' if doi else f'[官方页面]({f["url"]})'
 lines.append(f'| {i} | {key} | {title} | {f["year"]} | {source} |')
lines+=['','## 当前文件核验','',f'- 重新编译成功：{pages} 页，50 条参考文献；{len(links)} 个内部链接、{validation["citation_links"]} 个文献链接覆盖 50 个独立文献目标，没有悬空目标。','- 有四条 BibTeX 缺页码警告及非致命 Underfull 提示；无未定义引用、Overfull 越界或致命错误。','- 本轮主稿 main.revised.tex 与开始时逐字节一致；参考文献仅有 ProtocolGuard 作者去重一项变更。','- 旧版两个验证脚本因比较更早正文快照而失败，未将它们标记为通过；本轮使用其中只读 PDF 检查逻辑，针对当前条目集合独立验证。','- 当前结果见 [current_validation.json](current_validation.json)，可运行 python3 reference_reality_audit_20260930/finalize_audit.py 复核。','','## 证据文件','','- [42 条实时 Crossref 查询比较](live_crossref_comparison.json)。','- [原始缓存字段比较](cached_metadata_comparison.json)：保留未经人工解释覆盖的初始差异，ProtocolGuard 以官方作者表优先。','- [八篇官方 BibTeX 逐字段比较](official_metadata_comparison.json)。','- [官方页面抓取时间与 SHA-256](live_official_manifest.json)。','- PDF 的实际命名目标和链接注释分别见 pdf_destinations.txt、pdf_annotations.txt。','- references.before_protocolguard_fix.bib 是按唯一单行修正反向重建的修改前副本；原 Crossref/官方缓存均保留。','','## 核验范围','','本轮确认出版记录存在，检查主要书目字段并修正已确证错误；没有逐篇精读全部 50 篇全文核验每一句正文论断，也没有进行完整撤稿状态审查或会议期刊等级评级。不能把“文献真实”写成“所有引用完全正确”或“50 篇都是近年顶会顶刊”。']
(OUT/'REFERENCE_REALITY_AUDIT_20260930.md').write_text('\n'.join(lines)+'\n')
status=ROOT/'CITATION_STATUS.md'
if not (OUT/'CITATION_STATUS.before.md').exists():(OUT/'CITATION_STATUS.before.md').write_bytes(status.read_bytes())
status.write_text('# 引用状态（更新于 2026-09-30）\n\n当前主稿实际使用 references.expanded.bib，共 50 条且全部实际引用。42 条匹配本轮 Crossref DOI 查询，8 条匹配 USENIX/PMLR 官方 BibTeX。未发现不存在的条目；本轮按 NDSS 官方作者表删除 ProtocolGuard 的重复作者。\n\n逐条来源、字段差异、页码缺失、T-Scheduler 身份未确认以及当前 PDF 核验结果见 [真实性审计](reference_reality_audit_20260930/REFERENCE_REALITY_AUDIT_20260930.md)。书目真实性不替代全文引用准确性审查。旧版 25 条状态已经归档。\n')
print(json.dumps({k:v for k,v in validation.items() if k not in ['official_comparison','hashes']},ensure_ascii=False,indent=2))
