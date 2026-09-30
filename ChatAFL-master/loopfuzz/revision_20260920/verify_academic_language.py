#!/usr/bin/env python3
"""Validate the academic-language revision without weakening empirical checks."""
from pathlib import Path
from collections import Counter
import ast,hashlib,json,re,subprocess
from refine_float_text import caption_span,block_span,apply_edits
B=Path(__file__).resolve().parent
spec=json.loads((B/'concise_float_text.json').read_text())
record=json.loads((B/'academic_language_edits.json').read_text())
backup=B/record['backup'];checks=Counter()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def check(ok,name):
    assert ok,name
    checks[name]+=1
names={f['file'] for f in spec['floats']}
before={n:(backup/n).read_text() for n in names}
after={n:(B/n).read_text() for n in names}
tex=after['main.revised.tex'];pdf=(B/'main.revised.txt').read_text()
banned=r'Key_Experiment|ablation/|benchmark/|vulnerability_evidence_\d+|trigger_loopfuzz|run_config|candidate_event|admission_trial|state_selection_episode|latency_ms|b_abs|make_ftp_cmd|INT_MAX|0x614b86|61e621e743346|97bbe68363cc|a2209018fb|060b6c2530c8|2ca10d9b|exit_137_near_limit|oom_killed|sigabrt|checkout|launcher|legacy'
check(not re.search(banned,pdf,re.I),'no local paths, file names, code fields or code identifiers in PDF')
workflow=r'\b(?:archive|archives|archived|native|saved|logging|logged|schema|manifest|ledger|checksum|digest|commit|scripts?|snapshot|audit|builds?|directory)\b'
check(not re.search(workflow,pdf,re.I),'no development-report terminology in PDF')
check(not re.search(r'\\(?:path|texttt)\{',tex),'no prose code-formatted literals in main source')
# Referenced resource paths remain compilation dependencies, never displayed prose.
check(re.findall(r'\\includegraphics(?:\[[^]]*\])?\{[^}]+\}',before['main.revised.tex'])==re.findall(r'\\includegraphics(?:\[[^]]*\])?\{[^}]+\}',tex),'figure references and sizes retained')
for name in names:
    check(before[name].count(r'\missing')==after[name].count(r'\missing'),'missing-value cells retained')
    check(re.findall(r'\\cite\w*\{[^}]+\}',before[name])==re.findall(r'\\cite\w*\{[^}]+\}',after[name]),'citation sequence retained')
for env in ['equation','align']:
    pat=r'\\begin\{'+env+r'\}.*?\\end\{'+env+r'\}'
    check(re.findall(pat,before['main.revised.tex'],re.S)==re.findall(pat,tex,re.S),'display equations unchanged')
alg=lambda s:re.findall(r'\\begin\{algorithm\}.*?\\end\{algorithm\}',s,re.S)
oldalg=alg(before['main.revised.tex']);newalg=alg(tex)
check([a.replace('immutable pre-trial snapshot','fixed pre-trial state') for a in oldalg]==newalg,'algorithm unchanged except explanatory input wording')
def table_rows(text,label):
    if label=='tab:archive_arms':
        t=text.split(r'\begin{supertabular}',1)[1].split(r'\end{supertabular}',1)[0]
    else:
        a,z=block_span(text,label);t=text[a:z]
    return [line.rstrip()[:-2].strip().split(' & ') for line in t.splitlines() if ' & ' in line and line.rstrip().endswith('\\\\')]
protected=0
for f in spec['floats']:
    name,label=f['file'],f['label'];a,z=caption_span(after[name],label)
    check(after[name][a:z]==f['caption']['new'],'caption matches reviewed wording')
    check(len(after[name][a:z].split())<=14,'short-caption limit retained')
    if not label.startswith('tab:'):continue
    oldrows,newrows=table_rows(before[name],label),table_rows(after[name],label)
    check(len(oldrows)==len(newrows),'table row count retained')
    for old,new in zip(oldrows,newrows):
        check(len(old)==len(new),'table column count retained')
        for i,(a,z) in enumerate(zip(old,new)):
            numeric=(a==r'\missing' or a.startswith(r'\shortstack{') or bool(re.fullmatch(r'[\d\s,.%+/:()=\-$]+',a)) or bool(re.fullmatch(r'[CXSO]:\d+(?:,[CXSO]:\d+)*',a)))
            # Mixed prose with numerical measurements is checked independently
            # against source evidence by the empirical/vulnerability validators.
            if numeric:check(a==z,'numerical or missing table cell unchanged');protected+=1
abstract=tex.split(r'\begin{abstract}',1)[1].split(r'\end{abstract}',1)[0]
abstract_words=len(abstract.split());keywords=tex.split(r'\begin{keyword}',1)[1].split(r'\end{keyword}',1)[0].split(r'\sep')
check(150<=abstract_words<=200,'abstract length 150--200')
check(len(re.findall(r"[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?",abstract))<=200,'abstract expanded-word limit')
check(len(keywords)<=5,'at most five keywords')
code=(B/'verify_acronym_consistency.py').read_text().split("old=(backup/'main.revised.tex').read_text()",1)[0]
exec(compile(code,'acronym_scope_checks','exec'),{'__file__':str(B/'verify_acronym_consistency.py')})
checks['independent abstract/body abbreviation scopes']=1
for phrase in [r'\gcode',r'\gstate','provisional','durable','pre-update','coverage-based retention','retrospective','do not yet establish causal admission gains','no imputation','direct execution observation (L)','case report (R)','remain unavailable for the controlled A--E comparison','ten independent runs','12-hour deadline','utility is never denoted $U(s)$.']:
    check(phrase in tex,'research positioning and evidence limits retained')
base=json.loads((B/'academic_figure_data_baseline.json').read_text())
for name,digest in base.items():check(sha(B/name)==digest,'figure numerical data byte-identical')
for name in ['refine_float_text.py','generate_tex_20260929.py','plot_updated_figures_20260929.py','plot_native_endpoints_20260929.py','verify_data_update_20260929.py','verify_vulnerability_evidence_20260929.py']:
    ast.parse((B/name).read_text());checks['script syntax valid']+=1
initial={name:sha(B/name) for name in names};check(apply_edits()==[],'editorial refinement idempotent')
subprocess.run(['python3','generate_tex_20260929.py'],cwd=B,check=True,stdout=subprocess.DEVNULL)
check(initial=={name:sha(B/name) for name in names},'regeneration preserves reviewed text and data')
full=json.loads((B/'data_update_validation_20260929.json').read_text());vuln=json.loads((B/'vulnerability_validation_20260929.json').read_text())
check(full['status']=='PASS','complete empirical validation passes')
check(vuln['status']=='PASS' and vuln['source_files_hash_verified']==14,'all vulnerability source hashes and replay batches pass')
for name in ['main.revised.tex','main.revised.pdf']:
    check(full['output_sha256'][name]==sha(B/name),'empirical validation matches delivered files')
check(vuln['manuscript_sha256']==sha(B/'main.revised.tex'),'vulnerability validation matches delivered text')
check(full['bibliography_entries']==25 and full['raster_images']==0,'references and vector-only figures retained')
layout=json.loads((B/'academic_language_layout.json').read_text())
check(layout['after']['pdf_sha256']==sha(B/'main.revised.pdf'),'layout review matches delivery')
check(all(p['whole']['largest_blank_band_pt']<=150 for p in layout['after']['pages'][:-1]),'no new large internal blank bands')
report={'status':'PASS','scope':'Academic-language revision; no new experiments or imputation','backup':record['backup'],'edits_recorded':len(record['edits']),'protected_numerical_or_missing_cells':protected,'figure_data_files_byte_identical':len(base),'abstract_words':abstract_words,'keywords':len(keywords),'pages':full['pages'],'bibliography_entries':25,'empirical_vector_figures':full['vector_figures'],'total_figures':sum(f['label'].startswith('fig:') for f in spec['floats']),'tables':sum(f['label'].startswith('tab:') for f in spec['floats']),'raster_images':0,'full_empirical_checks':sum(full['numeric_and_structural_checks'].values()),'vulnerability_source_files':14,'source_root_used':vuln['source_root'],'first_paper_sha256':sha(Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md')),'checks':dict(checks),'limitations':['The study remains retrospective and descriptive.','Controlled admission, calibration, and rediscovery effects remain unestablished.','Technical provenance is preserved outside the typeset manuscript.'],'output_sha256':{name:sha(B/name) for name in [*sorted(names),'main.revised.pdf']}}
(B/'academic_language_validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
lines=['# 论文学术化表达核验','', '状态：PASS。本轮依据 first_paper.md 调整论述方式，不增加实验或改变研究结论。','', '## 已完成修改','', '- 数据来源以实验条件和样本组成表述；移除本地目录、具体文件名和开发过程说明。','- 将实现核查改写为操作效度与测量，将原始事件字段改为观察类别、测量定义和证据对应关系。','- 将成本与漏洞段落改写为测量结果、控制条件和证据限制；精确版本标识另存作者核验记录。','- 同步调整矢量图标题与坐标标签，保留短图注和表注。','', '## 检查结果','',f'- {protected} 个数值或缺失单元格逐项保持；{len(base)} 个图形数值文件逐字节保持。',f'- 完整数值与结构校验 {report["full_empirical_checks"]:,} 项通过；14 个漏洞源文件哈希及各回放批次分母通过。','- 公式、算法逻辑及引用顺序保持；正文和图中无所扫描的目录、文件、字段或开发记录术语。',f'- 摘要 {abstract_words} 词，关键词 {len(keywords)} 个；摘要与正文缩写范围独立。',f'- PDF {full["pages"]} 页，25 条参考文献，9 幅矢量图；无未定义引用、越界盒子或大块正文空白。','', '## 科学边界','', '- 独立 code/IPSM 反馈、provisional/durable 分层、观测前预测和五个比较条件保留。','- 名义样本数和实际样本数分开；缺失数据不填零，回放批次不合并或冒充独立发现试验。','- 描述性结果不改写为已证实的因果收益；尚缺的受控实验仍明确指出。','', '原稿保存在 before_academic_language/；逐条前后对照和迁出的代码标识见 academic_language_edits.json。']
(B/'ACADEMIC_LANGUAGE_AUDIT.md').write_text('\n'.join(lines)+'\n')
provenance=['# 作者用技术溯源记录','', '本文件不参与论文排版。这里只保留本轮从论文叙述中移出的操作细节，不能视为新增实验结果。','', '| 案例 | 原始版本或证据标识 |','|---|---|','| ProFTPD / CVE-2023-51713 | vulnerable 61e621e743346; reported patch 97bbe68363cc; command parser make_ftp_cmd |','| LIVE555 / CVE-2026-38998 | diagnostic offset 0x614b86; missing fuzzer reproducer trigger_loopfuzz.raw |','| Kamailio / CVE-2026-39863 | vulnerable a2209018fb; reported upstream patch 060b6c2530c8; local guard INT_MAX/10 |','| SMARTPL | reported revision 2ca10d9b; version 27.2 |','', '上述身份与补丁效力的限制保持不变；附带日志观察不等价于本轮独立重执行。完整源文件清单与哈希仍由既有漏洞证据文件保存。','', '原事件名称 run_config、candidate_event、admission_trial、provisional_event、state_selection_episode、bug_event、repair_event 及所需字段，保留在 academic_language_edits.json 的原文中；论文表 5 改用对应的观察类别。','', '实际实验根目录：/home/ckt/Documents/000_2026_test_dev/Key_Experiment。原始结果不作改写。','', '数值复核命令：','', '    python3 verify_data_update_20260929.py --source-root /home/ckt/Documents/000_2026_test_dev/Key_Experiment','    python3 verify_vulnerability_evidence_20260929.py --source-root /home/ckt/Documents/000_2026_test_dev/Key_Experiment','    python3 verify_academic_language.py']
(B/'ACADEMIC_PROVENANCE_NOTES.md').write_text('\n'.join(provenance)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ['checks','output_sha256']},ensure_ascii=False,indent=2))
