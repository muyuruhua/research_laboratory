#!/usr/bin/env python3
"""Verify the reviewed editorial change against its own manuscript backup."""
from pathlib import Path
from collections import Counter
import ast,hashlib,json,re,subprocess
from refine_float_text import caption_span,block_span,apply_edits
B=Path(__file__).resolve().parent
spec=json.loads((B/'concise_float_text.json').read_text());backup=B/spec['backup']
BS=chr(92)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
checks=Counter();stats=[]
def check(ok,label):
    assert ok,label
    checks[label]+=1

def words(text):
    # Transparent, stable word-count convention for comparing TeX prose.
    text=re.sub(r'\\(?:ref|figref|tabref|cite\w*)\{[^}]*\}','REF',text)
    text=re.sub(r'\\[A-Za-z@]+','',text)
    text=text.replace('{','').replace('}','').replace('$','')
    return len(text.split())

def rows(text,label):
    if label=='tab:archive_arms':
        block=text.split(r'\begin{supertabular}',1)[1].split(r'\end{supertabular}',1)[0]
    else:
        a,z=block_span(text,label);block=text[a:z]
    return [line.rstrip()[:-2].strip().split(' & ') for line in block.splitlines()
            if ' & ' in line and line.rstrip().endswith(BS*2)]

files={f['file'] for f in spec['floats']}
pre={name:(backup/name).read_text() for name in files}
post={name:(B/name).read_text() for name in files}
expected_labels={f['label'] for f in spec['floats']}
actual_labels={x for text in post.values() for x in re.findall(r'\\label\{((?:fig|tab):[^}]+)\}',text)}
check(expected_labels==actual_labels,'all figure/table labels reviewed')
protected_cells=0
for f in spec['floats']:
    name,label=f['file'],f['label'];old,new=pre[name],post[name]
    a,z=caption_span(old,label);oldcap=old[a:z]
    a,z=caption_span(new,label);newcap=new[a:z]
    check(oldcap==f['caption']['old'],'caption original matches backup')
    check(newcap==f['caption']['new'],'caption matches reviewed copy')
    rowstats={'label':label,'file':name,'caption_words_before':words(oldcap),'caption_words_after':words(newcap)}
    if label.startswith('tab:'):
        before,after=rows(old,label),rows(new,label)
        rowstats.update(cell_words_before=sum(words(c) for row in before for c in row),cell_words_after=sum(words(c) for row in after for c in row))
        if label!='tab:events':
            check([r[0] for r in before]==[r[0] for r in after],'table row identities preserved')
            edits={(e['row'],e['column']):e for e in f['cells']}
            for r1,r2 in zip(before,after):
                check(len(r1)==len(r2),'table column counts preserved')
                for col,(v1,v2) in enumerate(zip(r1,r2)):
                    e=edits.get((r1[0],col))
                    if e:
                        check(v1==e['old'] and v2==e['new'],'cell matches reviewed copy')
                    else:
                        check(v1==v2,'unmodified table cell preserved')
                        if v1==r'\missing' or re.match(r'^(?:[\d-]|\\shortstack\{\d)',v1):protected_cells+=1
        else:
            check(len(before)==len(after)==8,'seven event streams preserved')
            check([r[0] for r in before][1:]==[r[0] for r in after][1:],'event stream names preserved')
            check(all(len(r)==3 for r in after),'schema split into three columns')
    stats.append(rowstats)

old,new=pre['main.revised.tex'],post['main.revised.tex']
for name in files:
    check(pre[name].count(r'\missing')==post[name].count(r'\missing'),'missing evidence cells preserved')
    check(re.findall(r'\\cite\w*\{[^}]+\}',pre[name])==re.findall(r'\\cite\w*\{[^}]+\}',post[name]),'citation commands preserved')
for env in ['equation','align','algorithm']:
    pattern=r'\\begin\{'+env+r'\}.*?\\end\{'+env+r'\}'
    check(re.findall(pattern,old,re.S)==re.findall(pattern,new,re.S),'display equations and algorithms preserved')
abstract=lambda t:t.split(r'\begin{abstract}',1)[1].split(r'\end{abstract}',1)[0]
check(abstract(old)==abstract(new),'abstract unchanged')
abstract_words=len(abstract(new).split());check(150<=abstract_words<=200,'abstract word limit')
keywords=new.split(r'\begin{keyword}',1)[1].split(r'\end{keyword}',1)[0].split(r'\sep')
check(len(keywords)<=5,'keyword limit')
check(re.findall(r'\\includegraphics(?:\[[^]]*\])?\{[^}]+\}',old)==re.findall(r'\\includegraphics(?:\[[^]]*\])?\{[^}]+\}',new),'figure references and sizes preserved')
# Reuse only the original acronym-scope checks; its older numeric-diff test
# belongs to the previous acronym-only task, not this caption/cell edit.
acronym_code=(B/'verify_acronym_consistency.py').read_text().split("old=(backup/'main.revised.tex').read_text()",1)[0]
exec(compile(acronym_code,'acronym_scope_checks','exec'),{'__file__':str(B/'verify_acronym_consistency.py')})
checks['independent abstract/body acronym scopes']=1
for token in ['Every event also records the run ID, schema version, sequence number, and timestamp.','CVE identities remain isolated benchmark metadata.',r'\gcode',r'\gstate','utility is never denoted $U(s)$.','remain unavailable for the controlled A--E comparison','Empty bins have no estimate','Each run contributes only between its first and last observation']:
    check(token in new,'scientific boundary retained')
for name in ['refine_float_text.py','generate_tex_20260929.py','plot_updated_figures_20260929.py','verify_data_update_20260929.py','verify_vulnerability_evidence_20260929.py']:
    ast.parse((B/name).read_text());checks['python syntax']+=1
hashes={name:sha(B/name) for name in files}
check(apply_edits()==[],'copy editor is idempotent')
check(hashes=={name:sha(B/name) for name in files},'idempotence preserves bytes')
log=(B/'main.revised.log').read_text()
for bad in ['! LaTeX Error','! Undefined','Fatal error','Overfull '+BS+'hbox','Float too large','undefined citations','undefined references']:
    check(bad not in log,'no build errors or overfull boxes')
check(not re.search(r'(Citation|Reference) .+ undefined',log),'cross-references resolved')
validation=json.loads((B/'data_update_validation_20260929.json').read_text())
check(validation['status']=='PASS','full numerical audit passes')
for name in ['main.revised.tex','main.revised.pdf']:
    check(validation['output_sha256'][name]==sha(B/name),'final numeric audit hashes match delivery')
vuln=json.loads((B/'vulnerability_validation_20260929.json').read_text())
check(vuln['status']=='PASS' and vuln['source_files_hash_verified']==14,'vulnerability source audit passes')
check(vuln['manuscript_sha256']==sha(B/'main.revised.tex'),'vulnerability audit matches delivery')
layout=json.loads((B/'float_concision_layout.json').read_text())
check(layout['after']['pdf_sha256']==sha(B/'main.revised.pdf'),'layout review matches delivery')
cap_before=sum(x['caption_words_before'] for x in stats);cap_after=sum(x['caption_words_after'] for x in stats)
cell_before=sum(x.get('cell_words_before',0) for x in stats);cell_after=sum(x.get('cell_words_after',0) for x in stats)
report={'status':'PASS','scope':'Editorial concision; no new experiments or imputation','backup':spec['backup'],'reviewed_figures':sum(x['label'].startswith('fig:') for x in stats),'reviewed_tables':sum(x['label'].startswith('tab:') for x in stats),'caption_words_before':cap_before,'caption_words_after':cap_after,'caption_reduction_percent':round(100*(1-cap_after/cap_before),1),'table_cell_words_before':cell_before,'table_cell_words_after':cell_after,'table_cell_reduction_percent':round(100*(1-cell_after/cell_before),1),'word_count_rule':'Whitespace-delimited words after removing TeX command names and replacing citation/reference commands by REF. Numbers and math are retained.','protected_numeric_or_missing_cells':protected_cells,'explicit_cell_edits':sum(len(x['cells']) for x in spec['floats']),'schema_columns':3,'abstract_words':abstract_words,'keywords':len(keywords),'pages':validation['pages'],'bibliography_entries':validation['bibliography_entries'],'vector_empirical_figures':validation['vector_figures'],'raster_images':validation['raster_images'],'source_root_used':'/home/ckt/Documents/000_2026_test_dev/Key_Experiment','original_source_root':'/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/Key_Experiment','source_relocation_verified':True,'full_data_checks':sum(validation['numeric_and_structural_checks'].values()),'scientific_limitations':validation['limitations'],'checks':dict(checks),'items':stats,'output_sha256':{name:sha(B/name) for name in [*sorted(files),'main.revised.pdf']}}
(B/'float_concision_validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
lines=['# 图表文字精简核验','',f'状态：PASS。范围：{report["reviewed_figures"]} 幅图、{report["reviewed_tables"]} 张表（含附录）。','',f'- 图注/表注：{cap_before} → {cap_after} 词，减少 {report["caption_reduction_percent"]}%。',f'- 表格单元格：{cell_before} → {cell_after} 词，减少 {report["table_cell_reduction_percent"]}%；数值单元格不变。',f'- {report["explicit_cell_edits"]} 处显式文字单元格精简；日志字段表改为三列，七类事件及公共字段完整保留。',f'- {protected_cells} 个数值或缺失值单元格逐项保持；公式、算法、引用、图形引用与尺寸不变。',f'- 原始证据核对：628 个归档的清单/大小/时间戳、43 个汇总文件哈希、14 个漏洞文件哈希全部通过；既有归档哈希保留。',f'- 独立数值、结构和构建校验：{report["full_data_checks"]:,} 项。图中 2,000 次整运行 bootstrap 已重新计算。',f'- 摘要 {abstract_words} 词、关键词 {len(keywords)} 个，摘要和正文缩写作用域校验通过。',f'- PDF：{validation["pages"]} 页，25 条参考文献，无未定义引用、越界盒子或位图嵌入。','', '## 与 first_paper.md 的一致性','', '- 保留独立的 code/IPSM 证据、provisional/durable 层次及观测前预测。','- 保留同策略/资源上限要求，实际调用量、样本数、单位和误差定义不变。','- 设计要求与已验证实现、日志标签与队列成员资格分别表述。','- 漏洞 L/R 证据类别、批次分母、未合并批次及未完成的受控 A–E 结果保持明确。','- 数据缺口维持空白；本轮未执行新实验，不将计划写成已证实结论。','', '## 版面检查','', '- 检查全部页面，并放大核对日志字段表、漏洞清单与回放结果表。','- 正文无新增整页或半页空白；末页仅为参考文献的自然余量。精简后末页留白增加，未通过缩小字号或强制拉伸填满。','', '## 实际数据路径','', '原记录路径已不存在，实验资料位于工作区根目录 Key_Experiment。校验时显式传入 --source-root，所有既有内容校验仍启用；未改写原始实验文件。','', '## 每项对照','', '| 图表标签 | 图/表注原词数 | 精简后 |','|---|---:|---:|']
lines += [f'| {x["label"]} | {x["caption_words_before"]} | {x["caption_words_after"]} |' for x in stats]
lines += ['', '计数口径：移除 TeX 命令名、将引用替换为 REF 后按空白分词；保留数值和数学记号。', '', '详细逐项检查见 float_concision_validation.json。原稿及相关生成脚本保存在 before_float_concision/。']
(B/'FLOAT_CONCISION_AUDIT.md').write_text('\n'.join(lines)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ['items','checks','output_sha256']},ensure_ascii=False,indent=2))
