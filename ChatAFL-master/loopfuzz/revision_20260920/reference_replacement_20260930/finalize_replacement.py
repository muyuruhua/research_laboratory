"""Validate the explicitly requested three-reference replacement, without rewriting history."""
from pathlib import Path
import ast
import collections
import difflib
import hashlib
import json
import re
import subprocess
import tempfile

A = Path(__file__).resolve().parent
R = A.parent
OLD = R / 'fulltext_claim_audit_20260930'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
dump = lambda p, x: p.write_text(json.dumps(x, ensure_ascii=False, indent=2) + '\n')

# Reuse read-only parsers, not historical scripts with outdated completion assertions.
for file, function in [(R / 'reference_expansion/verify_reference_expansion.py', 'parse_bib'),
                       (OLD / 'finalize_claim_audit.py', 'occurrences')]:
    node = next(n for n in ast.parse(file.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == function)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(file), 'exec'))

tex = (R / 'main.revised.tex').read_text()
before = (A / 'before/main.revised.tex').read_text()
bib = parse_bib((R / 'references.expanded.bib').read_text())
oldbib = parse_bib((A / 'before/references.expanded.bib').read_text())
removed = {'ssgfuzz2026', 'zhang2026thompson', 'brier1950'}
added = {'seqfuzzsdn2026', 'entropic2020', 'validation2017'}
reviewed = added | {'nsfuzz', 'wingmuzz2025'}
assert set(oldbib) - set(bib) == removed
assert set(bib) - set(oldbib) == added
assert all(bib[k] == oldbib[k] for k in set(bib) & set(oldbib))
assert len(bib) == 51
assert not any(k in tex for k in removed)
assert 'SSGFuzz' not in tex
assert 'tscheduler2024' in bib and 'bandits_states2023' in bib

before_occ = occurrences(before)
after_occ = occurrences(tex)
cites = [k for o in after_occ for k in o['keys']]
assert set(cites) == set(bib)
assert len(after_occ) == len(before_occ) == 54
assert len(cites) == 59
results_marker = r'\section{Available Evidence and Results}'
assert tex.split(results_marker, 1)[1] == before.split(results_marker, 1)[1]
equations = lambda t: re.findall(r'\\begin\{equation\*?\}(.*?)\\end\{equation\*?\}', t, re.S)
assert equations(tex) == equations(before)
protected = []
for path, data in json.loads((OLD / 'snapshot.json').read_text()).items():
    p = Path(path)
    if p.name in {'main.revised.tex', 'main.revised.pdf', 'references.expanded.bib'}:
        continue
    assert sha(p) == data['sha256'], path
    protected.append(path)

sources = {}
assessments = json.loads((OLD / 'assessments.json').read_text())
for k in removed:
    assessments.pop(k)
for k in bib:
    root = A if k in reviewed else OLD
    p = root / 'sources' / k / 'retrieval.json'
    sources[k] = json.loads(p.read_text())
    sources[k]['retrieval_record'] = str(p.relative_to(R))
    if k in reviewed:
        s = sources[k]
        assert sha(root / 'sources' / k / 'paper.pdf') == s['sha256']
        assessments[k] = {
            'assessment': s['review_status'], 'pages': s['evidence_pdf_pages'],
            'page_kind': 'page in the specifically archived PDF, not publisher page numbering',
            'section': s['evidence_section'], 'note': s['note'],
            'source_version': s.get('source_version', 'User-supplied publisher PDF'),
            'reviewed_this_round': True,
        }
    else:
        assessments[k]['reviewed_this_round'] = False
        assessments[k]['inherited_from'] = 'fulltext_claim_audit_20260930/assessments.json'

matrix = []
for o in after_occ:
    for k in o['keys']:
        e = assessments[k]
        matrix.append({
            'id': o['id'] + ':' + k, 'key': k, 'line': o['line'],
            'sentence': o['sentence'], 'paragraph': o['paragraph'],
            'assessment': e, 'source': sources[k],
        })
assert len(matrix) == 59
changed_uses = [x for x in matrix if x['key'] in reviewed]
assert len(changed_uses) == 7
dump(A / 'assessments.current.json', assessments)
dump(A / 'retrieval_manifest.current.json', sources)
dump(A / 'sentence_evidence_matrix.current.json', matrix)
dump(A / 'sentence_occurrences.before.json', before_occ)
dump(A / 'sentence_occurrences.after.json', after_occ)

# All actual citation uses must resolve to distinct reference destinations in the PDF.
run = lambda args: subprocess.check_output(args, cwd=R, text=True, stderr=subprocess.PIPE)
aux = (R / 'main.revised.aux').read_text()
bbl = (R / 'main.revised.bbl').read_text()
assert set(re.findall(r'\\bibcite\{([^{}]+)\}', aux)) == set(bib)
assert set(re.findall(r'\\bibitem(?:\[[^]]*\])?\{([^{}]+)\}', bbl)) == set(bib)
info = run(['pdfinfo', 'main.revised.pdf'])
pages = int(re.search(r'^Pages:\s*(\d+)', info, re.M)[1])
desttext = run(['pdfinfo', '-dests', 'main.revised.pdf'])
(A / 'pdf_destinations.txt').write_text(desttext)
dests = {}
for line in desttext.splitlines():
    m = re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"', line)
    if m:
        dests[m[4]] = (int(m[1]), int(m[2]), int(m[3]))
tree = ast.parse((R / 'verify_reference_links_20260930.py').read_text())
ps = next(ast.literal_eval(n.value) for n in tree.body
          if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ps' for t in n.targets))
with tempfile.TemporaryDirectory(prefix='citation_replacement_') as temp:
    p = Path(temp) / 'inspect.ps'
    p.write_text(ps)
    annotations = run(['gs', '-q', '-dNODISPLAY', '-dBATCH', '-dNOSAFER', '-f', str(p)])
(A / 'pdf_annotations.txt').write_text(annotations)
counts = collections.Counter()
internal = 0
for line in annotations.splitlines():
    if line.startswith('EXTERNAL\t'):
        continue
    typ, page, dest, rect = line.split('\t', 3)
    assert typ == 'INTERNAL' and dest in dests
    xy = list(map(float, re.findall(r'-?\d+(?:\.\d+)?', rect)))
    assert len(xy) == 4 and xy[2] > xy[0] and xy[3] > xy[1]
    assert 1 <= dests[dest][0] <= pages
    counts[dest] += 1
    internal += 1
for k, n in collections.Counter(cites).items():
    assert counts['cite.' + k] >= n
assert len({dests['cite.' + k] for k in bib}) == len(bib)

abstract = re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}', tex, re.S)[1]
words = re.findall(r"\b[A-Za-z0-9]+(?:[’'-][A-Za-z0-9]+)*\b", abstract)
keywords = re.search(r'\\begin\{keyword\}(.*?)\\end\{keyword\}', tex, re.S)[1].split(r'\sep')
assert 150 <= len(words) <= 200 and len(keywords) <= 5
log = (R / 'main.revised.log').read_text()
critical = [l for l in log.splitlines() if any(t in l for t in
            ['Overfull', 'undefined', 'destination with the same identifier', '! LaTeX Error', '! Package'])]
assert not critical, critical
for name in ['main.revised.tex', 'references.expanded.bib']:
    diff = ''.join(difflib.unified_diff((A / 'before' / name).read_text().splitlines(True),
                    (R / name).read_text().splitlines(True), fromfile='before/' + name, tofile='after/' + name))
    (A / (name + '.diff')).write_text(diff)
snapshot = {str(p.relative_to(A)): {'sha256': sha(p), 'size': p.stat().st_size}
            for p in (A / 'before').iterdir() if p.is_file()}
dump(A / 'snapshot.json', snapshot)
validation = {
    'structural_and_build_validation': 'PASS',
    'all_51_final_publisher_versions_verified': False,
    'references': len(bib), 'citation_groups': len(after_occ), 'citation_uses': len(cites),
    'reviewed_this_round': sorted(reviewed), 'reviewed_citation_uses': len(changed_uses),
    'new_author_manuscript_sources': sorted(added), 'removed_references': sorted(removed),
    'unavailable_current_sources': [k for k, s in sources.items() if s['status'] == 'unavailable'],
    'inherited_version_limited': [k for k, s in sources.items()
                                if s['status'] == 'fulltext_preprint_version_limited'],
    'inherited_browser_only_fulltexts': [k for k, s in sources.items()
                                       if s['status'] == 'fulltext_web_reviewed'],
    'source_status_counts': dict(collections.Counter(s['status'] for s in sources.values())),
    'pages': pages, 'abstract_words': len(words), 'keywords': len(keywords),
    'internal_links': internal, 'citation_links': sum(v for k, v in counts.items() if k.startswith('cite.')),
    'linked_citation_targets': len(bib), 'dangling_links': 0,
    'critical_latex_messages': critical, 'underfull_notices': log.count('Underfull'),
    'bibtex_warnings': [l for l in (R / 'main.revised.blg').read_text().splitlines() if l.startswith('Warning--')],
    'results_section_unchanged': True, 'all_equation_blocks_unchanged': True,
    'protected_inputs_unchanged': protected,
    'file_hashes': {p.name: sha(p) for p in [R / 'main.revised.tex', R / 'main.revised.pdf', R / 'references.expanded.bib']},
}
dump(A / 'validation.json', validation)

lines = [
    '# 三篇文献替换及两篇新增全文核查（2026-09-30）', '',
    '## 本轮结果', '',
    '按用户明确指令，保留并核查本地 NSFuzz、WingMuzz 完整原文；移除 SSGFuzz、Zhang 等（2026）和 Brier（1950）三个书目条目，以三篇软工顶会/顶刊论文替代。正文、比较表及参考文献同步修改，实际引用仍为 51 篇。', '',
    '**本报告中的 PASS 仅指结构、编译和链接检查通过，不表示全部 51 篇出版社正式版全文逐句核查通过。** 新增三篇均已取得公开作者全文，具体版本及限制分别列明。其余文献沿用前轮判断，未伪称本轮重新阅读全文。', '',
    '## 替换关系与论断调整', '',
    '| 移除条目 | 替代条目 | 正式出版信息 | 本文的引用用途 |',
    '|---|---|---|---|',
    '| SSGFuzz | Learning-Guided Fuzzing for Testing Stateful SDN Controllers | TOSEM 35(2), 2026, 1–45; DOI 10.1145/3733717 | SeqFuzzSDN 从事件轨迹学习扩展有限状态机并规划控制消息序列；不冒称其采用 state-significance 调度。 |',
    '| Zhang 等（2026） | Boosting Fuzzer Efficiency: An Information Theoretic Perspective | ESEC/FSE 2020, 678–689; DOI 10.1145/3368089.3409748 | Entropic 按信息量估计分配种子能量；不将它称为 Thompson sampling。真正的 T-Scheduler 保留。 |',
    '| Brier（1950） | An Empirical Comparison of Model Validation Techniques for Defect Prediction Models | IEEE TSE 43(1), 2017, 1–18; DOI 10.1109/TSE.2016.2584050 | 引用软工缺陷预测中使用 Brier 分数的先例及平方误差定义，不归属该指标的原创权。 |', '',
    '选择依据是软工主流顶会/顶刊且有可核验的相关原文，不按年份机械凑数。三篇分别为 2026、2020 和 2017 年，不能统一表述为近年论文。', '',
    '## 两篇保留文献', '',
    '- NSFuzz：用户提供的 TOSEM 正式 PDF，26 页。第 9–12 页第 4.2–4.5 节支持基于程序状态变量的识别、注释及跟踪。相关工作现已明确区分 StateAFL 的内存快照与 NSFuzz 的变量跟踪。',
    '- WingMuzz：用户提供的 ASE 2025 正式 PDF，13 页。第 3–5 页第 III 节及 Figure 1 支持两维分别调度开源协议实现（wingmates）和种子。正文已点明两维含义，没有把它写成响应状态调度。', '',
    '## 新增全文的版本边界', '',
]
for k in ['seqfuzzsdn2026', 'entropic2020', 'validation2017']:
    s = sources[k]
    lines += [f"- **{k}**：{s['source_version']} 原文位置：PDF {s['evidence_pdf_pages']}，{s['evidence_section']}。"]
lines += [
    '', '出版元数据由 Crossref 的出版社登记记录核对；本地保存 JSON、PDF 和 SHA-256。SeqFuzzSDN 的 arXiv 记录与正式 DOI 对应，但其 2025 年作者稿与 2026 年出版社版未做逐页同一性比对。TSE 作者稿共 21 页，而正式版书目页码为 1–18；不得把作者稿页码写成正式出版页码。', '',
    '新增三份作者稿也存放在工作区 papers 目录，文件名明确标注 author manuscript；用户原有两份文件未改写。', '',
    '## first_paper.md 的约束', '',
    '- 保留 response-derived state 只是代理、独立 code productivity 才是校准目标的主线。',
    '- 保留 execute-before-promote 及 provisional/durable 准入分层；不把 Beta/Thompson 本身当作创新。',
    '- 要求文件举例点名 SSGFuzz；本轮根据用户后续明确指令移除该引文。该操作只改变可引用证据，不意味着否认 state-significance 研究存在，也不建立排他性首创声明。The Bandit’s States、T-Scheduler 和其他既有状态研究保留。',
    '- Brier 分数名称和计算公式完整保留。新引用支持指标在软工中的使用，不代替其历史发明归属。',
    '- 实验结果章节逐字一致；全部 equation 块一致；主要实验输入和要求文件哈希均一致。', '',
    '## 当前引用句与证据', '',
]
for row in changed_uses:
    k = row['key']; e = row['assessment']; s = row['source']
    lines += [f"### {row['id']} — main.revised.tex:{row['line']}", '',
              row['sentence'], '', f"- 依据：PDF {e['pages']}，{e['section']}。",
              '- 支持范围：' + e['note'], f"- 来源记录：[{k}](sources/{k}/retrieval.json)", '']
lines += [
    '另检查比较表中未重复带引文的 NSFuzz 行（main.revised.tex:159），其“内部状态反馈”与第 4.2–4.5 节相容。', '',
    '## 编译与保留限制', '',
    f"- PDF {pages} 页；{len(bib)} 个不同文献目的地；{validation['citation_links']} 个文献链接；{internal} 个内部链接；无悬空目的地。",
    f"- 摘要 {len(words)} 词，关键词 {len(keywords)} 个。无未定义引用、Overfull 或致命 LaTeX 错误。",
    f"- 仍有 {validation['underfull_notices']} 条非致命 Underfull 提示；四条既有 BibTeX 缺少页码提示保留，未捏造出版页码。",
    '- FuzzGPT、HGFuzzer 仍保留前轮的早期版本差异限制；Cliff 和 Mann–Whitney 的浏览器全文来源限制也未因本轮替换自动解决。',
    '- 三篇被移除的文献不再出现在当前主稿引用与书目中；历史审计原样保留，不改写过去“未取得全文”的事实。', '',
    '可机读记录：[validation.json](validation.json)、[全部 59 次引文使用](sentence_evidence_matrix.current.json)、[主稿差异](main.revised.tex.diff)、[书目差异](references.expanded.bib.diff)。',
]
(A / 'REFERENCE_REPLACEMENT_AUDIT.md').write_text('\n'.join(lines) + '\n')
(R / 'CITATION_STATUS.md').write_text(
    '# 引用状态（2026-09-30，本轮替换后）\n\n'
    '当前主稿实际引用 **51 篇**，54 处引文组、59 次文献使用。\n\n'
    '此前缺少全文的 5 篇已按本轮指令处理：NSFuzz、WingMuzz 根据用户提供的正式 PDF 核查并修正机制描述；'
    'SSGFuzz、Zhang 等（2026）、Brier（1950）移除，分别替换为 SeqFuzzSDN（TOSEM 2026）、Entropic（ESEC/FSE 2020）及 Tantithamthavorn 等（IEEE TSE 2017）。'
    '三篇替代文献均取得公开作者全文，正文和比较表同步调整。Brier 分数名称与公式保留，新引用仅支持软工中的指标使用，未改写指标原创归属。\n\n'
    '**版本边界仍需保留：**新增三篇采用作者全文，未宣称与出版社正式版逐页一致；SeqFuzzSDN 为 2025 年 arXiv v2，正式版登记为 2026 年。'
    '此前 FuzzGPT/HGFuzzer 的早期版本差异、Cliff/Mann–Whitney 的浏览器全文来源限制未消除。不得写作全部 51 篇正式版全文核验通过。\n\n'
    '本轮报告：[文献替换及全文核查](reference_replacement_20260930/REFERENCE_REPLACEMENT_AUDIT.md)；'
    '[当前引用证据矩阵](reference_replacement_20260930/sentence_evidence_matrix.current.json)；'
    '[编译与链接检查](reference_replacement_20260930/validation.json)。\n\n'
    '上一轮报告保留为历史快照：[原 50 篇逐句审查](fulltext_claim_audit_20260930/FULLTEXT_CLAIM_AUDIT_20260930.md)。'
    '历史脚本含旧文献集合断言，不应用于覆盖当前状态。\n')
print(json.dumps(validation, ensure_ascii=False, indent=2))
