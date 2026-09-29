#!/usr/bin/env python3
"""Check the revised appendix, unchanged plot data, citations and PDF layout."""
from pathlib import Path
import collections
import json
import re
import subprocess
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parent
NAMES = dict(zip(['lightftp','bftpd','proftpd','pure-ftpd','exim','live555','kamailio','forked-daapd','lighttpd1'], ['LightFTP','bftpd','ProFTPD','Pure-FTPd','Exim','Live555','Kamailio','Forked-daapd','Lighttpd1']))
ARMS = {a:a for a in 'ABCDE'} | {'E-gamma099':r'E, $\gamma=.99$', 'E-gamma100':r'E, $\gamma=1$'}
STATUS = {'completed':'C', 'exit_137_near_limit':'X', 'sigabrt':'S', 'oom_killed':'O'}

def main():
    manuscript = (BASE/'main.revised.tex').read_text()
    appendix = (BASE/'archive_arm_results.layout_20260928.tex').read_text()
    aggregate = json.loads((BASE/'filled_experiment_data.json').read_text())['aggregate']
    rows = [s for s in appendix.splitlines() if re.match(r'[ABCDE](?:,| &)',s)]
    assert len(rows) == len(aggregate) == 60
    for key, a in aggregate.items():
        arm, target = key.split('|')
        prefix = f'{ARMS[arm]} & {NAMES[target]} &'
        matches = [s for s in rows if s.startswith(prefix)]
        assert len(matches) == 1, key
        cells = [s.strip() for s in matches[0].removesuffix(r'\\').split(' & ')]
        assert cells[2] == str(a['runs_available']), key
        assert a['runs_nominal'] == 10
        for idx, metric in enumerate(['branches','auc_branch_hours','ipsm_edges'],3):
            d = a[metric]
            assert d['n'] == a['runs_available'], (key,metric)
            assert cells[idx] == f"{d['mean']:.1f} $\\pm$ {d['sd']:.1f}", (key, metric)
        expected = {STATUS[k]:v for k,v in a['status'].items() if v}
        recorded = {s.split(':')[0]:int(s.split(':')[1]) for s in cells[6].split(', ')}
        assert expected == recorded, key
    assert 'E|bftpd' not in aggregate
    assert r'\resizebox' not in appendix and r'\small' in appendix
    assert 'archive_arm_results.layout_20260928.tex' in manuscript

    original = BASE/'figures_20260928'
    current = BASE/'figures_layout_20260928'
    numeric_files = list(current.glob('*.csv')) + [current/f for f in ['episode_audit.json','coverage_audit.json','posterior_case_selection.json']]
    for p in numeric_files:
        assert p.read_bytes() == (original/p.name).read_bytes(), f'Changed figure evidence: {p.name}'

    bib = (BASE/'references.verified_20260928.bib').read_text()
    bibkeys = re.findall(r'@\w+\{([^,]+),', bib)
    assert len(bibkeys) == len(set(bibkeys)) == 25
    sources = [manuscript] + [(BASE/p).read_text() for p in ['observed_tables.tex','observed_costs.tex','archive_arm_results.layout_20260928.tex','figures_layout_20260928/logged_calibration_table.tex']]
    cited = {k.strip() for text in sources for group in re.findall(r'\\cite(?:[tp])?(?:\[[^]]*\])?\{([^}]+)\}',text) for k in group.split(',')}
    assert cited == set(bibkeys), (cited-set(bibkeys),set(bibkeys)-cited)
    bbl = (BASE/'main.revised.bbl').read_text()
    bblkeys = set(re.findall(r'\\bibitem(?:\[[^]]*\])?\{([^}]+)\}',bbl))
    assert bblkeys == cited
    dois = re.findall(r'doi\s*=\s*\{([^}]+)\}',bib,re.I)
    assert len(dois) == len({d.casefold() for d in dois})
    assert 'B{"o}hme' not in bib and r'B{\"o}hme' in bib
    assert 'Reference completion required' not in manuscript and 'T-Scheduler' not in manuscript
    for k in ['bandits_states2023','ssgfuzz2026','magma2020','zhang2026thompson']:
        assert manuscript.count(k) >= 2, k
    log = (BASE/'main.revised.log').read_text()
    for bad in ['! LaTeX Error','! Undefined','undefined citations','undefined references','Overfull','Float too large']:
        assert bad not in log, bad
    blg = (BASE/'main.revised.blg').read_text()
    assert 'Warning--' not in blg and 'error message' not in blg, blg[-2000:]
    fonts = subprocess.check_output(['pdffonts',str(BASE/'main.revised.pdf')],text=True)
    assert 'Type 3' not in fonts, fonts
    assert 'LMRoman' not in fonts, fonts
    assert 'NimbusRom' in fonts and 'LMMono' in fonts
    images = subprocess.check_output(['pdfimages','-list',str(BASE/'main.revised.pdf')],text=True)
    assert len(images.strip().splitlines()) == 2

    def inspect(pdf):
        raw = subprocess.check_output(['pdftohtml','-xml','-zoom','1','-i','-stdout',str(pdf)],stderr=subprocess.DEVNULL)
        root = ET.fromstring(raw)
        fonts = {f.attrib['id']:f.attrib for f in root.iter('fontspec')}
        pages = []
        for page in root.findall('page'):
            text = [t for t in page.findall('text') if ''.join(t.itertext()).strip() != page.attrib['number']]
            words = sum(len(''.join(t.itertext()).split()) for t in text)
            sizes = collections.Counter({})
            for t in text:
                sizes[fonts[t.attrib['font']]['size']] += len(''.join(t.itertext()).split())
            pages.append({'page':int(page.attrib['number']),'words':words,
                          'last_text_y':max((float(t.attrib['top'])+float(t.attrib['height']) for t in text),default=0),
                          'font_size_word_counts':dict(sizes)})
        return raw,pages
    _,before = inspect(BASE/'before_layout_20260928/main.revised.pdf')
    raw,after = inspect(BASE/'main.revised.pdf')
    (BASE/'layout_checks_20260928/layout.xml').write_bytes(raw)
    pdftext = subprocess.check_output(['pdftotext','-layout',str(BASE/'main.revised.pdf'),'-'],text=True)
    (BASE/'main.revised.txt').write_text(pdftext)
    assert 'References' in pdftext and '[25]' in pdftext
    rendered_figures = re.findall(r'^\s*Figure (\d+):', pdftext, re.M)
    rendered_tables = re.findall(r'\bTable ([A-Z.\d]+):', pdftext)
    assert rendered_figures == [str(i) for i in range(1,10)], rendered_figures
    assert rendered_tables == [str(i) for i in range(1,20)] + ['A.1'], rendered_tables
    pages = pdftext.split('\f')
    refs_page = next(i+1 for i,t in enumerate(pages) if re.search(r'^\s*References\b',t,re.M))
    result = {'status':'PASS','appendix_rows_verified':60,'unchanged_numeric_figure_files':len(numeric_files),
              'cited_references':25,'unique_dois':len(dois),'reference_page':refs_page,
              'pages_before':len(before),'pages_after':len(after),'raster_images':0,'type3_fonts':0,
              'bibtex_warnings':0,'overfull_boxes':0,'underfull_notices':log.count('Underfull'),
              'metadata_notes':{'ssgfuzz':'Publisher BibTeX year 2026; first online 2025-07-09.',
                                'T-Scheduler':'Name remains unverified. Zhang et al. (2026) is cited as a distinct verified study, not identified as T-Scheduler.'},
              'before':before,'after':after}
    (BASE/'layout_reference_validation_20260928.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['before','after']},indent=2))

if __name__ == '__main__':
    main()
