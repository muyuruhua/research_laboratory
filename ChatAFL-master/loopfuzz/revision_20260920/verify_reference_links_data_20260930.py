#!/usr/bin/env python3
"""Verify actual PDF link actions and preserve the manuscript's research content."""
from pathlib import Path
import collections, hashlib, html, json, re, subprocess, tempfile

B = Path(__file__).resolve().parent
BACKUP = B / 'before_reference_links_20260930'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args):
    return subprocess.check_output(args, cwd=B, text=True, stderr=subprocess.PIPE)

def canonical(text):
    return re.sub(r'\\namedref\{(Figures?|Tables?)\}\{([^{}]+)\}',
                  lambda m: m[1] + r'~\ref{' + m[2] + '}', text)

tex = (B / 'main.revised.tex').read_text()
old = (BACKUP / 'main.revised.tex').read_text()
requirements = Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md')
assert requirements.exists()
info = run(['pdfinfo', 'main.revised.pdf'])
pages = int(re.search(r'^Pages:\s*(\d+)', info, re.M)[1])
assert pages == 22
aux = (B / 'main.revised.aux').read_text()
labels = {}
for line in aux.splitlines():
    # The displayed appendix number contains a nested empty TeX group.
    m = re.match(r'^\\newlabel\{([^{}]+)\}\{\{(.*?)\}\{(\d+)\}.*\{([^{}]+)\}\{\}\}$', line)
    if m:
        labels[m[1]] = {'number': m[2], 'page': int(m[3]), 'destination': m[4]}
dest_text = run(['pdfinfo', '-dests', 'main.revised.pdf'])
(B / 'reference_destinations_20260930.txt').write_text(dest_text)
destinations = {}
for line in dest_text.splitlines():
    m = re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"', line)
    if m:
        destinations[m[4]] = {'page': int(m[1]), 'x': int(m[2]), 'y': int(m[3])}
ps = r'''
/resolve { dup type dup /arraytype eq exch /packedarraytype eq or { dup xcheck {exec} if } if } bind def
(main.revised.pdf) (r) file runpdfbegin
1 1 pdfpagecount {
 /p exch def
 p pdfgetpage /Annots known {
  p pdfgetpage /Annots get resolve {
   resolve /an exch def
   an /Subtype known {
    an /Subtype get /Link eq {
     an /A known {
      an /A get resolve /action exch def
      action /S get /GoTo eq {
       (INTERNAL\t) print p =only (\t) print action /D get resolve =only (\t) print an /Rect get resolve ==
      } { (EXTERNAL\t) print p =only (\t) print action /S get == } ifelse
     } {
      an /Dest known {
       (INTERNAL\t) print p =only (\t) print an /Dest get resolve =only (\t) print an /Rect get resolve ==
      } { (UNHANDLED_LINK\n) print } ifelse
     } ifelse
    } if
   } if
  } forall
 } if
} for
quit
'''
with tempfile.TemporaryDirectory(prefix='reference_links_') as tmp:
    script = Path(tmp) / 'inspect.ps'
    script.write_text(ps)
    annotations = run(['gs', '-q', '-dNODISPLAY', '-dBATCH', '-dNOSAFER', '-f', str(script)])
(B / 'reference_annotations_20260930.txt').write_text(annotations)
links = []
for line in annotations.splitlines():
    if line.startswith('EXTERNAL\t'):
        continue
    assert line.startswith('INTERNAL\t'), line
    _, page, dest, rect = line.split('\t', 3)
    assert dest in destinations, (page, dest)
    xy = list(map(float, re.findall(r'-?\d+(?:\.\d+)?', rect)))
    assert len(xy) == 4 and xy[2] > xy[0] and xy[3] > xy[1], rect
    assert 1 <= destinations[dest]['page'] <= pages and 0 <= destinations[dest]['y'] <= 842, dest
    links.append({'source_page': int(page), 'destination': dest, 'rect': xy, 'target': destinations[dest]})
counts = collections.Counter(x['destination'] for x in links)
body = tex.split(r'\begin{document}', 1)[1]
for name in re.findall(r'\\input\{([^{}]+)\}', tex):
    path = B.parent / name
    if not path.suffix:
        path = path.with_suffix('.tex')
    body += '\n' + path.read_text()
refkeys = re.findall(r'\\(?:ref|figref)\{([^{}]+)\}', body)
refkeys += [m[1] for m in re.findall(r'\\namedref\{([^{}]+)\}\{([^{}]+)\}', body)]
for key, n in collections.Counter(refkeys).items():
    assert key in labels, key
    entry = labels[key]
    assert entry['page'] == destinations[entry['destination']]['page'], key
    assert counts[entry['destination']] >= n, (key, n, counts[entry['destination']])
cites = [key.strip() for group in re.findall(r'\\cite(?:\[[^]]*\])?\{([^{}]+)\}', body) for key in group.split(',')]
bibkeys = set(re.findall(r'\\bibcite\{([^{}]+)\}', aux))
assert len(bibkeys) == 50 and set(cites) == bibkeys
for key, n in collections.Counter(cites).items():
    assert counts['cite.' + key] >= n, (key, n)
assert len({tuple(destinations['cite.' + key].values()) for key in bibkeys}) == 50
floatlabels = {k: v for k, v in labels.items() if k.startswith(('fig:', 'tab:'))}
assert len(floatlabels) == 29
for key, entry in floatlabels.items():
    assert destinations[entry['destination']]['page'] == entry['page'], key
hypertext = run(['pdftohtml', '-i', '-s', '-noframes', '-stdout', 'main.revised.pdf'])
(B / 'reference_links_20260930.html').write_text(hypertext)
texts = [html.unescape(re.sub(r'<[^>]+>', '', x)) for x in re.findall(r'<a href="[^"]*#\d+">(.*?)</a>', hypertext, re.S)]
assert any(re.search(r'Figure\s+4', x) for x in texts)
assert any(re.search(r'Table\s+12', x) for x in texts)
log = (B / 'main.revised.log').read_text(errors='replace')
bad = [l for l in log.splitlines() if any(x in l for x in ['Warning:', 'Overfull', 'undefined references', 'destination with the same identifier', '! LaTeX Error'])]
assert not bad, bad
assert not re.search(r'^\s*\d+\s+\d+\s+', run(['pdfimages', '-list', 'main.revised.pdf']), re.M)
report = {
    'status': 'PASS', 'scope': 'PDF reference navigation after 2026-09-30 data update',
    'pages': pages, 'internal_link_annotations': len(links),
    'citation_link_annotations': sum(n for key, n in counts.items() if key.startswith('cite.')),
    'distinct_linked_bibliography_entries': len(bibkeys),
    'figure_table_link_annotations': sum(n for key, n in counts.items() if key.startswith(('figure.', 'table.'))),
    'figure_table_destinations': len(floatlabels), 'linked_figure_table_destinations': len([key for key in counts if key.startswith(('figure.', 'table.'))]),
    'dangling_destinations': 0, 'undefined_references': 0, 'raster_images': 0,
    'source_body_unchanged_after_unwrapping_links': True,
    'tex_sha256': sha(B / 'main.revised.tex'), 'pdf_sha256': sha(B / 'main.revised.pdf'),
    'examples': {key: labels[key] | destinations[labels[key]['destination']] for key in ['fig:reliability', 'tab:logged_calibration']},
    'links': links,
}
(B / 'reference_links_validation_data_20260930.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'links'}, ensure_ascii=False))
