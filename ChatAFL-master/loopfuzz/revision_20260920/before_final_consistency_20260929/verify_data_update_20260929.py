from pathlib import Path
import json, re, subprocess, xml.etree.ElementTree as ET
BASE=Path(__file__).resolve().parent
ledger=json.loads((BASE/'filled_run_evidence_20260929.json').read_text())
agg=json.loads((BASE/'filled_experiment_data_20260929.json').read_text())['aggregate']
tex=(BASE/'main.revised.tex').read_text();log=(BASE/'main.revised.log').read_text();
assert len(ledger['runs'])==628 and sum(v['runs_available'] for v in agg.values())==628
assert len([r for r in ledger['runs'] if r['arm'] in 'ABCDE'])==465
assert not any('gated_fixed' in r['source_rel'] for r in ledger['runs'])
assert all(r['endpoint_matches_summary'] for r in ledger['runs'])
for old in ['figures_reflow_20260928','observed_tables.tex','observed_costs.tex','archive_arm_results.flow_20260928.tex','469 archives','375 observations','28,866 E-archive']:
 assert old not in tex, old
for f in ['observed_tables.updated_20260929.tex','observed_costs.updated_20260929.tex','archive_arm_results.updated_20260929.tex']:
 s=(BASE/f).read_text(); assert '\\\\begin' not in s and '\\\\caption' not in s
assert len(re.findall(r'^(?:[A-D]\d+|E\d+|\$E_\{(?:99|100)\}\$\d+) & ',(BASE/'archive_arm_results.updated_20260929.tex').read_text(),re.M))==61
figdir=BASE/'figures_updated_20260929'
figs=['coverage_trajectories','logged_reward_reliability','candidate_dispositions','token_cost_coverage','call_cost_coverage','posterior_cases']
for name in figs:
 assert (figdir/(name+'.pdf')).exists() and (figdir/(name+'.svg')).exists()
 root=ET.parse(figdir/(name+'.svg')).getroot();assert not root.findall('.//{http://www.w3.org/2000/svg}image')
for bad in ['! LaTeX Error','Overfull \\hbox','Float too large','Undefined','undefined citations','undefined references','Missing $']:
 assert bad not in log,bad
assert 'References' in subprocess.check_output(['pdftotext','-layout',str(BASE/'main.revised.pdf'),'-'],text=True)
print(json.dumps({'status':'PASS','archives':628,'core_figure_archives':465,'appendix_rows':61,'vector_figures':6,'raster_svg_images':0,'pages':int(subprocess.check_output(['pdfinfo',str(BASE/'main.revised.pdf')],text=True).split('Pages:')[1].splitlines()[0])},indent=2))
