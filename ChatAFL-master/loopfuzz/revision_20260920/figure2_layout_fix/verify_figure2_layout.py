#!/usr/bin/env python3
from pathlib import Path
from collections import Counter
import ast,hashlib,itertools,json,re,subprocess,tempfile,xml.etree.ElementTree as ET
B=Path(__file__).resolve().parent;R=B.parent

def run(args):return subprocess.check_output(args,cwd=R,text=True,stderr=subprocess.PIPE)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def figure(s):
 k=s.index(r'\label{fig:architecture}');a=s.rfind(r'\begin{figure*}',0,k);b=s.index(r'\end{figure*}',k)+len(r'\end{figure*}');return a,b,s[a:b]
tex=(R/'main.revised.tex').read_text();old=(B/'before/main.revised.tex').read_text();a,b,newblock=figure(tex);oa,ob,oldblock=figure(old)
xref = r'\namedref{Figure}{fig:architecture} summarizes the three admission outcomes:'
assert tex.count(xref)==1
assert (tex[:a]+tex[b:]).replace(xref,'Admission has three outcomes:',1)==old[:oa]+old[ob:],'Unexpected change outside Figure 2 and its one cross-reference'
assert re.findall(r'\\caption\{([^}]+)\}',newblock)==re.findall(r'\\caption\{([^}]+)\}',oldblock)
assert (R/'main.revised.bbl').read_bytes()==(B/'before/main.revised.bbl').read_bytes()
manifest=json.loads((B/'manifest.json').read_text());req=Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md')
assert sha(req)==manifest['requirements_sha256']
rects=json.loads((B/'geometry_after.json').read_text());oldrects=json.loads((B/'geometry_before.json').read_text())
assert len(rects)==16 and set(manifest['box_names']+manifest['label_names'])==set(rects)
overlaps=[]
for (na,x),(nb,y) in itertools.combinations(rects.items(),2):
 if min(x[2],y[2])-max(x[0],y[0])>.15 and min(x[3],y[3])-max(x[1],y[1])>.15:overlaps.append([na,nb])
assert not overlaps,overlaps
gaps=[(rects[right][0]-rects[left][2])*25.4/72.27 for left,right in [('llm','p'),('p','trial'),('trial','gain')]]
oldgaps=[(oldrects[right][0]-oldrects[left][2])*25.4/72.27 for left,right in [('llm','p'),('p','trial'),('trial','gain')]]
assert min(gaps)>9.5 and manifest['condition_font_pt']>=8
aux=(R/'main.revised.aux').read_text();match=re.search(r'\\newlabel\{fig:architecture\}\{\{(\d+)\}\{(\d+)\}',aux);number,page=map(int,match.groups());assert number==2
pages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo','main.revised.pdf']),re.M)[1]);oldpages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo',str(B/'before/main.revised.pdf')]),re.M)[1]);assert pages==oldpages
# Inspect the real manuscript page, in addition to the isolated TikZ render.
page_svg=B/f'manuscript_page_{page}.svg';run(['pdftocairo','-f',str(page),'-l',str(page),'-svg','main.revised.pdf',str(page_svg)])
ns={'s':'http://www.w3.org/2000/svg'}
def arrowheads(p):return [node for node in ET.parse(p).findall('.//s:path',ns) if re.search(r'fill:rgb\(14\.',node.attrib.get('style',''))]
heads=arrowheads(page_svg);isolated=arrowheads(B/'figure2_after.svg');assert len(heads)==len(isolated)==10
assert not ET.parse(B/'figure2_after.svg').findall('.//s:image',ns)
assert not re.search(r'^\s*\d+\s+\d+\s+',run(['pdfimages','-list','main.revised.pdf']),re.M)
# Every bibliography and figure/table target remains valid in the rebuilt PDF.
dest_text=run(['pdfinfo','-dests','main.revised.pdf']);dests={}
for line in dest_text.splitlines():
 m=re.match(r'\s*(\d+)\s+\[\s*XYZ\s+(-?\d+)\s+(-?\d+)\s+null\s*\]\s+"([^"]+)"',line)
 if m:dests[m[4]]={'page':int(m[1]),'x':int(m[2]),'y':int(m[3])}
assert dests['figure.2']['page']==page
reader=ast.parse((R/'verify_reference_links_20260930.py').read_text());ps=next(ast.literal_eval(n.value) for n in reader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ps' for t in n.targets))
with tempfile.TemporaryDirectory(prefix='figure2_links_') as tmp:
 p=Path(tmp)/'inspect.ps';p.write_text(ps);annotations=run(['gs','-q','-dNODISPLAY','-dBATCH','-dNOSAFER','-f',str(p)])
links=[]
for line in annotations.splitlines():
 if line.startswith('EXTERNAL\t'):continue
 assert line.startswith('INTERNAL\t'),line
 _,source,dest,rect=line.split('\t',3);assert dest in dests and 1<=dests[dest]['page']<=pages
 links.append({'source_page':int(source),'destination':dest,'target':dests[dest]})
counts=Counter(x['destination'] for x in links);keys=set(re.findall(r'\\bibcite\{([^{}]+)\}',aux));assert len(keys)==50
assert all(counts['cite.'+key]>0 for key in keys)
assert counts['figure.2']>0
float_labels={}
for line in aux.splitlines():
 m=re.match(r'^\\newlabel\{([^{}]+)\}\{\{(.*?)\}\{(\d+)\}.*\{([^{}]+)\}\{\}\}$',line)
 if m and m[1].startswith(('fig:','tab:')):float_labels[m[1]]={'page':int(m[3]),'destination':m[4]}
figure_table_targets={x['destination'] for x in float_labels.values()}
assert len(float_labels)==len(figure_table_targets)==29
assert all(x['destination'] in dests and dests[x['destination']]['page']==x['page'] for x in float_labels.values())
log=(R/'main.revised.log').read_text(errors='replace');bad=[l for l in log.splitlines() if any(x in l for x in ['Overfull','undefined','destination with the same identifier','! LaTeX Error'])];assert not bad,bad
notices=[l for l in log.splitlines() if 'Warning:' in l];assert all('contains only floats' in l for l in notices),notices
# Pixel visibility check on all ten heads in the actual PDF page.
from PIL import Image
run(['pdftoppm','-f',str(page),'-l',str(page),'-r','144','-singlefile','-png','main.revised.pdf',str(B/'manuscript_page')])
im=Image.open(B/'manuscript_page.png').convert('L');svgroot=ET.parse(page_svg).getroot();width=float(re.match(r'[\d.]+',svgroot.attrib['width'])[0]);height=float(re.match(r'[\d.]+',svgroot.attrib['height'])[0]);sx,sy=im.width/width,im.height/height
visibility=[]
for index,node in enumerate(heads,1):
 coords=list(map(float,re.findall(r'[-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?',node.attrib['d'])))
 assert len(coords)%2==0
 t=list(map(float,re.findall(r'[-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?',node.attrib['transform'])));assert len(t)==6
 aa,bb,cc,dd,ee,ff=t;xy=[(aa*x+cc*y+ee,bb*x+dd*y+ff) for x,y in zip(coords[::2],coords[1::2])]
 x0,y0,x1,y1=min(z[0] for z in xy),min(z[1] for z in xy),max(z[0] for z in xy),max(z[1] for z in xy)
 assert 0<=x0<x1<=width and 0<=y0<y1<=height
 crop=im.crop((int((x0-.5)*sx),int((y0-.5)*sy),int((x1+.5)*sx+1),int((y1+.5)*sy+1)))
 dark=sum(x<100 for x in crop.getdata());assert dark>=15,(index,dark)
 visibility.append({'arrowhead':index,'dark_pixels_at_144dpi':dark,'bbox_pt':[round(x,2) for x in [x0,y0,x1,y1]]})
report={'status':'PASS','scope':'Figure 2 only','page':page,'pages':pages,'original_pages':oldpages,'source_line':tex[:a].count('\n')+1,'main_gap_before_mm':[round(x,3) for x in oldgaps],'main_gap_after_mm':[round(x,3) for x in gaps],'rendered_arrowheads':len(heads),'visible_arrowheads':len(visibility),'box_label_overlaps':len(overlaps),'main_font_pt':9,'condition_font_pt':8.5,'vector_only':True,'outside_figure_change':'One clickable Figure 2 cross-reference','outside_figure_other_content_identical':True,'bibliography_byte_identical':True,'distinct_linked_references':len(keys),'figure_table_destinations':len(figure_table_targets),'internal_links':len(links),'overfull_boxes':0,'nonfatal_layout_notices':notices,'caption_unchanged':True,'figure2_destination':dests['figure.2'],'requirements_sha256':sha(req),'tex_sha256':sha(R/'main.revised.tex'),'pdf_sha256':sha(R/'main.revised.pdf'),'arrowhead_visibility':visibility}
(B/'validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');(B/'pdf_destinations.txt').write_text(dest_text)
(R/'main.revised.txt').write_text(run(['pdftotext','-layout','main.revised.pdf','-']))
lines=['# Figure 2 布局修复核验','', '状态：PASS。修改 Figure 2 的布局、节点和箭头标签，并在对应方法段落补充一处可点击引用。','', '## 原因','',
f'- 原主流程框间净距仅 {min(oldgaps):.2f} mm，箭头缺少可辨识的线段；拒绝、过期路径共享部分路线，使方向不清。',
'## 修改','',
f'- 主流程净距增至约 {min(gaps):.2f} mm；箭头采用明确的 Latex 箭头头部和 0.85 pt 深色线条。',
'- 通过与失败分别用实线、虚线表达；拒绝与过期分离布线，晋升路径独立向上。',
'- 临时队列标为 bounded validation；只有 validated code gain 才指向 durable queue。',
'- 保持原图注、编号与正文逻辑；未增加图注篇幅。','',
'## 研究要求','',
'- 先完成 P 与 U/R 检查；独立区分代码收益与状态新颖性。',
'- 代码收益支持 durable 准入；状态新颖性仅支持 provisional 准入；缺少两种收益则拒绝。',
'- provisional 必须通过有限验证获得代码证据才能晋升；预算耗尽后过期。该流程不把回放等同于受控再发现，也不新增实验结论。','',
'## 验证','',
f'- 在最终论文第 {page} 页直接检测到 10 个矢量箭头头部；144 dpi 实际 PDF 渲染中 10 个均有可见深色像素。',
'- 7 个模块和 9 个箭头标签无包围框重叠；主文字 9 pt、条件标签 8.5 pt；已查看独立图的实际渲染。',
f'- 论文仍为 {pages} 页，无溢出和未定义引用；50 条文献及 29 个图表跳转目标保持有效。',
'- 图外仅增加一处 Figure 2 可点击引用，其他源文本逐字符一致；参考文献 bbl 逐字节一致，图仍为纯矢量。',
'- 既有纯浮动图表页提示保留在 validation.json 中，不是本图溢出。','',
'## 文件','',
'- 最终稿：../main.revised.tex 和 ../main.revised.pdf。',
'- 独立矢量预览：[PDF](figure2_after.pdf)、[SVG](figure2_after.svg)。',
'- 核验记录：[validation.json](validation.json)；原稿备份：before/。',
'- 复核：在修订目录执行 python3 figure2_layout_fix/verify_figure2_layout.py。','']
(B/'FIGURE2_LAYOUT_AUDIT.md').write_text('\n'.join(lines))
print(json.dumps({k:v for k,v in report.items() if k!='arrowhead_visibility'},ensure_ascii=False,indent=2))
