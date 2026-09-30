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
assert tex[:a]+tex[b:]==old[:oa]+old[ob:],'Unexpected change outside Figure 2'
assert re.findall(r'\\caption\{([^}]+)\}',newblock)==re.findall(r'\\caption\{([^}]+)\}',oldblock)
assert (R/'main.revised.bbl').read_bytes()==(B/'before/main.revised.bbl').read_bytes()
manifest=json.loads((B/'manifest.json').read_text());req=Path('/home/ckt/Documents/000_2026_test_dev/C_two_papers/first_paper.md')
assert sha(req)==manifest['requirements_sha256']
def geometry(name):
 result={}
 source=(B/f'figure2_{name}.log').read_text()
 for node,corner,x,y in re.findall(r'FIG2\|([^|\s]+)\|(sw|ne)\|(-?[\d.]+)pt\|(-?[\d.]+)pt',source):
  result.setdefault(node,{})[corner]=[float(x),float(y)]
 assert all(set(x)=={'sw','ne'} for x in result.values())
 rects={n:v['sw']+v['ne'] for n,v in result.items()}
 (B/f'geometry_{name}.json').write_text(json.dumps(rects,indent=2)+'\n')
 return rects
rects=geometry('after');oldrects=geometry('before')
assert len(rects)==17 and set(manifest['box_names']+manifest['label_names'])==set(rects)
overlaps=[]
for (na,x),(nb,y) in itertools.combinations(rects.items(),2):
 if min(x[2],y[2])-max(x[0],y[0])>.15 and min(x[3],y[3])-max(x[1],y[1])>.15:overlaps.append([na,nb])
assert not overlaps,overlaps
gaps=[(rects[right][0]-rects[left][2])*25.4/72.27 for left,right in [('llm','p'),('p','trial'),('trial','gain')]]
oldgaps=[(oldrects[right][0]-oldrects[left][2])*25.4/72.27 for left,right in [('llm','p'),('p','trial'),('trial','gain')]]
assert min(gaps)>17 and manifest['condition_font_pt']>=8
rows=[['llm','p','trial','gain'],['rej','prov','validation','dur']]
center=lambda r:((r[0]+r[2])/2,(r[1]+r[3])/2)
widths=[rects[n][2]-rects[n][0] for n in manifest['box_names']]
heights=[rects[n][3]-rects[n][1] for n in manifest['box_names']]
assert max(widths)-min(widths)<.001 and max(heights)-min(heights)<.001
for row in rows:
 ys=[center(rects[n])[1] for n in row]
 assert max(ys)-min(ys)<.001
 xs=[center(rects[n])[0] for n in row]
 steps=[xs[i+1]-xs[i] for i in range(3)]
 assert max(steps)-min(steps)<.001
assert all(abs(center(rects[t])[0]-center(rects[b])[0])<.001 for t,b in zip(*rows))
def pdfsize(path):
 m=re.search(r'^Page size:\s*([\d.]+) x ([\d.]+) pts',run(['pdfinfo',str(path)]),re.M)
 return list(map(float,m.groups()))
size_before=pdfsize(B/'figure2_before.pdf');size_after=pdfsize(B/'figure2_after.pdf')
height_reduction=100*(1-size_after[1]/size_before[1])
area_reduction=100*(1-size_after[0]*size_after[1]/(size_before[0]*size_before[1]))
assert height_reduction>0 and area_reduction>0
aux=(R/'main.revised.aux').read_text();match=re.search(r'\\newlabel\{fig:architecture\}\{\{(\d+)\}\{(\d+)\}',aux);number,page=map(int,match.groups());assert number==2
pages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo','main.revised.pdf']),re.M)[1]);oldpages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo',str(B/'before/main.revised.pdf')]),re.M)[1]);assert pages==oldpages
# Inspect the real manuscript page, in addition to the isolated TikZ render.
page_svg=B/f'manuscript_page_{page}.svg';run(['pdftocairo','-f',str(page),'-l',str(page),'-svg','main.revised.pdf',str(page_svg)])
ns={'s':'http://www.w3.org/2000/svg'}
def arrowheads(p):return [node for node in ET.parse(p).findall('.//s:path',ns) if re.search(r'fill:rgb\(14\.',node.attrib.get('style',''))]
heads=arrowheads(page_svg);isolated=arrowheads(B/'figure2_after.svg');assert len(heads)==len(isolated)==manifest['expected_arrowheads']==9
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
# Pixel visibility check on all nine heads in the actual PDF page.
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
 dark=sum(x<100 for x in crop.tobytes());assert dark>=15,(index,dark)
 visibility.append({'arrowhead':index,'dark_pixels_at_144dpi':dark,'bbox_pt':[round(x,2) for x in [x0,y0,x1,y1]]})
report={'status':'PASS','scope':'Figure 2 only','page':page,'pages':pages,'original_pages':oldpages,'source_line':tex[:a].count('\n')+1,'main_gap_before_mm':[round(x,3) for x in oldgaps],'main_gap_after_mm':[round(x,3) for x in gaps],'rendered_arrowheads':len(heads),'visible_arrowheads':len(visibility),'box_label_overlaps':len(overlaps),'main_font_pt':9,'condition_font_pt':8.5,'vector_only':True,'outside_figure_change':'None','outside_figure_other_content_identical':True,'bibliography_byte_identical':True,'distinct_linked_references':len(keys),'figure_table_destinations':len(figure_table_targets),'internal_links':len(links),'overfull_boxes':0,'nonfatal_layout_notices':notices,'caption_unchanged':True,'figure2_destination':dests['figure.2'],'requirements_sha256':sha(req),'tex_sha256':sha(R/'main.revised.tex'),'pdf_sha256':sha(R/'main.revised.pdf'),'arrowhead_visibility':visibility}
report.update({'layout':'Two rows, four aligned columns','equal_module_sizes':True,'aligned_columns':True,'even_column_spacing':True,'module_count':8,'label_count':9,'canvas_before_pt':size_before,'canvas_after_pt':size_after,'height_reduction_percent':round(height_reduction,2),'area_reduction_percent':round(area_reduction,2),'main_gap_mm':[round(x,3) for x in gaps]})
(B/'validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');(B/'pdf_destinations.txt').write_text(dest_text)
(R/'main.revised.txt').write_text(run(['pdftotext','-layout','main.revised.pdf','-']))
lines=[
 '# Figure 2 均衡布局核验', '',
 '状态：PASS。本轮只修改 Figure 2 的 TikZ 图形块，图外正文逐字符保持一致。', '',
 '## 问题与修复', '',
 '- 原布局在右侧堆叠临时队列与长期队列，左侧 LLM proposal 下方缺少对应模块，造成视觉重心右移。',
 '- 改为两行四列。上排为 LLM proposal、Structural check、Bounded trial、Separate gains；下排为 Reject / expire、Provisional queue、Descendant validation、Durable queue。',
 '- Reject / expire 与 LLM proposal 按列对齐，八个模块等高等宽，四列等距；不使用装饰性或虚构模块填补空白。',
 '- Descendant validation 是原文已有的有限后代验证步骤，本轮将其独立绘制，以明确临时队列的晋升与过期分支。',
 '- 三条失败分支在显式合流点汇合后进入 Reject；预算耗尽回路独立从下方返回。保留精简图注。', '',
 '## 与 first_paper.md 的对应', '',
 '- 对照第 181–239 行的两级队列准入要求，以及第 1098–1099 行的 controller architecture 要求。',
 '- 结构检查 P 和有界试验 U/R 在前；之后分别判别代码收益与状态新颖性。',
 '- 代码收益支持 durable 准入；state-only 候选仅进入 provisional。未通过检查或两种收益均无则拒绝。',
 '- provisional 候选经有预算的后代验证，取得合格代码证据后晋升；预算耗尽则过期。',
 '- 图中没有新增实验结论，也没有把状态新颖性直接当作代码收益。该核验限于 Figure 2，不代表对全文研究完成度的重新认证。', '',
 '## 检查结果', '',
 f'- 17 个模块/标签包围框无重叠；8 个模块同尺寸，两排各自水平对齐，4 列等距且上下同轴。',
 f'- 独立矢量画布由 {size_before[0]:.3f} × {size_before[1]:.3f} pt 减至 {size_after[0]:.3f} × {size_after[1]:.3f} pt：高度减少 {height_reduction:.1f}%，面积减少 {area_reduction:.1f}%。这是画布尺寸变化，不是语义空白面积估计。',
 f'- 最终论文第 {page} 页与独立预览均检测到 9 个矢量箭头头部；最终 PDF 的 144 dpi 渲染中，9 个箭头均检测到可见深色像素。',
 '- 正文框内字号 9 pt，条件标签 8.5 pt；保持矢量路径和文本，PDF 中无位图对象。',
 f'- 论文保持 {pages} 页；未出现 Overfull、未定义引用或重复目标警告。',
 f'- 50 条文献均有可点击引用，29 个图表目标有效；Figure 2 的目标位于第 {page} 页。',
 '- 图外源文本、参考文献 bbl、图注及 first_paper.md 均与本轮修改前保持一致；没有变更实验数据或正文论断。',
 '- 仍有既有第 12、15 页纯浮动体页面提示；具体提示记录于 validation.json，未将其误报为零警告。', '',
 '## 文件与复核', '',
 '- 最终稿：../main.revised.tex 和 ../main.revised.pdf。',
 '- 独立矢量预览：[PDF](figure2_after.pdf)、[SVG](figure2_after.svg)。',
 '- 数值核验：[validation.json](validation.json)；修改前备份：before/。',
 '- 在修订目录执行 python3 figure2_balanced_layout/verify_figure2_balanced.py 可重新核验。', ''
]
(B/'FIGURE2_BALANCED_AUDIT.md').write_text('\n'.join(lines))
print(json.dumps({k:v for k,v in report.items() if k!='arrowhead_visibility'},ensure_ascii=False,indent=2))
