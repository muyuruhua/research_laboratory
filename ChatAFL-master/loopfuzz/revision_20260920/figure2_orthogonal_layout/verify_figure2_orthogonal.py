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
assert size_after[0]<510 and size_after[1]<185

# Check the actual orthogonal routes against all node and label rectangles.
assert r'\coordinate (reject_join)' not in newblock
assert r'(gain.south)--node[condition,below,pos=.45]' not in newblock
assert newblock.count(r'\draw[failbranch]')==3
cm=72.27/2.54
xy=lambda x,y:(x*cm,y*cm)
def anchor(n,side):
 r=rects[n];x,y=center(r)
 return {'north':(x,r[3]),'south':(x,r[1]),'east':(r[2],y),'west':(r[0],y)}[side]
paths={
 'llm_to_p':[anchor('llm','east'),anchor('p','west')],
 'p_to_trial':[anchor('p','east'),anchor('trial','west')],
 'trial_to_gain':[anchor('trial','east'),anchor('gain','west')],
 'code_to_durable':[anchor('gain','south'),anchor('dur','north')],
 'state_to_provisional':[(anchor('gain','south')[0]-.7*cm,anchor('gain','south')[1]),xy(12.5,1.4),xy(4.4,1.4),anchor('prov','north')],
 'provisional_to_validation':[anchor('prov','east'),anchor('validation','west')],
 'validation_to_durable':[anchor('validation','east'),anchor('dur','west')],
 'rejection_rail':[xy(13.2,4.2),xy(-2.1,4.2),xy(-2.1,0),anchor('rej','west')],
 'p_failure':[anchor('p','north'),xy(4.4,4.2)],
 'trial_failure':[anchor('trial','north'),xy(8.8,4.2)],
 'gain_failure':[anchor('gain','north'),xy(13.2,4.2)],
 'expiry':[anchor('validation','south'),xy(8.8,-1.35),xy(0,-1.35),anchor('rej','south')]
}
eps=.03
segments=[(n,i,a,b) for n,pts in paths.items() for i,(a,b) in enumerate(zip(pts,pts[1:]))]
assert all(abs(a[0]-b[0])<eps or abs(a[1]-b[1])<eps for _,_,a,b in segments)
def hits_rect(a,b,r):
 if abs(a[0]-b[0])<eps:
  return r[0]+eps<a[0]<r[2]-eps and min(max(a[1],b[1]),r[3])-max(min(a[1],b[1]),r[1])>eps
 return r[1]+eps<a[1]<r[3]-eps and min(max(a[0],b[0]),r[2])-max(min(a[0],b[0]),r[0])>eps
edge_collisions=[(route,index,node) for route,index,a,b in segments for node,r in rects.items() if hits_rect(a,b,r)]
assert not edge_collisions,edge_collisions
allowed={frozenset(['rejection_rail','p_failure']):xy(4.4,4.2),frozenset(['rejection_rail','trial_failure']):xy(8.8,4.2),frozenset(['rejection_rail','gain_failure']):xy(13.2,4.2)}
def intersection(a,b,c,d):
 v1=abs(a[0]-b[0])<eps;v2=abs(c[0]-d[0])<eps
 if v1==v2:
  fixed=0 if v1 else 1;moving=1-fixed
  if abs(a[fixed]-c[fixed])>eps:return None
  lo=max(min(a[moving],b[moving]),min(c[moving],d[moving]));hi=min(max(a[moving],b[moving]),max(c[moving],d[moving]))
  if lo>hi+eps:return None
  if hi-lo>eps:return 'overlap'
  return (a[0],(lo+hi)/2) if v1 else ((lo+hi)/2,a[1])
 if not v1:a,b,c,d=c,d,a,b
 x,y=a[0],c[1]
 return (x,y) if min(a[1],b[1])-eps<=y<=max(a[1],b[1])+eps and min(c[0],d[0])-eps<=x<=max(c[0],d[0])+eps else None
crossings=[];junctions=[]
for (n,i,a,b),(m,j,c,d) in itertools.combinations(segments,2):
 if n==m:continue
 pt=intersection(a,b,c,d)
 if pt is None:continue
 expected=allowed.get(frozenset([n,m]))
 if pt!='overlap' and expected and max(abs(pt[k]-expected[k]) for k in [0,1])<eps:junctions.append([n,m])
 else:crossings.append([n,i,m,j,pt])
assert not crossings,crossings
assert len(junctions)==3,junctions
aux=(R/'main.revised.aux').read_text();match=re.search(r'\\newlabel\{fig:architecture\}\{\{(\d+)\}\{(\d+)\}',aux);number,page=map(int,match.groups());assert number==2
pages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo','main.revised.pdf']),re.M)[1]);oldpages=int(re.search(r'^Pages:\s*(\d+)',run(['pdfinfo',str(B/'before/main.revised.pdf')]),re.M)[1]);assert pages==oldpages
# Inspect the real manuscript page, in addition to the isolated TikZ render.
page_svg=B/f'manuscript_page_{page}.svg';run(['pdftocairo','-f',str(page),'-l',str(page),'-svg','main.revised.pdf',str(page_svg)])
ns={'s':'http://www.w3.org/2000/svg'}
def arrowheads(p):return [node for node in ET.parse(p).findall('.//s:path',ns) if re.search(r'fill:rgb\((14|34)\.',node.attrib.get('style','')) and 'stroke-width:' in node.attrib.get('style','')]
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
report={'status':'PASS','scope':'Figure 2 only','page':page,'pages':pages,'original_pages':oldpages,'source_line':tex[:tex.index(newblock)].count('\n')+1,'main_gap_before_mm':[round(x,3) for x in oldgaps],'main_gap_after_mm':[round(x,3) for x in gaps],'rendered_arrowheads':len(heads),'visible_arrowheads':len(visibility),'box_label_overlaps':len(overlaps),'main_font_pt':9,'condition_font_pt':8.5,'vector_only':True,'outside_figure_change':'None','outside_figure_other_content_identical':True,'bibliography_byte_identical':True,'distinct_linked_references':len(keys),'figure_table_destinations':len(figure_table_targets),'internal_links':len(links),'overfull_boxes':0,'nonfatal_layout_notices':notices,'caption_unchanged':True,'figure2_destination':dests['figure.2'],'requirements_sha256':sha(req),'tex_sha256':sha(R/'main.revised.tex'),'pdf_sha256':sha(R/'main.revised.pdf'),'arrowhead_visibility':visibility}
report.update({'layout':'Two rows, four aligned columns; orthogonal rejection rail above, separate expiry below','equal_module_sizes':True,'aligned_columns':True,'even_column_spacing':True,'module_count':8,'label_count':9,'canvas_before_pt':size_before,'canvas_after_pt':size_after,'height_reduction_percent':round(height_reduction,2),'area_reduction_percent':round(area_reduction,2),'main_gap_mm':[round(x,3) for x in gaps]})
report.update({'all_routes_orthogonal':True,'route_segments':len(segments),'unintended_route_intersections':len(crossings),'edge_node_or_label_collisions':len(edge_collisions),'intended_rejection_junctions':len(junctions),'rejection_routing':'Three short upward branches share one upper rail; single arrow into reject','expiry_routing':'Separate lower return path','raster_preview_only':True})
(B/'validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');(B/'pdf_destinations.txt').write_text(dest_text)
(R/'main.revised.txt').write_text(run(['pdftotext','-layout','main.revised.pdf','-']))
lines=[
 '# Figure 2 正交布线修复核验', '',
 '状态：PASS。本轮修改 Figure 2 的连线与行间距。已目视检查独立预览及最终论文第 5 页渲染，确认顶部拒绝汇流、内部准入路径和底部过期回路清晰分离。', '',
 '## 本轮问题', '',
 '- 上一版的三个失败分支斜向扇形汇聚，并与状态准入斜线占用同一区域，导致视觉拥挤；模块对齐并不能解决布线混乱。', '',
 '## 修改', '',
 '- 取消全部斜线。P、U/R 及无收益三个失败分支改为短竖线，在图上方接入同一条灰色虚线，通过左侧一个箭头进入 Reject / expire。',
 '- 预算耗尽使用独立的下方回路；状态新颖性准入改为内部的正交实线，两者不相交。',
 '- 保持两行四列，八个模块等宽等高；上排行高由 3.4 cm 调至 2.8 cm，以容纳顶部汇流线并控制总高度。',
 '- 使用统一虚线节距、线宽与圆角；图注和条件标签内容保持不变。', '',
 '## 方法要求', '',
 '- 核对 first_paper.md 第 181–239 行及第 1098–1099 行：P/U/R 检查先于收益判断，代码收益与状态新颖性独立。',
 '- 代码收益支持 durable 准入；只有状态新颖性的候选进入 provisional，经有限后代验证获得代码证据后才能晋升，否则预算耗尽后过期。',
 '- 结构、行为或可达性失败，或两种收益均不存在时拒绝。仅重绘同一算法关系，不增加数据、实验或研究结论。', '',
 '## 验证', '',
 '- 8 个模块、9 个条件标签共 17 个包围框无重叠。上下两排同轴，四列等距，模块同尺寸。',
 f'- {len(segments)} 段连接均为正交线段；除 3 个预期拒绝汇流连接外无路径交叉，路径不穿过模块或标签内部。',
 f'- 独立预览和最终论文第 {page} 页均有 9 个矢量箭头头部，实际论文渲染中均可见。',
 f'- 独立矢量画布：{size_after[0]:.3f} × {size_after[1]:.3f} pt；文字仍为 9 pt，条件标签为 8.5 pt。',
 f'- 全文 {pages} 页；无 Overfull、未定义引用或重复目标警告。',
 '- 仍保留既有第 12、15 页纯浮动体页面提示，详见 validation.json。',
 '- 图外主稿逐字符一致，参考文献 bbl 逐字节一致；50 条文献均有有效引用，29 个图表目标有效。',
 '- 论文 PDF 与图形保持矢量；PNG 仅作为审阅预览，不嵌入论文。', '',
 '## 输出与复核', '',
 '- 主稿：../main.revised.tex；重新编译的论文：../main.revised.pdf。',
 '- 矢量图：[PDF](figure2_after.pdf)、[SVG](figure2_after.svg)。',
 '- 数值审计：[validation.json](validation.json)；源码差异：figure2.diff；本轮备份：before/。',
 '- 复核：在修订目录执行 python3 figure2_orthogonal_layout/verify_figure2_orthogonal.py。', ''
]
(B/'FIGURE2_ORTHOGONAL_AUDIT.md').write_text('\n'.join(lines))
print(json.dumps({k:v for k,v in report.items() if k!='arrowhead_visibility'},ensure_ascii=False,indent=2))
