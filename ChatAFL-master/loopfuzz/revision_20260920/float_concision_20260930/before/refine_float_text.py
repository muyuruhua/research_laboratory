#!/usr/bin/env python3
"""Apply reviewed, idempotent figure/table copy edits without rewriting data.

Each changed text cell must match its recorded original or final text. Changed
source data therefore trigger review instead of silently restoring old values.
"""
from pathlib import Path
import json,re
BASE=Path(__file__).resolve().parent
SPEC=BASE/'concise_float_text.json'
BS=chr(92)

def brace_end(text,start):
    assert text[start]=='{'
    depth=0
    for i in range(start,len(text)):
        if text[i] in '{}' and (i==0 or text[i-1]!=BS):
            depth+=1 if text[i]=='{' else -1
            if depth==0:return i
    raise ValueError('Unclosed caption')

def caption_span(text,label):
    marker=BS+'label{'+label+'}';assert text.count(marker)==1,label
    pos=text.index(marker)
    starts=list(re.finditer(r'\\caption(?:of\{table\})?\{',text[:pos]))
    assert starts,label
    start=starts[-1].end()-1
    return start+1,brace_end(text,start)

def block_span(text,label):
    pos=text.index(BS+'label{'+label+'}')
    for m in re.finditer(r'\\begin\{(table\*?|figure\*?)\}.*?\\end\{\1\}',text,re.S):
        if m.start()<pos<m.end():return m.start(),m.end()
    raise ValueError('No float block for '+label)

def apply_edits():
    spec=json.loads(SPEC.read_text());pending={}
    for item in spec['floats']:
        name=item['file'];text=pending.get(name,(BASE/name).read_text())
        a,z=caption_span(text,item['label']);old=text[a:z];cap=item['caption']
        assert old in [cap['old'],cap['new']],('Caption changed; review required',item['label'])
        text=text[:a]+cap['new']+text[z:]
        if item.get('cells'):
            a,z=block_span(text,item['label']);block=text[a:z];lines=block.splitlines()
            for edit in item['cells']:
                names={edit['row'],item.get('row_aliases',{}).get(edit['row'],edit['row'])}
                idx=[i for i,line in enumerate(lines) if any(line.startswith(name+' & ') for name in names)]
                assert len(idx)==1,(item['label'],edit['row'])
                i=idx[0];line=lines[i];assert line.rstrip().endswith(BS*2)
                cells=line.rstrip()[:-2].strip().split(' & ');col=edit['column']
                assert cells[col] in [edit['old'],edit['new']],('Cell changed; review required',item['label'],edit['row'],col)
                cells[col]=edit['new'];lines[i]=' & '.join(cells)+' '+BS*2
            text=text[:a]+chr(10).join(lines)+text[z:]
        pending[name]=text
    for edit in spec.get('prose_edits',[]):
        name=edit['file'];text=pending.get(name,(BASE/name).read_text())
        if edit['new'] in text:
            assert text.count(edit['new'])==1,(name,edit['new'][:60])
        else:
            assert text.count(edit['old'])==1,('Missing or ambiguous prose anchor',name)
            text=text.replace(edit['old'],edit['new'],1)
        pending[name]=text
    changed=[]
    for name,text in pending.items():
        path=BASE/name
        if path.read_text()!=text:path.write_text(text);changed.append(name)
    # This is a derived manuscript excerpt, not raw vulnerability evidence.
    main=pending.get('main.revised.tex',(BASE/'main.revised.tex').read_text())
    start=main.index(BS+'section{Vulnerability Replay Evidence and Rediscovery Protocol}')
    end=main.index(BS+'section{',start+10)
    excerpt=main[start:end].strip()+chr(10)
    path=BASE/'vulnerability_section_20260929.tex'
    if path.read_text().strip()!=excerpt.strip():path.write_text(excerpt);changed.append(path.name)
    print('Concise float text applied:',len(spec['floats']),'floats;',len(changed),'files changed')
    return changed

if __name__=='__main__':apply_edits()
