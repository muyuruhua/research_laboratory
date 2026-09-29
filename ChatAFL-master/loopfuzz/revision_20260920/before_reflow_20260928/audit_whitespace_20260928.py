#!/usr/bin/env python3
"""Measure large blank bands inside the text area; rasterization is inspection only."""
from pathlib import Path
from PIL import Image
import hashlib
import json
import subprocess
import numpy as np

BASE=Path(__file__).resolve().parent
OUT=BASE/'whitespace_checks_20260928'
OUT.mkdir(exist_ok=True)
THRESHOLD_PT=28

def runs(mask):
    edges=np.diff(np.r_[False,mask,False].astype(int))
    return list(zip(np.flatnonzero(edges==1).tolist(),np.flatnonzero(edges==-1).tolist()))

def measure(pdf,stem):
    digest=hashlib.sha256(pdf.read_bytes()).hexdigest()
    folder=OUT/stem;folder.mkdir(exist_ok=True)
    signature=folder/'source.sha256'
    if not signature.exists() or signature.read_text()!=digest:
        subprocess.run(['pdftoppm','-r','72','-png',str(pdf),str(folder/'page')],check=True,stderr=subprocess.DEVNULL)
        signature.write_text(digest)
    text=subprocess.check_output(['pdftotext','-layout',str(pdf),'-'],text=True).split('\f')
    page_count=len([p for p in text if p.strip()])
    records=[]
    for number in range(1,page_count+1):
        candidates=[p for p in folder.glob('page-*.png') if int(p.stem.split('-')[-1])==number]
        assert len(candidates)==1
        im=Image.open(candidates[0]).convert('L')
        if im.width<im.height:
            box=(36,80,im.width-36,im.height-88)
        else:
            box=(80,36,im.width-88,im.height-36)
        a=np.array(im.crop(box))<230
        def bands(region):
            blank=np.count_nonzero(region,axis=1)<3
            gaps=[{'start_pt':lo,'end_pt':hi,'height_pt':hi-lo} for lo,hi in runs(blank) if hi-lo>=THRESHOLD_PT]
            return {'largest_blank_band_pt':max([g['height_pt'] for g in gaps],default=0),
                    'large_blank_band_total_pt':sum(g['height_pt'] for g in gaps),'bands':gaps}
        mid=a.shape[1]//2
        record={'page':number,'orientation':'portrait' if im.width<im.height else 'landscape',
                'body_width_pt':a.shape[1],'body_height_pt':a.shape[0],
                'whole':bands(a),'left':bands(a[:,:mid-8]),'right':bands(a[:,mid+8:]),
                'words':len(text[number-1].split())}
        records.append(record)
    return {'pdf_sha256':digest,'page_count':page_count,'pages':records,
            'whole_width_blank_page_equivalents':sum(r['whole']['large_blank_band_total_pt']/r['body_height_pt'] for r in records),
            'half_width_blank_page_equivalents':sum((r['left']['large_blank_band_total_pt']+r['right']['large_blank_band_total_pt'])/(2*r['body_height_pt']) for r in records)}

def main():
    before=measure(BASE/'before_whitespace_20260928/main.revised.pdf','before')
    after=measure(BASE/'main.revised.pdf','after')
    report={'method':'72 dpi inspection raster, pixels <230, fewer than 3 dark pixels per row, contiguous gaps >=28pt. Body margins/footer excluded; this is a layout proxy, not a semantic content score.',
            'before':before,'after':after}
    for key in ['whole_width_blank_page_equivalents','half_width_blank_page_equivalents']:
        report[key+'_reduction_percent']=100*(1-after[key]/before[key])
    (OUT/'whitespace_metrics.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['before','after']},indent=2))
    for name,data in [('before',before),('after',after)]:
        print(name,data['page_count'],'pages','blank page equivalents:',round(data['whole_width_blank_page_equivalents'],2),round(data['half_width_blank_page_equivalents'],2))
        print([(r['page'],r['whole']['largest_blank_band_pt'],r['left']['largest_blank_band_pt'],r['right']['largest_blank_band_pt']) for r in data['pages'] if max(r[k]['largest_blank_band_pt'] for k in ['whole','left','right'])>=130])

if __name__=='__main__':main()
