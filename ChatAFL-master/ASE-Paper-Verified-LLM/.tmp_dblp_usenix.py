from urllib.parse import quote
from urllib.request import urlopen, Request
import json
queries = [
    'Fuzzing Hardware Like Software',
    'Android SmartTVs Vulnerability Discovery via Log-Guided Fuzzing',
    'Coverage-Guided Fuzzing of Embedded Systems Leveraging Hardware Tracing',
]
for q in queries:
    url='https://dblp.org/search/publ/api?q='+quote('title:'+q)+'&h=5&format=json'
    req=Request(url, headers={'User-Agent':'Mozilla/5.0'})
    with urlopen(req, timeout=20) as resp:
        data=json.load(resp)
    print('===', q, '===')
    hits=data.get('result',{}).get('hits',{}).get('hit',[])
    if isinstance(hits, dict): hits=[hits]
    for hit in hits[:5]:
        info=hit.get('info',{})
        print(info.get('year'), '|', info.get('title'), '|', info.get('venue'), '|', info.get('pages'), '|', info.get('doi') or info.get('ee'))
    print()
