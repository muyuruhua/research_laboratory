from urllib.parse import quote
from urllib.request import urlopen, Request
import json

queries = [
    'Fuzzing Hardware Like Software',
    'Android SmartTVs Vulnerability Discovery via Log-Guided Fuzzing',
    'Coverage-Guided Fuzzing of Embedded Systems Leveraging Hardware Tracing',
    'Prompt Fuzzing for Fuzz Driver Generation',
    'Large Language Model guided Protocol Fuzzing',
    'Stateful greybox fuzzing',
]
for q in queries:
    url='https://api.crossref.org/works?rows=5&query.title='+quote(q)
    req=Request(url, headers={'User-Agent':'Mozilla/5.0'})
    with urlopen(req, timeout=20) as resp:
        data=json.load(resp)
    print('===', q, '===')
    for item in data.get('message', {}).get('items', [])[:5]:
        t=(item.get('title') or [''])[0]
        venue=((item.get('container-title') or [''])[:1] or [''])[0]
        year=None
        for key in ('published-print','published-online','issued','created'):
            dp=item.get(key,{}).get('date-parts')
            if dp and dp[0]:
                year=dp[0][0]
                break
        print(year, '|', t, '|', venue, '|', item.get('page',''), '|', item.get('DOI',''))
    print()
