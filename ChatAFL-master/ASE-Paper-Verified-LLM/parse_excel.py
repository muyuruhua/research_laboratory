import pandas as pd
import json

xls = pd.ExcelFile("conference.xlsx")
papers = []
for sheet in xls.sheet_names:
    df = pd.read_excel(xls, sheet_name=sheet)
    if '论文' not in df.columns:
        continue
    for _, row in df.iterrows():
        title = str(row.get('论文', '')).strip()
        author = str(row.get('作者', '')).strip()
        year = str(row.get('年份', '')).strip()
        if title and title != 'nan':
            papers.append({
                'title': title,
                'author': author,
                'year': year,
                'venue': sheet.strip()
            })

with open("new_papers.json", "w") as f:
    json.dump(papers, f, indent=2)

print(len(papers))
