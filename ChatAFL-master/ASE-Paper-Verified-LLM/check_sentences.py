import re

with open('main.tex', 'r') as f:
    text = f.read()

# remove latex commands mostly
text = re.sub(r'\\[a-zA-Z]+(\[.*?\])?(\{.*?\})?', '', text)
sentences = re.split(r'(?<=[.!?])\s+', text)
for s in sentences:
    if s and len(s.split()) > 35:
        print(len(s.split()), s.strip())
