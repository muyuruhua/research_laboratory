import json
import re

with open("new_papers.json") as f:
    papers = json.load(f)

# Exclude some known titles already in references.bib or too short
existing_titles = [
    "stateful greybox fuzzing", "aflnet", "chatafl", "fuzz4all", "snapfuzz", "formatted stateful",
    "snipuzz", "gramatron", "fuzzing javascript jit", "rulf: rust library", "winnie",
    "profuzzbench", "edhoc", "dtls-fuzzer", "prompt fuzzing", "no grammar no problem",
    "carpetfuzz", "logos", "msgfuzzer", "bleem", "afl", "peach"
]

selected = []
for p in papers:
    title = p['title'].lower()
    
    # check against existing to avoid dupes vaguely
    if any(ex in title for ex in existing_titles):
        continue
        
    if "fuzz" in title or "protocol" in title or "state" in title or "network" in title or "llm" in title:
        selected.append(p)

print("Selected candidates:", len(selected))
for i, p in enumerate(selected[:50]):
    print(f"{i+1}. {p['title']} ({p['venue']} {p['year']})")
