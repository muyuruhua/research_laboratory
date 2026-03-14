import re
text = open("main.tex").read()
keys = set(re.findall(r"\cite\{([^}]*)\}", text))
all_keys = set()
for k_str in keys:
    all_keys.update([x.strip() for x in k_str.split(",")])
print("Total unique citations in main.tex:", len(all_keys))