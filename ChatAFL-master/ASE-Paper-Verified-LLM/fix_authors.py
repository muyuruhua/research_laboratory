import re
import sys

def fix_authors(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    def replace_commas(match):
        author_line = match.group(0)
        # Author line inside curly braces
        inner = re.search(r"\{(.*?)\}", author_line)
        if inner:
            # Also replace "DOI", "Media Attached" etc. if they exist at the end
            authors_str = inner.group(1).replace(" Media Attached", "").replace(" File Attached", "").replace(" DOI", "")
            # replace comma with " and "
            authors = [a.strip() for a in authors_str.split(",")]
            new_authors = " and ".join(authors)
            return author_line.replace(inner.group(1), new_authors)
        return author_line

    new_content = re.sub(r"author\s*=\s*\{[^\}]+\}", replace_commas, content)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(new_content)

fix_authors("/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/references.bib")
