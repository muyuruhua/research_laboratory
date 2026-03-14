import re
import os

repo_path = '/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/references.bib'

with open(repo_path, 'r') as f:
    content = f.read()

# 1. Remove URLs from @inproceedings (but keep for @misc where appropriate)
content = re.sub(r',\s*url\s*=\s*\{[^}]*\}', '', content)

# 2. Fix howpublished/note for misc/manual entries
content = content.replace('  howpublished = {[Online]},\n  note   = {Technical white paper. Accessed: Mar. 10, 2026},',
                         '  note   = {Technical white paper. [Online].}')
content = content.replace('  howpublished = {[Online]},\n  note   = {Software project, online resource. Accessed: Mar. 11, 2026},',
                         '  note   = {Software project. [Online].}')
content = content.replace('  howpublished = {[Online]},\n  note   = {Software framework, online resource. Accessed: Mar. 10, 2026},',
                         '  note   = {Software framework. [Online].}')
content = content.replace('  howpublished = {[Online]},\n  note   = {Software project, online resource. Accessed: Mar. 10, 2026},',
                         '  note   = {Software project. [Online].}')
content = content.replace('  howpublished = {[Online]},\n  note   = {Online documentation. Accessed: Mar. 10, 2026},',
                         '  note   = {Online documentation. [Online].}')

# 3. Standardize NDSS booktitles
content = content.replace('booktitle = {Proceedings 2021 Network and Distributed System Security Symposium}',
                          'booktitle = {28th Annual Network and Distributed System Security Symposium ({NDSS} 2021)}')
content = content.replace('booktitle = {Proceedings 2023 Network and Distributed System Security Symposium}',
                          'booktitle = {30th Annual Network and Distributed System Security Symposium ({NDSS} 2023)}')
content = content.replace('booktitle = {31st Annual Network and Distributed System Security Symposium ({NDSS} 2024)}',
                          'booktitle = {31st Annual Network and Distributed System Security Symposium ({NDSS} 2024)}')

# 4. Protect acronyms in titles
acronyms = ['JavaScript', 'JIT', 'TLS', 'DTLS', 'EDHOC', 'IoT', 'Linux', 'USB', 'Wi-Fi', 'SmartTVs', 'UI-based', 'NICs', 'Windows', 'Deep-Learning', 'API', 'Android', 'AFLNet', 'StateAFL']

for word in acronyms:
    def repl_word(m):
        title = m.group(0)
        # Regex to find word matching case-insensitively, but not already inside {}
        title = re.sub(r'(?<!\{)\b' + re.escape(word) + r'\b(?!\})', r'{' + word + r'}', title, flags=re.IGNORECASE)
        # Also handle hyphenated or compound words properly if they exist as substrings
        return title
        
    content = re.sub(r'title\s*=\s*\{[^}]*\}', repl_word, content)
    
# Manual Title Casings fixes to ensure proper capitalization in output
fix_map = {
    '{Javascript}': '{JavaScript}',
    '{javascript}': '{JavaScript}',
    '{Windows}': '{Windows}',
    '{windows}': '{Windows}',
    '{IoT}': '{IoT}',
    '{iot}': '{IoT}',
    '{Tls}': '{TLS}',
    '{tls}': '{TLS}',
    '{Dtls}': '{DTLS}',
    '{dtls}': '{DTLS}',
    '{Edhoc}': '{EDHOC}',
    '{edhoc}': '{EDHOC}',
    '{Wi-Fi}': '{Wi-Fi}',
    '{wi-fi}': '{Wi-Fi}',
    '{UI-based}': '{UI}-based',
    '{ui-based}': '{UI}-based',
    '{Nics}': '{NICs}',
    '{nics}': '{NICs}',
    '{Api}': '{API}',
    '{api}': '{API}',
    '{Android}': '{Android}',
    '{android}': '{Android}',
    '{Deep-learning}': '{Deep-Learning}',
    '{deep-learning}': '{Deep-Learning}',
    '{Usb}': '{USB}',
    '{usb}': '{USB}',
    '{Linux}': '{Linux}',
    '{linux}': '{Linux}',
    '{Smarttvs}': '{SmartTVs}',
    '{smarttvs}': '{SmartTVs}',
    '{Jit}': '{JIT}',
    '{jit}': '{JIT}',
    '{Fuzzilli}': '{FUZZILLI}',
    '{fuzzilli}': '{FUZZILLI}',
    '{Winnie}': '{WINNIE}',
    '{winnie}': '{WINNIE}',
    '{Bcfuzz}': '{BCFuzz}',
    '{bcfuzz}': '{BCFuzz}',
    '{AFLNet}': '{AFLNet}',
    '{aflnet}': '{AFLNet}',
    '{StateAFL}': '{StateAFL}',
    '{stateafl}': '{StateAFL}',
    '{DNAFuzz}': '{DNAFuzz}',
    '{dnafuzz}': '{DNAFuzz}',
}

for k, v in fix_map.items():
    content = content.replace(k, v)

with open(repo_path, 'w') as f:
    f.write(content)

print("Formatting applied locally.")
