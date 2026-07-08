import re

with open(r'C:\Users\lamic\.gemini\antigravity-ide\brain\6af4bdcb-99eb-41a3-b1c2-5fb1fb8aeef4\scratch\new_html.ts', 'r', encoding='utf-8') as f:
    text = f.read()

# We need to escape \ and $ inside the script tags, because the whole HTML is wrapped in \
def replacer(match):
    script_content = match.group(1)
    # escape backticks and dollar signs
    script_content = script_content.replace('\', '\\\\').replace('$', '\\\\$')
    return '<script>' + script_content + '</script>'

text = re.sub(r'<script>(.*?)</script>', replacer, text, flags=re.DOTALL)

with open(r'C:\Users\lamic\.gemini\antigravity-ide\brain\6af4bdcb-99eb-41a3-b1c2-5fb1fb8aeef4\scratch\new_html_escaped.ts', 'w', encoding='utf-8') as f:
    f.write(text)
