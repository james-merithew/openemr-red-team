"""Regenerate the offline, self-contained presentation file.

Wraps ``defense_onepager.html`` (the lean source that renders diagrams via the
claude.ai artifact runtime) into a complete HTML document with the mermaid diagram
engine inlined, so ``defense_onepager_standalone.html`` opens in any browser —
double-click, press F11 — with the diagrams rendered and **no network required**.

The standalone output is git-ignored (it is a large generated export); regenerate it
on demand with:  python defense/week3/build_standalone.py
"""

import pathlib
import urllib.request

HERE = pathlib.Path(__file__).parent
MERMAID_URL = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"

src = (HERE / "defense_onepager.html").read_text(encoding="utf-8")
mermaid = urllib.request.urlopen(MERMAID_URL).read().decode("utf-8")  # noqa: S310 (trusted CDN)

# The source is authored as artifact-body content (a <title>, a <style>, then the
# page markup). Split at the first content div: everything before is head material.
i = src.index('<div class="wrap">')
head, body = src[:i], src[i:]

doc = (
    '<!doctype html>\n<html lang="en">\n<head>\n'
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    + head
    + '</head>\n<body>\n'
    + body
    + '\n<script>\n' + mermaid + '\n</script>\n'
    '<script>mermaid.initialize({startOnLoad:true, securityLevel:"loose", '
    'flowchart:{htmlLabels:true}});</script>\n'
    '</body>\n</html>\n'
)

out = HERE / "defense_onepager_standalone.html"
out.write_text(doc, encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")
