#!/usr/bin/env python3
"""
Threat Pulse — HTML report generator.

Converts a rendered Threat Pulse **markdown** report into a self-contained, dark-theme
HTML file matching the SOC report suite. Dependency-free (Python stdlib only) so it runs
in the constrained SRE Agent sandbox — no `markdown` / `jinja2` packages required.

Usage:
    python3 generate_html_report.py "reports/threat-pulse/Threat_Pulse_<ts>.md" --output-dir reports/threat-pulse/
    python3 generate_html_report.py report.md            # writes report.html next to the .md
    python3 generate_html_report.py report.md -o out/    # writes out/report.html

Prints the output HTML path on stdout. Read-only with respect to the source markdown.
Supported markdown: ATX headings, GFM pipe tables, ordered/unordered lists, fenced and
inline code, bold/italic, links, blockquotes, horizontal rules, paragraphs (emoji pass
through unchanged).
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import os
import re
import sys

# Force UTF-8 stdout/stderr on Windows so emoji don't crash a cp1252 console.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

TITLE_DEFAULT = "Threat Pulse — Security Scan"

# --------------------------------------------------------------------------
# Inline formatting (code spans + links are stashed so they're not re-escaped)
# --------------------------------------------------------------------------
_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_ITAL_RE = re.compile(r"(?<![\*\w])\*([^*\n]+)\*(?![\*\w])")
_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")
_HR_RE = re.compile(r"^(-{3,}|\*{3,}|_{3,})$")


def _inline(text):
    """Escape HTML then apply inline markdown; code spans and links are escaped once."""
    tokens = []

    def _stash(fragment):
        tokens.append(fragment)
        return f"\x00{len(tokens) - 1}\x00"

    text = _CODE_RE.sub(
        lambda m: _stash(f"<code>{html.escape(m.group(1), quote=False)}</code>"), text
    )
    text = _LINK_RE.sub(
        lambda m: _stash(
            f'<a href="{html.escape(m.group(2), quote=True)}">'
            f"{html.escape(m.group(1), quote=False)}</a>"
        ),
        text,
    )
    text = html.escape(text, quote=False)
    text = _BOLD_RE.sub(r"<strong>\1</strong>", text)
    text = _ITAL_RE.sub(r"<em>\1</em>", text)
    text = re.sub(r"\x00(\d+)\x00", lambda m: tokens[int(m.group(1))], text)
    return text


def _split_row(line):
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _render_table(header, rows):
    th = "".join(f"<th>{_inline(c)}</th>" for c in header)
    body = []
    for r in rows:
        cells = (r + [""] * len(header))[: len(header)]
        body.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
    return (
        f"<table><thead><tr>{th}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _is_block_start(line, nxt):
    s = line.strip()
    if not s:
        return True
    if s.startswith("#") or s.startswith("```") or s.startswith(">"):
        return True
    if _HR_RE.match(s):
        return True
    if re.match(r"[-*+]\s+", s) or re.match(r"\d+\.\s+", s):
        return True
    if "|" in line and _SEP_RE.match(nxt):
        return True
    return False


# --------------------------------------------------------------------------
# Block parser (line-based)
# --------------------------------------------------------------------------
def md_to_html(md):
    lines = md.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    i, n = 0, len(lines)

    def flush_list(buf, ordered):
        if not buf:
            return
        tag = "ol" if ordered else "ul"
        out.append(f"<{tag}>")
        out.extend(f"<li>{_inline(item)}</li>" for item in buf)
        out.append(f"</{tag}>")

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # fenced code block
        if stripped.startswith("```"):
            i += 1
            code = []
            while i < n and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            out.append(
                f"<pre><code>{html.escape(chr(10).join(code), quote=False)}</code></pre>"
            )
            continue

        # blank line
        if not stripped:
            i += 1
            continue

        # horizontal rule
        if _HR_RE.match(stripped):
            out.append("<hr>")
            i += 1
            continue

        # heading
        m = re.match(r"(#{1,6})\s+(.*)", stripped)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2).strip())}</h{level}>")
            i += 1
            continue

        # pipe table (header line + separator line)
        if "|" in line and i + 1 < n and _SEP_RE.match(lines[i + 1]):
            header = _split_row(line)
            i += 2
            rows = []
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(_split_row(lines[i]))
                i += 1
            out.append(_render_table(header, rows))
            continue

        # blockquote
        if stripped.startswith(">"):
            quote = []
            while i < n and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            out.append(f"<blockquote>{_inline(' '.join(quote))}</blockquote>")
            continue

        # unordered list
        if re.match(r"[-*+]\s+", stripped):
            buf = []
            while i < n and re.match(r"\s*[-*+]\s+", lines[i]):
                buf.append(re.sub(r"\s*[-*+]\s+", "", lines[i], count=1))
                i += 1
            flush_list(buf, ordered=False)
            continue

        # ordered list
        if re.match(r"\d+\.\s+", stripped):
            buf = []
            while i < n and re.match(r"\s*\d+\.\s+", lines[i]):
                buf.append(re.sub(r"\s*\d+\.\s+", "", lines[i], count=1))
                i += 1
            flush_list(buf, ordered=True)
            continue

        # paragraph
        para = [line]
        i += 1
        while i < n and lines[i].strip() and not _is_block_start(
            lines[i], lines[i + 1] if i + 1 < n else ""
        ):
            para.append(lines[i])
            i += 1
        out.append(f"<p>{_inline(' '.join(l.strip() for l in para))}</p>")

    return "\n".join(out)


# --------------------------------------------------------------------------
# Page shell (dark theme, consistent with the SOC report suite)
# --------------------------------------------------------------------------
def render_page(body_html, title):
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.55}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px 22px 60px}}
.hd{{background:linear-gradient(135deg,#0b3d66,#155e8a,#0e7490);border-radius:14px;padding:26px 28px;margin-bottom:24px}}
.ttl{{font-size:30px;font-weight:800;letter-spacing:.3px}}
.sub{{margin-top:6px;font-size:15px;color:#cfe6f5;font-weight:600}}
.meta{{margin-top:10px;font-size:12.5px;color:#a9c6db}}
.content h1{{font-size:24px;border-bottom:2px solid #1f2c47;padding-bottom:8px;margin:28px 0 14px}}
.content h2{{font-size:20px;margin:26px 0 12px;color:#bfe0ff}}
.content h3{{font-size:17px;margin:22px 0 10px;color:#cfe6f5}}
.content h4{{font-size:15px;margin:18px 0 8px;color:#cfe6f5}}
.content p{{margin:10px 0}}
.content ul,.content ol{{margin:10px 0;padding-left:24px}}
.content li{{margin:5px 0}}
a{{color:#5ec5ff;text-decoration:none}}
a:hover{{text-decoration:underline}}
strong{{color:#fff}}
code{{background:#16203a;padding:2px 7px;border-radius:5px;color:#9fd7ff;font-size:13px}}
pre{{background:#0e1730;border:1px solid #1f2c47;border-radius:10px;padding:14px 16px;overflow:auto}}
pre code{{background:none;padding:0;color:#cfe6f5}}
blockquote{{border-left:4px solid #2a7fb8;background:#0e1730;margin:12px 0;padding:10px 16px;border-radius:0 10px 10px 0;color:#cfe6f5}}
hr{{border:none;border-top:1px solid #1f2c47;margin:24px 0}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:13px;margin:14px 0}}
th{{background:#16203a;text-align:left;padding:11px 12px;font-size:12px;color:#9fd7ff;border-bottom:1px solid #1f2c47}}
td{{padding:10px 12px;border-bottom:1px solid #16203a;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.ft{{margin-top:36px;text-align:center;font-size:12px;color:#6b7f99}}
</style></head>
<body><div class="wrap">
  <div class="hd">
    <div class="ttl">🛰️ Threat Pulse</div>
    <div class="sub">Broad-spectrum security scan · 8 domains · 14 queries</div>
    <div class="meta">Gerado em {ts}</div>
  </div>
  <div class="content">
{body_html}
  </div>
  <div class="ft">Threat Pulse · SOC Autônomo · 100% read-only</div>
</div></body></html>"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Render a Threat Pulse markdown report to themed, self-contained HTML."
    )
    ap.add_argument("markdown", help="path to the Threat Pulse .md report")
    ap.add_argument(
        "-o", "--output-dir", default=None,
        help="output directory (default: alongside the markdown file)",
    )
    ap.add_argument("--title", default=None, help="page title (default: first H1 in the markdown)")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.markdown):
        print(f"✗ markdown não encontrado: {args.markdown}", file=sys.stderr)
        return 1

    with open(args.markdown, "r", encoding="utf-8") as f:
        md = f.read()

    title = args.title
    if not title:
        m = re.search(r"^#\s+(.+)$", md, re.MULTILINE)
        title = m.group(1).strip() if m else TITLE_DEFAULT
    title = re.sub(r"[*`#]", "", title).strip() or TITLE_DEFAULT

    page = render_page(md_to_html(md), title)

    out_dir = args.output_dir or os.path.dirname(os.path.abspath(args.markdown))
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(args.markdown))[0]
    out_path = os.path.join(out_dir, stem + ".html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)

    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
