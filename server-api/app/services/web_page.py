# server-api/app/services/web_page.py
"""The Web Protection block page. Saved HTML is sanitised here (nh3 for markup;
<style> blocks are cleaned separately because nh3 drops them). Agents render it
like render()/document() below and serve it with a strict CSP (stage B2)."""
from __future__ import annotations

import html as _html
import re

import nh3

MAX_PAGE_BYTES = 256 * 1024
VARIABLES = ("domain", "reason", "source", "time", "hostname", "contact")
SAMPLE = {"domain": "malicious.example", "reason": "Listed by URLhaus as malware distribution",
          "source": "urlhaus", "time": "2026-11-07 10:00 UTC", "hostname": "WS-0142",
          "contact": "the security team"}

DEFAULT_PAGE_HTML = """<style>
body{margin:0;font-family:system-ui,sans-serif;background:#0b1220;color:#e5e7eb;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:560px;padding:32px}
h1{font-size:24px;margin:0 0 12px}
p{line-height:1.5;color:#cbd5e1}
code{background:#1f2937;padding:2px 6px;border-radius:4px}
small{color:#94a3b8}
</style>
<main>
<h1>This site is blocked</h1>
<p>Access to <code>{{domain}}</code> was blocked by your organisation's security policy.</p>
<p>Reason: {{reason}}</p>
<p><small>Source: {{source}} · Host: {{hostname}} · {{time}}</small></p>
<p>If you need this site for your work, contact {{contact}}.</p>
</main>"""

_STYLE = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.I | re.S)
_IMPORT = re.compile(r"@import[^;]*;?", re.I)
_CSS_URL = re.compile(r"url\(\s*(?!['\"]?data:image/)[^)]*\)", re.I)
_COMMENT = re.compile(r"/\*.*?(?:\*/|$)", re.S)
_IMAGE_SET = re.compile(r"(?:-webkit-)?image-set\s*\([^)]*\)?", re.I)
_PLACEHOLDER = re.compile(r"\{\{.*?\}\}", re.S)
_EXPRESSION = re.compile(r"expression\s*\(", re.I)
_VAR = re.compile(r"\{\{\s*(" + "|".join(VARIABLES) + r")\s*\}\}")
_TAGS = set(nh3.ALLOWED_TAGS) | {"main", "section", "header", "footer", "article", "span", "div", "small", "img"}
_ATTRIBUTES = {"*": {"class", "id", "style", "title", "lang", "dir"}, "a": {"href", "title"},
               "img": {"src", "alt", "width", "height"}}


class PageError(ValueError):
    """Why a block page cannot be saved; shown to the analyst."""


def _clean_css_once(css: str) -> str:
    # Every removal leaves a space so the text around it cannot splice into a
    # live token (urexpression(l( -> url(). Comments and backslash escapes could
    # spell "@import", "url(" or "expression(" (u\72l(, @\69mport), so go too.
    css = _PLACEHOLDER.sub(" ", css)
    css = _COMMENT.sub(" ", css).replace("\\", " ").replace("<", " ")
    css = _IMPORT.sub(" ", css)
    css = _CSS_URL.sub("none", css)
    css = _IMAGE_SET.sub(" ", css)
    return _EXPRESSION.sub(" ", css).strip()


def _clean_css(css: str) -> str:
    """Clean until stable: a removal may expose a new pattern."""
    for _ in range(10):
        cleaned = _clean_css_once(css)
        if cleaned == css:
            return css
        css = cleaned
    return ""


def _attribute_filter(tag: str, attr: str, value: str) -> str | None:
    if attr == "style":  # inline styles get the same cleaning as <style> blocks
        return _clean_css(value) or None
    if attr not in ("title", "alt"):  # a rendered value must not reach a URL/class/id
        value = _PLACEHOLDER.sub("", value)
    normalized = re.sub(r"[\x00-\x20]", "", value).lower()
    if normalized.startswith(("javascript:", "vbscript:")):
        return None
    if tag == "img" and attr == "src":
        return value if normalized.startswith("data:image/") else None
    if attr == "href" and normalized.startswith("data:"):
        return None
    return value


def sanitize(page_html: str) -> str:
    if len(page_html.encode()) > MAX_PAGE_BYTES:
        raise PageError("The block page is larger than 256 KB")
    css = "\n".join(c for c in (_clean_css(m) for m in _STYLE.findall(page_html)) if c)
    body = nh3.clean(_STYLE.sub("", page_html), tags=_TAGS, attributes=_ATTRIBUTES,
                     url_schemes={"https", "http", "mailto", "data"}, attribute_filter=_attribute_filter,
                     link_rel="noopener noreferrer")
    return (f"<style>\n{css}\n</style>\n" if css else "") + body


def render(page_html: str, values: dict) -> str:
    return _VAR.sub(lambda m: _html.escape(str(values.get(m.group(1), "")), quote=True), page_html)


def document(page_html: str, values: dict) -> str:
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Site blocked</title></head><body>{render(page_html, values)}</body></html>")
