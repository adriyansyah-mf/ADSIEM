# tests/server-api/test_web_page.py
"""Block page HTML (services/web_page.py): no script survives saving; variables
are escaped at render."""
import pytest

from app.services import web_page as wp


def test_script_tags_and_handlers_are_removed():
    out = wp.sanitize('<p>hi</p><script>alert(1)</script><img src="data:image/png;base64,AA" onerror="x()">')
    assert "<p>hi</p>" in out and "<script" not in out and "onerror" not in out
    assert 'src="data:image/png;base64,AA"' in out


@pytest.mark.parametrize("html,forbidden", [
    ('<a href="javascript:alert(1)">x</a>', "javascript"),
    ('<a href="data:text/html,x">x</a>', "data:"),
    ('<img src="https://tracker.example/p.gif">', "tracker.example"),
    ('<iframe src="https://x.example"></iframe>', "iframe"),
    ('<object data="x"></object>', "object"),
    ('<form action="https://x.example"><input></form>', "form"),
])
def test_dangerous_markup_is_dropped(html, forbidden):
    assert forbidden not in wp.sanitize(html)


def test_style_blocks_are_kept_but_cleaned():
    out = wp.sanitize('<style>body{color:red} @import url(http://x.example/a.css); '
                      '.a{background:url(http://x.example/i.png)}</style><p>x</p>')
    assert out.startswith("<style>") and "color:red" in out
    assert "@import" not in out and "x.example" not in out and "<p>x</p>" in out


def test_style_cannot_break_out_into_script():
    out = wp.sanitize('<style>a{content:"</style><script>alert(1)</script>"}</style>')
    assert "<script" not in out


def test_variables_survive_sanitising():
    assert "{{domain}}" in wp.sanitize("<p>{{domain}}</p>")
    default = wp.sanitize(wp.DEFAULT_PAGE_HTML)
    assert "{{domain}}" in default and "<main>" in default


def test_oversized_page_is_rejected():
    with pytest.raises(wp.PageError):
        wp.sanitize("<p>" + "a" * (wp.MAX_PAGE_BYTES + 1) + "</p>")


def test_render_escapes_values_and_keeps_unknown_placeholders():
    assert wp.render("<p>{{ domain }}</p>{{other}}", {"domain": "<b>x</b>"}) == "<p>&lt;b&gt;x&lt;/b&gt;</p>{{other}}"


def test_document_wraps_a_full_page():
    doc = wp.document("<p>{{domain}}</p>", wp.SAMPLE)
    assert doc.startswith("<!doctype html>") and wp.SAMPLE["domain"] in doc and '<meta charset="utf-8">' in doc


@pytest.mark.parametrize("html", [
    '<p style="background:url(http://x.example/i.png)">x</p>',
    '<p style="background:url(javascript:alert(1))">x</p>',
    '<p style="width:expression(alert(1))">x</p>',
    '<p style="background:image-set(\'http://x.example/i.png\' 1x)">x</p>',
    '<style>@im/**/port "http://x.example/a.css";</style>',
    '<style>a{background:image-set("http://x.example/i.png" 1x)}</style>',
])
def test_css_bypasses_are_neutralised(html):
    out = wp.sanitize(html)
    assert "x.example" not in out and "javascript" not in out and "expression" not in out


@pytest.mark.parametrize("html", [
    '<style>a{background:u\\72l(http://x.example/i.png)}</style>',
    '<style>@\\69mport "http://x.example/a.css";</style>',
    '<p style="background:u\\72l(http://x.example/i.png)">x</p>',
])
def test_css_escapes_are_removed(html):
    # an escape could spell url( or @import for the browser; without the
    # backslash the leftover text is an inert unknown function / at-rule
    out = wp.sanitize(html)
    assert "\\" not in out


def test_inline_style_is_kept_when_harmless():
    assert 'style="color:red"' in wp.sanitize('<p style="color:red">x</p>')
