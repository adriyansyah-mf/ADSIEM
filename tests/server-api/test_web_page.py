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
    assert "\\" not in out and "url(http" not in out and "@import" not in out


@pytest.mark.parametrize("html", [
    '<style>a{background:urexpression(l(http://x.example/i.png)}</style>',
    '<style>@impexpression(ort "http://x.example/a.css";</style>',
    '<style>@im/**/port "http://x.example/a.css";</style>',  # comment is a token break: inert "@im port"
    '<style>a{background:image-sexpression(et("http://x.example/i.png" 1x)}</style>',
    '<p style="background:urexpression(l(http://x.example/i.png)">x</p>',
    '<p style="background:image-sexpression(et(\'http://x.example/i.png\' 1x)">x</p>',
])
def test_css_removals_cannot_splice_live_tokens(html):
    out = wp.sanitize(html)
    assert "url(http" not in out and "@import" not in out and "image-set" not in out


@pytest.mark.parametrize("html", [
    '<a href="da&#9;ta:text/html,x">x</a>',
    '<a href="d&#10;ata:text/html,x">x</a>',
    '<a href="&#1;data:text/html,x">x</a>',
    '<a href="java&#13;script:alert(1)">x</a>',
    '<img src="da&#9;ta:text/html,x">',
])
def test_control_characters_in_scheme_do_not_hide_it(html):
    out = wp.sanitize(html)
    assert "href=" not in out and "src=" not in out


def test_placeholders_only_survive_in_text_title_and_alt():
    out = wp.sanitize('<p title="{{domain}}">{{domain}}</p><img alt="{{domain}}">'
                      '<a href="{{reason}}" class="{{reason}}">x</a><p style="color:red;{{reason}}">y</p>'
                      '<style>a{color:{{reason}}}</style>')
    assert 'title="{{domain}}"' in out and "<p" in out and ">{{domain}}</p>" in out and 'alt="{{domain}}"' in out
    assert "{{reason}}" not in out


def test_rendered_values_cannot_become_urls_or_css():
    link = wp.render(wp.sanitize('<a href="{{reason}}">x</a>'), {"reason": "javascript:alert(1)"})
    assert "javascript:" not in link
    style = wp.render(wp.sanitize('<p style="color:red;{{reason}}">x</p>'),
                      {"reason": "background:url(http://x.example/i.png)"})
    assert "url(http" not in style


def test_inline_style_is_kept_when_harmless():
    assert 'style="color:red"' in wp.sanitize('<p style="color:red">x</p>')


@pytest.mark.parametrize("scheme", ["ms-msdt:/id", "search-ms:query=a", "file:///c:/x", "ftp://x.example/f"])
def test_scheme_revealed_by_placeholder_removal_is_dropped(scheme):
    out = wp.sanitize(f'<a href="{{{{x}}}}{scheme}">x</a>')
    assert "href=" not in out and scheme not in out


@pytest.mark.parametrize("href", ["https://example.org/a?b=c:d", "http://example.org", "/relative:path",
                                  "#anchor", "mailto:x@y.example", "page.html?u=a:b"])
def test_ordinary_hrefs_are_kept(href):
    assert f'href="{href}"' in wp.sanitize(f'<a href="{href}">x</a>')


def test_unclosed_url_is_neutralised():
    assert "url(http" not in wp.sanitize('<p style="background:url(http://x.example/i">x</p>')
    assert "url(http" not in wp.sanitize('<style>a{background:url(http://x.example/i</style>'
                                         '<style>)}</style>')
