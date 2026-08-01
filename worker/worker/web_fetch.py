# worker/worker/web_fetch.py
"""Fetch and read the full text of a web page for the AI analyst — not just a
search snippet. Runs unattended on every alert, so a URL sourced from search
results (or, indirectly, from log/alert content) must never be able to reach
an internal service: everything here is scoped to public IPs only (SSRF
guard), with a tight timeout, redirect cap, and response size cap.
"""
import asyncio
import html
import ipaddress
import re
import socket

import httpx
import structlog

log = structlog.get_logger()

_TIMEOUT = 10.0
_MAX_REDIRECTS = 3
_MAX_BYTES = 300_000
_UA = "ADSIEM-AI-Analyst/1.0 (+threat-intel-research)"

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"[ \t]+")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


async def _resolves_to_public_ip(host: str) -> bool:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
    return True


def _html_to_text(raw: str) -> str:
    text = _SCRIPT_STYLE_RE.sub(" ", raw)
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    text = _SPACE_RE.sub(" ", text)
    lines = [ln.strip() for ln in text.splitlines()]
    text = "\n".join(ln for ln in lines if ln)
    return _BLANK_LINES_RE.sub("\n\n", text).strip()


async def fetch_page_text(url: str, max_chars: int = 1500) -> str | None:
    """Best-effort: return the page's plain-text content, or None if it can't
    be fetched safely (private target, wrong content type, too many hops...)."""
    current = url
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
        for _ in range(_MAX_REDIRECTS + 1):
            try:
                u = httpx.URL(current)
            except Exception:
                return None
            if u.scheme not in ("http", "https") or not u.host:
                return None
            if not await _resolves_to_public_ip(u.host):
                log.warning("web_fetch_blocked_private_target", host=u.host)
                return None
            try:
                resp = await client.get(current, headers={"User-Agent": _UA})
            except Exception as exc:
                log.warning("web_fetch_failed", url=current, error=str(exc))
                return None
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return None
                current = str(u.join(location))
                continue
            if resp.status_code != 200:
                return None
            ctype = resp.headers.get("content-type", "")
            if "text/html" not in ctype and "text/plain" not in ctype:
                return None
            body = resp.content[:_MAX_BYTES]
            try:
                text = body.decode(resp.encoding or "utf-8", errors="ignore")
            except (LookupError, TypeError):
                text = body.decode("utf-8", errors="ignore")
            return _html_to_text(text)[:max_chars] or None
    return None
