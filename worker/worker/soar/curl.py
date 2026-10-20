"""Turn a pasted `curl` command into HTTP Request node params.

Only reads the command — nothing is executed. Unknown flags are reported so the
UI can tell the user what was ignored.
"""
from __future__ import annotations

import base64
import json
import shlex
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii"}
_NO_ARG_IGNORED = {"-s", "--silent", "-S", "--show-error", "-L", "--location", "-v", "--verbose",
                   "-i", "--include", "--compressed", "-f", "--fail", "-k", "--insecure", "-g", "--globoff"}
_ARG_IGNORED = {"-o", "--output", "-w", "--write-out", "--connect-timeout", "--retry", "-e", "--referer",
                "-x", "--proxy", "--cacert", "--cert", "--key"}


class CurlParseError(ValueError):
    pass


def _set_header(headers: dict, name: str, value: str) -> None:
    for k in list(headers):
        if k.lower() == name.lower():
            del headers[k]
    headers[name] = value


def parse_curl(command: str) -> dict:
    """Return {"params": {...}, "ignored": [flags]} for the HTTP Request node."""
    text = (command or "").replace("\\\r\n", " ").replace("\\\n", " ").strip()
    try:
        argv = shlex.split(text)
    except ValueError as exc:
        raise CurlParseError(f"cannot split command: {exc}") from None
    if not argv or argv[0] != "curl":
        raise CurlParseError("command must start with curl")

    method: str | None = None
    url: str | None = None
    headers: dict[str, str] = {}
    data: list[str] = []
    json_body: str | None = None
    urlencoded: list[str] = []
    get_mode = False
    timeout: float | None = None
    ignored: list[str] = []

    i = 1
    while i < len(argv):
        arg = argv[i]

        def value() -> str:
            nonlocal i
            if "=" in arg and arg.startswith("--"):
                return arg.split("=", 1)[1]
            i += 1
            if i >= len(argv):
                raise CurlParseError(f"{arg} needs a value")
            return argv[i]

        flag = arg.split("=", 1)[0] if arg.startswith("--") else arg
        if flag in ("-X", "--request"):
            method = value().upper()
        elif flag in ("-H", "--header"):
            raw = value()
            name, sep, val = raw.partition(":")
            if not sep:
                raise CurlParseError(f"bad header: {raw!r}")
            _set_header(headers, name.strip(), val.strip())
        elif flag in _DATA_FLAGS:
            v = value()
            if v.startswith("@"):
                raise CurlParseError("reading the body from a file (@file) is not supported")
            data.append(v)
        elif flag == "--data-urlencode":
            urlencoded.append(value())
        elif flag == "--json":
            json_body = value()
        elif flag in ("-u", "--user"):
            cred = value()
            _set_header(headers, "Authorization", "Basic " + base64.b64encode(cred.encode()).decode())
        elif flag in ("-A", "--user-agent"):
            _set_header(headers, "User-Agent", value())
        elif flag in ("-b", "--cookie"):
            _set_header(headers, "Cookie", value())
        elif flag in ("-m", "--max-time"):
            try:
                timeout = float(value())
            except ValueError:
                raise CurlParseError("--max-time needs a number") from None
        elif flag in ("-G", "--get"):
            get_mode = True
        elif flag == "--url":
            url = value()
        elif flag in ("-I", "--head"):
            method = "HEAD"
        elif flag in _NO_ARG_IGNORED:
            ignored.append(flag)
        elif flag in _ARG_IGNORED:
            value()
            ignored.append(flag)
        elif arg.startswith("-"):
            ignored.append(arg)
        elif url is None:
            url = arg
        else:
            raise CurlParseError(f"unexpected argument: {arg!r}")
        i += 1

    if not url:
        raise CurlParseError("no URL in command")
    if "://" not in url:
        url = "http://" + url

    split = urlsplit(url)
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    url = urlunsplit((split.scheme, split.netloc, split.path, "", ""))

    for item in urlencoded:
        name, sep, val = item.partition("=")
        data.append(urlencode({name: val}) if sep else urlencode({"": name})[1:])

    body_type, body = "none", None
    if json_body is not None:
        body_type, body = "json", json_body
        _set_header(headers, "Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
    elif data:
        joined = "&".join(data)
        if get_mode:
            query.update(dict(parse_qsl(joined, keep_blank_values=True)))
        else:
            ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
            if "json" in ctype.lower():
                body_type, body = "json", joined
            elif not ctype or "x-www-form-urlencoded" in ctype.lower():
                body_type, body = "form", dict(parse_qsl(joined, keep_blank_values=True))
            else:
                body_type, body = "text", joined

    if body_type == "json" and isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body_type = "text"

    if method is None:
        method = "POST" if body_type != "none" else "GET"

    params = {"method": method, "url": url, "query": query, "headers": headers,
              "body_type": body_type, "body": body}
    if timeout is not None:
        params["timeout"] = timeout
    return {"params": params, "ignored": ignored}
