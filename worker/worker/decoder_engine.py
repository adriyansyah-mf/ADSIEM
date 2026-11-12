# worker/worker/decoder_engine.py
import re
import yaml
from dataclasses import dataclass, field
from typing import Any

_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_KV_UNESCAPE_RE = re.compile(r'\\(["\\])')

# Web request fields are URL-decoded before rules see them: payloads arrive
# encoded (UNION%20SELECT, %27, %3Cscript, %252e%252e%252f), and rules are
# written against the decoded text. The raw path stays in url.original.
_WEB_URL_FIELDS = ("url.path", "url.query", "url.referrer")
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def url_decode(value: str, rounds: int = 3) -> str:
    """Percent-decode up to `rounds` times (double/triple encoding), '+' as a
    space in the query part only; NUL bytes stay visible as %00."""
    from urllib.parse import unquote, unquote_plus
    for _ in range(rounds):
        if not _PERCENT_RE.search(value) and "+" not in value.partition("?")[2]:
            break
        path, sep, query = value.partition("?")
        decoded = unquote(path, errors="replace") + sep + (unquote_plus(query, errors="replace") if sep else "")
        if decoded == value:
            break
        value = decoded
    return value.replace("\x00", "%00")


def normalize_web_fields(fields: dict[str, Any]) -> dict[str, Any]:
    for name in _WEB_URL_FIELDS:
        raw = fields.get(name)
        if isinstance(raw, str) and ("%" in raw or "+" in raw):
            decoded = url_decode(raw)
            if decoded != raw:
                if name == "url.path":
                    fields.setdefault("url.original", raw)
                fields[name] = decoded
    return fields

def _parse_kv(raw: str) -> dict[str, str]:
    """Extract key=value and key="value" pairs from a FortiGate-style log line.

    Inside quotes \\" is a quote and \\\\ a backslash (the Windows agent's
    escaping); any other backslash is literal, so C:\\Windows stays as is."""
    result = {}
    for key, val in _KV_RE.findall(raw):
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = _KV_UNESCAPE_RE.sub(r"\1", val[1:-1])
        elif val.endswith("'") and val.count("'") == 1:
            val = val[:-1]  # last field inside auditd's msg='...' wrapper: res=failed'
        result[key] = val
    return result


_CEF_HEADER_KEYS = ("cef_version", "device_vendor", "device_product", "device_version",
                    "signature_id", "name", "severity")
# an extension key starts after whitespace; a backslash is not a key character, so an
# escaped "a\=b" stays inside its value
_CEF_KEY_RE = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]-]+)=")
_CEF_EXT_UNESCAPE = {"=": "=", "\\": "\\", "n": "\n", "r": "\r"}


def _cef_unescape(value: str, table: dict[str, str]) -> str:
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in table:
            out.append(table[value[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_cef(raw: str) -> dict[str, str]:
    """ArcSight CEF ("CEF:0|vendor|product|version|sig|name|sev|ext") anywhere in
    the line (it often follows a syslog header). Header fields get the names in
    _CEF_HEADER_KEYS; extension keys keep their CEF names (src, dst, suser, ...)."""
    start = raw.find("CEF:")
    if start < 0:
        return {}
    text = raw[start + 4:]
    header, buf, i = [], [], 0
    while i < len(text) and len(header) < 7:
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in "|\\":
            buf.append(text[i + 1])
            i += 2
            continue
        if ch == "|":
            header.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if len(header) < 7:
        return {}
    result = dict(zip(_CEF_HEADER_KEYS, (h.strip() for h in header)))
    ext = text[i:]
    keys = list(_CEF_KEY_RE.finditer(ext))
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(ext)
        result[m.group(1)] = _cef_unescape(ext[m.end():end].strip(), _CEF_EXT_UNESCAPE)
    return result


_JSON = __import__("json").JSONDecoder()
_MISSING = object()


def _parse_json(raw: str) -> dict | None:
    """The JSON object in a line: from the first '{', so one forwarded with a
    syslog header ("Mmm dd host suricata[12]: {...}") parses too."""
    start = raw.find("{")
    if start < 0:
        return None
    try:
        obj, _ = _JSON.raw_decode(raw, start)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def _json_get(obj: Any, path: str) -> Any:
    """A dotted path into nested objects; a literal dotted key wins (Zeek writes
    flat keys like "id.orig_h"); numeric parts index lists ("queries.0.rrname")."""
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    head, _, rest = path.partition(".")
    if isinstance(obj, dict):
        nxt = obj.get(head, _MISSING)
    elif isinstance(obj, list) and head.isdigit() and int(head) < len(obj):
        nxt = obj[int(head)]
    else:
        return _MISSING
    if nxt is _MISSING or not rest:
        return nxt
    return _json_get(nxt, rest)


def _json_str(value: Any) -> str:
    """Field values are strings, like every other decoder type's."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return __import__("json").dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value)


def _json_flatten(obj: dict, prefix: str = "") -> dict[str, str]:
    """Every scalar under its dotted path ({"id": {"orig_h": x}} -> "id.orig_h"),
    lists as JSON text: the source's own field names, for Sigma rules written
    against them (SigmaHQ's zeek rules use query, id.orig_h, ...)."""
    out: dict[str, str] = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_json_flatten(value, name + "."))
        elif value is not None:
            out[name] = _json_str(value)
    return out


def _json_when(obj: dict, when: dict[str, Any]) -> bool:
    """Every condition holds: path == value, value "*" = the path exists, a list
    = any of its values."""
    for path, expected in when.items():
        value = _json_get(obj, path)
        if value is _MISSING or value is None:
            return False
        if expected == "*":
            continue
        options = expected if isinstance(expected, list) else [expected]
        if _json_str(value) not in {_json_str(o) for o in options}:
            return False
    return True


@dataclass
class DecoderDef:
    name: str
    log_type: str
    decoder_type: str          # "regex", "kv", "cef" or "json"
    pattern: re.Pattern | None # only used for regex
    fields_map: dict[str, str]
    static_fields: dict[str, str]
    priority: int
    match_filter: str | None = None  # optional substring required in message
    when: dict[str, Any] = field(default_factory=dict)  # json: conditions on the parsed object
    raw_fields: bool = False  # json: also keep the source's own field names


class DecoderEngine:
    def __init__(self):
        self._decoders: list[DecoderDef] = []

    def load_from_yaml_list(self, yaml_contents: list[str]) -> None:
        decoders = []
        for content in yaml_contents:
            try:
                d = yaml.safe_load(content)
                if not d.get("enabled", True):
                    continue

                decoder_type = d.get("type", "regex")
                fields_map: dict[str, str] = {}
                static_fields: dict[str, str] = {}

                if decoder_type == "regex":
                    pattern_obj = re.compile(d["pattern"])
                    for output_field, source in d.get("fields", {}).items():
                        if source in pattern_obj.groupindex:
                            fields_map[output_field] = source
                        else:
                            static_fields[output_field] = source
                    decoders.append(DecoderDef(
                        name=d["name"],
                        log_type=d["log_type"],
                        decoder_type="regex",
                        pattern=pattern_obj,
                        fields_map=fields_map,
                        static_fields=static_fields,
                        priority=d.get("priority", 100),
                        match_filter=d.get("match"),
                    ))

                elif decoder_type == "json":
                    # fields: { output_field: path | [path, fallback path, ...] }
                    decoders.append(DecoderDef(
                        name=d["name"],
                        log_type=d["log_type"],
                        decoder_type="json",
                        pattern=None,
                        fields_map=dict(d.get("fields", {})),
                        static_fields=dict(d.get("static_fields", {})),
                        priority=d.get("priority", 100),
                        match_filter=d.get("match"),
                        when=dict(d.get("when", {})),
                        raw_fields=bool(d.get("raw_fields", False)),
                    ))

                elif decoder_type in ("kv", "cef"):
                    # fields: { output_field: key } — all are KV / CEF key references
                    fields_map = dict(d.get("fields", {}))
                    # static_fields: { output_field: literal_value }
                    static_fields = dict(d.get("static_fields", {}))
                    decoders.append(DecoderDef(
                        name=d["name"],
                        log_type=d["log_type"],
                        decoder_type=decoder_type,
                        pattern=None,
                        fields_map=fields_map,
                        static_fields=static_fields,
                        priority=d.get("priority", 100),
                        match_filter=d.get("match"),
                    ))

            except Exception:
                continue
        self._decoders = sorted(decoders, key=lambda x: x.priority)

    def decode(self, log_type: str, raw_message: str) -> dict[str, Any]:
        return self.decode_named(log_type, raw_message)[0]

    def decode_named(self, log_type: str, raw_message: str) -> tuple[dict[str, Any], str | None]:
        """decode() plus the name of the decoder that matched (None if none did)."""
        parsed_json = None  # parsed once per line, shared by every json decoder tried
        for decoder in self._decoders:
            if decoder.log_type != log_type:
                continue
            if decoder.match_filter and decoder.match_filter not in raw_message:
                continue

            if decoder.decoder_type == "regex":
                match = re.search(decoder.pattern, raw_message)
                if not match:
                    continue
                groups = match.groupdict()
                result: dict[str, Any] = {}
                for output_field, group_name in decoder.fields_map.items():
                    result[output_field] = groups.get(group_name)
                result.update(decoder.static_fields)
                return normalize_web_fields(result), decoder.name

            elif decoder.decoder_type == "json":
                obj = parsed_json if parsed_json is not None else _parse_json(raw_message)
                parsed_json = obj if obj is not None else {}
                if not obj or not _json_when(obj, decoder.when):
                    continue
                result = _json_flatten(obj) if decoder.raw_fields else {}
                for output_field, paths in decoder.fields_map.items():
                    for path in (paths if isinstance(paths, list) else [paths]):
                        value = _json_get(obj, path)
                        if value is not _MISSING and value is not None:
                            result[output_field] = _json_str(value)
                            break
                result.update(decoder.static_fields)
                return normalize_web_fields(result), decoder.name

            elif decoder.decoder_type in ("kv", "cef"):
                kv = _parse_kv(raw_message) if decoder.decoder_type == "kv" else _parse_cef(raw_message)
                if not kv:
                    continue
                result = {}
                for output_field, kv_key in decoder.fields_map.items():
                    if kv_key in kv:
                        result[output_field] = kv[kv_key]
                result.update(decoder.static_fields)
                return normalize_web_fields(result), decoder.name

        return {}, None
