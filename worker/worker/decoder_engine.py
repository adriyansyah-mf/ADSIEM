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


@dataclass
class DecoderDef:
    name: str
    log_type: str
    decoder_type: str          # "regex" or "kv"
    pattern: re.Pattern | None # only used for regex
    fields_map: dict[str, str]
    static_fields: dict[str, str]
    priority: int
    match_filter: str | None = None  # optional substring required in message


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

                elif decoder_type == "kv":
                    # fields: { output_field: kv_key } — all are KV key references
                    fields_map = dict(d.get("fields", {}))
                    # static_fields: { output_field: literal_value }
                    static_fields = dict(d.get("static_fields", {}))
                    decoders.append(DecoderDef(
                        name=d["name"],
                        log_type=d["log_type"],
                        decoder_type="kv",
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

            elif decoder.decoder_type == "kv":
                kv = _parse_kv(raw_message)
                if not kv:
                    continue
                result = {}
                for output_field, kv_key in decoder.fields_map.items():
                    if kv_key in kv:
                        result[output_field] = kv[kv_key]
                result.update(decoder.static_fields)
                return normalize_web_fields(result), decoder.name

        return {}, None
