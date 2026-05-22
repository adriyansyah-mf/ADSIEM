# worker/worker/decoder_engine.py
import re
import yaml
from dataclasses import dataclass, field
from typing import Any

@dataclass
class DecoderDef:
    name: str
    log_type: str
    pattern: re.Pattern
    fields_map: dict[str, str]
    static_fields: dict[str, str]
    priority: int

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
                fields_map = {}
                static_fields = {}
                for output_field, source in d.get("fields", {}).items():
                    pattern_obj = re.compile(d["pattern"])
                    if source in pattern_obj.groupindex:
                        fields_map[output_field] = source
                    else:
                        static_fields[output_field] = source
                decoders.append(DecoderDef(
                    name=d["name"],
                    log_type=d["log_type"],
                    pattern=re.compile(d["pattern"]),
                    fields_map=fields_map,
                    static_fields=static_fields,
                    priority=d.get("priority", 100),
                ))
            except Exception:
                continue
        self._decoders = sorted(decoders, key=lambda x: x.priority)

    def decode(self, log_type: str, raw_message: str) -> dict[str, Any]:
        for decoder in self._decoders:
            if decoder.log_type != log_type:
                continue
            match = re.search(decoder.pattern, raw_message)
            if not match:
                continue
            groups = match.groupdict()
            result: dict[str, Any] = {}
            for output_field, group_name in decoder.fields_map.items():
                result[output_field] = groups.get(group_name)
            result.update(decoder.static_fields)
            return result
        return {}
