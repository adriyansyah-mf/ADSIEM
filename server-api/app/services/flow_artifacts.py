# server-api/app/services/flow_artifacts.py
"""Live-response artifacts: parse, validate, compile into agent requests, filter rows.

An artifact is YAML kept on the server (built-ins in app/artifacts/, custom ones
in the flow_artifacts table). Each source names an agent *plugin* that collects
rows, plus an optional Sigma `detection` block and `fields` projection that the
server applies to the rows the agent sends back. Agents only ever receive the
compiled plugin calls, so new artifacts need no agent update as long as the
plugins they use exist.

    name: Linux.Sys.Pslist
    parameters:
      - name: ProcessRegex
        default: "."
    sources:
      - name: Processes
        plugin: pslist
        detection:
          selection:
            Name|re: "{{ProcessRegex}}"
          condition: selection
        fields: [Pid, Name, Exe, CommandLine]
"""
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import yaml

from worker.sigma_engine import RuleError, compile_detection

ARTIFACT_DIR = Path(__file__).resolve().parent.parent / "artifacts"

# Plugins the agent implements (agent/internal/task/plugins.go).
PLUGINS = {
    "info", "pslist", "netstat", "users", "glob", "hash", "read_file",
    "persistence", "dmesg", "open_files", "yara",
    "memyara", "memrwx",  # process memory (agent/internal/task/memory.go)
    "eventlog", "services", "programs",  # Windows agents only
}
# Plugins no saved artifact may use: exec runs an operator-approved command
# (investigator.run_command) and only appears in the flows that runs.
INTERNAL_PLUGINS = {"exec"}

# Display order for each plugin's columns. Rows are stored as JSONB, which does
# not keep key order, so results are re-ordered by this (or a source's `fields`).
PLUGIN_COLUMNS = {
    "info": ["Hostname", "OSRelease", "Kernel", "Arch", "OS", "UptimeSec"],
    "pslist": ["Pid", "Ppid", "Name", "Username", "Uid", "Exe", "CommandLine", "State", "RssKb", "Threads"],
    "netstat": ["Proto", "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort", "State", "Pid", "Process", "Uid", "Inode"],
    "users": ["Username", "Uid", "Gid", "Description", "Home", "Shell"],
    "glob": ["Path", "Name", "Size", "Mode", "Uid", "ModTime", "IsDir"],
    "hash": ["Path", "Size", "MD5", "SHA1", "SHA256"],
    "read_file": ["Path", "Size", "Truncated", "SHA256", "Encoding", "Data"],
    "persistence": ["Category", "Path", "ModTime", "Content"],
    "dmesg": ["Line"],
    "open_files": ["Pid", "Process", "Fd", "Path"],
    "yara": ["Rule", "File", "Size", "Strings"],
    "memyara": ["Pid", "Process", "Rule", "Namespace", "Address", "RegionStart", "RegionPerms",
                "RegionKind", "RegionPath", "Strings"],
    "memrwx": ["Pid", "Process", "Start", "End", "Size", "Perms", "Kind", "Path"],
    # eventlog rows also carry each event's EventData fields (after these)
    "eventlog": ["TimeCreated", "EventID", "Channel", "Provider", "Computer", "RecordID", "Level"],
    "services": ["Name", "DisplayName", "State", "StartMode", "Account", "Pid", "PathName", "Description"],
    "programs": ["Name", "Version", "Publisher", "InstallDate", "InstallLocation", "Scope", "UninstallString"],
    "exec": ["Stream", "Line", "Text", "ExitCode"],
}

DEFAULT_TIMEOUT = 600
MAX_TIMEOUT = 3600
DEFAULT_MAX_ROWS = 10_000
MAX_MAX_ROWS = 100_000

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{2,99}$")
_SOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_PARAM_TYPES = ("string", "int", "bool")


class ArtifactError(ValueError):
    """Artifact YAML or flow parameters are invalid."""


@dataclass
class Parameter:
    name: str
    type: str = "string"
    default: Any = ""
    description: str = ""


@dataclass
class Source:
    name: str
    plugin: str
    args: dict = field(default_factory=dict)
    detection: dict | None = None
    fields: list[str] | None = None


@dataclass
class ArtifactDef:
    name: str
    description: str
    parameters: list[Parameter]
    sources: list[Source]
    timeout: int
    max_rows: int
    content: str
    builtin: bool = False

    def summary(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "builtin": self.builtin,
            "parameters": [p.__dict__ for p in self.parameters],
            "sources": [{"name": s.name, "plugin": s.plugin, "filtered": s.detection is not None}
                        for s in self.sources],
            "timeout": self.timeout,
            "max_rows": self.max_rows,
            "content": self.content,
        }


# ─── Parameters ──────────────────────────────────────────────────

def _coerce(param: Parameter, value: Any) -> Any:
    try:
        if param.type == "int":
            if isinstance(value, bool):
                raise ValueError
            return int(value)
        if param.type == "bool":
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in ("true", "1", "yes", "y"):
                return True
            if text in ("false", "0", "no", "n", ""):
                return False
            raise ValueError
        return "" if value is None else str(value)
    except (TypeError, ValueError):
        raise ArtifactError(f"parameter '{param.name}' must be {param.type}, got {value!r}") from None


def resolve_params(art: ArtifactDef, given: dict | None) -> dict:
    given = given or {}
    known = {p.name for p in art.parameters}
    unknown = sorted(set(given) - known)
    if unknown:
        raise ArtifactError(f"unknown parameter(s) {unknown} for {art.name}")
    return {p.name: _coerce(p, given.get(p.name, p.default)) for p in art.parameters}


def substitute(obj: Any, params: dict) -> Any:
    """Replace {{Param}} placeholders. A string that is exactly one placeholder
    takes the parameter's typed value; otherwise the value is interpolated."""
    if isinstance(obj, dict):
        return {k: substitute(v, params) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute(v, params) for v in obj]
    if not isinstance(obj, str):
        return obj
    whole = _PLACEHOLDER_RE.fullmatch(obj.strip())
    if whole and whole.group(1) in params:
        return params[whole.group(1)]

    def repl(m: re.Match) -> str:
        if m.group(1) not in params:
            raise ArtifactError(f"placeholder '{{{{{m.group(1)}}}}}' has no matching parameter")
        value = params[m.group(1)]
        return ("true" if value else "false") if isinstance(value, bool) else str(value)
    return _PLACEHOLDER_RE.sub(repl, obj)


# ─── Parsing ─────────────────────────────────────────────────────

def _bounded_int(raw: Any, default: int, maximum: int, what: str) -> int:
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ArtifactError(f"{what} must be an integer") from None
    if not 1 <= value <= maximum:
        raise ArtifactError(f"{what} must be between 1 and {maximum}")
    return value


def parse_artifact(content: str, builtin: bool = False, internal: bool = False) -> ArtifactDef:
    """internal=True also accepts INTERNAL_PLUGINS — only for re-reading the
    snapshot of a flow the server built itself, never for saved artifacts."""
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ArtifactError(f"invalid YAML: {exc}") from None
    if not isinstance(doc, dict):
        raise ArtifactError("artifact must be a YAML mapping")

    name = doc.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ArtifactError("name must be 3-100 chars of letters, digits, '.' or '_' (e.g. Custom.Linux.Thing)")
    art_type = doc.get("type", "CLIENT")
    if art_type != "CLIENT":
        raise ArtifactError("only type: CLIENT artifacts are supported")

    params: list[Parameter] = []
    for raw in doc.get("parameters") or []:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            raise ArtifactError("each parameter needs a name")
        ptype = raw.get("type", "string")
        if ptype not in _PARAM_TYPES:
            raise ArtifactError(f"parameter '{raw['name']}' type must be one of {_PARAM_TYPES}")
        p = Parameter(name=raw["name"], type=ptype, default=raw.get("default", ""),
                      description=str(raw.get("description", "")))
        p.default = _coerce(p, p.default)
        params.append(p)
    if len({p.name for p in params}) != len(params):
        raise ArtifactError("parameter names must be unique")

    raw_sources = doc.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ArtifactError("artifact needs at least one source")
    sources: list[Source] = []
    for raw in raw_sources:
        if not isinstance(raw, dict):
            raise ArtifactError("each source must be a mapping")
        sname = raw.get("name")
        if not isinstance(sname, str) or not _SOURCE_RE.match(sname):
            raise ArtifactError("each source needs a name of letters, digits or '_'")
        plugin = raw.get("plugin")
        if plugin not in PLUGINS and not (internal and plugin in INTERNAL_PLUGINS):
            raise ArtifactError(f"source '{sname}': unknown plugin {plugin!r} (available: {sorted(PLUGINS)})")
        args = raw.get("args") or {}
        if not isinstance(args, dict):
            raise ArtifactError(f"source '{sname}': args must be a mapping")
        fields = raw.get("fields")
        if fields is not None and (not isinstance(fields, list) or not all(isinstance(f, str) for f in fields)):
            raise ArtifactError(f"source '{sname}': fields must be a list of column names")
        sources.append(Source(name=sname, plugin=plugin, args=args,
                              detection=raw.get("detection"), fields=fields))
    if len({s.name for s in sources}) != len(sources):
        raise ArtifactError("source names must be unique")

    resources = doc.get("resources") or {}
    art = ArtifactDef(
        name=name,
        description=str(doc.get("description", "")).strip(),
        parameters=params,
        sources=sources,
        timeout=_bounded_int(resources.get("timeout"), DEFAULT_TIMEOUT, MAX_TIMEOUT, "resources.timeout"),
        max_rows=_bounded_int(resources.get("max_rows"), DEFAULT_MAX_ROWS, MAX_MAX_ROWS, "resources.max_rows"),
        content=content,
        builtin=builtin,
    )
    # Compile once with the defaults so syntax errors surface on save, not on first run.
    defaults = resolve_params(art, {})
    for src in sources:
        substitute(src.args, defaults)
        _compile_source_filter(src, defaults)
    return art


@lru_cache(maxsize=1)
def builtin_artifacts() -> dict[str, ArtifactDef]:
    arts = {}
    for path in sorted(ARTIFACT_DIR.glob("*.yaml")):
        art = parse_artifact(path.read_text(), builtin=True)
        arts[art.name] = art
    return arts


# ─── Compilation & row filtering ─────────────────────────────────

def compile_request(art: ArtifactDef, flow_id: str, params: dict, timeout: int, max_rows: int,
                    yara_rules: list[dict] | None = None) -> dict:
    """The exact request the agent receives: plugin calls only, no detection logic."""
    sources = []
    for src in art.sources:
        args = substitute(src.args, params)
        if src.plugin in ("yara", "memyara") and "rules" not in args:
            args["rules"] = yara_rules or []
        sources.append({"name": src.name, "plugin": src.plugin, "args": args})
    return {"id": flow_id, "artifact": art.name, "timeout": timeout, "max_rows": max_rows, "sources": sources}


def _compile_source_filter(src: Source, params: dict) -> Callable[[dict], bool] | None:
    if src.detection is None:
        return None
    try:
        return compile_detection(substitute(src.detection, params))
    except RuleError as exc:
        raise ArtifactError(f"source '{src.name}': detection: {exc}") from None


@dataclass
class RowFilter:
    matchers: dict[str, Callable[[dict], bool] | None]
    fields: dict[str, list[str] | None]

    def apply(self, source: str, rows: list[dict]) -> list[dict]:
        if source not in self.matchers:
            raise ArtifactError(f"unknown source '{source}'")
        match, cols = self.matchers[source], self.fields[source]
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if match is not None and not match(row):
                continue
            out.append({c: row.get(c) for c in cols} if cols else row)
        return out


def column_order(content: str, source: str, rows: list[dict]) -> list[str]:
    """Columns for display: the source's `fields`, else the plugin's natural
    order, then any remaining keys alphabetically."""
    preferred: list[str] = []
    try:
        src = next((s for s in parse_artifact(content, internal=True).sources if s.name == source), None)
        if src:
            preferred = src.fields or PLUGIN_COLUMNS.get(src.plugin, [])
    except ArtifactError:
        pass
    present = {key for row in rows for key in row}
    return [c for c in preferred if c in present] + sorted(present - set(preferred))


def build_row_filter(content: str, params: dict) -> RowFilter:
    art = parse_artifact(content, internal=True)  # reads flow snapshots, incl. command flows
    return RowFilter(
        matchers={s.name: _compile_source_filter(s, params) for s in art.sources},
        fields={s.name: s.fields for s in art.sources},
    )
