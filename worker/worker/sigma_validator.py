import re
from uuid import UUID

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from worker.sigma_condition import SigmaRuleError

_TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):")


def validate_sigma_yaml(content: str) -> None:
    """Parse one rule with pySigma while preserving legacy local rule metadata."""
    normalized = _normalize_legacy_metadata(content)
    try:
        collection = SigmaCollection.from_yaml(normalized)
    except SigmaError as exc:
        raise SigmaRuleError(f"pySigma validation failed: {exc}") from exc
    if len(collection.rules) != 1:
        raise SigmaRuleError("rule document must contain exactly one Sigma rule")


def _normalize_legacy_metadata(content: str) -> str:
    lines = content.splitlines(keepends=True)
    keys = {
        match.group(1)
        for line in lines
        if (match := _TOP_LEVEL_KEY.match(line)) is not None
    }
    normalized_lines = [line for line in lines if not _is_invalid_identifier(line)]
    prefix: list[str] = []
    if "title" not in keys:
        prefix.append("title: Untitled\n")
    if "logsource" not in keys:
        prefix.append("logsource:\n  product: adsiem\n")
    if lines and lines[0].strip() == "---":
        normalized = lines[0] + "".join(prefix) + "".join(normalized_lines[1:])
    else:
        normalized = "".join(prefix) + "".join(normalized_lines)
    return re.sub(r"\|nocase(?=\s*:|\|)", "", normalized)


def _is_invalid_identifier(line: str) -> bool:
    if not line.startswith("id:"):
        return False
    value = line[3:].split("#", 1)[0].strip().strip("'\"")
    try:
        UUID(value)
    except ValueError:
        return True
    return False
