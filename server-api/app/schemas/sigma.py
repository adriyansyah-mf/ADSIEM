from pydantic import BaseModel, Field, JsonValue


class SigmaHuntRequest(BaseModel):
    content: str
    size: int = Field(default=100, ge=1, le=500)
    search_after: list[JsonValue] | None = None


class SigmaHuntResponse(BaseModel):
    lucene_query: str
    matches: list[dict[str, JsonValue]]
    total: int
    next_cursor: list[JsonValue] | None = None


class SigmaImportRequest(BaseModel):
    content: str = Field(min_length=1)


class SigmaImportResponse(BaseModel):
    imported: list[dict[str, JsonValue]]


class SigmaRepositoryImportRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class SigmaQualityResponse(BaseModel):
    rule_id: str
    score: int
    checks: dict[str, bool]
    recommendation: str


class SigmaRevisionOut(BaseModel):
    id: str
    version: int
    content: str
    created_by: str | None
    created_at: str


class SigmaDiffResponse(BaseModel):
    rule_id: str
    from_version: int
    to_version: int
    diff: str
