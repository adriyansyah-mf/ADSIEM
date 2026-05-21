from __future__ import annotations
from pydantic import BaseModel, Field
from worker.ti.iocs import IOC


class IOCReputationScore(BaseModel):
    ioc_value: str
    ioc_type: str
    score: float = Field(..., ge=0.0, le=1.0)
    rationale: str = ""


class EnrichmentSummary(BaseModel):
    iocs: list[IOC] = Field(default_factory=list)
    provider_bullets: list[str] = Field(default_factory=list)
    reputation: list[IOCReputationScore] = Field(default_factory=list)
    overall_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    triage_hints: list[str] = Field(default_factory=list)
