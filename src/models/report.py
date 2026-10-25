from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SOCReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: list[str]
    uncertainties: list[str] = Field(default_factory=list)
    iocs: list[str]
    attack_techniques: list[str]
    recommended_actions: list[str]
    requires_human_review: bool = True
    containment_status: Literal["not_performed"] = "not_performed"
