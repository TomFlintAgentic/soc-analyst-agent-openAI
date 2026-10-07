from pydantic import BaseModel, Field


class SOCReport(BaseModel):
    incident_id: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: list[str]
    iocs: list[str]
    attack_techniques: list[str]
    recommended_actions: list[str]
    requires_human_review: bool = True
