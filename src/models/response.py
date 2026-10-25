from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class InvestigationAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1)
    rationale: str = Field(min_length=1)


class ContainmentAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    proposed_effect: str = Field(min_length=1)
    requires_human_approval: Literal[True] = True


class ResponsePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    investigate: list[InvestigationAction]
    containment: list[ContainmentAction]
    limitations: list[str]
    requires_human_review: Literal[True] = True
