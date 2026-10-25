"""HTTP contracts reuse the workflow's alert and report models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.models.alert import Alert
from src.models.report import SOCReport


class AnalyseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts: list[Alert] = Field(min_length=1)

    @field_validator("alerts")
    @classmethod
    def require_unique_ids(cls, alerts: list[Alert]) -> list[Alert]:
        if len({alert.id for alert in alerts}) != len(alerts):
            raise ValueError("Alert IDs must be unique.")
        return alerts


class AnalyseResponse(BaseModel):
    reports: list[SOCReport]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
