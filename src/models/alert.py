from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Alert(BaseModel):
    id: str
    source: str
    timestamp: datetime
    alert_type: str
    description: str
    severity: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    file_hash: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @field_validator("id", "source", "alert_type", "description")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Required alert text must not be empty or whitespace.")
        return value
