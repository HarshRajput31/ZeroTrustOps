from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AccessRequestCreate(BaseModel):
    server_id: int
    reason: str = Field(min_length=5, max_length=500)
    requested_minutes: int = Field(
        default=60,
        ge=5,
        le=480,
    )


class AccessRequestResponse(BaseModel):
    id: int
    user_id: int
    server_id: int
    reason: str
    status: str
    risk_score: int | None
    requested_minutes: int
    created_at: datetime
    expires_at: datetime | None

    model_config = ConfigDict(from_attributes=True)
