from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SessionCreate(BaseModel):
    server_id: int
    source_ip: str


class SessionResponse(BaseModel):
    id: int
    user_id: int
    server_id: int
    source_ip: str
    started_at: datetime
    ended_at: datetime | None
    status: str

    model_config = ConfigDict(from_attributes=True)
