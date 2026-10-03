from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SSHKeyCreate(BaseModel):
    name: str = Field(
        min_length=2,
        max_length=100,
    )
    public_key: str = Field(
        min_length=20,
        max_length=8192,
    )


class SSHKeyResponse(BaseModel):
    id: int
    user_id: int
    name: str
    public_key: str
    fingerprint: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
