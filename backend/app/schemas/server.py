from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class ServerCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: IPvAnyAddress
    ssh_port: int = Field(default=22, ge=1, le=65535)
    environment: str = Field(default="lab", min_length=1, max_length=50)


class ServerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    ip_address: IPvAnyAddress | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    environment: str | None = Field(default=None, min_length=1, max_length=50)
    is_active: bool | None = None


class ServerResponse(BaseModel):
    id: int
    name: str
    hostname: str
    ip_address: str
    ssh_port: int
    environment: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
