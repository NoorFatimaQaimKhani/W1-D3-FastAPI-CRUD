from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.api.core.permissions import Role


class UserOut(BaseModel):

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: Role
    is_active: bool
    public_key_fingerprint: str | None = None
    created_at: datetime


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def at_least_one(self):
        if self.role is None and self.is_active is None:
            raise ValueError("Provide at least one of: role, is_active")
        return self


class PublicKeyRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")

    public_key_pem: str = Field(min_length=50, max_length=4096)
