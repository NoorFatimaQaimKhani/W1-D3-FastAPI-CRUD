from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, UUID4, model_validator

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
    current_password: str = Field(min_length=1, max_length=128)
    rotation_challenge_id: UUID4 | None = None
    rotation_signature: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def rotation_proof_is_complete(self):
        proof_fields = (self.rotation_challenge_id, self.rotation_signature)
        if any(proof_fields) and not all(proof_fields):
            raise ValueError("Provide both rotation_challenge_id and rotation_signature")
        return self


class PublicKeyRotationChallenge(BaseModel):
    challenge_id: UUID4
    challenge: str
