from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PHONE_PATTERN = r"^[0-9+()\-\s]{5,30}$"


class CustomerCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, pattern=PHONE_PATTERN)
    address: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)


class CustomerUpdate(BaseModel):

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, pattern=PHONE_PATTERN)
    address: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("full_name")
    @classmethod
    def name_not_null(cls, v):
        if v is None:
            raise ValueError("full_name cannot be null")
        return v


class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    full_name: str
    email: str | None
    phone: str | None
    address: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime


class CustomerList(BaseModel):
    items: list[CustomerOut]
    limit: int
    offset: int
