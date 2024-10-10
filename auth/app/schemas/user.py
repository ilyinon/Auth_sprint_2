from typing import Optional
from uuid import UUID

from pydantic import EmailStr, Field
from schemas.base import OrjsonBaseModel


class UserBase(OrjsonBaseModel):
    email: EmailStr
    username: str = Field(title="Username")
    full_name: str = Field(title="Full Name")


class UserLoginModel(OrjsonBaseModel):
    email: str = Field()
    password: str = Field()


class UserCreate(UserBase):
    password: str = Field(title="Password")


class UserResponse(UserBase):
    id: UUID

    class Config:
        orm_mode = True
        from_attributes = True


class UserResponseLogin(UserBase):
    hashed_password: str = Field()
    id: UUID

    class Config:
        orm_mode = True
        from_attributes = True


class UserPatch(OrjsonBaseModel):
    email: Optional[EmailStr] = Field(None, title="Email")
    full_name: Optional[str] = Field(None, title="Full Name")
    password: Optional[str] = Field(None, title="Password")
    username: Optional[str] = Field(None, title="Username")
