from typing import Dict, Optional, List

from pydantic import ConfigDict, Field, TypeAdapter
from schemas.base import OrjsonBaseModel
from typing_extensions import TypedDict


class Credentials(OrjsonBaseModel):
    username: str = Field(title="Email")
    password: str = Field(title="Password")


class Token(OrjsonBaseModel):
    token: str


class RefreshToken(OrjsonBaseModel):
    refresh_token: str


class TwoTokens(RefreshToken):
    access_token: str


class UserLoginModel(OrjsonBaseModel):
    email: str = Field()
    password: str = Field()


class TokenPayload(OrjsonBaseModel):
    user_id: str
    email: Optional[str] = None
    roles: Optional[List[str]] = None
