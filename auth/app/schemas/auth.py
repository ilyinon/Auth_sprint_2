from typing import Dict

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


class UserData(TypedDict, total=False):

    email: str
    user_id: str
    roles: list


class Payload(OrjsonBaseModel):
    __pydantic_config__ = ConfigDict(extra="forbid")

    user: UserData


class TokenPayload(OrjsonBaseModel):
    email: str
    user_id: str
    roles: list
