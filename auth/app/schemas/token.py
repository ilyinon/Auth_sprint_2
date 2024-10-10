from uuid import UUID

from pydantic import Field
from schemas.base import OrjsonBaseModel


class TokenResponse(OrjsonBaseModel):
    user_id: UUID = Field(..., title="User ID")
    access_jti: UUID = Field(..., title="Access token JTI")
    refresh_jti: UUID = Field(..., title="Refresh token JTI")
    access_exp: int = Field(..., title="Access Token expiration")
    refresh_exp: int = Field(..., title="Refresh Token expiration")

    class Config:
        orm_mode = True
        from_attributes = True
