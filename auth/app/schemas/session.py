from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import Field
from schemas.base import OrjsonBaseModel


class SessionCreate(OrjsonBaseModel):
    user_id: UUID = Field(..., title="User ID")
    user_agent: Optional[str] = Field(None, title="User Agent")
    user_action: str = Field(..., title="User Action")


class SessionUpdate(OrjsonBaseModel):
    user_id: Optional[UUID] = Field(None, title="User ID")
    user_agent: Optional[str] = Field(None, title="User Agent")
    user_action: Optional[str] = Field(None, title="User Action")


class SessionResponse(SessionCreate):
    id: UUID = Field(..., title="Session ID")
    created_at: datetime = Field(..., title="Created At")

    class Config:
        orm_mode = True
        from_attributes = True
