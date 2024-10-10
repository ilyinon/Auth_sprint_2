from enum import Enum
from uuid import UUID

from pydantic import Field
from schemas.base import OrjsonBaseModel


class AllowRole(Enum):
    admin = "admin"
    editor = "editor"
    subscriber = "subscriber"


class RoleBase(OrjsonBaseModel):
    name: str = Field(..., title="Description")


class RoleBaseUUID(OrjsonBaseModel):
    id: UUID = Field(..., title="Id")


class RoleResponse(RoleBaseUUID, RoleBase):
    pass

    class Config:
        orm_mode = True
        from_attributes = True
