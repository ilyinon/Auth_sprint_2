from functools import lru_cache
from typing import List, Optional
from uuid import UUID

from db.pg import get_session
from fastapi import Depends
from models.role import Role
from schemas.role import RoleBase, RoleResponse
from services.database import BaseDb, PostgresqlEngine
from sqlalchemy.ext.asyncio import AsyncSession


class RoleService:
    def __init__(self, db: BaseDb):
        self.db = db

    async def list_roles(self) -> List[RoleResponse]:
        roles = await self.db.list_all(Role)
        return [RoleResponse.from_orm(role) for role in roles]

    async def create_role(self, role_data: RoleBase) -> RoleResponse:
        new_role = Role(**role_data.dict())
        created_role = await self.db.create(new_role, Role)
        return RoleResponse.from_orm(created_role)

    async def get_role_by_id(self, role_id: UUID) -> Optional[RoleResponse]:
        role = await self.db.get_by_id(role_id, Role)
        if role:
            return RoleResponse.from_orm(role)
        return None

    async def delete_role(self, role_id: UUID) -> None:
        await self.db.delete(role_id, Role)

    async def update_role(
        self, role_id: UUID, role_data: RoleBase
    ) -> Optional[RoleResponse]:
        updated_role = await self.db.update(role_id, role_data, Role)
        if updated_role:
            return RoleResponse.from_orm(updated_role)
        return None


@lru_cache()
def get_role_service(db_session: AsyncSession = Depends(get_session)) -> RoleService:

    db_engine = PostgresqlEngine(db_session)
    base_db = BaseDb(db_engine)
    return RoleService(base_db)
