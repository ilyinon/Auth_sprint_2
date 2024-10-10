import logging
from functools import lru_cache
from typing import Optional
from uuid import UUID

from db.pg import get_session
from fastapi import Depends
from fastapi.encoders import jsonable_encoder
from models.role import Role, UserRole
from models.user import User
from pydantic import EmailStr
from schemas.user import UserCreate, UserPatch, UserResponse, UserResponseLogin
from services.database import BaseDb, PostgresqlEngine
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class UserService:
    def __init__(self, db: BaseDb):
        self.db = db

    async def get_user_by_email(self, email: EmailStr) -> Optional[UserResponse]:
        logger.info(f"Checking if user with email {email} exists")
        user = await self.db.get_by_key("email", email, User)
        if user:
            return UserResponseLogin.from_orm(user)
        return None

    async def get_user_by_username(self, username: str) -> Optional[UserResponse]:
        logger.info(f"Checking if user with username {username} exists")
        user = await self.db.get_by_key("username", username, User)
        if user:
            return UserResponse.from_orm(user)
        return None

    async def create_user(self, user_create: UserCreate) -> UserResponse:
        user = User(**user_create.dict())
        logger.info(f"Creating a new user with data: {user_create}")
        new_user = await self.db.create(user, User)
        return UserResponse.from_orm(new_user)

    async def get_current_user(self, user_id: UUID) -> Optional[UserResponse]:
        user = await self.db.get_by_id(user_id, User)
        if user:
            return UserResponse.from_orm(user)
        return None

    async def update_user(
        self, user_id: UUID, user_patch: UserPatch
    ) -> Optional[UserResponse]:
        current_user = await self.db.get_by_id(user_id, User)

        if not current_user:
            raise ValueError("User not found")

        user_data = jsonable_encoder(user_patch, exclude_unset=True)

        updated_user = await self.db.update(user_id, user_data, User)
        if updated_user:
            return UserResponse.from_orm(updated_user)

    async def delete_user(self, user_id: UUID) -> None:
        await self.db.delete(user_id, User)

    async def add_role_to_user(self, user_id: UUID, role_id: UUID) -> None:
        user = await self.db.get_by_id(user_id, User)
        if not user:
            raise ValueError("User not found")

        role = await self.db.get_by_id(role_id, Role)
        if not role:
            raise ValueError("Role not found")

        user_role = UserRole(user_id=user.id, role_id=role.id)

        await self.db.create(user_role, UserRole)

        return f"Role {role_id} assigned succesfully to User {user_id}"

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> None:
        user = await self.db.get_by_id(user_id, User)
        if not user:
            raise ValueError("User not found")

        role = await self.db.get_by_id(role_id, Role)
        if not role:
            raise ValueError("Role not found")

        user_role = await self.db.get_by_key("user_id", user.id, UserRole)
        if not user_role or user_role.role_id != role.id:
            raise ValueError("UserRole association not found")

        await self.db.delete(user_role.id, UserRole)

        return f"Role {role_id} removed succesfully from User {user_id}"


@lru_cache()
def get_user_service(db_session: AsyncSession = Depends(get_session)) -> UserService:

    db_engine = PostgresqlEngine(db_session)
    base_db = BaseDb(db_engine)
    return UserService(base_db)
