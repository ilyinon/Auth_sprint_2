import logging
from functools import lru_cache
from typing import Optional
from uuid import UUID

from db.pg import get_session
from fastapi import Depends
from models.session import Session
from schemas.session import SessionCreate, SessionResponse, SessionUpdate
from services.database import BaseDb, PostgresqlEngine
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class SessionService:
    def __init__(self, db: BaseDb):
        self.db = db

    async def create_session(self, session_data: SessionCreate) -> Session:
        new_session = Session(**session_data.dict())
        return await self.db.create(new_session, Session)

    async def get_session(self, session_id: UUID) -> Optional[SessionResponse]:
        session = await self.db.get_by_id(session_id, Session)

        if session:
            return SessionResponse.from_orm(session)
        return None

    async def get_session_by_user_and_agent(
        self, user_id: str, user_agent: str
    ) -> Optional[SessionResponse]:
        sessions = await self.db.get_by_key("user_id", user_id, Session)

        if isinstance(sessions, Session):
            sessions = [sessions]

            for session in sessions:
                if session.user_agent == user_agent:
                    return SessionResponse.from_orm(session)
        return None

    async def get_sessions_by_user(self, user_id: str) -> list[SessionResponse]:
        sessions = await self.db.get_by_key("user_id", user_id, Session)

        if sessions:
            if isinstance(sessions, Session):
                sessions = [sessions]

            return [SessionResponse.from_orm(session) for session in sessions]
        return None

    async def update_session(
        self, session_id: UUID, session_data: SessionUpdate
    ) -> Optional[Session]:
        return await self.db.update(session_id, session_data.dict(), Session)

    async def delete_session(self, session_id: UUID) -> None:
        await self.db.delete(session_id, Session)


@lru_cache()
def get_session_service(
    db_session: AsyncSession = Depends(get_session),
) -> SessionService:

    db_engine = PostgresqlEngine(db_session)
    base_db = BaseDb(db_engine)
    return SessionService(base_db)
