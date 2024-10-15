from models.base import ModelBase
from models.mixin import IdMixin, TimestampMixin
from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from models.base import ModelBase
from sqlalchemy import Column, DateTime
from sqlalchemy.sql import func
from uuid import uuid4


class Session(ModelBase, TimestampMixin):
    __tablename__ = "sessions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)

    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    user_agent = Column(String, nullable=True)
    user_action = Column(String, nullable=False)  # login, logout, refresh

    user = relationship("User", back_populates="sessions", lazy="selectin")
    session_date = Column(DateTime, default=func.now(), nullable=False)
