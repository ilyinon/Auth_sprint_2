from models.base import Base
from models.mixin import IdMixin, TimestampMixin
from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship


class Session(Base, IdMixin, TimestampMixin):
    __tablename__ = "sessions"

    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    user_agent = Column(String, nullable=True)
    user_action = Column(String, nullable=False)  # login, logout, refresh

    user = relationship("User", back_populates="sessions", lazy="selectin")
