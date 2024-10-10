from datetime import datetime
from uuid import uuid4

from models.base import Base
from models.mixin import IdMixin
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship


class Token(Base, IdMixin):
    __tablename__ = "tokens"

    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    access_jti = Column(UUID(as_uuid=True), default=uuid4)
    refresh_jti = Column(UUID(as_uuid=True), default=uuid4)

    access_exp = Column(Integer, nullable=True)
    refresh_exp = Column(Integer, nullable=True)

    created_at = Column(DateTime, default=datetime.now())

    user = relationship("User", back_populates="tokens", lazy="selectin")
