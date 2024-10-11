from models.base import ModelBase
from models.mixin import IdMixin, TimestampMixin
from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship


class Role(ModelBase, TimestampMixin, IdMixin):
    __tablename__ = "roles"

    name = Column(String, unique=True, nullable=False)
    users = relationship("UserRole", back_populates="role", lazy="selectin")


class UserRole(IdMixin, TimestampMixin, ModelBase):
    __tablename__ = "user_roles"

    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id = Column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )

    role = relationship("Role", back_populates="users", lazy="selectin")
    user = relationship("User", back_populates="roles", lazy="selectin")
