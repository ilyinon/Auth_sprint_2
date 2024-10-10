from models.base import Base
from models.mixin import IdMixin, TimestampMixin
from pydantic import EmailStr
from sqlalchemy import Column, String
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash


class User(Base, TimestampMixin, IdMixin):
    __tablename__ = "users"

    email = Column(String, unique=True, nullable=False)
    username = Column(String, unique=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)

    roles = relationship("UserRole", back_populates="user", lazy="selectin")

    sessions = relationship(
        "Session", back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )
    tokens = relationship(
        "Token", back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )

    def __init__(
        self, email: EmailStr, password: str, username: str, full_name: str
    ) -> None:
        self.email = email
        self.username = username
        self.full_name = full_name
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.hashed_password, password)

    def __repr__(self) -> str:
        return f"<User {self.email}>"
