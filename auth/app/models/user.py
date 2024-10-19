from models.base import ModelBase
from models.mixin import IdMixin, TimestampMixin
from pydantic import EmailStr
from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash


class User(ModelBase, TimestampMixin, IdMixin):
    __tablename__ = "users"

    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(255), unique=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))

    roles = relationship("UserRole", back_populates="user", lazy="selectin")

    sessions = relationship(
        "Session", back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )
    tokens = relationship(
        "Token", back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )

    social_accounts = relationship(
        "UserSocialAccount",
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
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


class UserSocialAccount(ModelBase, TimestampMixin, IdMixin):
    __tablename__ = "user_social_accounts"

    user_id = Column(ForeignKey("users.id"), nullable=False)
    provider = Column(String(255), nullable=False)
    provider_user_id = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)

    user = relationship("User", back_populates="social_accounts")

    def __repr__(self) -> str:
        return f"<UserSocialAccount {self.provider} - {self.email}>"
