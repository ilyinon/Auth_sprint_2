import pytest
from faker import Faker
from sqlalchemy import create_engine, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from tests.models.role import Role, UserRole
from tests.models.session import Session
from tests.models.token import Token
from tests.models.user import User

fake = Faker()


@pytest.fixture(scope="package")
def admin_login_data(get_db):
    user_data = {
        "email": fake.email(),
        "password": fake.password(),
        "full_name": fake.name(),
        "username": fake.simple_profile()["username"],
    }

    # TODO: add func to cleanup database before enable it
    # user_id = add_user(get_db, user_data)
    # role_id = add_role(get_db, "admin")
    # add_role_to_user(get_db, user_id, role_id)

    return user_data


@pytest.fixture(scope="package")
def user_login_data(get_db) -> dict:
    user_data = {
        "email": fake.email(),
        "password": fake.password(),
        "full_name": fake.name(),
        "username": fake.simple_profile()["username"],
    }

    # TODO: add func to cleanup database before enable it
    # user_id = add_user(get_db, user_data)
    # role_id = add_role(get_db, "user")
    # add_role_to_user(get_db, user_id, role_id)
    return user_data


def add_role(get_db, role_name):
    role = Role(name=role_name)
    get_db.add(role)
    get_db.commit()
    get_db.refresh(role)
    role_id = role.id

    return role_id


def add_user(get_db, user_data):
    user = User(
        email=user_data["email"],
        password=user_data["password"],
        full_name=user_data["full_name"],
        username=user_data["username"],
    )
    get_db.add(user)
    get_db.commit()
    get_db.refresh(user)
    result = get_db.execute(select(User).where(User.email == user_data["email"]))
    user = result.scalars().first()

    return user.id


def add_role_to_user(get_db, user_id, role_id):

    user_role = UserRole(user_id=user_id, role_id=role_id)
    get_db.add(user_role)
    get_db.commit()
    get_db.refresh(user_role)
    return True
