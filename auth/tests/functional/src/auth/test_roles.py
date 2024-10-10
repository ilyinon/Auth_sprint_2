import http

import pytest
from faker import Faker

from tests.functional.settings import test_settings

pytestmark = pytest.mark.asyncio
from sqlalchemy import create_engine, select
from tests.models.role import Role, UserRole
from tests.models.session import Session
from tests.models.token import Token
from tests.models.user import User

fake = Faker()

auth_url_template = "{service_url}/api/v1/auth/{endpoint}"
role_url_template = "{service_url}/api/v1/roles/{endpoint}"


headers = {"Content-Type": "application/json"}

url_signup = auth_url_template.format(
    service_url=test_settings.app_dsn, endpoint="signup"
)
url_login = auth_url_template.format(
    service_url=test_settings.app_dsn, endpoint="login"
)

url_roles = role_url_template.format(service_url=test_settings.app_dsn, endpoint="")


admin_user = {
    "email": fake.email(),
    "password": fake.password(),
    "full_name": fake.name(),
    "username": fake.simple_profile()["username"],
}

admin_login_data = {"email": admin_user["email"], "password": admin_user["password"]}


async def test_get_all_roles_wo_creds(session, get_db):

    user = User(
        email=admin_user["email"],
        password=admin_user["password"],
        username=admin_user["username"],
        full_name=admin_user["full_name"],
    )
    get_db.add(user)
    get_db.commit()
    get_db.refresh(user)

    user = get_db.query(User).first()
    # assert user.email == admin_user["email"]
    async with session.get(url_roles) as response:

        assert response.status == http.HTTPStatus.UNPROCESSABLE_ENTITY


async def test_get_all_roles_not_admin(session):
    async with session.post(url_signup, json=admin_user) as response:

        body = await response.json()

    async with session.post(url_login, json=admin_user) as response:

        body = await response.json()
        access_token = body["access_token"]

    async with session.get(
        url_roles, headers={"Authorization": f"Bearer {access_token}"}
    ) as response:
        await response.json()

    assert response.status == http.HTTPStatus.UNAUTHORIZED
