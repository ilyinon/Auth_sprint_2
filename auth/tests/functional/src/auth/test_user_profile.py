import http

import pytest
from faker import Faker

from tests.functional.settings import test_settings

pytestmark = pytest.mark.asyncio


fake = Faker()

auth_url_template = "{service_url}/api/v1/auth/{endpoint}"
users_url_template = "{service_url}/api/v1/users/"


headers = {"Content-Type": "application/json"}

url_signup = auth_url_template.format(
    service_url=test_settings.app_dsn, endpoint="signup"
)
url_users = users_url_template.format(service_url=test_settings.app_dsn, endpoint="")
url_login = auth_url_template.format(
    service_url=test_settings.app_dsn, endpoint="login"
)


user = {
    "email": fake.email(),
    "password": fake.password(),
    "full_name": fake.name(),
    "username": fake.simple_profile()["username"],
}

login_data = {"email": user["email"], "password": user["password"]}


async def test_get_user_profile_wo_creds(session):
    async with session.get(url_users) as response:

        assert response.status == http.HTTPStatus.UNPROCESSABLE_ENTITY


async def test_get_user_profile(session):
    async with session.post(url_signup, json=user) as response:

        body = await response.json()

    async with session.post(url_login, json=user) as response:

        body = await response.json()
        access_token = body["access_token"]

    async with session.get(
        url_users, headers={"Authorization": f"Bearer {access_token}"}
    ) as response:
        body = await response.json()

    assert response.status == http.HTTPStatus.OK


async def test_update_user_profile(session):
    async with session.post(url_signup, json=user) as response:

        body = await response.json()

    async with session.post(url_login, json=user) as response:

        body = await response.json()
        access_token = body["access_token"]

    new_username = fake.simple_profile()["username"]
    async with session.patch(
        url_users,
        json={"username": new_username},
        headers={"Authorization": f"Bearer {access_token}"},
    ) as response:
        body = await response.json()
    assert response.status == http.HTTPStatus.OK

    new_passord = fake.password()
    async with session.patch(
        url_users,
        json={"password": new_passord},
        headers={"Authorization": f"Bearer {access_token}"},
    ) as response:
        body = await response.json()
    assert response.status == http.HTTPStatus.OK

    async with session.get(
        url_users, headers={"Authorization": f"Bearer {access_token}"}
    ) as response:
        body = await response.json()

    assert body["username"] == new_username

    login_data["password"] = new_passord
    # async with session.post(url_login, json=login_data) as response:

    #     body = await response.json()

    #     assert response.status == http.HTTPStatus.OK
    #     assert isinstance(body["access_token"], str)
    #     assert isinstance(body["refresh_token"], str)
