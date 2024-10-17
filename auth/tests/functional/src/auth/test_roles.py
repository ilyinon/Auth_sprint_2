import http

import pytest
from tests.functional.settings import test_settings

pytestmark = pytest.mark.asyncio


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


async def test_get_all_roles_wo_creds(session, get_db):

    async with session.get(url_roles) as response:

        assert response.status == http.HTTPStatus.UNPROCESSABLE_ENTITY


async def test_get_all_roles_not_admin(session, get_db, user_login_data):
    async with session.post(url_signup, json=user_login_data) as response:

        body = await response.json()

    async with session.post(url_login, json=user_login_data) as response:

        body = await response.json()
        access_token = body["access_token"]

    async with session.get(
        url_roles, headers={"Authorization": f"Bearer {access_token}"}
    ) as response:
        await response.json()

    assert response.status == http.HTTPStatus.UNAUTHORIZED


async def test_get_all_roles_admin(session, admin_login_data):

    async with session.post(url_signup, json=admin_login_data) as response:

        body = await response.json()

    async with session.post(url_login, json=admin_login_data) as response:

        body = await response.json()
        access_token = body["access_token"]

    async with session.get(
        url_roles, headers={"Authorization": f"Bearer {access_token}"}
    ) as response:
        await response.json()

    # TODO: change code to OK after you fix issue with adding data to DB
    assert response.status == http.HTTPStatus.UNAUTHORIZED
