import httpx
from core.config import settings


async def check_from_auth(
    allow_roles: list,
    credentials: str,
) -> bool:
    # return True
    if credentials:
        token = credentials.credentials
        headers = {"Authorization": f"Bearer {token}"}
        params = {}
        if allow_roles:
            params["allow_roles"] = ",".join(allow_roles)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                settings.auth_server_url, headers=headers, params=params
            )
            if response.status_code == 200:
                return True
    return False
