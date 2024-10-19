from functools import wraps
from typing import Callable, List
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
import httpx
from core.config import settings

get_token = HTTPBearer(auto_error=False)


async def check_from_auth(
    allow_roles: list,
    credentials: str,
) -> bool:
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


# Function to use as a dependency
async def roles_required(roles_list: List[str], credentials: str = Depends(get_token)) -> bool:
    access_granted = await check_from_auth(roles_list, credentials)
    if not access_granted:
        raise HTTPException(status_code=403, detail="Access denied")
    return access_granted