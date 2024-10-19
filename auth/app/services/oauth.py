import urllib.parse
from functools import lru_cache

import httpx
import requests
from core.config import auth_settings
from core.logger import logger
from fastapi import Depends
from schemas.session import SessionCreate
from services.auth import AuthService, get_auth_service
from services.session import SessionService, get_session_service
from services.user import UserService, get_user_service


class OAuthService:
    def __init__(
        self,
        auth_service: AuthService = Depends(get_auth_service),
        user_service: UserService = Depends(get_user_service),
        session_service: SessionService = Depends(get_session_service),
    ):
        self.auth_service = auth_service
        self.user_service = user_service
        self.session_service = session_service

    async def make_oauth_login(
        self, email, request, oauth_provider: str, oauth_id: str
    ):
        user = await self.user_service.get_user_by_social_account(
            oauth_provider, oauth_id
        )

        if user:
            tokens = await self.auth_service.oauth_login(email)
            if tokens:
                add_session = {
                    "user_id": user.id,
                    "user_agent": request.headers.get("user-agent", "Unknown"),
                    "user_action": f"login_oauth_{oauth_provider}",
                }
                await self.session_service.create_session(SessionCreate(**add_session))
            return tokens

        user = await self.user_service.get_user_by_email(email)

        if user:
            await self.user_service.link_social_account(
                user.id, oauth_provider, oauth_id, email
            )

            tokens = await self.auth_service.oauth_login(email)
            if tokens:
                add_session = {
                    "user_id": user.id,
                    "user_agent": request.headers.get("user-agent", "Unknown"),
                    "user_action": f"login_oauth_{oauth_provider}",
                }
                await self.session_service.create_session(SessionCreate(**add_session))
            return tokens

        user = await self.user_service.create_oauth_user(email)

        if user:
            await self.user_service.link_social_account(
                user.id, oauth_provider, oauth_id, email
            )

            tokens = await self.auth_service.oauth_login(email)
            if tokens:
                add_session = {
                    "user_id": user.id,
                    "user_agent": request.headers.get("user-agent", "Unknown"),
                    "user_action": f"login_oauth_{oauth_provider}",
                }
                await self.session_service.create_session(SessionCreate(**add_session))
            return tokens

        raise Exception("Failed to log in or create user")

    async def get_access_token(self, provider, code, device_id=None):
        if provider == "google":

            async with httpx.AsyncClient() as client:
                token_response = await client.post(
                    auth_settings.google_token_uri,
                    data={
                        "code": code,
                        "client_id": auth_settings.google_client_id,
                        "client_secret": auth_settings.google_client_secret,
                        "redirect_uri": auth_settings.google_redirect_uri,
                        "grant_type": auth_settings.google_grant_type,
                    },
                )

                token_data = token_response.json()
                access_token = token_data.get("access_token")
                user_info_response = await client.get(
                    auth_settings.google_user_info_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                return user_info_response.json()
        if provider == "yandex":
            async with httpx.AsyncClient() as client:
                token_response = await client.post(
                    auth_settings.yandex_token_uri,
                    data={
                        "grant_type": auth_settings.yandex_grant_type,
                        "code": code,
                        "client_id": auth_settings.yandex_client_id,
                        "client_secret": auth_settings.yandex_client_secret,
                        "redirect_uri": auth_settings.yandex_redirect_uri,
                    },
                )

                token_data = token_response.json()
                access_token = token_data.get("access_token")

                if not access_token:
                    logger.error("Failed to retrieve access token")
                    return {"error": "Failed to retrieve access token"}

                params = {"oauth_token": access_token, "format": "json"}
                encoded_params = urllib.parse.urlencode(params)
                full_url = f"{auth_settings.yandex_user_info_url}?{encoded_params}"
                logger.info(f"full url: {full_url}")

                response = requests.get(full_url)
                return response.json()

        if provider == "vk":
            params = {
                "grant_type": auth_settings.vk_grant_type,
                "code": code,
                "code_verifier": auth_settings.vk_code_verifier,
                "device_id": device_id,
                "redirect_uri": auth_settings.vk_redirect_uri,
                "client_id": auth_settings.vk_client_id,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=auth_settings.vk_token_uri, data=params, headers=headers
                )
                data = response.json()

            access_token = data["access_token"]

            async with httpx.AsyncClient() as client:
                user_info_response = await client.post(
                    url=auth_settings.vk_user_info_url,
                    data={
                        "access_token": access_token,
                        "client_id": auth_settings.vk_client_id,
                    },
                    headers=headers,
                )
            return user_info_response.json()


@lru_cache()
def get_oauth_service(
    auth_service: AuthService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    session_service: SessionService = Depends(get_session_service),
) -> OAuthService:
    return OAuthService(
        auth_service=auth_service,
        user_service=user_service,
        session_service=session_service,
    )
