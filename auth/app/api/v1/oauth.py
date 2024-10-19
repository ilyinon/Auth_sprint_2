import urllib.parse
from typing import Optional

import httpx
import requests
from core.config import auth_settings
from core.logger import logger
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, OAuth2AuthorizationCodeBearer
from schemas.auth import TwoTokens
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from services.oauth import OAuthService, get_oauth_service
from utils.generate_string import generate_string

get_token = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
)

router = APIRouter()


oauth_providers = {
    "google": {
        "authorization_endpoint": auth_settings.google_auth_uri,
        "token_endpoint": auth_settings.google_token_uri,
        "client_id": auth_settings.google_client_id,
        "user_info_endpoint": auth_settings.google_user_info_url,
        "redirect_uri": auth_settings.google_redirect_uri,
        "scope": auth_settings.google_scope,
    },
    "yandex": {
        "authorization_endpoint": auth_settings.yandex_auth_uri,
        "token_endpoint": auth_settings.yandex_token_uri,
        "client_id": auth_settings.yandex_client_id,
        "user_info_endpoint": auth_settings.yandex_user_info_url,
        "redirect_uri": auth_settings.yandex_redirect_uri,
        "scope": auth_settings.yandex_scope,
    },
    "vk": {
        "authorization_endpoint": auth_settings.vk_auth_url,
        "token_endpoint": auth_settings.vk_token_uri,
        "client_id": auth_settings.vk_client_id,
        "user_info_endpoint": auth_settings.vk_user_info_url,
        "redirect_uri": auth_settings.vk_redirect_uri,
        "scope": auth_settings.vk_scope,
    },
}


@router.get(
    "/login/{provider}",
    summary="OAuth {provider}",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def social_login(request: Request, provider: str):
    """OAuth thru different providers."""
    provider_config = oauth_providers.get(provider)
    if not provider_config:
        raise HTTPException(status_code=400, detail="Invalid OAuth provider")

    url = (
        f"{provider_config['authorization_endpoint']}?"
        f"response_type=code&"
        f"client_id={provider_config['client_id']}&"
        f"redirect_uri={provider_config['redirect_uri']}&"
        f"scope={provider_config['scope']}"
    )
    if provider == "vk":
        url += (
            f"&code_verifier={auth_settings.vk_code_verifier}&"
            f"code_challenge={auth_settings.vk_code_challenge}&"
            f"code_challenge_method={auth_settings.vk_code_challenge_method}&"
            f"state={generate_string()}&"
            f"prompt=consent"
        )
    logger.info(f"{provider} request url: {url}")
    return RedirectResponse(url=url)


@router.get(
    "/login/{provider}/callback",
    summary="callback for {provider}",
    response_model=TwoTokens,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def login_callback(
    code: str,
    request: Request,
    provider: str,
    device_id: Optional[str] = None,
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    provider_config = oauth_providers.get(provider)
    if not provider_config:
        raise HTTPException(status_code=400, detail="Invalid OAuth provider")

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
            user_info = user_info_response.json()
            logger.info(f"user_info: {user_info}")
            user_email = user_info.get("email")
            social_account_id = user_info.get("id")

    elif provider == "yandex":
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
            data = response.json()
            user_email = data["default_email"]
            social_account_id = data.get("id")

    elif provider == "vk":
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
            user_info = user_info_response.json()
        # return user_info
        user_email = user_info["user"]["email"]
        social_account_id = user_info["user"].get("id")
        if not social_account_id:
            import uuid

            social_account_id = str(uuid.uuid4())

    return await oauth_service.make_oauth_login(
        email=user_email,
        oauth_id=social_account_id,
        oauth_provider=provider,
        request=request,
    )
