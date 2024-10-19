from typing import Optional

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

        user_info = await oauth_service.get_access_token(provider, code)
        logger.info(f"user_info: {user_info}")
        user_email = user_info.get("email")
        social_account_id = user_info.get("id")

    elif provider == "yandex":

        data = await oauth_service.get_access_token(provider, code)
        user_email = data["default_email"]
        social_account_id = data.get("id")

    elif provider == "vk":
        user_info = await oauth_service.get_access_token(provider, code, device_id)

        user_email = user_info["user"]["email"]
        social_account_id = user_info["user"].get("id")
        if not social_account_id:
            import uuid

            social_account_id = str(uuid.uuid4())

    logger.info(f"User email: {user_email}")

    return await oauth_service.make_oauth_login(
        email=user_email,
        oauth_id=social_account_id,
        oauth_provider=provider,
        request=request,
    )
