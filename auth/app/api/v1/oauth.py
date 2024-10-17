import urllib.parse

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


@router.get(
    "/login/google",
    summary="OAuth w/google",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def google_login(request: Request):

    url = f"{auth_settings.google_auth_uri}?response_type=code&client_id={auth_settings.google_client_id}&redirect_uri={auth_settings.google_redirect_uri}&scope={auth_settings.google_scope}"
    return RedirectResponse(url=url)


@router.get(
    "/login/google/callback",
    summary="callback for google",
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
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": auth_settings.google_client_id,
                "client_secret": auth_settings.google_client_secret,
                "redirect_uri": auth_settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )

        logger.info(f"token_response is {token_response}")
        token_data = token_response.json()
        logger.info(f"token_data is {token_data}")

        access_token = token_data.get("access_token")
        logger.info(f"You have access_token: {access_token}")

        user_info_response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_info = user_info_response.json()
        user_email = user_info.get("email")
        logger.info(f"User email: {user_email}")
        return await oauth_service.make_oauth_login(user_email, request)


@router.get(
    "/login/yandex",
    summary="OAuth w/Yandex",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def yandex_login(request: Request):

    url = f"{auth_settings.yandex_auth_uri}?response_type=code&client_id={auth_settings.yandex_client_id}&redirect_uri={auth_settings.yandex_redirect_uri}&scope={auth_settings.yandex_scope}"
    return RedirectResponse(url=url)


@router.get(
    "/login/yandex/callback",
    summary="Callback for Yandex",
    response_model=TwoTokens,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def yandex_callback(
    code: str,
    request: Request,
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            auth_settings.yandex_token_uri,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": auth_settings.yandex_client_id,
                "client_secret": auth_settings.yandex_client_secret,
                "redirect_uri": auth_settings.yandex_redirect_uri,
            },
        )

        logger.info(f"token_response is {token_response}")
        token_data = token_response.json()
        logger.info(f"token_data is {token_data}")

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
        email = data["default_email"]
        logger.info(f"email: email")

        return await oauth_service.make_oauth_login(email, request)


@router.get(
    "/login/vk",
    summary="OAuth with VK",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def vk_login(request: Request):
    # https://example-app.com/pkce
    state = generate_string()
    code_verifier = "e6be27b0a2b616b77c432f2baf7abdb95ecd064dd97e90c1dbd381da"
    code_challenge = "oOCWcELRm1m6JkISl0IL2tyLOWul_CtIhoy8B8a34RM"
    code_challenge_method = "s256"
    # content-type: application/x-www-form-urlencoded

    client_id = auth_settings.vk_client_id
    redirect_uri = auth_settings.vk_redirect_uri
    scope = "email phone"
    state = state
    code_challenge = code_challenge
    code_challenge_method = "s256"

    url = auth_settings.vk_auth_url
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scopes": "email",
    }
    encoded_params = urllib.parse.urlencode(params)
    full_url = f"{url}?{encoded_params}"
    logger.info(f"full url: {full_url}")

    return RedirectResponse(url=full_url)


@router.get(
    "/login/vk/callback",
    summary="Callback for VK",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def vk_callback(
    code: str,
    device_id: str,
    request: Request,
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    code_verifier = "e6be27b0a2b616b77c432f2baf7abdb95ecd064dd97e90c1dbd381da"

    logger.info("START TO CALLBACK")
    logger.info(f"code: {code}")
    logger.info(f"request: {request}")

    params = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "device_id": device_id,
        "redirect_uri": auth_settings.vk_redirect_uri,
        "client_id": auth_settings.vk_client_id,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    logger.info(f"!!!!! params: {params}")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            url=auth_settings.vk_token_uri, data=params, headers=headers
        )
        data = response.json()

        logger.info(f"access_token response is {data["access_token"]}")

    id_token = data["id_token"]

    async with httpx.AsyncClient() as client:
        user_info_response = await client.post(
            url=auth_settings.vk_user_info_url,
            data={
                "id_token": id_token,
                "client_id": auth_settings.vk_client_id,
            },
            headers=headers,
        )
        user_info = user_info_response.json()
    # return user_info
    email = user_info["user"]["email"]
    return email
    logger.info(f"You have email: {email}")
    return await oauth_service.make_oauth_login(email, request)
