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
        logger.info(f"email: {data["default_email"]}")

        return await oauth_service.make_oauth_login(data["default_email"], request)


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
    code_verifier = "3a96f295cfac52f3c773807516640aea82332e4532a3b8ee6c07969f"
    code_challenge = "imQqAF9Wcln0pBYnaXulli6JutiG6qbAXG70VlLZo80"
    code_challenge_method = "s256"
    # content-type: application/x-www-form-urlencoded

    client_id = {auth_settings.vk_client_id}
    redirect_uri = {auth_settings.vk_redirect_uri}
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
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    encoded_params = urllib.parse.urlencode(params)
    full_url = f"{url}?{encoded_params}"
    logger.info(f"full url: {full_url}")

    response = requests.get(full_url)
    if response.status_code == 200:
        return response.url
    else:
        return response.text

    # return RedirectResponse(url=url)


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
async def vk_callback(code: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            auth_settings.vk_token_uri,
            params={
                "client_id": auth_settings.vk_client_id,
                "client_secret": auth_settings.vk_client_secret,
                "redirect_uri": auth_settings.vk_redirect_uri,
                "code": code,
            },
        )

    logger.info(f"token_response is {response}")
    data = response.json()
    if "access_token" not in data:
        raise HTTPException(
            status_code=400, detail="Invalid code or no access token received"
        )
    logger.info(f"token_data is {response}")

    access_token = data["access_token"]
    user_id = data["user_id"]

    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            auth_settings.vk_user_info_url,
            params={"access_token": access_token, "user_ids": user_id, "v": "5.131"},
        )
        user_info = user_info_response.json()

    logger.info(f"You have access_token: {user_info}")
    return user_info
