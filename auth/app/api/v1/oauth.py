import httpx
from core.config import auth_settings
from core.logger import logger
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, OAuth2AuthorizationCodeBearer
from schemas.base import HTTPExceptionResponse, HTTPValidationError

get_token = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
)

router = APIRouter()


GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_CLIENT_ID = auth_settings.google_client_id
GOOGLE_REDIRECT_URI = auth_settings.google_redirect_uri
SCOPE = "email"


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

    url = f"{GOOGLE_AUTH_URL}?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope={SCOPE}"
    return RedirectResponse(url=url)


@router.get(
    "/login/google/callback",
    summary="callback for google",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def login_callback(code: str):
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": auth_settings.google_client_secret,
                "redirect_uri": GOOGLE_REDIRECT_URI,
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
        logger.info(f"User info: {user_info}")

        return {
            "access_token": access_token,
            "email": user_info.get("email"),
            "name": user_info.get("name"),
        }



YANDEX_AUTH_URL = "https://oauth.yandex.ru/authorize"
YANDEX_TOKEN_URL = "https://oauth.yandex.ru/token"
YANDEX_CLIENT_ID = auth_settings.yandex_client_id
YANDEX_CLIENT_SECRET = auth_settings.yandex_client_secret
YANDEX_REDIRECT_URI = auth_settings.yandex_redirect_uri
YANDEX_SCOPE = "login:email login:info"


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

    url = f"{YANDEX_AUTH_URL}?response_type=code&client_id={YANDEX_CLIENT_ID}&redirect_uri={YANDEX_REDIRECT_URI}&scope={YANDEX_SCOPE}"
    return RedirectResponse(url=url)


@router.get(
    "/login/yandex/callback",
    summary="Callback for Yandex",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def yandex_callback(code: str):
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            YANDEX_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": YANDEX_CLIENT_ID,
                "client_secret": YANDEX_CLIENT_SECRET,
                "redirect_uri": YANDEX_REDIRECT_URI,
            },
        )

        logger.info(f"token_response is {token_response}")
        token_data = token_response.json()
        logger.info(f"token_data is {token_data}")

        access_token = token_data.get("access_token")
        if not access_token:
            logger.error("Failed to retrieve access token")
            return {"error": "Failed to retrieve access token"}

        logger.info(f"You have access_token: {access_token}")
        return {"access_token": access_token}


VK_AUTH_URL = "https://id.vk.com/authorize"
VK_TOKEN_URL = "https://id.vk.com/access_token"
VK_CLIENT_ID = auth_settings.vk_client_id
VK_CLIENT_SECRET = auth_settings.vk_client_secret
VK_REDIRECT_URI = auth_settings.vk_redirect_uri
VK_SCOPE = "email"


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
    url = (
        f"{VK_AUTH_URL}?"
        f"client_id={VK_CLIENT_ID}&"
        f"redirect_uri={VK_REDIRECT_URI}&"
        f"scope={VK_SCOPE}&"
        f"response_type=code"
    )
    return RedirectResponse(url=url)


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
        token_response = await client.post(
            VK_TOKEN_URL,
            data={
                "client_id": VK_CLIENT_ID,
                "client_secret": VK_CLIENT_SECRET,
                "redirect_uri": VK_REDIRECT_URI,
                "code": code,
            },
        )

    logger.info(f"token_response is {token_response}")
    token_data = token_response.json()
    logger.info(f"token_data is {token_data}")

    access_token = token_data.get("access_token")

    if not access_token:
        logger.error("Failed to retrieve access token")
        return {"error": "Failed to retrieve access token"}

    logger.info(f"You have access_token: {access_token}")
    return {"access_token": access_token}
