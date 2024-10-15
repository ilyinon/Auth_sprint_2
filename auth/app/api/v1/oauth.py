import httpx
from core.config import auth_settings
from core.logger import logger
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, OAuth2AuthorizationCodeBearer
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from schemas.session import SessionCreate, SessionUpdate
from schemas.user import UserCreate, UserResponse
from services.auth import AuthService, get_auth_service
from services.session import SessionService, get_session_service
from services.user import UserService, get_user_service

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
    response_model=None,
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
    auth_service: AuthService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    session_service: SessionService = Depends(get_session_service)
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
        logger.info(f"User info: {user_info}")

        logger.info(f"User email: {user_info.get("email")}")

        user = await user_service.get_user_by_email(user_info.get("email"))
        if user:
            add_session = {
                        "user_id": user.id,
                        "user_agent": request.headers.get("user-agent", "Unknown"),
                        "user_action": "login_oauth",
                    }
            return await auth_service.oauth_login(user_info.get("email"))

        user = await user_service.create_oauth_user(user_info.get("email"))

        if user:
            tokens =  await auth_service.oauth_login(user_info.get("email"))
            if tokens:
                add_session = {
                        "user_id": user.id,
                        "user_agent": request.headers.get("user-agent", "Unknown"),
                        "user_action": "login_oauth",
                    }
                await session_service.create_session(SessionCreate(**add_session))
                return tokens






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

        logger.info(f"You have access_token: {access_token}")
        return {"access_token": access_token}


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
    f"{auth_settings.vk_auth_uri}?"
    f"client_id={auth_settings.vk_client_id}&"
    f"display=page&redirect_uri={auth_settings.vk_redirect_uri}&"
    f"response_type=code")
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
        response = await client.get(
            auth_settings.vk_token_uri, params={
            "client_id": auth_settings.vk_client_id,
            "client_secret": auth_settings.vk_client_secret,
            "redirect_uri": auth_settings.vk_redirect_uri,
            "code": code,
        }
        )


    logger.info(f"token_response is {response}")
    data = response.json()
    if "access_token" not in data:
        raise HTTPException(status_code=400, detail="Invalid code or no access token received")
    logger.info(f"token_data is {response}")

    access_token = data["access_token"]
    user_id = data["user_id"]

    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(auth_settings.vk_user_info_url, params={
            "access_token": access_token,
            "user_ids": user_id,
            "v": "5.131"
        })
        user_info = user_info_response.json()

    logger.info(f"You have access_token: {user_info}")
    return user_info
