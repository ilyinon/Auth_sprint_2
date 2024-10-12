from typing import Annotated, Literal, Optional, Union
from uuid import UUID

from core.logger import logger
from fastapi import APIRouter, Body, Depends, Request, Response, status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer
from schemas.auth import TwoTokens, UserLoginModel
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from schemas.session import SessionCreate, SessionUpdate
from schemas.user import UserCreate, UserResponse
from services.auth import AuthService, get_auth_service
from services.session import SessionService, get_session_service
from services.user import UserService, get_user_service
from urllib.parse import urlencode, parse_qs
from fastapi.responses import RedirectResponse
from starlette.datastructures import URL
from starlette.config import Config
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2AuthorizationCodeBearer
import httpx
from core.config import auth_settings
from fastapi.responses import JSONResponse

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


    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
    GOOGLE_CLIENT_ID = auth_settings.google_client_id
    GOOGLE_REDIRECT_URI = auth_settings.google_redirect_uri
    SCOPE = "email"
    url = f"{GOOGLE_AUTH_URL}?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope={SCOPE}"
    return RedirectResponse(url=url)

@router.get(
        "/login/google/callback",
        summary="callback for google",
        response_model=None,
        responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},},
    tags=["Authorization"],
    )
async def login_callback(code: str):
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    logger.info(f"You have access_token: {access_token}")
    return {"access_token": access_token}

