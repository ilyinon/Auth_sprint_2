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


@router.post(
    "/signup",
    response_model=UserResponse,
    summary="User registration",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": HTTPExceptionResponse},
        status.HTTP_422_UNPROCESSABLE_ENTITY: {"model": HTTPValidationError},
    },
    tags=["Registration"],
)
async def signup(
    user_create: UserCreate, user_service: UserService = Depends(get_user_service)
) -> Union[UserResponse, HTTPExceptionResponse, HTTPValidationError]:
    """
    Register a new user.
    """
    logger.info(f"Requested /signup with {user_create}")
    if not await user_service.get_user_by_email(user_create.email):
        if not await user_service.get_user_by_username(user_create.username):
            created_new_user = await user_service.create_user(user_create)
            return created_new_user
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="The email or username is already in use",
    )
