from typing import Union

from core.logger import logger
from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer, OAuth2AuthorizationCodeBearer
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from schemas.user import UserCreate, UserResponse
from services.user import UserService, get_user_service

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
