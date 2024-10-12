from typing import Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from schemas.user import UserPatch, UserResponse
from services.auth import AuthService, get_auth_service
from services.user import UserService, get_user_service

get_token = HTTPBearer(auto_error=False)

router = APIRouter()


@router.post(
    "/{user_id}/roles/{role_id}",
    response_model=None,
    summary="Add role to user",
    responses={
        "400": {"model": HTTPExceptionResponse},
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Manage access"],
)
async def add_role_to_user(
    request: Request,
    user_id: UUID,
    role_id: UUID,
    access_token: str = Depends(get_token),
    user_service: UserService = Depends(get_user_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Union[HTTPExceptionResponse, HTTPValidationError]]:
    """
    Add a role to a user.
    """
    if access_token:
        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            try:
                msg = await user_service.add_role_to_user(user_id, role_id)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                )
            return {"message": msg}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


@router.delete(
    "/{user_id}/roles/{role_id}",
    summary="Remove role from user",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "404": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Manage access"],
)
async def take_away_role_from_user(
    request: Request,
    user_id: UUID,
    role_id: UUID,
    access_token: str = Depends(get_token),
    user_service: UserService = Depends(get_user_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Union[HTTPExceptionResponse, HTTPValidationError]]:
    """
    Remove a role from a user.
    """
    if access_token:
        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            try:
                msg = await user_service.remove_role_from_user(user_id, role_id)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=str(e)
                )

            return {"message": msg}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


@router.get(
    "/",
    response_model=UserResponse,
    summary="Get user details",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": HTTPExceptionResponse},
        status.HTTP_404_NOT_FOUND: {"model": HTTPExceptionResponse},
    },
    tags=["User profile"],
)
async def get_user_info(
    request: Request,
    access_token: str = Depends(get_token),
    user_service: UserService = Depends(get_user_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> Union[UserResponse, HTTPExceptionResponse]:
    """
    Retrieve current user's information.
    """
    if access_token:
        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            user_uuid = UUID(user.user_id)
            user_info = await user_service.get_current_user(user_uuid)
            if not user_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )

            return user_info
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


@router.patch(
    "/",
    response_model=UserResponse,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "404": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["User profile"],
)
async def patch_current_user(
    request: Request,
    body: UserPatch,
    access_token: str = Depends(get_token),
    user_service: UserService = Depends(get_user_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> Union[UserResponse, HTTPExceptionResponse, HTTPValidationError]:
    """
    Update the current user's profile.
    """
    if access_token:
        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            try:
                user_uuid = UUID(user.user_id)
                updated_user = await user_service.update_user(user_uuid, body)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=str(e)
                )
            return updated_user

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
