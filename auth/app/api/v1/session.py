from typing import List, Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from pydantic import conint
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from schemas.session import SessionResponse
from services.auth import AuthService, get_auth_service
from services.session import SessionService, get_session_service

get_token = HTTPBearer(auto_error=False)

router = APIRouter()


@router.delete(
    "/sessions/{session_id}",
    summary="Delete user session",
    responses={
        "401": {"model": HTTPExceptionResponse},
        "404": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Manage sessions"],
)
async def delete_user_session(
    session_id: UUID,
    access_token: str = Depends(get_token),
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Union[HTTPExceptionResponse, HTTPValidationError]]:
    """
    Delete user session by session ID.
    """
    if access_token:
        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            session = await session_service.get_session(session_id)
            if session:
                await session_service.delete_session(session_id)
                return {"message": "Session deleted successfully."}
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


PageSizeType = Optional[conint(ge=1)]


@router.get(
    "/sessions",
    response_model=List[SessionResponse],
    summary="History of user activities",
    responses={
        "401": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Manage sessions"],
)
async def get_user_sessions(
    request: Request,
    page_size: PageSizeType = 50,
    page_number: PageSizeType = 1,
    access_token: str = Depends(get_token),
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> Union[List[SessionResponse], HTTPExceptionResponse]:
    """
    Retrieve user's session history with optional pagination and activity filter.
    """
    if access_token:
        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            user_uuid = UUID(user.user_id)
            sessions = await session_service.get_sessions_by_user(user_uuid)
            if not sessions:
                return []

            # Optional pagination logic
            start = (page_number - 1) * page_size
            end = start + page_size

            return sessions[start:end]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
