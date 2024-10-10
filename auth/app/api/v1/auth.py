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

get_token = HTTPBearer(auto_error=False)

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


@router.post(
    "/login",
    response_model=TwoTokens,
    summary="User login",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": HTTPExceptionResponse},
        status.HTTP_422_UNPROCESSABLE_ENTITY: {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def login(
    form_data: UserLoginModel,
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service),
) -> Union[TwoTokens, HTTPExceptionResponse, HTTPValidationError]:
    """
    Login a user to get a tokens pair.
    """
    logger.info(f"Requested /register with {form_data}")
    user = await auth_service.get_user_by_email(form_data.email)
    if user:
        logger.info(f"user agent is {request.headers.get('user-agent')}")

        user_agent = request.headers.get("user-agent", "Unknown")

        tokens = await auth_service.login(form_data.email, form_data.password)
        if tokens:
            session = await session_service.get_session_by_user_and_agent(
                user_id=user.id, user_agent=user_agent
            )

            if session:
                # Update existing session with login action
                logger.info(
                    f"Updating existing session for user {user.id} and agent {user_agent}"
                )
                await session_service.update_session(
                    session_id=session.id,
                    session_data=SessionUpdate(
                        user_id=user.id,
                        user_agent=user_agent,
                        user_action="login",
                    ),
                )
            else:
                session_data = SessionCreate(
                    user_id=user.id,
                    user_agent=user_agent,
                    user_action="login",
                )
                await session_service.create_session(session_data)

            return tokens

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad username or password"
    )


@router.post(
    "/logout",
    response_model=None,
    status_code=status.HTTP_200_OK,
    summary="User logout",
    responses={status.HTTP_401_UNAUTHORIZED: {"model": HTTPExceptionResponse}},
    tags=["Authorization"],
)
async def logout(
    request: Request,
    access_token: str = Depends(get_token),
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service),
) -> Optional[HTTPExceptionResponse]:
    """
    Log out the user from service and update session with a logout action.
    This only logs out if the user-agent matches the session's recorded user-agent.
    """
    if access_token:
        user_agent = request.headers.get("user-agent", "Unknown")

        user = await auth_service.check_access(creds=access_token.credentials)
        if user:
            user_uuid = UUID(user.get("user_id"))
            session = await session_service.get_session_by_user_and_agent(
                user_id=user_uuid, user_agent=user_agent
            )

            if session:
                await session_service.update_session(
                    session.id,
                    SessionUpdate(
                        user_id=user_uuid,
                        user_agent=user_agent,
                        user_action="logout",
                    ),
                )

                await auth_service.logout(access_token.credentials)
                return status.HTTP_200_OK

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found for matching user-agent",
            )

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.post(
    "/refresh",
    response_model=TwoTokens,
    summary="Refresh tokens",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": HTTPExceptionResponse},
        status.HTTP_422_UNPROCESSABLE_ENTITY: {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def refresh_tokens(
    refresh_token: Annotated[str, Body(embed=True)],
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service),
) -> Union[TwoTokens, HTTPExceptionResponse, HTTPValidationError]:
    """
    Refresh tokens and update session with a refresh action.
    """
    logger.info(f"Refresh token with token {refresh_token}")

    if refresh_token:
        logger.info(f"token to refresh {refresh_token}")

        decoded_token = await auth_service.decode_jwt(refresh_token)

        if decoded_token and decoded_token.get("refresh"):
            if await auth_service.check_access(refresh_token):
                user = await auth_service.get_user_by_email(
                    decoded_token["user"]["email"]
                )
                logger.info(f"get user to refresh: {user}")

                if user:
                    tokens = await auth_service.refresh_tokens(refresh_token)

                    user_uuid = UUID(decoded_token["user"]["user_id"])
                    user_agent = request.headers.get("user-agent", "Unknown")
                    session = await session_service.get_session_by_user_and_agent(
                        user_id=user_uuid, user_agent=user_agent
                    )
                    if session:
                        await session_service.update_session(
                            session.id,
                            SessionUpdate(
                                user_id=user_uuid,
                                user_agent=user_agent,
                                user_action="refresh",
                            ),
                        )

                    return tokens

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.get(
    "/check_access",
    summary="Check access",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPValidationError},
    },
    tags=["Authorization"],
)
async def check_access(
    request: Request,
    access_token: str = Depends(get_token),
    allow_roles: Literal["admin", "user"] = None,
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Union[HTTPExceptionResponse, HTTPValidationError]]:
    """
    check access.
    """
    if access_token:
        logger.info(f"Check access for {access_token.credentials}")

        if allow_roles:
            if await auth_service.check_access_with_roles(
                creds=access_token.credentials, allow_roles=allow_roles
            ):
                return status.HTTP_200_OK
        if not allow_roles:
            if await auth_service.check_access(creds=access_token.credentials):
                return status.HTTP_200_OK

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
