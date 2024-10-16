from random import randint
from typing import Annotated, List, Literal, LiteralString, Optional, Union
from uuid import UUID

from core.logger import logger
from fastapi import APIRouter, Body, Depends, Request, Response, status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer, OAuth2AuthorizationCodeBearer
from schemas.auth import TwoTokens, UserLoginModel
from schemas.base import HTTPExceptionResponse, HTTPValidationError
from schemas.session import SessionCreate, SessionUpdate
from services.auth import AuthService, get_auth_service
from services.session import SessionService, get_session_service
from services.user import UserService, get_user_service

get_token = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
)

router = APIRouter()


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
            user_uuid = UUID(user.user_id)
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
    },
    tags=["Authorization"],
)
async def refresh_tokens(
    request: Request,
    refresh_token: Annotated[str, Body(embed=True)],
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service),
) -> Union[TwoTokens, HTTPExceptionResponse, HTTPValidationError]:
    """
    Refresh tokens and update session with a refresh action.
    """
    logger.info(f"Refresh token with token {refresh_token}")

    if refresh_token:
        decoded_token = await auth_service.decode_jwt(refresh_token)

        if decoded_token and decoded_token.get("refresh"):
            if await auth_service.check_access(refresh_token):
                user = await auth_service.get_user_by_email(decoded_token["email"])
                logger.info(f"get user to refresh: {user}")

                if user:

                    tokens = await auth_service.refresh_tokens(refresh_token)
                    add_session = {
                        "user_id": UUID(decoded_token["user_id"]),
                        "user_agent": request.headers.get("user-agent", "Unknown"),
                        "user_action": "refresh",
                    }

                    await session_service.create_session(SessionCreate(**add_session))
                    return tokens

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
    )


@router.get(
    "/check_access",
    summary="Check access",
    response_model=None,
    responses={
        "401": {"model": HTTPExceptionResponse},
        "403": {"model": HTTPExceptionResponse},
        "422": {"model": HTTPExceptionResponse},
    },
    tags=["Authorization"],
)
async def check_access(
    access_token: str = Depends(get_token),
    # Optional[Literal["admin", "user"]] = None
    # allow_roles: Optional[Union[Literal["admin", "user"]]] = None,
    allow_roles: Optional[str] = None,
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Union[HTTPExceptionResponse, HTTPValidationError]]:
    """
    Check access by provided access_token.s
    """
    if access_token:
        logger.info(f"Check access for {access_token}")

        # check access w/roles
        if allow_roles:
            logger.info(f"allow_roles is {allow_roles}")
            list_roles = allow_roles.split(",")
            logger.info(f"requested verification with roles {list_roles}")
            is_authorized = await auth_service.check_access_with_roles(
                access_token.credentials, list_roles
            )
            if is_authorized:
                return status.HTTP_200_OK

        # check access w/o roles
        else:
            logger.info("requested access only by token")
            is_authorized = await auth_service.check_access(access_token.credentials)
            if is_authorized:
                return status.HTTP_200_OK

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
        )

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
