from functools import lru_cache

from fastapi import Depends
from schemas.session import SessionCreate
from services.auth import AuthService, get_auth_service
from services.session import SessionService, get_session_service
from services.user import UserService, get_user_service


class OAuthService:
    def __init__(
        self,
        auth_service: AuthService = Depends(get_auth_service),
        user_service: UserService = Depends(get_user_service),
        session_service: SessionService = Depends(get_session_service),
    ):
        self.auth_service = auth_service
        self.user_service = user_service
        self.session_service = session_service

    async def make_oauth_login(self, email, request):

        user = await self.user_service.get_user_by_email(email)
        if user:
            add_session = {
                "user_id": user.id,
                "user_agent": request.headers.get("user-agent", "Unknown"),
                "user_action": "login_oauth",
            }
            return await self.auth_service.oauth_login(email)

        user = await self.user_service.create_oauth_user(email)

        if user:
            tokens = await self.auth_service.oauth_login(email)
            if tokens:
                add_session = {
                    "user_id": user.id,
                    "user_agent": request.headers.get("user-agent", "Unknown"),
                    "user_action": "login_oauth",
                }
                await self.session_service.create_session(SessionCreate(**add_session))
                return tokens
        raise Exception("Failed to log in or create user")


@lru_cache()
def get_oauth_service(
    auth_service: AuthService = Depends(get_auth_service),
    user_service: UserService = Depends(get_user_service),
    session_service: SessionService = Depends(get_session_service),
) -> OAuthService:
    return OAuthService(
        auth_service=auth_service,
        user_service=user_service,
        session_service=session_service,
    )
