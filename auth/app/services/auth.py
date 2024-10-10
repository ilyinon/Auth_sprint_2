from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional
from uuid import UUID, uuid4

import jwt as jwt_auth
from core.config import auth_settings
from core.logger import logger
from db.pg import get_session
from db.redis import add_jti_to_blocklist, get_redis, token_in_blocklist
from fastapi import Depends
from models.role import Role, UserRole
from models.token import Token
from models.user import User

# from services.user import User
from pydantic import EmailStr
from redis.asyncio import Redis
from schemas.auth import Payload, TwoTokens
from services.database import BaseDb, PostgresqlEngine
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession


class AuthService:
    def __init__(self, db: BaseDb, redis: Redis):
        self.db = db
        self.redis = redis
        self.auth_jwt = jwt_auth

    async def login(self, email, hashed_password) -> Optional[TwoTokens]:
        logger.info(f"Start to login procedure with {email}")
        user = await self.get_user_by_email(email)
        logger.info(f"User has the following entry in db {user}")
        if user:
            if user.check_password(hashed_password):
                logger.info(f"User {email} provided the correct password")
                r = await self.db.execute(
                    select(Role.name).where(UserRole.user_id == user.id).join(UserRole)
                )
                user_roles = [role[0] for role in r.fetchall()]
                logger.info(f"User {email} has roles {user_roles}")
                user_data = {
                    "email": user.email,
                    "user_id": str(user.id),
                    "roles": [role for role in user_roles],
                }
                return await self.create_tokens(user, True, user_data)

        logger.info(f"Failed to login {email}")
        return None

    async def get_user_by_email(self, email: EmailStr) -> Optional[User]:
        logger.info(f"Get user by email {email}")
        user = await self.db.get_by_key("email", email, User)
        return user

    async def create_tokens(
        self, user: User, is_exist: bool = True, user_data={}
    ) -> TwoTokens:

        access_token = await self.create_token(user, user_data, False)
        logger.info(f"access token is {access_token}")

        refresh_token = await self.create_token(user, user_data, True)
        logger.info(f"refresh token is {refresh_token}")

        if await self.save_token_jti_to_db(user, access_token, refresh_token):
            logger.info("Tokens jti and exp were save to tokens table in db")

        return TwoTokens(access_token=access_token, refresh_token=refresh_token)

    async def create_token(
        self,
        user: User,
        user_data={},
        refresh=False,
    ):
        logger.info("Start to create token")
        logger.info("User data is user_data")
        expires_time = datetime.now(tz=timezone.utc) + timedelta(
            seconds=auth_settings.jwt_access_token_expires_in_seconds
        )
        logger.info(f"expires_time is {expires_time}")

        payload = {}

        payload["user"] = user_data

        payload["exp"] = expires_time
        payload["jti"] = str(uuid4())

        payload["refresh"] = refresh

        token = jwt_auth.encode(
            payload=payload,
            key=auth_settings.authjwt_secret_key,
            algorithm=auth_settings.authjwt_algorithm,
        )
        logger.info("Token is generated")
        return token

    async def check_access(self, creds) -> None:
        logger.info(f"Check access for token {creds}")
        try:
            result = (await self.verify_jwt(creds)).user
            logger.info(f"The result is {result}")

        except Exception as e:
            logger.info(e)
            return None
        return result

    async def check_access_with_roles(
        self, creds, allow_roles: list[str] = None
    ) -> None:
        logger.info(f"check {creds} against {allow_roles}")
        user_payload = await self.check_access(creds)
        if user_payload:
            logger.info("check roles if allow")
            if not user_payload.get("roles", None):
                logger.info("User has no roles")

            else:
                if allow_roles:
                    logger.info(f"check if user has permission is {allow_roles}")
                    if not set(allow_roles) & set(user_payload.get("roles", "fake")):
                        return False
                return True
        return False

    async def verify_jwt(self, jwtoken: str) -> bool:
        logger.info("Start to verify")
        try:
            logger.info("Start to get payload from decode_jwt")
            payload = await self.decode_jwt(jwtoken)
            logger.info(f"Get payload from decode_jwt {payload}")
        except:  # noqa
            return None

        if await token_in_blocklist(payload["jti"]):
            logger.info(f"Token {payload['jti']} is in blacklist")
            return None
        logger.info(f"Payload is {payload}")
        return Payload(**payload)

    async def decode_jwt(self, token: str) -> dict:
        logger.info("Start to decode")
        try:
            decoded_token = self.auth_jwt.decode(
                token,
                key=auth_settings.authjwt_secret_key,
                algorithms=auth_settings.authjwt_algorithm,
            )
            logger.info(f"decoded token is {decoded_token}")
            return decoded_token
        except Exception as e:
            logger.error(e)
            return False

    async def logout(self, access_token: str) -> None:
        logger.info(f"Logout user {access_token}")
        decoded_token = await self.decode_jwt(access_token)
        if not decoded_token:
            return False
        logger.info("End session token")
        await self.end_session(decoded_token["jti"], decoded_token["user"]["user_id"])

    async def end_session(self, jti: str, user_id: str):
        logger.info(f"End session for {jti}")

        opposite_jti = await self.get_opposite_token(user_id, jti)

        logger.info(f"opposite jti is {opposite_jti}")
        if opposite_jti:
            await self.revoke_token(jti)
            await self.revoke_token(opposite_jti)

    async def revoke_token(self, jti: UUID):
        await add_jti_to_blocklist(str(jti))

    async def get_opposite_token(self, user_id, jti):
        logger.info(f"To find opposite jti user_id: {user_id}, jti: {jti}")

        query = select(Token.refresh_jti).where(
            and_(Token.user_id == user_id, Token.access_jti == jti)
        )
        result = await self.db.execute(query)
        jti_to_add = result.scalars().first()

        if jti_to_add:
            logger.info(f"Got opposite jti: {jti_to_add}")
            return jti_to_add

        else:
            query = select(Token.access_jti).where(
                and_(Token.user_id == user_id, Token.refresh_jti == jti)
            )
            result = await self.db.execute(query)
            jti_to_add = result.scalars().first()

            if jti_to_add:
                logger.info(f"Got opposite jti: {jti_to_add}")
                return jti_to_add

        return False

    async def refresh_tokens(self, refresh_token: str) -> Optional[TwoTokens]:
        logger.info("From auth service start to refresh token")
        decoded_token = await self.decode_jwt(refresh_token)
        if decoded_token:
            logger.info(f"decoded refresh token: {decoded_token}")
            logger.info("End session token")
            await self.end_session(
                decoded_token["jti"], decoded_token["user"]["user_id"]
            )
            user = await self.get_user_by_email(decoded_token["user"]["email"])
            logger.info(f"get user to refresh: {user}")
            if user:
                if decoded_token["refresh"]:
                    return await self.create_tokens(user, True, decoded_token["user"])
        return False

    async def is_token_in_redis(self, refresh_token: str) -> bool:
        decoded_token = await self.decode_jwt(refresh_token)
        if decoded_token and await self.redis.exists(decoded_token["jti"]):
            return True
        return False

    async def save_token_jti_to_db(
        self, user: User, access_token: str, refresh_token: str
    ) -> bool:
        decoded_access = await self.decode_jwt(access_token)
        decoded_refresh = await self.decode_jwt(refresh_token)
        access_jti = decoded_access["jti"]
        access_exp = decoded_access["exp"]
        refresh_jti = decoded_refresh["jti"]
        refresh_exp = decoded_refresh["exp"]
        token = Token(
            user_id=user.id,
            access_jti=access_jti,
            access_exp=access_exp,
            refresh_jti=refresh_jti,
            refresh_exp=refresh_exp,
        )

        await self.db.create(token, Token)
        return True


@lru_cache()
def get_auth_service(
    db_session: AsyncSession = Depends(get_session),
    redis: Redis = Depends(get_redis),
) -> AuthService:

    db_engine = PostgresqlEngine(db_session)
    base_db = BaseDb(db_engine)
    return AuthService(base_db, redis)
