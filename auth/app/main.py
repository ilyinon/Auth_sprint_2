from api.v1 import auth, roles, users
from core.config import auth_settings
from db import redis
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from redis.asyncio import Redis

app = FastAPI(
    title=auth_settings.project_name,
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    default_response_class=ORJSONResponse,
)


@app.on_event("startup")
async def startup():
    redis.redis = Redis.from_url(auth_settings.redis_dsn)


@app.on_event("shutdown")
async def shutdown():
    await redis.redis.close()


app.include_router(auth.router, prefix="/api/v1/auth")
app.include_router(roles.router, prefix="/api/v1/roles")
app.include_router(users.router, prefix="/api/v1/users")
