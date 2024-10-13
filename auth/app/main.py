from api.v1 import auth, oauth, roles, session, signup, users
from core.config import auth_settings
from db import redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from redis.asyncio import Redis

# from fastapi.openapi.docs import get_swagger_ui_html
# from fastapi.openapi.utils import get_openapi


app = FastAPI(
    title=auth_settings.project_name,
    docs_url="/api/v1/auth/openapi",
    openapi_url="/api/v1/auth/openapi.json",
    default_response_class=ORJSONResponse,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.on_event("startup")
async def startup():
    redis.redis = Redis.from_url(auth_settings.redis_dsn)


@app.on_event("shutdown")
async def shutdown():
    await redis.redis.close()


# @app.get("/api/openapi", include_in_schema=False)
# async def get_documentation():
#     return get_swagger_ui_html(openapi_url="/api/openapi.json", title="Swagger")

app.include_router(signup.router, prefix="/api/v1/auth")
app.include_router(auth.router, prefix="/api/v1/auth")
app.include_router(oauth.router, prefix="/api/v1/auth")

app.include_router(roles.router, prefix="/api/v1/roles")
app.include_router(users.router, prefix="/api/v1/users")
app.include_router(session.router, prefix="/api/v1/users")
