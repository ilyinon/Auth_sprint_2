import uuid

from api.v1 import films, genres, persons
from core.config import settings
from core.tracer import configure_tracer
from db import elastic, redis
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI, Request
from fastapi.responses import ORJSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from redis.asyncio import Redis

app = FastAPI(
    title=settings.project_name,
    docs_url="/api/v1/films/openapi",
    openapi_url="/api/v1/films/openapi.json",
    default_response_class=ORJSONResponse,
)


if settings.enable_tracer:
    configure_tracer()
    FastAPIInstrumentor.instrument_app(app)


@app.on_event("startup")
async def startup():
    redis.redis = Redis.from_url(settings.redis_dsn)
    elastic.es = AsyncElasticsearch(hosts=[settings.elastic_dsn])


@app.on_event("shutdown")
async def shutdown():
    await redis.redis.close()
    await elastic.es.close()


@app.middleware("http")
async def before_request(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id")
    if not request_id:
        request_id = str(uuid.uuid4())
    # if not request_id:
    #     return ORJSONResponse(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         content={"detail": "X-Request-Id is required"},
    #     )
    return await call_next(request)


app.include_router(films.router, prefix="/api/v1/films", tags=["films"])
app.include_router(genres.router, prefix="/api/v1/genres", tags=["genres"])
app.include_router(persons.router, prefix="/api/v1/persons", tags=["persons"])
