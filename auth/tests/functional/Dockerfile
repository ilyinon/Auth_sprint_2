FROM python:3.12.4-slim


ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH '/opt/tests'


WORKDIR /opt

COPY tests/functional/requirements.txt /opt/requirements.txt
RUN  pip install --upgrade pip \
     && pip install --no-cache-dir -r /opt/requirements.txt

COPY tests/functional/ /opt/tests/functional
COPY app/models/* /opt/tests/models/
COPY app/alembic /opt/alembic
COPY app/alembic.ini /opt/
COPY tests/core /opt/tests/core
COPY tests/utils /opt/tests/utils

RUN mv /opt/tests/functional/conftest.py /opt/tests/conftest.py && \
    mv /opt/tests/functional/fixtures /opt/tests/ && \
    chmod -R 755 /opt/tests && \
    sed -i 's/core.config/tests.core.config/g' /opt/alembic/env.py && \
    sed -i 's/app.models./tests.models./g' /opt/tests/models/* && \
    sed -i 's/app.models./tests.models./g' /opt/alembic/env.py




ENTRYPOINT \
  python3 tests/utils/wait_for_pg.py && \
  python3 tests/utils/wait_for_redis.py && \
  alembic upgrade head && find /opt/ && \
  python3 -m pytest tests -vvv --disable-warnings
