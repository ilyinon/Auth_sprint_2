#!/usr/bin/env bash

set -ev

echo "Verifying if db is available .."
while !</dev/tcp/db/5432; do "Trying to connect to db .. "; sleep 3; done;
python manage.py collectstatic --noinput
python manage.py migrate --noinput
uwsgi --strict --ini uwsgi.ini
