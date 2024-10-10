```bash
https://github.com/ilyinon/Auth_sprint_1
```

0. При настройке интеграции с остальными компонентами нужно корректно заполнить .env, для дев проекта можно скопировать из .env_example.
```bash
cp .env_example .env
```

1. Для запуска auth необходимы redis и pgsql,

Для запуска redis и pgslq
```bash
make infra
```

Для запуска сервиса auth
```bash
make auth
```

Для добавления админа
```bash
docker-compose exec -ti app python cli/manage.py
```

Сервис будет доступ по
```
http://localhost/api/openapi
```



Для добавления новых миграций
```bash
alembic revision --autogenerate -m "Initial migration"
```
