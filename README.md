```bash
https://github.com/ilyinon/Auth_sprint_2
```


0. При настройке интеграции с остальными компонентами нужно корректно заполнить .env, для дев проекта можно скопировать из .env_test.
```bash
cp .env_test .env
```

1. Запуск проекта

Первым шагом запускаем postgres, elastic и redis
```bash
make infra
```

Вторым шагом запускаем Auth
```bash
make auth
```

Третьим шагом запускаем Search, сервис поиска фильмов
```bash
make search
```

И наконец запускаем админку, создаём таблицу content
```bash
make admin_init
```

```bash
make admin
```

добавить админа
```bash
docker-compose exec -ti app python cli/manage.py
```


2. Для доступа к openapi используй пути
```bash
http://localhost/api/v1/auth/openapi
http://localhost/api/v1/films/openapi

```

для доступа к админке. Использовать нужно пользователей добавленных на Auth сервере. Пустить только в admin ролью.
```bash
http://localhost/admin
```


3. Для запуска тестов нужно выполнить следующие команду

Для запуска тестов auth
```bash
make test_auth
```

Для запуска тестов search
```bash
make test_search
```


4. Общая схема:


![Image alt](https://github.com/ilyinon/Auth_sprint_2/raw/dev_prepare_for_review_1/schema.png)
