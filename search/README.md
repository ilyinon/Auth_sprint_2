```bash
https://github.com/ilyinon/Async_API_sprint_2
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

И наконец запускаем админку
```bash
make admin
```


2. Для доступа к openapi используй пути
```bash
http://localhost/api/v1/auth/openapi
http://localhost/api/v1/films/openapi

```

3. Для запуска тестов нужно выполнить следующую команду

Для запуска тестов
```bash
make test_auth
```

Для запуска тестов
```bash
make test_search
```
