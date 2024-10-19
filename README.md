```bash
https://github.com/ilyinon/Auth_sprint_2
```


### 0. Подготовка переменных

При настройке интеграции с остальными компонентами нужно корректно заполнить .env, для дев проекта можно скопировать из .env_example.
```bash
cp .env_example .env
```

### 1. Запуск проекта

##### Первым шагом запускаем postgres, elastic и redis
```bash
make infra
```

##### Вторым шагом запускаем Auth
```bash
make auth
```

##### Третьим шагом запускаем Search, сервис поиска фильмов
```bash
make search
```

##### И наконец запускаем админку, создаём таблицу content
```bash
make admin_init
```

```bash
make admin
```

##### добавить админа
```bash
docker-compose exec -ti app python cli/manage.py
```


### 2. Для доступа к openapi используй пути
```bash
http://localhost/api/v1/auth/openapi
http://localhost/api/v1/films/openapi

```

для доступа к админке. Использовать нужно пользователей добавленных на Auth сервере. Пустить только в admin ролью.
```bash
http://localhost/admin
```


### 3. Для запуска тестов нужно выполнить следующие команду

##### Для запуска тестов auth
```bash
make test_auth
```

##### Для запуска тестов search
```bash
make test_search
```


### 4. Общая схема:


https://www.plantuml.com/plantuml/png/u-9oA2v9B2efpStXihem_yA-2xilzbpO3gGtNTXmiUd2LX3VIa51LzTEGSCdFp55mIan9p4lERMeM9EBAoy_9LL12LLOIQ6QIq4XsYyzCw_2K4_FBrQ1YwiMfZGuDR4eEKF1DGyecmfL2HLpB2Y8HIXqB2r1KmOKmL2KafkPbvq8LG3bmTI00P8pG5v0iGnT4cu5fXIQuKYcOEf4gCIK18EKn9B4fCHYeFi3yejBqejIYv5zwE8K2s8xv-ULfEQLWBcro7fSSnABIpAJWLfGnODIKpAB8QAORa0r3zFvK4EnIO7D1Kg078SGHhWLpC9Kxv2Qbm9AKm00
