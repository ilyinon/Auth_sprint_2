infra:
	docker-compose -f docker-compose.yml up -d --build

auth:
	$(MAKE) infra
	docker-compose -f docker-compose.yml -f app/docker-compose.yml up -d --build

test:
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml stop db_test redis_test
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml rm db_test redis_test -f
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml up db_test redis_test -d
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml stop test
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml rm --force test
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml up --build -d
	docker logs auth_sprint_1-test-1 -f

test_info:
	docker-compose -f docker-compose.yml -f tests/functional/docker-compose.yml logs -f test

all:
	$(MAKE) infra
	$(MAKE) api
	$(MAKE) test

stop:
	docker-compose -f docker-compose.yml -f app/docker-compose.yml -f tests/functional/docker-compose.yml down

status:
	docker-compose ps

logs:
	docker-compose logs -f

lint:
	pre-commit install
	flake8 app
	isort app
