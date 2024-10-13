infra:
	docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d --build

auth: auth_dir
	$(MAKE) infra
	docker-compose -f docker-compose.yml -f docker-compose.override.yml \
	-f auth/app/docker-compose.yml -f auth/app/docker-compose.override.yml \
	up -d --build
	docker logs -f auth_sprint_2-auth-1

auth_dir:
	@:

search: search_dir
	$(MAKE) infra
	docker-compose -f docker-compose.yml -f docker-compose.override.yml \
	-f search/app/docker-compose.yml -f search/app/docker-compose.override.yml \
	up -d --build
	docker logs -f auth_sprint_2-search-1

search_dir:
	@:

test_auth:
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml stop db_test_auth redis_test_auth
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml rm db_test_auth redis_test_auth -f
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml up db_test_auth redis_test_auth -d
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml stop test_auth
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml rm --force test_auth
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml up --build -d
	docker logs auth_sprint_2-test_auth-1 -f

test_search:
	docker-compose -f docker-compose.yml -f search/tests/functional/docker-compose.yml stop test_search
	docker-compose -f docker-compose.yml -f search/tests/functional/docker-compose.yml rm --force test_search
	docker-compose -f docker-compose.yml -f search/tests/functional/docker-compose.yml up -d --build
	docker logs auth_sprint_2-test_search-1 -f



all:
	$(MAKE) infra
	$(MAKE) auth
	$(MAKE) search
	$(MAKE) admin

stop:
	docker-compose -f docker-compose.yml -f auth/app/docker-compose.yml \
	-f search/app/docker-compose.yml -f admin/app/docker-compose.yml down

status:
	docker-compose ps
