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
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml stop test
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml rm --force test
	docker-compose -f docker-compose.yml -f auth/tests/functional/docker-compose.yml up -d --build

test_search:
	docker-compose -f docker-compose.yml -f search/tests/functional/docker-compose.yml stop test
	docker-compose -f docker-compose.yml -f search/tests/functional/docker-compose.yml rm --force test
	docker-compose -f docker-compose.yml -f search/tests/functional/docker-compose.yml up -d --build


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
