include app.env
export $(shell sed 's/=.*//' app.env)

export GO111MODULE=on

prod_docker_compose_file=./docker/hs_auth/docker-compose.yml
dev_docker_compose_file=./docker/hs_auth_dev/docker-compose.yml
test_docker_compose_file=./docker/hs_auth_test/docker-compose.yml

default: build test

# checks the code for problems
.PHONY: vet
vet:
	go vet

# starts the app
run: vet
	@echo "=============vetting the code============="
	go run main.go wire_gen.go server.go

.PHONY: mocks
mocks: clean-mocks
	@echo "=============generating mocks============="
	grep -rl --exclude "./vendor/*" --include "*.go" "interface {" . | while read -r file ; do mockgen --source=$$file --destination mocks/$$file ; done

# runs test
test: vet mocks
	go test -cover ./...

test-integration: vet mocks
	docker-compose -f $(test_docker_compose_file) up -d
	go test -cover ./... -tags integration

# build target for CI
ci: vet
	grep -rl --exclude "./vendor/*" --include "*.go" "interface {" . | while read -r file ; do mockgen --source=$$file --destination mocks/$$file ; done
	docker-compose -f $(test_docker_compose_file) up -d
	go test ./... -coverprofile=coverage.txt -covermode=atomic -tags integration

# builds the executable
build:
	go build -o bin/hs_auth main.go

# builds the docker image
build-docker:
	@echo "=============building hs_auth============="
	docker build -f docker/hs_auth/Dockerfile -t hs_auth . ;

# sets up the hacker suite docker network
setup-network:
	@echo "=============setting up the hacker suite network============="
	docker network create --driver bridge hacker_suite || echo "This is most likely fine, it just means that the network has already been created"

# starts the app and MongoDB in docker containers
up: vet build-docker setup-network
	@echo "=============starting hs_auth============="
	docker-compose -f $(prod_docker_compose_file) up -d

# starts the app and MongoDB in docker containers for dev environment
up-dev: export ENVIRONMENT=dev
up-dev: export PORT=8000
up-dev: export MONGO_HOST=127.0.0.1:8002
up-dev: vet setup-network
	@echo "=============starting hs_auth (dev)============="
	docker-compose -f $(dev_docker_compose_file) up -d
	refresh run

# prints the logs from all containers
logs:
ifeq ($(ENV), dev)
	docker-compose -f $(dev_docker_compose_file) logs -f
else
	docker-compose -f $(prod_docker_compose_file) logs -f
endif

# prints the logs only from the go app
logs-app:
	docker-compose -f $(prod_docker_compose_file) logs -f hs_auth

# prints the logs only from the database
logs-db:
ifeq ($(ENV), dev)
	docker-compose -f $(dev_docker_compose_file) logs -f mongo
else
	docker-compose -f $(prod_docker_compose_file) logs -f mongo
endif

# shuts down the containers
down:
	docker-compose -f $(prod_docker_compose_file) down
	docker-compose -f $(dev_docker_compose_file) down
	docker-compose -f $(test_docker_compose_file) down

# cleans up unused images, networks and containers
# WARNING: this will delete ALL docker images on the system
#          that are not being used
clean: down
	@echo "=============cleaning up============="
	rm -f hs_auth
	docker container prune -f
	docker network prune -f
	docker system prune -f
	docker volume prune -f

clean-mocks:
	rm -rf ./mocks
