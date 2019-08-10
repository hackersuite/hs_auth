include app.env

default: build test

# checks the code for problems
.PHONY: vet
vet:
	go vet

# starts the app
run: vet
	@echo "=============vetting the code============="
	go run main.go

# runs test
test: vet
	go test -v -cover ./...

# builds the executable
build:
	go build -o bin/hs_auth main.go

# builds the docker image
build-docker: $(objects)
	@echo "=============building hs_auth============="
	if docker image ls | grep -qw hs_auth; then \
		echo "image already exists, skipping build"; \
	else \
		echo "creating new image"; \
		docker build -f docker/dev/Dockerfile -t hs_auth . ;\
	fi

# builds the docker image for dev environment
build-docker-dev: $(objects)
	@echo "=============building hs_auth_dev============="
	if docker image ls | grep -qw hs_auth_dev; then \
		echo "image already exists, skipping build"; \
	else \
		echo "creating new image"; \
		docker build -f docker/dev/Dockerfile -t hs_auth_dev . ;\
	fi

# sets up the hacker suite docker network
setup-network:
	@echo "=============setting up the hacker suite network============="
	docker network create --driver bridge hacker_suite || echo "This is most likely fine, it just means that the network has already been created"

# starts the app and MongoDB in docker containers
up: vet build-docker setup-network
	@echo "=============starting hs_auth============="
	docker-compose up -d

# starts the app and MongoDB in docker containers for dev environment
up-dev: vet build-docker-dev setup-network
	@echo "=============starting hs_auth (dev)============="
	docker-compose up -d

# prints the logs from all containers
logs:
	docker-compose logs -f

# prints the logs only from the go app
logs-app:
	docker-compose logs -f hs_auth

# prints the logs only from the database
logs-db:
	docker-compose logs -f mongo

# shuts down the containers
down:
	docker-compose down

# cleans up unused images, networks and containers
clean: down
	@echo "=============cleaning up============="
	rm -f hs_auth
	docker container prune -f
	docker network prune -f
	docker system prune -f
	docker volume prune -f
