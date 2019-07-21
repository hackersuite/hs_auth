include app.env

default: build test

# starts the app
run:
	go run main.go

# runs test
test:
	go test -v -cover ./...

# builds the executable
build:
	go build -o bin/hs_auth main.go

# builds the docker image
docker-build: $(objects)
	@echo "=============building hs_auth============="
	docker build -f docker/prod/Dockerfile -t hs_auth .

# builds the docker image for dev environment
docker-build-dev: $(objects)
	@echo "=============building hs_auth (dev)============="
	docker build -f docker/dev/Dockerfile -t hs_auth .

# sets up the hacker suite docker network
setup-network:
	@echo "=============setting up the hacker suite network============="
	docker network create --driver bridge hacker_suite || echo "This is most likely fine, it just means that the network has already been created"

# starts the app and MongoDB in docker containers
up: docker-build setup-network
	@echo "=============starting hs_auth============="
	docker-compose up -d

# starts the app and MongoDB in docker containers for dev environment
up-dev: docker-build-dev setup-network
	@echo "=============starting hs_auth (dev)============="
	docker-compose up -d

# prints the logs from all containers
logs:
	docker-compose logs -f

# prints the logs only from the go app
logs-app:
	docker-compose logs -f app

# prints the logs only from the database
logs-mongo:
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
