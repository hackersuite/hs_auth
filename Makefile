default:
	@echo "=============building docker image============="
	docker build -t hs_auth .

up: default
	@echo "=============starting app============="
	docker-compose up -d

logs:
	docker-compose logs -f

down:
	docker-compose down

test:
	go test -v -cover ./...

clean: down
	@echo "=============cleaning up============="
	rm -f hs_auth
	docker system prune -f
	docker volume prune -f
