.PHONY: dev test build clean docker-up docker-down docker-build

dev:
	npm run dev

test:
	npm test

build:
	npm run build

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf dist node_modules secrets
