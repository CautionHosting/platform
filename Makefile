# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-include .env
export

export DOCKER_BUILDKIT=1

.PHONY: build-all build-enclave network postgres migrate run-api run-gateway run-frontend up up-dev down down-clean logs clean clean-enclave build-cli release-cli sign-cli verify-cli reproduce-cli test test-unit

OUT_DIR := out
ENCLAVE_OUT_DIR := $(OUT_DIR)/enclave
NETWORK := caution-network
DB_NAME ?= caution
DB_USER ?= postgres
DB_PASSWORD ?= postgres
DB_HOST ?= postgres
DATABASE_URL ?= postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):5432/$(DB_NAME)
DB_VOLUME := caution-postgres-data
SSH_PORT ?= 2222
CAUTION_DATA_DIR ?= $(PWD)/caution-cache
CONTAINER_DATA_DIR := /var/cache/caution

ifdef NOCACHE
	NO_CACHE := --no-cache
endif

DEV_BUILD_ARGS := --build-arg CARGO_BUILD_FLAGS="" --build-arg CARGO_PROFILE_DIR="debug" --build-arg EXTRA_RUSTFLAGS=""

build-gateway:
	@echo "Building Gateway binary..."
	@mkdir -p $(OUT_DIR)
	@docker rmi -f caution-gateway 2>/dev/null || true
	@docker build -t caution-gateway -f ./containerfiles/Containerfile.gateway .
	@echo "Gateway image build complete"

build-api:
	@echo "Building API service..."
	@docker build -t caution-api -f ./containerfiles/Containerfile.api .
	@echo "API service image built: caution-api"

build-email:
	@echo "Building Email service..."
	@docker build -t caution-email -f ./containerfiles/Containerfile.email-service .
	@echo "Email service image built: caution-email"

build-gateway-dev:
	@echo "Building Gateway binary (dev)..."
	@mkdir -p $(OUT_DIR)
	@docker rmi -f caution-gateway 2>/dev/null || true
	@docker build -t caution-gateway $(DEV_BUILD_ARGS) -f ./containerfiles/Containerfile.gateway .
	@echo "Gateway dev image build complete"

build-api-dev:
	@echo "Building API service (dev)..."
	@docker build -t caution-api $(DEV_BUILD_ARGS) -f ./containerfiles/Containerfile.api .
	@echo "API dev service image built: caution-api"

build-email-dev:
	@echo "Building Email service (dev)..."
	@docker build -t caution-email $(DEV_BUILD_ARGS) -f ./containerfiles/Containerfile.email-service .
	@echo "Email dev service image built: caution-email"

build-frontend:
	@echo "Building Frontend..."
	@docker build -t caution-frontend -f ./containerfiles/Containerfile.frontend .
	@echo "Frontend image built: caution-frontend"

# CLI release variables
CLI_VERSION := $(shell grep '^version' src/cli/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
CLI_BINARY := caution-linux-x86_64
CLI_OUT_DIR := $(OUT_DIR)/cli
GIT_REF := $(shell git log -1 --format=%H)
GIT_AUTHOR := $(shell git log -1 --format=%an)
GIT_PUBKEY := $(shell git log -1 --format=%GK)
GIT_TIMESTAMP := $(shell git log -1 --format=%cd --date=iso)
GPG ?= gpg

ifdef REPRODUCE
	-include dist/cli/release.env
	export
endif

build-cli:
	@echo "Building CLI binary..."
	@mkdir -p $(CLI_OUT_DIR)
	@docker build \
		--progress=plain \
		--build-arg SOURCE_DATE_EPOCH=1 \
		$(NO_CACHE) \
		-t caution-cli \
		-f ./containerfiles/Containerfile.cli \
		--target export \
		.
	@docker rm -f cli-extract 2>/dev/null || true
	@docker create --name cli-extract caution-cli
	@docker cp cli-extract:/caution $(CLI_OUT_DIR)/$(CLI_BINARY)
	@docker rm cli-extract
	@echo "CLI binary available at $(CLI_OUT_DIR)/$(CLI_BINARY)"

release-cli:
	@$(MAKE) build-cli NOCACHE=1
	@mkdir -p $(CLI_OUT_DIR)
	@echo 'VERSION=$(CLI_VERSION)'              > $(CLI_OUT_DIR)/release.env
	@echo 'GIT_REF=$(GIT_REF)'                 >> $(CLI_OUT_DIR)/release.env
	@echo 'GIT_AUTHOR=$(GIT_AUTHOR)'           >> $(CLI_OUT_DIR)/release.env
	@echo 'GIT_PUBKEY=$(GIT_PUBKEY)'           >> $(CLI_OUT_DIR)/release.env
	@echo 'GIT_TIMESTAMP=$(GIT_TIMESTAMP)'     >> $(CLI_OUT_DIR)/release.env
	@openssl sha256 -r \
		$(CLI_OUT_DIR)/$(CLI_BINARY) \
		$(CLI_OUT_DIR)/release.env \
	| sed -e 's| \*$(CLI_OUT_DIR)/| |g' -e 's| \./| |g' \
	> $(CLI_OUT_DIR)/manifest.txt
	@rm -rf dist/cli/*
	@mkdir -p dist/cli
	@cp $(CLI_OUT_DIR)/$(CLI_BINARY) $(CLI_OUT_DIR)/release.env $(CLI_OUT_DIR)/manifest.txt dist/cli/
	@echo ""
	@echo "Release assets in dist/cli/:"
	@ls -lh dist/cli/
	@echo ""
	@echo "Next steps:"
	@echo "  1. make sign-cli"
	@echo "  2. git add dist/cli/ && git commit -m 'Release CLI $(CLI_VERSION)'"
	@echo "  3. git push"

sign-cli:
	@set -e; \
	git config --get user.signingkey 2>&1 >/dev/null || { \
		echo "Error: git user.signingkey is not defined"; \
		exit 1; \
	}; \
	keyid=$$(git config --get user.signingkey); \
	fingerprint=$$(echo "$$keyid" | sed 's/.*\([A-Z0-9]\{16\}\).*/\1/g'); \
	$(GPG) --armor \
		--detach-sig \
		--local-user "$$keyid" \
		--output dist/cli/manifest.$${fingerprint}.asc \
		dist/cli/manifest.txt; \
	cp dist/cli/manifest.$${fingerprint}.asc $(CLI_OUT_DIR)/; \
	echo "Signed: dist/cli/manifest.$${fingerprint}.asc"

verify-cli: | dist/cli/manifest.txt
	@set -e; \
	for file in dist/cli/manifest.*.asc; do \
		echo "\nVerifying: $${file}\n"; \
		$(GPG) --verify $${file} dist/cli/manifest.txt; \
	done

reproduce-cli:
	@rm -rf $(CLI_OUT_DIR)
	@$(MAKE) build-cli REPRODUCE=true NOCACHE=1
	@diff -q $(CLI_OUT_DIR)/manifest.txt dist/cli/manifest.txt
	@echo "Reproduction successful - manifests match"

install-cli: build-cli
	@install -D -m 0755 $(CLI_OUT_DIR)/$(CLI_BINARY) $(HOME)/.local/bin/caution
	@echo "Installed caution to $(HOME)/.local/bin/caution"

build-all: build-gateway build-api build-email build-frontend build-cli

network:
	@docker network inspect $(NETWORK) >/dev/null 2>&1 || \
		(docker network create $(NETWORK) && echo "✓ Network $(NETWORK) created")

volume:
	@docker volume inspect $(DB_VOLUME) >/dev/null 2>&1 || \
		(docker volume create $(DB_VOLUME) && echo "✓ Volume $(DB_VOLUME) created")

postgres: network volume
	@if docker ps -a --format '{{.Names}}' | grep -q '^postgres$$'; then \
		if docker ps --format '{{.Names}}' | grep -q '^postgres$$'; then \
			echo "Postgres already running"; \
		else \
			echo "Starting existing postgres container..."; \
			docker start postgres; \
			sleep 2; \
			echo "Postgres started"; \
		fi \
	else \
		docker run -d \
			--name postgres \
			--network $(NETWORK) \
			-v $(DB_VOLUME):/var/lib/postgresql/data \
			-e POSTGRES_DB=$(DB_NAME) \
			-e POSTGRES_USER=$(DB_USER) \
			-e POSTGRES_PASSWORD=$(DB_PASSWORD) \
			-p 127.0.0.1:5432:5432 \
			postgres:16-alpine && \
		echo "Postgres started, waiting for ready..." && \
		sleep 5 && \
		until docker exec postgres pg_isready -U $(DB_USER) > /dev/null 2>&1; do \
			echo "   Waiting for postgres..."; \
			sleep 1; \
		done && \
		echo "Postgres ready"; \
	fi

migrate: postgres
	@echo "Running migrations..."
	@for migration in src/api/migrations/*.sql; do \
		echo "Applying $$(basename $$migration)..."; \
		docker run --rm \
			--network $(NETWORK) \
			-v $(PWD)/src/api/migrations:/migrations:ro \
			-e PGPASSWORD=$(DB_PASSWORD) \
			postgres:16-alpine \
			psql -h $(DB_HOST) -U $(DB_USER) -d $(DB_NAME) -f /migrations/$$(basename $$migration) || true; \
	done
	@echo "Migrations complete"

run-api: network postgres
	@docker rm -f api 2>/dev/null || true
	@mkdir -p $(CAUTION_DATA_DIR)/git-repos $(CAUTION_DATA_DIR)/build $(CAUTION_DATA_DIR)/terraform
	@docker run -d \
		--name api \
		--network $(NETWORK) \
		--dns 8.8.8.8 \
		--dns 8.8.4.4 \
		--group-add $$(stat -c '%g' /var/run/docker.sock) \
		-e AWS_REGION=us-west-2 \
		-e CAUTION_DATA_DIR=$(CONTAINER_DATA_DIR) \
		-e TF_PLUGIN_CACHE_DIR=$(CONTAINER_DATA_DIR)/terraform \
		-e DATABASE_URL=$(DATABASE_URL) \
		--env-file .env \
		-v $(PWD)/terraform:/app/terraform:ro \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(CAUTION_DATA_DIR):$(CONTAINER_DATA_DIR) \
		caution-api
	@echo "API service started (internal port 8080)"

run-gateway: network
	@docker rm -f gateway 2>/dev/null || true
	@mkdir -p $(CAUTION_DATA_DIR)/git-repos
	@docker run -d \
		--name gateway \
		--network $(NETWORK) \
		-p 8000:8080 \
		-p $(SSH_PORT):$(SSH_PORT) \
		--env-file .env \
		-e DATABASE_URL=$(DATABASE_URL) \
		-e SSH_PORT=$(SSH_PORT) \
		-e SSH_HOST_KEY_PATH=$(CONTAINER_DATA_DIR)/ssh_host_ed25519_key \
		-e CAUTION_DATA_DIR=$(CONTAINER_DATA_DIR) \
		-v $(CAUTION_DATA_DIR):$(CONTAINER_DATA_DIR) \
		caution-gateway
	@echo "Gateway started on port 8000 (HTTP) and $(SSH_PORT) (SSH)"

run-email: network
	@docker rm -f email 2>/dev/null || true
	@docker run -d \
		--name email \
		--network $(NETWORK) \
		--env-file .env \
		-e FRONTEND_URL=http://localhost:3000 \
		caution-email
	@echo "Email service started (internal port 8082)"

run-frontend: network
	@docker rm -f frontend 2>/dev/null || true
	@docker run -d \
		--name frontend \
		--network $(NETWORK) \
		-p 3000:3000 \
		--env-file .env \
		caution-frontend
	@echo "Frontend started on port 3000"

up: migrate
	@echo "Building all images in parallel..."
	@$(MAKE) -j4 build-api build-gateway build-email build-frontend
	@$(MAKE) run-email run-api run-frontend
	@echo "Waiting for API to be ready..."
	@sleep 2
	@$(MAKE) run-gateway
	@echo "  All services running"
	@echo "  Frontend: http://localhost:3000 (dev server with hot reload)"
	@echo "  Gateway: http://localhost:8000"
	@echo "  SSH: localhost:2222"
	@echo "  API: internal only (http://api:8080)"
	@echo "  Postgres: localhost:5432"
	@echo ""
	@echo "Database is persistent - safe to run 'make down' without losing data"

up-dev: migrate
	@echo "Building all images in parallel (dev)..."
	@$(MAKE) -j4 build-api-dev build-gateway-dev build-email-dev build-frontend
	@$(MAKE) run-email run-api run-frontend
	@echo "Waiting for API to be ready..."
	@sleep 2
	@$(MAKE) run-gateway
	@echo "  All services running (dev builds)"
	@echo "  Frontend: http://localhost:3000 (dev server with hot reload)"
	@echo "  Gateway: http://localhost:8000"
	@echo "  SSH: localhost:2222"
	@echo "  API: internal only (http://api:8080)"
	@echo "  Postgres: localhost:5432"
	@echo ""
	@echo "Database is persistent - safe to run 'make down' without losing data"

down:
	@docker rm -f gateway api email frontend 2>/dev/null || true
	@docker stop postgres 2>/dev/null || true
	@echo "Services stopped (postgres data preserved)"
	@echo "Run 'make up' to restart"
	@echo "Run 'make down-clean' to remove all data"

down-clean:
	@docker rm -f gateway api email frontend postgres 2>/dev/null || true
	@docker volume rm $(DB_VOLUME) 2>/dev/null || true
	@docker network rm $(NETWORK) 2>/dev/null || true
	@echo "All services and data removed"

logs:
	@echo "=== Gateway Logs ==="
	@docker logs gateway 2>&1 | tail -n 20 || true
	@echo "\n=== API Logs ==="
	@docker logs api 2>&1 | tail -n 20 || true
	@echo "\n=== Email Service Logs ==="
	@docker logs email 2>&1 | tail -n 20 || true
	@echo "\n=== Frontend Logs ==="
	@docker logs frontend 2>&1 | tail -n 20 || true
	@echo "\n=== Postgres Logs ==="
	@docker logs postgres 2>&1 | tail -n 20 || true

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUT_DIR)
	@docker rmi -f caution-cli caution-gateway caution-api caution-email caution-frontend 2>/dev/null || true
	@echo "Clean complete"

clean-enclave:
	@echo "Cleaning enclave artifacts..."
	@rm -rf $(ENCLAVE_OUT_DIR)
	@echo "Enclave artifacts cleaned"

db-shell:
	@docker exec -it postgres psql -U $(DB_USER) -d $(DB_NAME)

db-reset: down-clean
	@echo "Resetting database..."
	@$(MAKE) up

status:
	@echo "=== Container Status ==="
	@docker ps -a --filter "name=gateway" --filter "name=api" --filter "name=email" --filter "name=frontend" --filter "name=postgres" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo "\n=== Volume Status ==="
	@docker volume ls --filter "name=$(DB_VOLUME)"
	@echo "\n=== Network Status ==="
	@docker network ls --filter "name=$(NETWORK)"

test-unit:
	cargo test --workspace

test: test-unit
