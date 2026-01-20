# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-include .env
export

export DOCKER_BUILDKIT=1

.PHONY: build-all build-enclave network postgres migrate run-api run-gateway run-frontend up down down-clean logs clean clean-enclave
.PHONY: lago-build lago-redis lago-db lago-migrate lago-run lago-up lago-down lago-logs

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

build-metering:
	@echo "Building Metering service..."
	@docker build -t caution-metering -f ./containerfiles/Containerfile.metering .
	@echo "Metering service image built: caution-metering"

build-frontend:
	@echo "Building Frontend..."
	@docker build -t caution-frontend -f ./containerfiles/Containerfile.frontend .
	@echo "Frontend image built: caution-frontend"

build-all: build-gateway build-api build-email build-metering build-frontend

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
			-p 5432:5432 \
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
		-e TERRAFORM_STATE_BUCKET=caution-terraform-state \
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
		-p 8082:8082 \
		caution-email
	@echo "Email service started on http://localhost:8082"

run-metering: network postgres
	@docker rm -f metering 2>/dev/null || true
	@docker run -d \
		--name metering \
		--network $(NETWORK) \
		--env-file .env \
		-e DATABASE_URL=$(DATABASE_URL) \
		-e LAGO_URL=http://lago-api:3000 \
		-e METERING_INTERVAL_SECS=300 \
		caution-metering
	@echo "Metering service started (internal port 8083)"

run-frontend: network
	@docker rm -f frontend 2>/dev/null || true
	@docker run -d \
		--name frontend \
		--network $(NETWORK) \
		-p 3000:3000 \
		--env-file .env \
		caution-frontend
	@echo "Frontend started on port 3000"

# =============================================================================
# Billing / Lago
# =============================================================================

lago-build:
	@echo "Building Lago API from source..."
	@docker build -t caution-lago -f ./containerfiles/Containerfile.lago .
	@echo "Lago image built: caution-lago"

lago-redis: network
	@if docker ps -a --format '{{.Names}}' | grep -q '^lago-redis$$'; then \
		if docker ps --format '{{.Names}}' | grep -q '^lago-redis$$'; then \
			echo "Lago Redis already running"; \
		else \
			echo "Starting existing lago-redis container..."; \
			docker start lago-redis; \
			echo "Lago Redis started"; \
		fi \
	else \
		docker run -d \
			--name lago-redis \
			--network $(NETWORK) \
			redis:7-alpine && \
		echo "Lago Redis started"; \
	fi

lago-db: postgres
	@echo "Creating Lago database..."
	@docker exec postgres psql -U $(DB_USER) -tc "SELECT 1 FROM pg_database WHERE datname = 'lago'" | grep -q 1 || \
		docker exec postgres psql -U $(DB_USER) -c "CREATE DATABASE lago"
	@echo "Lago database ready"

lago-migrate: lago-build lago-db lago-redis
	@echo "Running Lago database migrations..."
	@docker run --rm \
		--network $(NETWORK) \
		-e DATABASE_URL=postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):5432/lago \
		-e REDIS_URL=redis://lago-redis:6379 \
		-e SECRET_KEY_BASE=$${LAGO_SECRET_KEY_BASE:-$$(openssl rand -hex 64)} \
		-e LAGO_RSA_PRIVATE_KEY="$${LAGO_RSA_PRIVATE_KEY}" \
		-e RAILS_ENV=production \
		caution-lago \
		bundle exec rails db:migrate 2>/dev/null || echo "Lago migrations completed (or already up to date)"

lago-run: lago-migrate
	@docker rm -f lago-api lago-worker 2>/dev/null || true
	@echo "Starting Lago API..."
	@docker run -d \
		--name lago-api \
		--network $(NETWORK) \
		-e DATABASE_URL=postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):5432/lago \
		-e REDIS_URL=redis://lago-redis:6379 \
		-e SECRET_KEY_BASE=$${LAGO_SECRET_KEY_BASE:-$$(openssl rand -hex 64)} \
		-e LAGO_RSA_PRIVATE_KEY="$${LAGO_RSA_PRIVATE_KEY}" \
		-e LAGO_API_URL=http://lago-api:3000 \
		-e LAGO_FRONT_URL=http://localhost:3001 \
		-e LAGO_DISABLE_SIGNUP=true \
		-e LAGO_WEBHOOK_URL=http://metering:8083/webhooks/lago \
		-e RAILS_ENV=production \
		-e RAILS_LOG_TO_STDOUT=true \
		caution-lago
	@echo "Starting Lago Worker..."
	@docker run -d \
		--name lago-worker \
		--network $(NETWORK) \
		-e DATABASE_URL=postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):5432/lago \
		-e REDIS_URL=redis://lago-redis:6379 \
		-e SECRET_KEY_BASE=$${LAGO_SECRET_KEY_BASE:-$$(openssl rand -hex 64)} \
		-e LAGO_RSA_PRIVATE_KEY="$${LAGO_RSA_PRIVATE_KEY}" \
		-e RAILS_ENV=production \
		-e RAILS_LOG_TO_STDOUT=true \
		--entrypoint "" \
		caution-lago \
		bundle exec sidekiq -C config/sidekiq.yml
	@echo "Lago services started (API on internal port 3000)"

lago-up: lago-run
	@echo "Lago billing system is running"

lago-down:
	@docker rm -f lago-api lago-worker 2>/dev/null || true
	@docker stop lago-redis 2>/dev/null || true
	@echo "Lago services stopped"

lago-logs:
	@echo "=== Lago API Logs ==="
	@docker logs lago-api 2>&1 | tail -n 30 || true
	@echo "\n=== Lago Worker Logs ==="
	@docker logs lago-worker 2>&1 | tail -n 30 || true
	@echo "\n=== Lago Redis Logs ==="
	@docker logs lago-redis 2>&1 | tail -n 10 || true

# =============================================================================
# Main targets
# =============================================================================

up: build-api build-gateway build-email build-metering build-frontend migrate lago-up run-email run-metering run-api run-frontend
	@echo "Waiting for API to be ready..."
	@sleep 2
	@$(MAKE) run-gateway
	@echo "  All services running"
	@echo "  Frontend: http://localhost:3000 (dev server with hot reload)"
	@echo "  Gateway: http://localhost:8000"
	@echo "  SSH: localhost:2222"
	@echo "  API: internal only (http://api:8080)"
	@echo "  Metering: internal only (http://metering:8083)"
	@echo "  Lago: internal only (http://lago-api:3000)"
	@echo "  Postgres: localhost:5432"
	@echo ""
	@echo "Database is persistent - safe to run 'make down' without losing data"

down:
	@docker rm -f gateway api email metering frontend 2>/dev/null || true
	@$(MAKE) lago-down
	@docker stop postgres 2>/dev/null || true
	@echo "Services stopped (postgres data preserved)"
	@echo "Run 'make up' to restart"
	@echo "Run 'make down-clean' to remove all data"

down-clean:
	@docker rm -f gateway api email metering frontend lago-api lago-worker lago-redis postgres 2>/dev/null || true
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
	@echo "\n=== Metering Service Logs ==="
	@docker logs metering 2>&1 | tail -n 20 || true
	@echo "\n=== Frontend Logs ==="
	@docker logs frontend 2>&1 | tail -n 20 || true
	@echo "\n=== Postgres Logs ==="
	@docker logs postgres 2>&1 | tail -n 20 || true
	@echo "\n(Run 'make lago-logs' for Lago billing logs)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUT_DIR)
	@docker rmi -f caution-cli caution-gateway caution-api caution-email caution-metering caution-frontend caution-lago 2>/dev/null || true
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
	@docker ps -a --filter "name=gateway" --filter "name=api" --filter "name=email" --filter "name=metering" --filter "name=frontend" --filter "name=postgres" --filter "name=lago-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo "\n=== Volume Status ==="
	@docker volume ls --filter "name=$(DB_VOLUME)"
	@echo "\n=== Network Status ==="
	@docker network ls --filter "name=$(NETWORK)"
