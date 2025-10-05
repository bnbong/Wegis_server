.PHONY: help build up down logs shell test test-up test-down clean

# Default target
help: ## Show this help message
	@echo "Wegis Server Docker Management"
	@echo "=============================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development Environment
build: ## Build the Docker images
	docker-compose build

up: ## Start all services in development mode
	docker-compose up -d
	@echo "Services are starting up..."
	@echo "Waiting for health checks to pass..."
	@docker-compose ps
	@echo "Server will be available at http://localhost:8000"
	@echo "API docs at http://localhost:8000/docs"

up-logs: ## Start all services and follow logs
	docker-compose up

down: ## Stop all services
	docker-compose down

logs: ## Show logs for all services
	docker-compose logs -f

logs-server: ## Show logs for wegis-server only
	docker-compose logs -f wegis-server

shell: ## Open shell in the wegis-server container
	docker-compose exec wegis-server /bin/bash

db-only: ## Start only database services (PostgreSQL, Redis, MongoDB)
	docker-compose up -d postgres redis mongodb

# Test Environment
test-up: ## Start test environment
	docker-compose -f docker-compose.test.yml up -d
	@echo "Test databases are ready"
	@echo "PostgreSQL: localhost:5433"
	@echo "Redis: localhost:6380"
	@echo "MongoDB: localhost:27018"

test-down: ## Stop test environment
	docker-compose -f docker-compose.test.yml down

test: ## Run tests against test database
	@if [ ! -f env.test ]; then echo "Please create env.test file first"; exit 1; fi
	@echo "Setting up test environment..."
	$(MAKE) test-up
	@echo "Waiting for test databases to be ready..."
	@sleep 10
	@echo "Running tests..."
	ENV_FILE=env.test python -m pytest tests/ -v
	@echo "Cleaning up test environment..."
	$(MAKE) test-down

test-logs: ## Show test environment logs
	docker-compose -f docker-compose.test.yml logs -f

# Utility Commands
clean: ## Clean up all containers, volumes, and images
	docker-compose down -v --remove-orphans
	docker-compose -f docker-compose.test.yml down -v --remove-orphans
	docker system prune -f

reset: ## Reset all data (WARNING: This will delete all data!)
	@echo "WARNING: This will delete all data!"
	@read -p "Are you sure? Type 'yes' to continue: " confirm && [ "$$confirm" = "yes" ]
	$(MAKE) clean
	docker volume rm $$(docker volume ls -q --filter name=wegis) 2>/dev/null || true

health: ## Check health of all services
	@echo "Checking service health..."
	@docker-compose ps

# Development Helpers
dev-setup: ## Setup development environment
	@echo "Setting up development environment..."
	@if [ ! -f .env ]; then cp env.example .env && echo "Created .env file from example"; fi
	@if [ ! -f env.test ]; then echo "Created env.test file"; fi
	$(MAKE) build
	$(MAKE) db-only
	@echo "Development environment is ready!"
	@echo "Edit .env file with your settings, then run 'make up'"

migrate: ## Run database migrations
	docker-compose exec wegis-server alembic upgrade head

migrate-create: ## Create a new migration (usage: make migrate-create MESSAGE="your message")
	docker-compose exec wegis-server alembic revision --autogenerate -m "$(MESSAGE)"

# Monitoring
monitor: ## Monitor resource usage
	@echo "Container Resource Usage:"
	@docker stats --no-stream $$(docker-compose ps -q)

# Security
security-scan: ## Run security scan on images
	@command -v trivy >/dev/null 2>&1 || { echo "Trivy not installed. Install it first."; exit 1; }
	trivy image wegis_server
