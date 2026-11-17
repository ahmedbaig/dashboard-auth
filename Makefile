APP        := dashboard-auth
CMD        := ./cmd/server
PORT       := 8081
ENV_DIR    ?= $(abspath $(CURDIR)/../dashboard-env)
CONFIG_DIR ?= $(ENV_DIR)/var/secrets

include make/go.mk

.PHONY: setup proto migrate seed api-docs

setup: ## create configs and keys in dashboard-env (keeps existing ones)
	$(ENV_DIR)/scripts/init-config.sh
	$(ENV_DIR)/scripts/gen-keys.sh

proto: ## regenerate proto/gen/go and proto/openapi from proto/dashboard
	cd proto && PATH=$(HOME)/go/bin:$$PATH buf lint && PATH=$(HOME)/go/bin:$$PATH buf generate

migrate: ## apply migrations/*.sql to the dashboard database
	CONFIG_DIR=$(CONFIG_DIR) scripts/migrate.sh

seed: ## insert the first users from $(CONFIG_DIR)/dashboard-auth-seed.sql (see seeds/admin.sql.sample)
	CONFIG_DIR=$(CONFIG_DIR) scripts/seed.sh

api-docs: proto ## lint the OpenAPI spec and upload it to Postman
	scripts/push-api-docs.sh
