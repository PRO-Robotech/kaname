# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

BINARY         := kacho-iam
CMD            := ./cmd/kacho-iam
# Отдельный binary мигратора.
MIGRATOR_BIN   := kacho-migrator
MIGRATOR_CMD   := ./cmd/migrator
IMAGE          := kacho-iam:dev

.PHONY: build build-migrator test test-short vet lint docker sync-migrations generate
.PHONY: proto-install-plugins proto-vendor proto-lint proto-gen

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) $(CMD)

build-migrator:
	CGO_ENABLED=0 go build -o bin/$(MIGRATOR_BIN) $(MIGRATOR_CMD)

test:
	go test ./... -race -cover -timeout 300s

test-short:
	go test ./... -race -cover -short -timeout 120s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Общая `operations`-таблица из kacho-corelib/migrations/common/0001_operations.sql
# встроена inline в internal/migrations/0001_initial.sql под схемой kacho_iam.
# Re-копирование common-файла создало бы конфликтующий unqualified
# public.operations — отсюда no-op.
sync-migrations:
	@echo "sync-migrations is a no-op — common operations table is inline in"
	@echo "internal/migrations/0001_initial.sql under schema kacho_iam."

docker:
	docker build -f Dockerfile -t $(IMAGE) .

.PHONY: migrate-up migrate-down migrate-status
# migrate-* дергают отдельный binary `bin/kacho-migrator`.
# Зависимость на build-migrator гарантирует, что bin/ актуальный.
migrate-up: build-migrator
	KACHO_IAM_DB_PASSWORD=secret bin/$(MIGRATOR_BIN) up

migrate-down: build-migrator
	KACHO_IAM_DB_PASSWORD=secret bin/$(MIGRATOR_BIN) down

migrate-status: build-migrator
	KACHO_IAM_DB_PASSWORD=secret bin/$(MIGRATOR_BIN) status

# proto-install-plugins — ставит protoc-плагины в $GOBIN (lookup через $PATH для buf).
# Доменный proto iam генерируется этими тремя плагинами.
proto-install-plugins:
	go install google.golang.org/protobuf/cmd/protoc-gen-go
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway

# proto-vendor — подтягивает универсальные инфра-протосы из kacho-corelib (единственный
# источник) в proto/ ТОЛЬКО для buf-резолва импортов доменного proto. В git этих файлов
# нет (gitignored) — их Go-stubs живут в kacho-corelib / canonical genproto, kacho-iam их
# не владеет и не дублирует. Цель идемпотентна: копирует поверх локальной копии.
CORELIB_PROTO  := ../kacho-corelib/proto
VENDORED_PROTOS := \
	google/api/annotations.proto \
	google/api/field_behavior.proto \
	google/api/http.proto \
	google/rpc/status.proto \
	kacho/cloud/api/operation.proto \
	kacho/cloud/operation/operation.proto \
	kacho/cloud/validation.proto \
	kacho/iam/authz/v1/authz_options.proto

proto-vendor:
	@for f in $(VENDORED_PROTOS); do \
		mkdir -p proto/$$(dirname $$f); \
		cp $(CORELIB_PROTO)/$$f proto/$$f; \
	done

proto-lint: proto-vendor
	cd proto && buf lint

# proto-gen — регенерация Go-stubs доменного proto iam (kacho/cloud/iam/v1) из proto/.
# Универсальная ИНФРА (operation/validation/authz_options/cloud-api/google) подтягивается
# из corelib через proto-vendor только для buf-резолва импортов и НЕ генерируется (Go-stubs
# живут в kacho-corelib / canonical genproto) — см. proto/buf.gen.yaml inputs.paths.
proto-gen: proto-vendor
	cd proto && buf generate

# permission_catalog.json — runtime-embedded grant-catalog для
# InternalIAMService.ListPermissions / PermissionCatalogService. Файл закоммичен и
# встроен через //go:embed (internal/apps/kacho/seed/embedded/permission_catalog.json),
# поэтому iam собирается standalone. Полный catalog по транзитивному набору всех
# доменных service.proto собирается в api-gateway (catalog god-node) — обновление
# этого зеркала прилетает оттуда. Локально это no-op.
.PHONY: sync-permission-catalog
sync-permission-catalog:
	@echo "sync-permission-catalog is a no-op — permission_catalog.json is committed"
	@echo "and embedded at internal/apps/kacho/seed/embedded/permission_catalog.json."
