# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

BINARY         := kacho-iam
CMD            := ./cmd/kacho-iam
# Отдельный binary мигратора.
MIGRATOR_BIN   := kacho-migrator
MIGRATOR_CMD   := ./cmd/migrator
IMAGE          := kacho-iam:dev

.PHONY: build build-migrator test test-short vet lint docker generate audit-list-filter
.PHONY: proto-install-plugins proto-vendor proto-lint proto-gen

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) $(CMD)

build-migrator:
	CGO_ENABLED=0 go build -o bin/$(MIGRATOR_BIN) $(MIGRATOR_CMD)

# Каноничная команда живёт в КОРНЕВОМ Makefile — здесь только делегация: у флагов
# и бюджета прогона должна быть ОДНА истина. Собственный `-timeout` в этом файле
# ни с CI, ни с соседними сервисами не сверялся ничем и разъехался (300s/900s
# вразнобой, и там где мало — молча недостижимо).
test:
	$(MAKE) -C ../.. test-service SVC=iam

test-short:
	$(MAKE) -C ../.. test-service-short SVC=iam

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# audit-list-filter — CI gate for kacho-iam's listing surface: every method that
# hands a page to a caller must narrow it, and must declare HOW. What is checked
# lives in tools/listfiltergate; how this service is laid out lives in
# services/iam/tools/auditlistfilter.
#
# iam carries the widest listing surface in the repository — 30 methods across 21
# packages, more than compute, nlb, registry and storage together — and for a long
# time had no gate of this class at all. Nothing was red, because the set of
# services to analyse was written by hand and iam was in neither the CI loop nor the
# set of directories anyone remembered to create.
#
# The check parses the tree, so a resource is recognised by what its declaration IS —
# a package declaring a listing method on the transport type — and never by which
# file holds it; see tools/listfiltergate for the whole contract.
#
# The run always prints its census (files, packages, resources, listing methods,
# undeclared, cluster-scoped): "zero findings" must be distinguishable from "zero
# read", so a tree the gate could not open is a finding, not an OK. Exclusions live
# in the profile as a declared SHAPE, next to the reason for each, and an exclusion
# with nothing left to exclude is a finding too — which is how the `conditions`
# entry left: its subject was retired, so there was nothing for it to describe.
#
# Invoked by CI as `make -C services/iam audit-list-filter`. That it is invoked at
# all is locked twice over: internal/repohygiene/listfiltergatewiring_test.go
# derives the service list from this Makefile and from the workflow and compares
# them in both directions, and tools/listfiltergate/coverage_test.go reports an
# unanalysed service as a finding.
audit-list-filter:
	@./tools/audit-list-filter.sh

# Общая `operations`-таблица из kacho-corelib/migrations/common/0001_operations.sql
# встроена inline в internal/migrations/0001_initial.sql под схемой kacho_iam.
# Re-копирование common-файла создало бы конфликтующий unqualified
# public.operations — отсюда no-op.
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
# Копия каталога у iam ОБЯЗАНА побайтово совпадать с копией шлюза — это один
# источник истины, и гейт `make -C ../../gateway permission-catalog-check` роняет
# сборку при расхождении. Раньше цель печатала два предложения и выходила с нулём:
# после регенерации у шлюза её вызывали, она сообщала «всё уже на месте», и копии
# расходились ровно тогда, когда синхронизация и требовалась. Теперь цель делает
# то, что называет, и проверяет результат.
GATEWAY_CATALOG := ../../gateway/internal/middleware/embed/permission_catalog.json
IAM_CATALOG_EMBED := internal/apps/kacho/seed/embedded/permission_catalog.json
.PHONY: sync-permission-catalog
sync-permission-catalog:
	@test -f "$(GATEWAY_CATALOG)" || { echo "нет копии шлюза: $(GATEWAY_CATALOG) — нужен полный чекаут монорепо"; exit 1; }
	cp "$(GATEWAY_CATALOG)" "$(IAM_CATALOG_EMBED)"
	@cmp -s "$(GATEWAY_CATALOG)" "$(IAM_CATALOG_EMBED)" || { echo "копии разошлись после копирования"; exit 1; }
	@echo "каталог прав синхронизирован из копии шлюза (побайтово)."
