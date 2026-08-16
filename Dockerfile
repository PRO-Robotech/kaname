# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Standalone single-repo build: kacho-iam несет proto-stubs локально (proto/gen) и
# подключает kacho-corelib как versioned-модуль с GitHub — siblings в build-context
# не нужны (нет COPY ../kacho-*; go mod download тянет зависимости с GitHub).
COPY . .

# КЭШ КОМПИЛЯЦИИ — ОБЩИЙ НА ВСЕ ОБРАЗЫ ЭТОГО МОДУЛЯ.
#
# Восемь образов компилируют ОДИН И ТОТ ЖЕ модуль: 3995 собранных пакетов
# суммарно против 879 в объединении, то есть 78% работы — повторная. Кэш
# buildkit принадлежит builder'у, а не образу, поэтому второй и далее образы
# на той же машине берут готовое.
#
# ЭТО НЕ КЛАСС «КЭШ СОХРАНИЛ НЕУДАЧУ»: кэш компиляции Go контент-адресуем —
# недописанная или битая запись не находится по хэшу входов и просто вызывает
# перекомпиляцию. Гейтить сохранение по исходу шага здесь нечего.
#
# Директивы `# syntax=` намеренно нет: встроенный frontend buildkit `--mount`
# понимает (проверено), а `docker/dockerfile:1` — движущийся тег, то есть версия
# менялась бы без правки дерева, плюс сетевая тяга на каждом builder'е. Сборка
# со ВЫКЛЮЧЕННЫМ buildkit падает громко и по имени («requires BuildKit»).
RUN --mount=type=cache,target=/go/pkg/mod go mod download
# Skill evgeniy §9 K.1 / AP-9: независимые binary в одном образе.
# kacho-iam       — gRPC API-сервер (единственный subcommand — `serve`).
# kacho-migrator  — CLI миграций (cobra: up|down|status|create), используется
#                   init-container'ом перед стартом основного pod'а.
#
# JWKS-ротатора здесь НЕТ и быть не должно: iam не чеканит токены и не владеет
# ключом подписи. Издатель/подписант — Hydra; iam лишь ПРОКСИРУЕТ публичный JWKS
# Hydra байт-в-байт (internal/handler/jwksproxyhttp, :9097). Ротировать iam
# нечего — см. комментарий там же.
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-iam ./services/iam/cmd/kacho-iam \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-migrator ./services/iam/cmd/migrator

FROM mirror.gcr.io/library/alpine:3.24
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /kacho-iam /usr/local/bin/kacho-iam
COPY --from=builder /kacho-migrator /usr/local/bin/kacho-migrator
USER 65532
ENTRYPOINT ["/usr/local/bin/kacho-iam"]
