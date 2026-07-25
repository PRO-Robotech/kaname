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

RUN go mod download
# Skill evgeniy §9 K.1 / AP-9: независимые binary в одном образе.
# kacho-iam       — gRPC API-сервер (единственный subcommand — `serve`).
# kacho-migrator  — CLI миграций (cobra: up|down|status|create), используется
#                   init-container'ом перед стартом основного pod'а.
#
# JWKS-ротатора здесь НЕТ и быть не должно: iam не чеканит токены и не владеет
# ключом подписи. Издатель/подписант — Hydra; iam лишь ПРОКСИРУЕТ публичный JWKS
# Hydra байт-в-байт (internal/handler/jwksproxyhttp, :9097). Ротировать iam
# нечего — см. комментарий там же.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-iam ./services/iam/cmd/kacho-iam \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-migrator ./services/iam/cmd/migrator

FROM mirror.gcr.io/library/alpine:3.24
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /kacho-iam /usr/local/bin/kacho-iam
COPY --from=builder /kacho-migrator /usr/local/bin/kacho-migrator
USER 65532
ENTRYPOINT ["/usr/local/bin/kacho-iam"]
