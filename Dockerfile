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
# kacho-iam       — gRPC API-сервер (только `serve`); также несет sub-command
#                   `jwks rotate`, который использует jwks-rotator CronJob.
# kacho-migrator  — CLI миграций (cobra: up|down|status|create), используется
#                   init-container'ом перед стартом основного pod'а.
# jwks-rotator    — отдельный standalone binary для JWKS-ротации (once|daemon|
#                   dpop-cleanup); собирается в образ для прямого запуска.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-iam ./services/iam/cmd/kacho-iam \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /kacho-migrator ./services/iam/cmd/migrator \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /jwks-rotator ./services/iam/cmd/jwks-rotator

FROM mirror.gcr.io/library/alpine:3.20
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /kacho-iam /usr/local/bin/kacho-iam
COPY --from=builder /kacho-migrator /usr/local/bin/kacho-migrator
COPY --from=builder /jwks-rotator /usr/local/bin/jwks-rotator
USER 65532
ENTRYPOINT ["/usr/local/bin/kacho-iam"]
