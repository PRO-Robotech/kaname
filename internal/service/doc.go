// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package service — use-case-слой kacho-iam (Clean Architecture, service-слой).
//
// Содержит бизнес-логику, не зависящую от транспорта (gRPC/HTTP) и storage
// (pgx/sqlc). Использует port-интерфейсы для repo и peer-клиентов; реализации
// инжектируются из cmd/kacho-iam/main.go.
package service
