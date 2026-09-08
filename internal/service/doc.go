// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package service — use-case-слой kaname (Clean Architecture, service-слой).
//
// Содержит бизнес-логику, не зависящую от транспорта (gRPC/HTTP) и storage
// (pgx/sqlc). Использует port-интерфейсы для repo и peer-клиентов; реализации
// инжектируются из cmd/kaname/main.go.
package service
