// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

import "embed"

// FS — embedded миграции (squashed baseline в одном файле).
// Используется cmd/migrator/main.go через runner.Config.FS.
//
//go:embed *.sql
var FS embed.FS

// Historical contains the exact retired collision lineage for upgrade evidence.
// It is deliberately separate from FS: goose must never collect both 90000s.
//
//go:embed historical/*.sql
var Historical embed.FS
