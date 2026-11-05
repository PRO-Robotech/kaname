// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

import "embed"

// FS — embedded миграции (squashed baseline в одном файле).
// Используется cmd/migrator/main.go через runner.Config.FS.
//
//go:embed *.sql
var FS embed.FS

// Historical содержит точную снятую конфликтующую линию для доказательств обновления.
// Она намеренно отделена от FS: goose никогда не должен собирать обе 90000.
//
//go:embed historical/*.sql
var Historical embed.FS
