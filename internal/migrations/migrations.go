// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package migrations

import "embed"

// FS — embedded миграции (squashed baseline в одном файле).
// Используется cmd/migrator/main.go через runner.Config.FS.
//
//go:embed *.sql
var FS embed.FS
