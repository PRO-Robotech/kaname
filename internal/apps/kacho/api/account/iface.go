// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// iface.go — re-export CQRS-типов из internal/repo/kacho под коротким именем
// (`Repo` / `Reader` / `Writer`). Use-case-код не импортирует pgx — только
// iface'ы из repo-слоя.

import (
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// Type-alias (не type wrap) — тип взаимозаменяем с источником.
type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)
