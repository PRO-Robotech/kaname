// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// iface.go — re-export CQRS-типов из internal/repo/kaname под коротким именем
// (`Repo` / `Reader` / `Writer`). Use-case-код не импортирует pgx — только
// iface'ы из repo-слоя.

import (
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Type-alias (не type wrap) — тип взаимозаменяем с источником.
type (
	Repo   = kanamerepo.Repository
	Reader = kanamerepo.Reader
	Writer = kanamerepo.Writer
)
