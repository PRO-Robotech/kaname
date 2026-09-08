// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// iface.go — re-export CQRS-типов из internal/repo/kaname под коротким именем
// (`Repo` / `Reader` / `Writer`). Parity с account/iface.go.

import (
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type (
	Repo   = kanamerepo.Repository
	Reader = kanamerepo.Reader
	Writer = kanamerepo.Writer
)
