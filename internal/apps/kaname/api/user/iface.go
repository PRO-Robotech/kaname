// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// iface.go — re-export CQRS-типов под коротким именем (parity с account/iface.go).

import (
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type (
	Repo   = kanamerepo.Repository
	Reader = kanamerepo.Reader
	Writer = kanamerepo.Writer
)
